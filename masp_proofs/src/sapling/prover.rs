use crate::circuit::append::Append;
use crate::circuit::authenticate::Authenticate;
use crate::circuit::convert::Convert;
use crate::circuit::sapling::{Output, Spend};
use bellman::{
    gadgets::multipack,
    groth16::{Parameters, PreparedVerifyingKey, Proof, create_random_proof, verify_proof},
};
use bls12_381::Bls12;
use group::cofactor::CofactorGroup;
use group::ff::Field;
use group::{Curve, GroupEncoding};
use masp_primitives::merkle_tree::Hashable;
use masp_primitives::{
    asset_type::AssetType,
    constants::{spending_key_generator, value_commitment_randomness_generator},
    convert::AllowedConversion,
    merkle_tree::MerklePath,
    sapling::{
        Diversifier, Node, Note, PaymentAddress, ProofGenerationKey, Rseed,
        redjubjub::{PrivateKey, PublicKey, Signature},
    },
    transaction::components::I128Sum,
};
use rand_core::OsRng;
use std::ops::{AddAssign, Neg};
use group::ff::PrimeField;

/// A context object for creating the Sapling components of a Zcash transaction.
pub struct SaplingProvingContext {
    bsk: jubjub::Fr,
    // (sum of the Spend value commitments) - (sum of the Output value commitments)
    cv_sum: jubjub::ExtendedPoint,
}

impl Default for SaplingProvingContext {
    fn default() -> Self {
        SaplingProvingContext::new()
    }
}

impl SaplingProvingContext {
    /// Construct a new context to be used with a single transaction.
    pub fn new() -> Self {
        SaplingProvingContext {
            bsk: jubjub::Fr::zero(),
            cv_sum: jubjub::ExtendedPoint::identity(),
        }
    }

    /// Create the value commitment, re-randomized key, and proof for a Sapling
    /// SpendDescription, while accumulating its value commitment randomness
    /// inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn spend_proof(
        &mut self,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        asset_type: AssetType,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        proving_key: &Parameters<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
        rcv: jubjub::Fr,
    ) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint, PublicKey), ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv;
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment
        let value_commitment = asset_type.value_commitment(value, rcv);

        // Construct the viewing key
        let viewing_key = proof_generation_key.to_viewing_key();

        // Construct the payment address with the viewing key / diversifier
        let payment_address = viewing_key.to_payment_address(diversifier).ok_or(())?;

        // This is the result of the re-randomization, we compute it for the caller
        let rk = PublicKey(proof_generation_key.ak.into()).randomize(ar, spending_key_generator());

        // Let's compute the nullifier while we have the position
        let note = Note {
            asset_type,
            value,
            g_d: diversifier.g_d().expect("was a valid diversifier before"),
            pk_d: *payment_address.pk_d(),
            rseed,
        };

        let nullifier = note.nf(&viewing_key.nk, merkle_path.position);

        // We now have the full witness for our circuit
        let instance = Spend {
            value_commitment: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key),
            payment_address: Some(payment_address),
            commitment_randomness: Some(note.rcm()),
            ar: Some(ar),
            auth_path: merkle_path
                .auth_path
                .iter()
                .map(|(node, b)| Some(((*node).into(), *b)))
                .collect(),
            anchor: Some(anchor),
        };

        // Create proof
        let proof =
            create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

        // Try to verify the proof:
        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::ZERO; 7];
        {
            let affine = rk.0.to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[0] = u;
            public_input[1] = v;
        }
        {
            let affine = jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[2] = u;
            public_input[3] = v;
        }
        public_input[4] = anchor;

        // Add the nullifier through multiscalar packing
        {
            let nullifier = multipack::bytes_to_bits_le(&nullifier.0);
            let nullifier = multipack::compute_multipacking(&nullifier);

            assert_eq!(nullifier.len(), 2);

            public_input[5] = nullifier[0];
            public_input[6] = nullifier[1];
        }

        // Verify the proof
        verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;

        // Compute value commitment
        let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

        // Accumulate the value commitment in the context
        self.cv_sum += value_commitment;

        Ok((proof, value_commitment, rk))
    }

    /// Create the value commitment and proof for a Sapling OutputDescription,
    /// while accumulating its value commitment randomness inside the context
    /// for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn output_proof(
        &mut self,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        asset_type: AssetType,
        value: u64,
        proving_key: &Parameters<Bls12>,
        rcv: jubjub::Fr,
    ) -> (Proof<Bls12>, jubjub::ExtendedPoint) {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv.neg(); // Outputs subtract from the total.
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment for the proof instance
        let value_commitment = asset_type.value_commitment(value, rcv);

        // Compute the actual value commitment
        let value_commitment_point: jubjub::ExtendedPoint = value_commitment.commitment().into();

        // We now have a full witness for the output proof.
        let instance = Output {
            value_commitment: Some(value_commitment),
            payment_address: Some(payment_address),
            commitment_randomness: Some(rcm),
            esk: Some(esk),
            asset_identifier: asset_type.identifier_bits(),
        };

        // Create proof
        let proof =
            create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

        // Accumulate the value commitment in the context. We do this to check internal consistency.
        self.cv_sum -= value_commitment_point; // Outputs subtract from the total.

        (proof, value_commitment_point)
    }

    /// Create the value commitment and proof for a ConvertDescription,
    /// while accumulating its value commitment randomness inside the context
    /// for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn convert_proof(
        &mut self,
        allowed_conversion: AllowedConversion,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
        proving_key: &Parameters<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
        rcv: jubjub::Fr,
    ) -> Result<(Proof<Bls12>, jubjub::ExtendedPoint), ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Accumulate the value commitment randomness in the context
        {
            let mut tmp = rcv;
            tmp.add_assign(&self.bsk);

            // Update the context
            self.bsk = tmp;
        }

        // Construct the value commitment
        let value_commitment = allowed_conversion.value_commitment(value, rcv);

        // We now have the full witness for our circuit
        let instance = Convert {
            value_commitment: Some(value_commitment.clone()),
            auth_path: merkle_path
                .auth_path
                .iter()
                .map(|(node, b)| Some(((*node).into(), *b)))
                .collect(),
            anchor: Some(anchor),
        };

        // Create proof
        let proof =
            create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

        // Try to verify the proof:
        // Construct public input for circuit
        let mut public_input = [bls12_381::Scalar::ZERO; 3];
        {
            let affine = jubjub::ExtendedPoint::from(value_commitment.commitment()).to_affine();
            let (u, v) = (affine.get_u(), affine.get_v());
            public_input[0] = u;
            public_input[1] = v;
        }
        public_input[2] = anchor;

        // Verify the proof
        verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;

        // Compute value commitment
        let value_commitment: jubjub::ExtendedPoint = value_commitment.commitment().into();

        // Accumulate the value commitment in the context
        self.cv_sum += value_commitment;

        Ok((proof, value_commitment))
    }

    /// Create the bindingSig for a Sapling transaction. All calls to spend_proof()
    /// and output_proof() must be completed before calling this function.
    pub fn binding_sig(
        &self,
        assets_and_values: &I128Sum,
        sighash: &[u8; 32],
    ) -> Result<(PublicKey, jubjub::Fr, Signature), ()> {
        // Initialize secure RNG
        let mut rng = OsRng;

        // Grab the current `bsk` from the context
        let bsk = PrivateKey(self.bsk);

        // Grab the `bvk` using DerivePublic.
        let bvk = PublicKey::from_private(&bsk, value_commitment_randomness_generator());

        // In order to check internal consistency, let's use the accumulated value
        // commitments (as the verifier would) and apply value_balance to compare
        // against our derived bvk.
        {
            // Compute cv_sum minus sum of all value balances
            let final_bvk =
                self.cv_sum - jubjub::ExtendedPoint::from(assets_and_values).clear_cofactor();
            // The result should be the same, unless the provided valueBalance is wrong.
            if bvk.0 != final_bvk {
                return Err(());
            }
        }

        // Construct signature message
        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

        // Sign
        let (c, sig) = bsk.sign(
            &data_to_be_signed,
            &mut rng,
            value_commitment_randomness_generator(),
        );
        Ok((bvk, c, sig))
    }
}

/// Create a new Merkle tree root by inserting new note commitments at the
/// given path and also return a proof that the new root was computed
/// correctly.
pub fn append_proof(
    merkle_path: MerklePath<Node>,
    new_cmus: Vec<Node>,
    proving_key: &Parameters<Bls12>,
    verifying_key: &PreparedVerifyingKey<Bls12>,
) -> Result<(Proof<Bls12>, Node, bls12_381::Scalar), ()> {
    // Initialize secure RNG
    let mut rng = OsRng;

    // We already have the full witness for our circuit
    let instance = Append {
        old_size: Some(merkle_path.position.into()),
        auth_path: merkle_path
            .auth_path
            .iter()
            .map(|(node, _b)| Some((*node).into()))
            .collect(),
        new_cmus: new_cmus
            .iter()
            .map(|x| Some(bls12_381::Scalar::from(*x)))
            .collect(),
    };

    // Create proof
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");

    // Try to verify the proof:
    // Construct public input for circuit
    let mut public_input = [bls12_381::Scalar::ZERO; 4];
    public_input[0] = merkle_path.position.into();
    public_input[1] = merkle_path.root(Node::blank()).into();
    public_input[2] = merkle_path.batch_root(new_cmus.clone())?.into();
    for cmu in new_cmus.iter().rev() {
        public_input[3] *= public_input[2];
        public_input[3] += bls12_381::Scalar::from(*cmu);
    }

    // Verify the proof
    verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;

    Ok((proof, Node::from_scalar(public_input[2]), public_input[3]))
}

// Convert i128 to Jubjub scalar respecting the modulus
pub fn i128_to_scalar(a: i128) -> jubjub::Fr {
    // Compute the absolute value
    let abs = if a >= 0 {
        a as u128
    } else {
        (-(a+1)) as u128
    };
    // Compute it in the exponent
    let mut abs_bytes = [0u8; 32];
    abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
    let abs_scalar = jubjub::Fr::from_bytes(&abs_bytes).unwrap();
    // Negate if necessary
    if a >= 0 {
        abs_scalar
    } else {
        -abs_scalar - jubjub::Fr::one()
    }
}

/// Prove that the given binding signature and spend authorizations siganture are
/// valid with respect to the message constant. Also prove that the given value
/// balance was computed correctly.
pub fn authenticate_proof(
    bvk: PublicKey,
    binding_c: jubjub::Fr,
    binding_sig: Signature,
    rks: PublicKey,
    spend_auths_c: jubjub::Fr,
    spend_auths_sig: Signature,
    value_sum: I128Sum,
    max_asset_types: usize,
    proving_key: &Parameters<Bls12>,
    verifying_key: &PreparedVerifyingKey<Bls12>,
) -> Result<(Proof<Bls12>, bls12_381::Scalar, bls12_381::Scalar, bls12_381::Scalar, bls12_381::Scalar), ()> {
    // Initialize secure RNG
    let mut rng = OsRng;

    // Compute asset generator witnesses
    let mut value_balance = vec![(Some(jubjub::ExtendedPoint::identity()), Some(jubjub::Fr::ZERO)); max_asset_types];
    for (i, (asset_type, value)) in value_sum.components().enumerate() {
        value_balance[i] = (Some(asset_type.asset_generator()), Some(i128_to_scalar(*value)));
    }
    // We now have the full witness for our circuit
    let instance = Authenticate {
        binding_c: Some(binding_c),
        spend_auths_c: Some(spend_auths_c),
        bvk: Some(bvk),
        rks: Some(rks),
        binding_sig: Some(binding_sig),
        spend_auths_sig: Some(spend_auths_sig),
        value_balance: value_balance.clone(),
    };
    // Create proof
    let proof =
        create_random_proof(instance, proving_key, &mut rng).expect("proving should not fail");
    // Extract the chalenge variables
    let binding_sig_r = jubjub::ExtendedPoint::from_bytes(&binding_sig.rbar()).unwrap().to_affine();
    let spend_auths_sig_r = jubjub::ExtendedPoint::from_bytes(&spend_auths_sig.rbar()).unwrap().to_affine();
    let neg_binding_s = -jubjub::Fr::from_repr(binding_sig.sbar()).unwrap();
    let neg_binding_s = bls12_381::Scalar::from_repr(neg_binding_s.to_repr()).unwrap();
    let binding_c = bls12_381::Scalar::from_repr(binding_c.to_repr()).unwrap();
    let neg_spend_auths_s = -jubjub::Fr::from_repr(spend_auths_sig.sbar()).unwrap();
    let neg_spend_auths_s = bls12_381::Scalar::from_repr(neg_spend_auths_s.to_repr()).unwrap();
    let spend_auths_c = bls12_381::Scalar::from_repr(spend_auths_c.to_repr()).unwrap();
    // Prepare the polynomial coefficients
    let mut x_vars = vec![
        neg_binding_s,
        binding_c,
        bvk.0.to_affine().get_u(),
        rks.0.to_affine().get_u(),
        binding_sig_r.get_u(),
        spend_auths_sig_r.get_u(),
    ];
    let mut y_vars = vec![
        neg_spend_auths_s,
        spend_auths_c,
        bvk.0.to_affine().get_v(),
        rks.0.to_affine().get_v(),
        binding_sig_r.get_v(),
        spend_auths_sig_r.get_v(),
    ];
    for (asset_generator, value) in value_balance {
        let value_commitment_generator = asset_generator.unwrap().mul_by_cofactor().to_affine();
        x_vars.push(value_commitment_generator.get_u());
        y_vars.push(bls12_381::Scalar::from_repr(value.unwrap().to_repr()).unwrap());
    }
    let value_sum = jubjub::ExtendedPoint::from(&value_sum).mul_by_cofactor();
    x_vars.push(value_sum.to_affine().get_u());
    y_vars.push(value_sum.to_affine().get_v());
    // Compute the challenges
    let mut x_challenge = Node::blank();
    let mut y_challenge = Node::blank();
    for (i, (x_var, y_var)) in x_vars.iter().zip(y_vars.iter()).enumerate().rev() {
        x_challenge = Node::combine(i, &Node::from_scalar(*x_var), &x_challenge);
        y_challenge = Node::combine(i, &Node::from_scalar(*y_var), &y_challenge);
    }
    // Compute the challenge responses
    let x_challenge = bls12_381::Scalar::from(x_challenge);
    let y_challenge = bls12_381::Scalar::from(y_challenge);
    let mut x_response = bls12_381::Scalar::ZERO;
    let mut y_response = bls12_381::Scalar::ZERO;
    for (x_var, y_var) in x_vars.into_iter().zip(y_vars) {
        x_response = x_response * x_challenge + x_var;
        y_response = y_response * y_challenge + y_var;
    }
    // Try to verify the proof:
    // Construct public input for circuit
    let mut public_input = [bls12_381::Scalar::ZERO; 4];
    public_input[0] = x_challenge;
    public_input[1] = x_response;
    public_input[2] = y_challenge;
    public_input[3] = y_response;

    // Verify the proof
    verify_proof(verifying_key, &proof, &public_input[..]).map_err(|_| ())?;
    Ok((proof, public_input[0], public_input[1], public_input[2], public_input[3]))
}

use masp_primitives::sapling::redjubjub::Signature;
use masp_primitives::sapling::redjubjub::PublicKey;
use bellman::SynthesisError;
use bellman::Circuit;
use bellman::ConstraintSystem;
use group::ff::PrimeField;
use jubjub::ExtendedPoint;
use group::GroupEncoding;
use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::{Assignment, num};
use bellman::LinearCombination;
use group::ff::Field;
use masp_primitives::sapling::Node;
use masp_primitives::merkle_tree::Hashable;
use crate::constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR, FixedGenerator};
use super::ecc;
use super::gadgets;
use super::pedersen_hash;

/// Maximum number of assets that can be included in value balance
pub const MAX_ASSETS: usize = 6;

/// This is an instance of the `Authenticate` circuit.
pub struct Authenticate {
    /// Binding validating key
    pub bvk: Option<PublicKey>,
    /// Randomized validating key
    pub rks: Option<PublicKey>,
    /// c value used in binding signature validation
    pub binding_c: Option<jubjub::Fr>,
    /// c value used in spend authorizations signature validation
    pub spend_auths_c: Option<jubjub::Fr>,
    /// Binding signature
    pub binding_sig: Option<Signature>,
    /// Spend authorizations signature
    pub spend_auths_sig: Option<Signature>,
    /// Balancing value
    pub value_balance: Vec<(Option<jubjub::ExtendedPoint>, Option<jubjub::Fr>)>,
}

// Assert that the given point is the zero point
fn assert_zero_point<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    p: &ecc::EdwardsPoint,
) -> Result<(), SynthesisError> {
    // u coordinate must be zero
    cs.enforce(
        || "u coordinate must be zero",
        |lc| lc,
        |lc| lc,
        |lc| lc + p.get_u().get_variable(),
    );
    // v coordinate must be one
    cs.enforce(
        || "v coordinate must be one",
        |lc| lc,
        |lc| lc,
        |lc| lc + p.get_v().get_variable() - CS::one(),
    );
    Ok(())
}

// Validate the given signture against the given validating key and message derivative.
// Enforces the equation: h([-S]P + R + [c]vk) = O
fn validate_signature<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    base: FixedGenerator,
    vk: &ecc::EdwardsPoint,
    r: &ecc::EdwardsPoint,
    c: &[Boolean],
    neg_s: &[Boolean],
) -> Result<(), SynthesisError> {
    // Compute the parts of the signature validation expression
    let neg_s_times_p = ecc::fixed_base_multiplication(
        cs.namespace(|| "compute [-S]P"),
        base,
        &neg_s,
    )?;
    let c_times_vk = vk.mul(cs.namespace(|| "compute [c]vk"), &c)?;
    // The signature validation expression from the Redjubjub specification
    let expr = neg_s_times_p
        .add(cs.namespace(|| "compute [-S]P + R"), &r)?
        .add(cs.namespace(|| "compute [-S]P + R + [c]vk"), &c_times_vk)?
        .double(cs.namespace(|| "signature verification first doubling"))?
        .double(cs.namespace(|| "signature verification second doubling"))?
        .double(cs.namespace(|| "signature verification third doubling"))?;
    // Force the expression to equal the zero point by examining coordinates
    assert_zero_point(cs.namespace(|| "validation expression must equal zero point"), &expr)?;
    Ok(())
}

// Allocate variables necessary for signature validation using the given
// witnesses, validate the given signature, and return the variables.
fn process_signature<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    base: FixedGenerator,
    vk: Option<PublicKey>,
    c: Option<jubjub::Fr>,
    sig: Option<Signature>,
) -> Result<(ecc::EdwardsPoint, ecc::EdwardsPoint, Vec<Boolean>, Vec<Boolean>), SynthesisError> {
    // Allocate signature variables using the given witnesses
    let vk = ecc::EdwardsPoint::witness(
        cs.namespace(|| "validating key"),
        vk.as_ref().map(|a| a.0),
    )?;
    let c = gadgets::field_into_boolean_vec_le(cs.namespace(|| "c"), c)?;
    let neg_s = gadgets::field_into_boolean_vec_le(
        cs.namespace(|| "signature S negated"),
        sig.as_ref().map(|x| -jubjub::Fr::from_repr(x.sbar()).unwrap()),
    )?;
    let r = ecc::EdwardsPoint::witness(
        cs.namespace(|| "signature R"),
        sig.as_ref().map(|a| ExtendedPoint::from_bytes(&a.rbar()).unwrap()),
    )?;
    // Then make constraints to validate the signature
    validate_signature(
        cs.namespace(|| "signature verification"),
        base,
        &vk,
        &r,
        &c,
        &neg_s,
    )?;
    Ok((vk, r, c, neg_s))
}

// Convert a little endian vector of bits into an allocated number
pub fn boolean_vec_le_into_field<Scalar, CS>(
    mut cs: CS,
    bits: Vec<Boolean>,
) -> Result<num::AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    // The location where allocated bits will be accumulated
    let mut lc = LinearCombination::<Scalar>::zero();
    // Where the powers of two will be maintained
    let mut coeff = Scalar::ONE;
    // The location where the witness will be accumulated
    let mut value = Some(Scalar::ZERO);

    for bit in bits.iter() {
        // Maintain the witness if possible
        value = value.zip(bit.get_value())
            .map(|(value, b)| if b { value + coeff } else { value });
        // Add the current bit to the accumulator
        lc = lc + &bit.lc(CS::one(), coeff);
        // Ensure next iteration has correct power of two
        coeff = coeff.double();
    }
    // Finally construct the allocated number
    let val = num::AllocatedNum::alloc(cs.namespace(|| "value"), || Ok(*value.get()?))?;
    // Force the number to equal the linear combination of bits
    lc = lc - val.get_variable();
    cs.enforce(|| "unpacking constraint", |lc| lc, |lc| lc, |_| lc);
    Ok(val)
}

// Commit to the given vector of inputs
pub fn commit<CS>(
    mut cs: CS,
    vars: &Vec<num::AllocatedNum<bls12_381::Scalar>>,
) -> Result<num::AllocatedNum<bls12_381::Scalar>, SynthesisError> where
    CS: ConstraintSystem<bls12_381::Scalar>, {
    let blank = bls12_381::Scalar::from(Node::blank());
    // Where the commitment hashes are accumulated
    let mut commitment = num::AllocatedNum::alloc(
        cs.namespace(|| format!("partial commitment {}", vars.len())),
        || Ok(bls12_381::Scalar::from(blank)),
    )?;
    // Force our new variable to equal to the blank node
    let lc = LinearCombination::from_variable(commitment.get_variable()) - (blank, CS::one());
    cs.enforce(|| "ensure empty leaf 0", |lc| lc, |lc| lc, |_| lc);
    // Repeateddly use binary hash function to commit to all inputs
    for (i, var) in vars.iter().enumerate().rev() {
        // Convert allocated numbers to bits in preparation for hashing
        let mut partial_commitment_bits = Vec::new();
        partial_commitment_bits.append(&mut var.to_bits_le(cs.namespace(|| format!("var {} to bits", i)))?);
        partial_commitment_bits.append(&mut commitment.to_bits_le(cs.namespace(|| format!("partial commitment {} to bits", i+1)))?);
        // Commit to the allocated numbers represented as bits
        commitment = pedersen_hash::pedersen_hash(
            cs.namespace(|| format!("partial commitment {}", i)),
            pedersen_hash::Personalization::MerkleTree(i),
            &partial_commitment_bits,
        )?.get_u().clone();
    }
    Ok(commitment)
}

// Expose a commitment to the given inputs and a polynomial computed over it
pub fn fiat_shamir<CS>(
    mut cs: CS,
    vars: Vec<num::AllocatedNum<bls12_381::Scalar>>,
) -> Result<(), SynthesisError> where
    CS: ConstraintSystem<bls12_381::Scalar>, {
    // Commit to the private inputs
    let challenge = commit(cs.namespace(|| "commit to inputs"), &vars)?;
    // Expose the challenge
    challenge.inputize(cs.namespace(|| "challenge"))?;
    // Evaluate a polynomial on the challenge
    let mut response =
        num::AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(bls12_381::Scalar::ZERO))?;
    // response = 0
    cs.enforce(
        || "enforce zero",
        |lc| lc,
        |lc| lc,
        |_| LinearCombination::from_variable(response.get_variable()),
    );
    for (i, var) in vars.iter().enumerate() {
        // new_response = response*challenge + var
        let partial_response = num::AllocatedNum::alloc(
            cs.namespace(|| format!("partial response {}", i)),
            || {
                Ok(response.get_value().get()? * challenge.get_value().get()?
                   + var.get_value().get()?)
            },
        )?;
        let la = LinearCombination::from_variable(response.get_variable());
        let lb = LinearCombination::from_variable(challenge.get_variable());
        let lc = LinearCombination::from_variable(partial_response.get_variable())
            - var.get_variable();
        cs.enforce(
            || format!("partial response constraint {}", i),
            |_| la,
            |_| lb,
            |_| lc,
        );
        response = partial_response;
    }
    // Make the response public
    response.inputize(cs.namespace(|| "response"))?;
    Ok(())
}

impl Circuit<bls12_381::Scalar> for Authenticate {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Process and validate the binding signature
        let (bvk, binding_r, binding_c, neg_binding_s) = process_signature(
            cs.namespace(|| "binding signature"),
            &VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
            self.bvk,
            self.binding_c,
            self.binding_sig,
        )?;
        // Validate the spend authorizations signature
        let (rks, spend_auths_r, spend_auths_c, neg_spend_auths_s) = process_signature(
            cs.namespace(|| "spend authorizations signature"),
            &SPENDING_KEY_GENERATOR,
            self.rks,
            self.spend_auths_c,
            self.spend_auths_sig,
        )?;
        // Initialize variables to be included in first challenge
        let mut x_vars = vec![
            boolean_vec_le_into_field(cs.namespace(|| "-binding S as scalar"), neg_binding_s)?,
            boolean_vec_le_into_field(cs.namespace(|| "binding c as scalar"), binding_c)?,
            bvk.get_u().clone(),
            rks.get_u().clone(),
            binding_r.get_u().clone(),
            spend_auths_r.get_u().clone(),
        ];
        // Initialize variables to be included in second challenge
        let mut y_vars = vec![
            boolean_vec_le_into_field(cs.namespace(|| "-spend authorizations S as scalar"), neg_spend_auths_s)?,
            boolean_vec_le_into_field(cs.namespace(|| "spend authorizations c as scalar"), spend_auths_c)?,
            bvk.get_v().clone(),
            rks.get_v().clone(),
            binding_r.get_v().clone(),
            spend_auths_r.get_v().clone(),
        ];
        
        // Compute the value balance
        let mut value_balance = ecc::EdwardsPoint::witness(
            cs.namespace(|| "zero point"),
            Some(ExtendedPoint::identity()),
        )?;
        // Initialize the value balance to the zero point
        assert_zero_point(cs.namespace(|| "initialize balancing value"), &value_balance)?;
        for (i, (asset_generator, value)) in self.value_balance.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("value balance component {}", i));
            let asset_generator = ecc::EdwardsPoint::witness(
                cs.namespace(|| "asset generator"),
                asset_generator,
            )?;
            let value = gadgets::field_into_boolean_vec_le(
                cs.namespace(|| "value"),
                value,
            )?;
            // Bind the value to the value commitment generator
            let value_commitment_generator = asset_generator
                .double(cs.namespace(|| "value commitment generator computation first doubling"))?
                .double(cs.namespace(|| "value commitment generator computation second doubling"))?
                .double(cs.namespace(|| "value commitment generator computation third doubling"))?;
            let component = value_commitment_generator.mul(cs.namespace(|| "compute [v]vb"), &value)?;
            // Accumulate this component onto the value balance
            value_balance = value_balance.add(cs.namespace(|| "accumulate value balance"), &component)?;
            // Record the value commitment generator
            x_vars.push(value_commitment_generator.get_u().clone());
            y_vars.push(boolean_vec_le_into_field(cs.namespace(|| "value as scalar"), value)?);
        }
        // Finally record the balancing value
        x_vars.push(value_balance.get_u().clone());
        y_vars.push(value_balance.get_v().clone());
        // Expose the inputs
        fiat_shamir(cs.namespace(|| "x variable inputs"), x_vars)?;
        fiat_shamir(cs.namespace(|| "y variable inputs"), y_vars)?;
        Ok(())
    }
}

#[test]
fn test_authenticate_circuit_with_bls12_381() {
    use bellman::gadgets::test::*;
    use group::ff::Field;

    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use rand_core::RngCore;
    use masp_primitives::sapling::redjubjub::PrivateKey;
    use masp_primitives::constants::{value_commitment_randomness_generator, spending_key_generator};
    use masp_primitives::sapling::redjubjub::h_star;
    use group::Curve;
    use masp_primitives::asset_type::AssetType;
    use masp_primitives::transaction::components::I128Sum;
    use crate::sapling::i128_to_scalar;

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for i in 0..32 {
        let r_sapling = value_commitment_randomness_generator();
        // Generate random key
        let bsk = PrivateKey(jubjub::Fr::random(&mut rng));
        let bvk = PublicKey::from_private(&bsk, r_sapling);
        // Generate random message
        let mut data_to_be_signed0 = [0u8; 64];
        rng.fill_bytes(&mut data_to_be_signed0);
        // Sign random message
        let binding_sig = bsk.sign(&data_to_be_signed0, &mut rng, r_sapling);
        // The c value used in validation
        let binding_c = h_star(&binding_sig.rbar()[..], &data_to_be_signed0);
        
        let g_sapling = spending_key_generator();
        // Generate random key
        let rsks = PrivateKey(jubjub::Fr::random(&mut rng));
        let rks = PublicKey::from_private(&rsks, g_sapling);
        // Generate random message
        let mut data_to_be_signed1 = [0u8; 64];
        rng.fill_bytes(&mut data_to_be_signed1);
        // Sign random message
        let spend_auths_sig = rsks.sign(&data_to_be_signed1, &mut rng, g_sapling);
        // The c value used in validation
        let spend_auths_c = h_star(&spend_auths_sig.rbar()[..], &data_to_be_signed1);

        // Generate a value balance
        let mut value_balance = Vec::new();
        let mut value_sum = I128Sum::zero();
        
        for _j in 0..i {
            let mut asset_type = [0u8; 64];
            rng.fill_bytes(&mut asset_type);
            let asset_type = AssetType::new(&asset_type).unwrap();
            let value: i64 = rng.next_u64() as i64;
            value_balance.push((Some(asset_type.asset_generator()), Some(i128_to_scalar(value.into()))));
            value_sum += I128Sum::from_pair(asset_type, i128::from(value));
        }

        {
            let mut cs = TestConstraintSystem::new();
            let instance = Authenticate {
                bvk: Some(bvk),
                rks: Some(rks),
                binding_c: Some(binding_c),
                spend_auths_c: Some(spend_auths_c),
                binding_sig: Some(binding_sig),
                spend_auths_sig: Some(spend_auths_sig),
                value_balance: value_balance.clone(),
            };

            instance.synthesize(&mut cs).unwrap();

            assert!(cs.is_satisfied());
            assert!(cs.num_constraints() >= 28450);
            assert!(cs.num_constraints() <= 223843);
            assert_eq!(cs.get("binding validating key/u/num"), bvk.0.to_affine().get_u());
            assert_eq!(cs.get("binding validating key/v/num"), bvk.0.to_affine().get_v());
            let binding_sig_r = ExtendedPoint::from_bytes(&binding_sig.rbar()).unwrap().to_affine();
            assert_eq!(cs.get("binding signature R/u/num"), binding_sig_r.get_u());
            assert_eq!(cs.get("binding signature R/v/num"), binding_sig_r.get_v());
            assert_eq!(cs.get("randomized validating key/u/num"), rks.0.to_affine().get_u());
            assert_eq!(cs.get("randomized validating key/v/num"), rks.0.to_affine().get_v());
            let spend_auths_sig_r = ExtendedPoint::from_bytes(&spend_auths_sig.rbar()).unwrap().to_affine();
            assert_eq!(cs.get("spend authorizations signature R/u/num"), spend_auths_sig_r.get_u());
            assert_eq!(cs.get("spend authorizations signature R/v/num"), spend_auths_sig_r.get_v());
            let neg_binding_s = -jubjub::Fr::from_repr(binding_sig.sbar()).unwrap();
            let neg_binding_s = bls12_381::Scalar::from_repr(neg_binding_s.to_repr()).unwrap();
            assert_eq!(cs.get("-binding S as scalar/value/num"), neg_binding_s);
            let binding_c = bls12_381::Scalar::from_repr(binding_c.to_repr()).unwrap();
            assert_eq!(cs.get("binding c as scalar/value/num"), binding_c);
            let neg_spend_auths_s = -jubjub::Fr::from_repr(spend_auths_sig.sbar()).unwrap();
            let neg_spend_auths_s = bls12_381::Scalar::from_repr(neg_spend_auths_s.to_repr()).unwrap();
            assert_eq!(cs.get("-spend authorizations S as scalar/value/num"), neg_spend_auths_s);
            let spend_auths_c = bls12_381::Scalar::from_repr(spend_auths_c.to_repr()).unwrap();
            assert_eq!(cs.get("spend authorizations c as scalar/value/num"), spend_auths_c);
            assert_eq!(cs.num_inputs(), 5);
            assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::ONE);
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

            let x_challenge = cs.get_input(1, "x variable inputs/challenge/input variable");
            let y_challenge = cs.get_input(3, "y variable inputs/challenge/input variable");
            let mut x_response = bls12_381::Scalar::ZERO;
            let mut y_response = bls12_381::Scalar::ZERO;
            for (x_var, y_var) in x_vars.into_iter().zip(y_vars) {
                x_response = x_response * x_challenge + x_var;
                y_response = y_response * y_challenge + y_var;
            }
            assert_eq!(cs.get_input(2, "x variable inputs/response/input variable"), x_response);
            assert_eq!(cs.get_input(4, "y variable inputs/response/input variable"), y_response);
        }
    }
}

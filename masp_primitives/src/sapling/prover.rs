//! Abstractions over the proving system and parameters.

use crate::{
    asset_type::AssetType,
    convert::AllowedConversion,
    merkle_tree::MerklePath,
    sapling::{
        redjubjub::{PublicKey, Signature},
        Node,
    },
    transaction::components::{I64Amt, GROTH_PROOF_SIZE},
};

use super::{Diversifier, PaymentAddress, ProofGenerationKey, Rseed};

/// Interface for creating zero-knowledge proofs for shielded transactions.
pub trait TxProver {
    /// Type for persisting any necessary context across multiple Sapling proofs.
    type SaplingProvingContext;

    /// Instantiate a new Sapling proving context.
    fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext;

    /// Create the value commitment, re-randomized key, and proof for a MASP
    /// [`SpendDescription`], while accumulating its value commitment randomness inside
    /// the context for later use.
    ///    
    /// [`SpendDescription`]: crate::transaction::components::SpendDescription
    #[allow(clippy::too_many_arguments)]
    fn spend_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        ar: jubjub::Fr,
        asset_type: AssetType,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()>;

    /// Create the value commitment and proof for a MASP OutputDescription,
    /// while accumulating its value commitment randomness inside the context for later
    /// use.
    ///
    fn output_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        esk: jubjub::Fr,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        asset_type: AssetType,
        value: u64,
    ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint);

    /// Create the value commitment, and proof for a MASP ConvertDescription,
    /// while accumulating its value commitment randomness inside
    /// the context for later use.
    ///
    fn convert_proof(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        allowed_conversion: AllowedConversion,
        value: u64,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath<Node>,
    ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()>;

    /// Create the `bindingSig` for a Sapling transaction. All calls to
    /// [`TxProver::spend_proof`] and [`TxProver::output_proof`] must be completed before
    /// calling this function.
    fn binding_sig(
        &self,
        ctx: &mut Self::SaplingProvingContext,
        amount: &I64Amt,
        sighash: &[u8; 32],
    ) -> Result<Signature, ()>;
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod mock {
    use ff::Field;
    use rand_core::OsRng;

    use crate::{
        asset_type::AssetType,
        constants::SPENDING_KEY_GENERATOR,
        convert::AllowedConversion,
        merkle_tree::MerklePath,
        sapling::{
            redjubjub::{PublicKey, Signature},
            Diversifier, Node, PaymentAddress, ProofGenerationKey, Rseed,
        },
        transaction::components::{I64Amt, GROTH_PROOF_SIZE},
    };

    use super::TxProver;

    pub struct MockTxProver;

    impl TxProver for MockTxProver {
        type SaplingProvingContext = ();

        fn new_sapling_proving_context(&self) -> Self::SaplingProvingContext {}

        fn spend_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            proof_generation_key: ProofGenerationKey,
            _diversifier: Diversifier,
            _rcm: Rseed,
            ar: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint, PublicKey), ()> {
            let mut rng = OsRng;

            let cv = asset_type
                .value_commitment(value, jubjub::Fr::random(&mut rng))
                .commitment()
                .into();

            let rk =
                PublicKey(proof_generation_key.ak.into()).randomize(ar, SPENDING_KEY_GENERATOR);

            Ok(([0u8; GROTH_PROOF_SIZE], cv, rk))
        }

        fn output_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _esk: jubjub::Fr,
            _payment_address: PaymentAddress,
            _rcm: jubjub::Fr,
            asset_type: AssetType,
            value: u64,
        ) -> ([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint) {
            let mut rng = OsRng;

            let cv = asset_type
                .value_commitment(value, jubjub::Fr::random(&mut rng))
                .commitment()
                .into();

            ([0u8; GROTH_PROOF_SIZE], cv)
        }

        fn convert_proof(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            allowed_conversion: AllowedConversion,
            value: u64,
            _anchor: bls12_381::Scalar,
            _merkle_path: MerklePath<Node>,
        ) -> Result<([u8; GROTH_PROOF_SIZE], jubjub::ExtendedPoint), ()> {
            let mut rng = OsRng;

            let cv = allowed_conversion
                .value_commitment(value, jubjub::Fr::random(&mut rng))
                .commitment()
                .into();

            Ok(([0u8; GROTH_PROOF_SIZE], cv))
        }

        fn binding_sig(
            &self,
            _ctx: &mut Self::SaplingProvingContext,
            _value: &I64Amt,
            _sighash: &[u8; 32],
        ) -> Result<Signature, ()> {
            Err(())
        }
    }
}

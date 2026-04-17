use bellman::groth16::{PreparedVerifyingKey, Proof, verify_proof};
use bls12_381::Bls12;
use group::GroupEncoding;
use masp_primitives::{
    constants::{spending_key_generator, value_commitment_randomness_generator},
    sapling::redjubjub::{PublicKey, Signature},
    transaction::components::I128Sum,
};

use super::SaplingVerificationContextInner;

/// A context object for verifying the Sapling components of a single Zcash transaction.
pub struct SaplingVerificationContext {
    inner: SaplingVerificationContextInner,
    zip216_enabled: bool,
}

impl SaplingVerificationContext {
    /// Construct a new context to be used with a single transaction.
    pub fn new(zip216_enabled: bool) -> Self {
        SaplingVerificationContext {
            inner: SaplingVerificationContextInner::new(),
            zip216_enabled,
        }
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn check_spend(
        &mut self,
        cv: jubjub::ExtendedPoint,
        anchor: bls12_381::Scalar,
        nullifier: &[u8; 32],
        rk: PublicKey,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        self.inner.check_spend(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            &mut (),
            |_, proof, public_inputs| {
                verify_proof(verifying_key, &proof, &public_inputs[..]).is_ok()
            },
        )
    }

    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    #[allow(clippy::too_many_arguments)]
    pub fn check_convert(
        &mut self,
        cv: jubjub::ExtendedPoint,
        anchor: bls12_381::Scalar,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        self.inner
            .check_convert(cv, anchor, zkproof, &mut (), |_, proof, public_inputs| {
                verify_proof(verifying_key, &proof, &public_inputs[..]).is_ok()
            })
    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    pub fn check_output(
        &mut self,
        cv: jubjub::ExtendedPoint,
        cmu: bls12_381::Scalar,
        epk: jubjub::ExtendedPoint,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        self.inner
            .check_output(cv, cmu, epk, zkproof, |proof, public_inputs| {
                verify_proof(verifying_key, &proof, &public_inputs[..]).is_ok()
            })
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    pub fn final_check(
        &self,
        sighash_value: &[u8; 32],
        value_balance: I128Sum,
        binding_sig: Signature,
        spend_auths_sig: Signature,
    ) -> bool {
        self.inner.final_check(
            sighash_value,
            value_balance,
            binding_sig,
            spend_auths_sig,
            |msg, bvk, binding_sig, rks, spend_auths_sig| {
                // Compute the signature's message for bvk/binding_sig
                let mut bvk_data_to_be_signed = [0u8; 64];
                bvk_data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
                bvk_data_to_be_signed[32..64].copy_from_slice(msg);

                // Compute the signature's message for rks/spend_auths_sig
                let mut rks_data_to_be_signed = [0u8; 64];
                rks_data_to_be_signed[0..32].copy_from_slice(&rks.0.to_bytes());
                rks_data_to_be_signed[32..64].copy_from_slice(msg);

                bvk.verify_with_zip216(
                    &bvk_data_to_be_signed,
                    &binding_sig,
                    value_commitment_randomness_generator(),
                    self.zip216_enabled,
                ) && rks.verify_with_zip216(
                    &rks_data_to_be_signed,
                    &spend_auths_sig,
                    spending_key_generator(),
                    self.zip216_enabled,
                )
            },
        )
    }
}

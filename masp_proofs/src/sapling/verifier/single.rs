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
        sighash_value: &[u8; 32],
        spend_auth_sig: Signature,
        zkproof: Proof<Bls12>,
        verifying_key: &PreparedVerifyingKey<Bls12>,
    ) -> bool {
        let zip216_enabled = true;
        self.inner.check_spend(
            cv,
            anchor,
            nullifier,
            rk,
            sighash_value,
            spend_auth_sig,
            zkproof,
            &mut (),
            |_, rk, msg, spend_auth_sig| {
                rk.verify_with_zip216(
                    &msg,
                    &spend_auth_sig,
                    spending_key_generator(),
                    zip216_enabled,
                )
            },
            |_, proof, public_inputs| {
                matches!(
                    verify_proof(verifying_key, &proof, &public_inputs[..]),
                    Ok(true)
                )
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
                matches!(
                    verify_proof(verifying_key, &proof, &public_inputs[..]),
                    Ok(true)
                )
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
                matches!(
                    verify_proof(verifying_key, &proof, &public_inputs[..]),
                    Ok(true)
                )
            })
    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    pub fn final_check(
        &self,
        value_balance: I128Sum,
        sighash_value: &[u8; 32],
        binding_sig: Signature,
    ) -> bool {
        self.inner.final_check(
            value_balance,
            sighash_value,
            binding_sig,
            |bvk, msg, binding_sig| {
                // Compute the signature's message for bvk/binding_sig
                let mut data_to_be_signed = [0u8; 64];
                data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
                data_to_be_signed[32..64].copy_from_slice(msg);

                bvk.verify_with_zip216(
                    &data_to_be_signed,
                    &binding_sig,
                    value_commitment_randomness_generator(),
                    self.zip216_enabled,
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use bellman::groth16::prepare_verifying_key;
    use ff::Field;
    use group::Group;

    use super::SaplingVerificationContext;
    use crate::sapling::verifier::test_util::dummy_params_and_proof;

    fn non_small_order_point() -> jubjub::ExtendedPoint {
        jubjub::SubgroupPoint::generator().into()
    }

    /// A well-formed proof for the wrong public inputs makes `verify_proof` return
    /// `Ok(false)`, not `Err`; it must still be rejected.
    #[test]
    fn check_output_rejects_proof_verifying_to_false() {
        // The output circuit has 5 public inputs.
        let (params, proof) = dummy_params_and_proof::<5>();
        let pvk = prepare_verifying_key(&params.vk);

        let mut ctx = SaplingVerificationContext::new(true);
        assert!(!ctx.check_output(
            non_small_order_point(),
            bls12_381::Scalar::ONE,
            non_small_order_point(),
            proof,
            &pvk,
        ));
    }

    #[test]
    fn check_convert_rejects_proof_verifying_to_false() {
        // The convert circuit has 3 public inputs.
        let (params, proof) = dummy_params_and_proof::<3>();
        let pvk = prepare_verifying_key(&params.vk);

        let mut ctx = SaplingVerificationContext::new(true);
        assert!(!ctx.check_convert(non_small_order_point(), bls12_381::Scalar::ONE, proof, &pvk,));
    }
}

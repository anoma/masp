use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;
use std::io::Write;

use super::{OutputDescription, SpendDescription};
use crate::{
    primitives::Nullifier,
    transaction::{util::*, Authorization},
};

impl<A: Authorization + PartialEq + BorshSerialize> BorshSerialize for SpendDescription<A>
where
    A::Proof: BorshSerialize,
    A::AuthSig: BorshSerialize,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        BorshSerialize::serialize(&self.cv.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.anchor.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.nullifier.0, writer)?;
        BorshSerialize::serialize(&self.rk, writer)?;
        BorshSerialize::serialize(&self.zkproof, writer)?;
        BorshSerialize::serialize(&self.spend_auth_sig, writer)
    }
}

impl<A: Authorization + PartialEq + BorshDeserialize> BorshDeserialize for SpendDescription<A>
where
    A::Proof: BorshDeserialize,
    A::AuthSig: BorshDeserialize,
{
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let cv = deserialize_extended_point(buf)?;
        let anchor = deserialize_scalar(buf)?;
        let nullifier_bytes: [u8; 32] = BorshDeserialize::deserialize(buf)?;
        let nullifier = Nullifier(nullifier_bytes);
        let rk = BorshDeserialize::deserialize(buf)?;
        let zkproof = BorshDeserialize::deserialize(buf)?;
        let spend_auth_sig = BorshDeserialize::deserialize(buf)?;
        Ok(Self {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }
}

impl<Proof: BorshDeserialize> BorshDeserialize for OutputDescription<Proof> {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let cv = deserialize_extended_point(buf)?;
        let cmu = deserialize_scalar(buf)?;
        let ephemeral_key = BorshDeserialize::deserialize(buf)?;
        let enc_ciphertext = deserialize_array(buf)?;
        let out_ciphertext = deserialize_array(buf)?;
        let zkproof = BorshDeserialize::deserialize(buf)?;
        Ok(Self {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }
}

impl<Proof: BorshSerialize> BorshSerialize for OutputDescription<Proof> {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        BorshSerialize::serialize(&self.cv.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.cmu.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.ephemeral_key, writer)?;
        writer.write_all(self.enc_ciphertext.as_ref())?;
        writer.write_all(self.out_ciphertext.as_ref())?;
        BorshSerialize::serialize(&self.zkproof, writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{
        testing::{arb_bundle, arb_output_description, arb_spend_description},
        Authorized, GrothProofBytes, OutputDescription, SpendDescription,
    };
    use borsh::{BorshDeserialize, BorshSerialize};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn spend_description_serialization(spend in arb_spend_description()) {
            // BorshSerialize
            let borsh = spend.try_to_vec().unwrap();
            // BorshDeserialize
            let de_code: SpendDescription<Authorized> = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            prop_assert_eq!(spend, de_code);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn output_description_serialization(output in arb_output_description()) {
            // BorshSerialize
            let borsh = output.try_to_vec().unwrap();
            // BorshDeserialize
            let de_code: OutputDescription<GrothProofBytes> = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            prop_assert_eq!(output, de_code);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn bundle_description_serialization(bundle in arb_bundle()) {
            // BorshSerialize
            let borsh = bundle.try_to_vec().unwrap();
            // BorshDeserialize
            let de_code = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            prop_assert_eq!(bundle, de_code);
        }
    }
}

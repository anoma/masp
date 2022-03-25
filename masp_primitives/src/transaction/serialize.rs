use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;
use std::io::Write;

use super::{OutputDescription, SpendDescription};
use crate::transaction::util::*;
use zcash_primitives::{sapling::Nullifier, transaction::components::sapling::Authorization};

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
        //writer.write(self.zkproof.as_ref());
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
        let zkproof = BorshDeserialize::deserialize(buf)?; //deserialize_array(buf)?;
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

/*impl<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> BorshSerialize for Bundle<A>
where
    A::Proof: BorshSerialize,
    A::AuthSig: BorshSerialize,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        BorshSerialize::serialize(&self.cv.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.anchor.to_bytes(), writer)?;
        BorshSerialize::serialize(&self.nullifier, writer)?;
        BorshSerialize::serialize(&self.rk, writer)?;
        writer.write(self.zkproof.as_ref());
        BorshSerialize::serialize(&self.spend_auth_sig, writer)
    }
}

impl<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> BorshDeserialize
    for Bundle<A>
{
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let cv = deserialize_extended_point(buf)?;
        let anchor = deserialize_scalar(buf)?;
        let nullifier = BorshDeserialize::deserialize(buf)?;
        let rk = BorshDeserialize::deserialize(buf)?;
        let zkproof = deserialize_array(buf)?;
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
}*/

impl<Proof: BorshDeserialize> BorshDeserialize for OutputDescription<Proof> {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let cv = deserialize_extended_point(buf)?;
        let cmu = deserialize_scalar(buf)?;
        let ephemeral_key = BorshDeserialize::deserialize(buf)?;
        let enc_ciphertext = deserialize_array(buf)?;
        let out_ciphertext = deserialize_array(buf)?;
        let zkproof = BorshDeserialize::deserialize(buf)?; //deserialize_array(buf)?;
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
        writer.write(self.enc_ciphertext.as_ref())?;
        writer.write(self.out_ciphertext.as_ref())?;
        BorshSerialize::serialize(&self.zkproof, writer)?;
        Ok(())
    }
}

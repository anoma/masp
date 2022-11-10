use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::fmt;
use ff::PrimeField;
use group::GroupEncoding;
use memuse::DynamicUsage;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};

use masp_note_encryption::{
    EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};
pub use secp256k1::PublicKey as TransparentAddress;

use crate::{
    asset_type::AssetType,
    consensus,
    note_encryption::SaplingDomain,
    primitives::Nullifier,
    prover::GROTH_PROOF_SIZE,
    redjubjub::{self, PublicKey, Signature},
    transaction::{amount::Amount, builder::{transparent, sapling}},
};

pub mod amount;
pub mod builder;
pub mod memo;
pub mod serialize;
pub mod util;
pub mod txid;
pub mod sighash;
pub mod sighash_v5;

pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

/// Authorization state for a bundle of transaction data.
pub trait Authorization {
    type TransparentAuth: builder::transparent::Authorization + PartialEq +BorshDeserialize + BorshSerialize;
    type SaplingAuth: builder::sapling::Authorization + PartialEq +BorshDeserialize + BorshSerialize;
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Unproven;
#[derive(Debug, PartialEq)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentAuth = builder::transparent::Authorized;
    type SaplingAuth = builder::sapling::Authorized;
}

pub struct Unauthorized;

impl Authorization for Unauthorized {
    type TransparentAuth = builder::transparent::Unauthorized;
    type SaplingAuth = builder::sapling::Unauthorized;
}

#[derive(Debug, PartialEq)]
pub struct TransactionData<A: Authorization> {
    transparent_bundle: Option<transparent::Bundle<A::TransparentAuth>>,
    sapling_bundle: Option<sapling::Bundle<A::SaplingAuth>>,
}

impl<A: Authorization> TransactionData<A> {
    pub fn digest<D: TransactionDigest<A>>(&self, digester: D) -> D::Digest {
        digester.combine(
            digester.digest_transparent(self.transparent_bundle.as_ref()),
            digester.digest_sapling(self.sapling_bundle.as_ref()),
        )
    }
}

#[derive(Clone, Debug)]
pub struct TransparentDigests<A> {
    pub outputs_digest: A,
}

#[derive(Clone, Debug)]
pub struct TxDigests<A> {
    pub transparent_digests: Option<TransparentDigests<A>>,
    pub sapling_digest: Option<A>,
}

pub trait TransactionDigest<A: Authorization> {
    type TransparentDigest;
    type SaplingDigest;
    type Digest;
    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest;

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth>>,
    ) -> Self::SaplingDigest;

    fn combine(
        &self,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
    ) -> Self::Digest;
}

pub enum DigestError {
    NotSigned,
}

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

memuse::impl_no_dynamic_usage!(TxId);

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The (byte-flipped) hex string is more useful than the raw bytes, because we can
        // look that up in RPC methods and block explorers.
        let txid_str = self.to_string();
        f.debug_tuple("TxId").field(&txid_str).finish()
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
    }
}

impl AsRef<[u8; 32]> for TxId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TxId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        TxId(bytes)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        Ok(TxId::from_bytes(hash))
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0)?;
        Ok(())
    }
}

/*
#[derive(
    Clone,
    Copy,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TxId(pub [u8; 32]);

impl std::fmt::Display for TxId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut data = self.0;
        data.reverse();
        formatter.write_str(&hex::encode(data))
    }
}*/

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use ff::Field;
    use group::{Group, GroupEncoding};
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};
    use std::convert::TryFrom;

    use crate::{
        constants::{SPENDING_KEY_GENERATOR, VALUE_COMMITMENT_RANDOMNESS_GENERATOR},
        primitives::Nullifier,
        redjubjub::{PrivateKey, PublicKey},
        transaction::{amount::testing::arb_amount, GROTH_PROOF_SIZE, GrothProofBytes},
    };

    use crate::transaction::builder::sapling::{Authorized, Bundle,  OutputDescription, ConvertDescription, SpendDescription};

    prop_compose! {
        fn arb_extended_point()(rng_seed in prop::array::uniform32(any::<u8>())) -> jubjub::ExtendedPoint {
            let mut rng = StdRng::from_seed(rng_seed);
            let scalar = jubjub::Scalar::random(&mut rng);
            jubjub::ExtendedPoint::generator() * scalar
        }
    }

    prop_compose! {
        /// produce a spend description with invalid data (useful only for serialization
        /// roundtrip testing).
        pub fn arb_spend_description()(
            cv in arb_extended_point(),
            anchor in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            nullifier in prop::array::uniform32(any::<u8>())
                .prop_map(|v| Nullifier::from_slice(&v).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_sighash_bytes in prop::array::uniform32(prop::num::u8::ANY),
        ) -> SpendDescription<Authorized> {
            let mut rng = StdRng::from_seed(rng_seed);
            let sk1 = PrivateKey(jubjub::Fr::random(&mut rng));
            let rk = PublicKey::from_private(&sk1, SPENDING_KEY_GENERATOR);
            SpendDescription {
                cv,
                anchor,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig: sk1.sign(&fake_sighash_bytes, &mut rng, SPENDING_KEY_GENERATOR),
            }
        }
    }

    prop_compose! {
        /// produce a spend description with invalid data (useful only for serialization
        /// roundtrip testing).
        pub fn arb_convert_description()(
            cv in arb_extended_point(),
            anchor in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
        ) -> ConvertDescription<GrothProofBytes> {
            ConvertDescription {
                cv,
                anchor,
                zkproof,
            }
        }
    }

    prop_compose! {
        /// produce an output description with invalid data (useful only for serialization
        /// roundtrip testing).
        pub fn arb_output_description()(
            cv in arb_extended_point(),
            cmu in vec(any::<u8>(), 64)
                .prop_map(|v| <[u8;64]>::try_from(v.as_slice()).unwrap())
                .prop_map(|v| bls12_381::Scalar::from_bytes_wide(&v)),
            enc_ciphertext in vec(any::<u8>(), 580 + 32)
                .prop_map(|v| <[u8;580 + 32]>::try_from(v.as_slice()).unwrap()),
            epk in arb_extended_point(),
            out_ciphertext in vec(any::<u8>(), 80)
                .prop_map(|v| <[u8;80]>::try_from(v.as_slice()).unwrap()),
            zkproof in vec(any::<u8>(), GROTH_PROOF_SIZE)
                .prop_map(|v| <[u8;GROTH_PROOF_SIZE]>::try_from(v.as_slice()).unwrap()),
        ) -> OutputDescription<GrothProofBytes> {
            OutputDescription {
                cv,
                cmu,
                ephemeral_key: epk.to_bytes().into(),
                enc_ciphertext,
                out_ciphertext,
                zkproof,
            }
        }
    }

    prop_compose! {
        pub fn arb_bundle()(
            shielded_spends in vec(arb_spend_description(), 0..30),
            shielded_converts in vec(arb_convert_description(), 0..30),
            shielded_outputs in vec(arb_output_description(), 0..30),
            value in arb_amount(),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_bvk_bytes in prop::array::uniform32(prop::num::u8::ANY),
        ) -> Option<Bundle<Authorized>> {
            if shielded_spends.is_empty() && shielded_outputs.is_empty() {
                None
            } else {
                let mut rng = StdRng::from_seed(rng_seed);
                let bsk = PrivateKey(jubjub::Fr::random(&mut rng));

                //let mut value_balance = std::collections::BTreeMap::new();
                //value_balance.insert(, value);
                let value_balance = crate::transaction::amount::Amount::from_pair(crate::asset_type::AssetType::new(b"prop_test").unwrap(), value).unwrap();
                Some(
                    Bundle {
                        shielded_spends,
                        shielded_converts,
                        shielded_outputs,
                        value_balance,
                        authorization: Authorized { binding_sig: bsk.sign(&fake_bvk_bytes, &mut rng, VALUE_COMMITMENT_RANDOMNESS_GENERATOR) },
                    }
                )
            }
        }
    }
}

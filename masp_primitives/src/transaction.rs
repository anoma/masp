use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;
use ff::PrimeField;
use group::GroupEncoding;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::io::{self, Read, Write};
use std::hash::{Hash,Hasher};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};

use masp_note_encryption::{
    EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};

use crate::{
    asset_type::AssetType,
    consensus,
    note_encryption::SaplingDomain,
    primitives::Nullifier,
    prover::GROTH_PROOF_SIZE,
    redjubjub::{self, PublicKey, Signature},
    transaction::amount::Amount,
};

pub mod amount;
pub mod builder;
pub mod memo;
pub mod serialize;
pub mod util;

pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

pub trait Authorization: Debug {
    type Proof: Clone + Debug + PartialEq;
    type AuthSig: Clone + Debug + PartialEq;
}
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Unproven;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Copy, Clone)]
pub struct Authorized {
    pub binding_sig: redjubjub::Signature,
}

impl Authorization for Authorized {
    type Proof = GrothProofBytes;
    type AuthSig = redjubjub::Signature;
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_proof(&self, p: A::Proof) -> B::Proof;
    fn map_auth_sig(&self, s: A::AuthSig) -> B::AuthSig;
    fn map_authorization(&self, a: A) -> B;
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub struct Bundle<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> {
    pub shielded_spends: Vec<SpendDescription<A>>,
    pub shielded_outputs: Vec<OutputDescription<A::Proof>>,
    pub value_balance: Amount,
    pub authorization: A,
}

impl<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> Bundle<A> {
    pub fn map_authorization<
        B: Authorization + PartialEq + BorshSerialize + BorshDeserialize,
        F: MapAuth<A, B>,
    >(
        self,
        f: F,
    ) -> Bundle<B> {
        Bundle {
            shielded_spends: self
                .shielded_spends
                .into_iter()
                .map(|d| SpendDescription {
                    cv: d.cv,
                    anchor: d.anchor,
                    nullifier: d.nullifier,
                    rk: d.rk,
                    zkproof: f.map_proof(d.zkproof),
                    spend_auth_sig: f.map_auth_sig(d.spend_auth_sig),
                })
                .collect(),
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(|o| OutputDescription {
                    cv: o.cv,
                    cmu: o.cmu,
                    ephemeral_key: o.ephemeral_key,
                    enc_ciphertext: o.enc_ciphertext,
                    out_ciphertext: o.out_ciphertext,
                    zkproof: f.map_proof(o.zkproof),
                })
                .collect(),
            value_balance: self.value_balance,
            authorization: f.map_authorization(self.authorization),
        }
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct OutPoint {
    hash: [u8; 32],
    n: u32,
}

impl OutPoint {
    pub fn new(hash: [u8; 32], n: u32) -> Self {
        OutPoint { hash, n }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let n = reader.read_u32::<LittleEndian>()?;
        Ok(OutPoint { hash, n })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.hash)?;
        writer.write_u32::<LittleEndian>(self.n)
    }

    pub fn n(&self) -> u32 {
        self.n
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl BorshDeserialize for OutPoint {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl BorshSerialize for OutPoint {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd)]
pub struct TxIn {
    pub prevout: OutPoint,
    //pub script_sig: Script,
    pub sequence: u32,
}

impl TxIn {
    #[cfg(feature = "transparent-inputs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "transparent-inputs")))]
    pub fn new(prevout: OutPoint) -> Self {
        TxIn {
            prevout,
            //script_sig: Script::default(),
            sequence: std::u32::MAX,
        }
    }

    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let prevout = OutPoint::read(&mut reader)?;
        //let script_sig = Script::read(&mut reader)?;
        let sequence = reader.read_u32::<LittleEndian>()?;

        Ok(TxIn {
            prevout,
            //script_sig,
            sequence,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.prevout.write(&mut writer)?;
        //self.script_sig.write(&mut writer)?;
        writer.write_u32::<LittleEndian>(self.sequence)
    }
}

impl BorshDeserialize for TxIn {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl BorshSerialize for TxIn {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}

#[derive(Clone, Debug, Hash, PartialOrd, PartialEq, Ord, Eq)]
pub struct TxOut {
    pub asset_type: AssetType,
    pub value: u64,
    //pub script_pubkey: Script,
}

impl TxOut {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let asset_type = {
            let mut tmp = [0u8; 32];
            reader.read_exact(&mut tmp)?;
            AssetType::from_identifier(&tmp)
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))?;
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            u64::from_le_bytes(tmp)
        };
        //let script_pubkey = Script::read(&mut reader)?;

        Ok(TxOut {
            asset_type,
            value,
            //script_pubkey,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.asset_type.get_identifier())?;
        writer.write_all(&self.value.to_le_bytes())
        //self.script_pubkey.write(&mut writer)
    }
}

impl BorshDeserialize for TxOut {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl BorshSerialize for TxOut {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}

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
}
#[derive(Clone, PartialEq, Eq)]
pub struct SpendDescription<A: Authorization + PartialEq> {
    pub cv: jubjub::ExtendedPoint,
    pub anchor: bls12_381::Scalar,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
    pub zkproof: A::Proof,
    pub spend_auth_sig: A::AuthSig,
}

impl<A: Authorization + PartialEq> std::fmt::Debug for SpendDescription<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "SpendDescription(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced here.
/// - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
///   (located in zcash_proofs::sapling::verifier).
pub fn read_point<R: Read>(mut reader: R, field: &str) -> io::Result<jubjub::ExtendedPoint> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let point = jubjub::ExtendedPoint::from_bytes(&bytes);

    if point.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {}", field),
        ))
    } else {
        Ok(point.unwrap())
    }
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
pub fn read_base<R: Read>(mut reader: R, field: &str) -> io::Result<bls12_381::Scalar> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    Option::from(bls12_381::Scalar::from_repr(f)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} not in field", field),
        )
    })
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced by the API of SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output() due to the need to parse this into a
///   bellman::groth16::Proof.
/// - Proof validity is enforced in SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output()
pub fn read_zkproof<R: Read>(mut reader: R) -> io::Result<GrothProofBytes> {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    reader.read_exact(&mut zkproof)?;
    Ok(zkproof)
}

impl SpendDescription<Authorized> {
    pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
        let mut nullifier = Nullifier([0u8; 32]);
        reader.read_exact(&mut nullifier.0)?;
        Ok(nullifier)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - "Not small order" is enforced in SaplingVerificationContext::check_spend()
    pub fn read_rk<R: Read>(mut reader: R) -> io::Result<PublicKey> {
        PublicKey::read(&mut reader)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - Signature validity is enforced in SaplingVerificationContext::check_spend()
    pub fn read_spend_auth_sig<R: Read>(mut reader: R) -> io::Result<Signature> {
        Signature::read(&mut reader)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        // Consensus rules (§4.4) & (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;
        // Consensus rules (§7.3) & (§7.4):
        // - Canonical encoding is enforced here
        let anchor = read_base(&mut reader, "anchor")?;
        let nullifier = Self::read_nullifier(&mut reader)?;
        let rk = Self::read_rk(&mut reader)?;
        let zkproof = read_zkproof(&mut reader)?;
        let spend_auth_sig = Self::read_spend_auth_sig(&mut reader)?;

        Ok(SpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.anchor.to_repr().as_ref())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)?;
        writer.write_all(&self.zkproof)?;
        self.spend_auth_sig.write(&mut writer)
    }

    pub fn write_v5_without_witness_data<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct SpendDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
}

impl SpendDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let nullifier = SpendDescription::read_nullifier(&mut reader)?;
        let rk = SpendDescription::read_rk(&mut reader)?;

        Ok(SpendDescriptionV5 { cv, nullifier, rk })
    }

    pub fn into_spend_description(
        self,
        anchor: bls12_381::Scalar,
        zkproof: GrothProofBytes,
        spend_auth_sig: Signature,
    ) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof,
            spend_auth_sig,
        }
    }
}

#[derive( Clone, PartialEq, Eq)]
pub struct ConvertDescription {
    //#[serde(serialize_with = "sserialize_extended_point")]
    //#[serde(deserialize_with = "sdeserialize_extended_point")]
    pub cv: jubjub::ExtendedPoint,
    //#[serde(serialize_with = "sserialize_scalar")]
    //#[serde(deserialize_with = "sdeserialize_scalar")]
    pub anchor: bls12_381::Scalar,
    //#[serde(serialize_with = "sserialize_array::<_, u8, u8, GROTH_PROOF_SIZE>")]
    //#[serde(deserialize_with = "sdeserialize_array::<_, u8, u8, GROTH_PROOF_SIZE>")]
    pub zkproof: [u8; GROTH_PROOF_SIZE],
}

impl PartialOrd for ConvertDescription {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (self.cv.to_bytes(), self.anchor.to_bytes(), self.zkproof).partial_cmp(&(other.cv.to_bytes(), other.anchor.to_bytes(), other.zkproof))
    }
}

impl Hash for ConvertDescription {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        self.cv.to_bytes().hash(state);
        self.anchor.to_bytes().hash(state);
        self.zkproof.hash(state);
    }
}
impl std::fmt::Debug for ConvertDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ConvertDescription(cv = {:?}, anchor = {:?})",
            self.cv, self.anchor
        )
    }
}

impl BorshDeserialize for ConvertDescription {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl BorshSerialize for ConvertDescription {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}
impl ConvertDescription {

pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
    // Consensus rules (§4.4) & (§4.5):
    // - Canonical encoding is enforced here.
    // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
    //   (located in zcash_proofs::sapling::verifier).
    let cv = read_point(&mut reader, "cv")?;
    // Consensus rules (§7.3) & (§7.4):
    // - Canonical encoding is enforced here
    let anchor = read_base(&mut reader, "anchor")?;
    let zkproof = read_zkproof(&mut reader)?;

    Ok(ConvertDescription {
        cv,
        anchor,
        zkproof,
    })
}

pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
    writer.write_all(&self.cv.to_bytes())?;
    writer.write_all(self.anchor.to_repr().as_ref())?;
    writer.write_all(&self.zkproof)
}
}

#[derive(Clone, PartialEq)]
pub struct OutputDescription<Proof> {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: EphemeralKeyBytes,
    pub enc_ciphertext: [u8; 580 + 32],
    pub out_ciphertext: [u8; 80],
    pub zkproof: Proof,
}

impl<Proof: PartialOrd> PartialOrd for OutputDescription<Proof> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (
            self.cv.to_bytes(),
            self.cmu.to_bytes(),
            self.ephemeral_key,
            self.enc_ciphertext,
            self.out_ciphertext,
            self.zkproof,
        )
            .partial_cmp(&(
                other.cv.to_bytes(),
                other.cmu.to_bytes(),
                other.ephemeral_key,
                other.enc_ciphertext,
                other.out_ciphertext,
                other.zkproof,
            ))
    }
}

impl<Proof: Hash> Hash for OutputDescription<Proof> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.cv.to_bytes().hash(state);
        self.cmu.to_bytes().hash(state);
        self.ephemeral_key.hash(state);
        self.enc_ciphertext.hash(state);
        self.out_ciphertext.hash(state);
        self.zkproof.hash(state);
    }
}

impl<P: consensus::Parameters, A> ShieldedOutput<SaplingDomain<P>, ENC_CIPHERTEXT_SIZE>
    for OutputDescription<A>
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

impl<Proof> std::fmt::Debug for OutputDescription<Proof>
where
    Proof: PartialEq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescription<GrothProofBytes> {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;

        // Consensus rule (§7.4): Canonical encoding is enforced here
        let cmu = read_base(&mut reader, "cmu")?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580 + 32];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        let zkproof = read_zkproof(&mut reader)?;

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(self.ephemeral_key.as_ref())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }

    pub fn write_v5_without_proof<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(self.ephemeral_key.as_ref())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)
    }
}

#[derive(Clone)]
pub struct OutputDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: EphemeralKeyBytes,
    pub enc_ciphertext: [u8; 580 + 32],
    pub out_ciphertext: [u8; 80],
}

impl OutputDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let cmu = read_base(&mut reader, "cmu")?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580 + 32];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        Ok(OutputDescriptionV5 {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    pub fn into_output_description(
        self,
        zkproof: GrothProofBytes,
    ) -> OutputDescription<GrothProofBytes> {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }
}

pub struct CompactOutputDescription {
    pub ephemeral_key: EphemeralKeyBytes,
    pub cmu: bls12_381::Scalar,
    pub enc_ciphertext: [u8; COMPACT_NOTE_SIZE],
}

impl<A> From<OutputDescription<A>> for CompactOutputDescription {
    fn from(out: OutputDescription<A>) -> CompactOutputDescription {
        CompactOutputDescription {
            ephemeral_key: out.ephemeral_key,
            cmu: out.cmu,
            enc_ciphertext: out.enc_ciphertext[..COMPACT_NOTE_SIZE].try_into().unwrap(),
        }
    }
}

impl<P: consensus::Parameters> ShieldedOutput<SaplingDomain<P>, COMPACT_NOTE_SIZE>
    for CompactOutputDescription
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.enc_ciphertext
    }
}

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
        transaction::{amount::testing::arb_amount, GROTH_PROOF_SIZE},
    };

    use super::{Authorized, Bundle, GrothProofBytes, OutputDescription, SpendDescription};

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

                let mut value_balance = std::collections::BTreeMap::new();
                value_balance.insert(crate::asset_type::AssetType::new(b"prop_test").unwrap(), value);
                let value_balance = crate::transaction::amount::Amount(value_balance);
                Some(
                    Bundle {
                        shielded_spends,
                        shielded_outputs,
                        value_balance,
                        authorization: Authorized { binding_sig: bsk.sign(&fake_bvk_bytes, &mut rng, VALUE_COMMITMENT_RANDOMNESS_GENERATOR) },
                    }
                )
            }
        }
    }
}

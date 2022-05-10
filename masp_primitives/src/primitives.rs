//! Structs for core MASP primitives.

use crate::{
    asset_type::AssetType,
    constants,
    group_hash::group_hash,
    keys::prf_expand,
    pedersen_hash::{pedersen_hash, Personalization},
};
use blake2s_simd::Params as Blake2sParams;
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use ff::PrimeField;
use group::{cofactor::CofactorGroup, Curve, Group, GroupEncoding};
use rand_core::{CryptoRng, RngCore};
use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone)]
pub struct ValueCommitment {
    pub asset_generator: jubjub::ExtendedPoint,
    pub value: u64,
    pub randomness: jubjub::Fr,
}

impl ValueCommitment {
    pub fn commitment(&self) -> jubjub::SubgroupPoint {
        (CofactorGroup::clear_cofactor(&self.asset_generator) * jubjub::Fr::from(self.value))
            + (constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR * self.randomness)
    }
}

#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: jubjub::SubgroupPoint,
    pub nsk: jubjub::Fr,
}

impl ProofGenerationKey {
    pub fn to_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            ak: self.ak,
            nk: constants::PROOF_GENERATION_KEY_GENERATOR * self.nsk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ViewingKey {
    pub ak: jubjub::SubgroupPoint,
    pub nk: jubjub::SubgroupPoint,
}

impl ViewingKey {
    pub fn rk(&self, ar: jubjub::Fr) -> jubjub::SubgroupPoint {
        self.ak + constants::SPENDING_KEY_GENERATOR * ar
    }

    pub fn ivk(&self) -> SaplingIvk {
        let mut h = [0; 32];
        h.copy_from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::CRH_IVK_PERSONALIZATION)
                .to_state()
                .update(&self.ak.to_bytes())
                .update(&self.nk.to_bytes())
                .finalize()
                .as_bytes(),
        );

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;

        SaplingIvk(jubjub::Fr::from_repr(h).unwrap())
    }
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }
}

#[derive(Debug, Clone)]
pub struct SaplingIvk(pub jubjub::Fr);

impl SaplingIvk {
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        diversifier.g_d().and_then(|g_d| {
            let pk_d = g_d * self.0;

            PaymentAddress::from_parts(diversifier, pk_d)
        })
    }

    pub fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        group_hash(&self.0, constants::KEY_DIVERSIFICATION_PERSONALIZATION)
    }
}

/// A Sapling payment address.
///
/// # Invariants
///
/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Debug)]
pub struct PaymentAddress {
    pk_d: jubjub::SubgroupPoint,
    diversifier: Diversifier,
}

impl PartialEq for PaymentAddress {
    fn eq(&self, other: &Self) -> bool {
        self.pk_d == other.pk_d && self.diversifier == other.diversifier
    }
}

impl PaymentAddress {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity.
    pub fn from_parts(diversifier: Diversifier, pk_d: jubjub::SubgroupPoint) -> Option<Self> {
        if pk_d.is_identity().into() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Only for test code, as this explicitly bypasses the invariant.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_parts_unchecked(
        diversifier: Diversifier,
        pk_d: jubjub::SubgroupPoint,
    ) -> Self {
        PaymentAddress { pk_d, diversifier }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };
        // Check that the diversifier is valid
        diversifier.g_d()?;

        let pk_d = jubjub::SubgroupPoint::from_bytes(bytes[11..43].try_into().unwrap());
        if pk_d.is_some().into() {
            PaymentAddress::from_parts(diversifier, pk_d.unwrap())
        } else {
            None
        }
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> &jubjub::SubgroupPoint {
        &self.pk_d
    }

    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        self.diversifier.g_d()
    }

    pub fn create_note(
        &self,
        asset_type: AssetType,
        value: u64,
        randomness: Rseed,
    ) -> Option<Note> {
        self.g_d().map(|g_d| Note {
            asset_type,
            value,
            rseed: randomness,
            g_d,
            pk_d: self.pk_d,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Note {
    /// The asset type that the note represents
    pub asset_type: AssetType,
    /// The value of the note
    pub value: u64,
    /// The diversified base of the address, GH(d)
    pub g_d: jubjub::SubgroupPoint,
    /// The public key of the address, g_d^ivk
    pub pk_d: jubjub::SubgroupPoint,
    /// rseed
    pub rseed: Rseed,
}
impl BorshSerialize for Note {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        // Write asset type
        self.asset_type.serialize(writer)?;
        // Write note value
        writer.write_u64::<LittleEndian>(self.value)?;
        // Write diversified base
        writer.write_all(&self.g_d.to_bytes())?;
        // Write diversified transmission key
        writer.write_all(&self.pk_d.to_bytes())?;
        match self.rseed {
            Rseed::BeforeZip212(rcm) => {
                // Write note plaintext lead byte
                writer.write_u8(1)?;
                // Write rseed
                writer.write_all(&rcm.to_repr())
            }
            Rseed::AfterZip212(rseed) => {
                // Write note plaintext lead byte
                writer.write_u8(2)?;
                // Write rseed
                writer.write_all(&rseed)
            }
        }?;
        Ok(())
    }
}

impl BorshDeserialize for Note {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        // Read asset type
        let asset_type = AssetType::deserialize(buf)?;
        // Read note value
        let value = buf.read_u64::<LittleEndian>()?;
        // Read diversified base
        let g_d_bytes = <[u8; 32]>::deserialize(buf)?;
        let g_d = Option::from(jubjub::SubgroupPoint::from_bytes(&g_d_bytes)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "g_d not in field")
        })?;
        // Read diversified transmission key
        let pk_d_bytes = <[u8; 32]>::deserialize(buf)?;
        let pk_d =
            Option::from(jubjub::SubgroupPoint::from_bytes(&pk_d_bytes)).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "pk_d not in field")
            })?;
        // Read note plaintext lead byte
        let rseed_type = buf.read_u8()?;
        // Read rseed
        let rseed_bytes = <[u8; 32]>::deserialize(buf)?;
        let rseed = if rseed_type == 0x01 {
            let data = Option::from(jubjub::Fr::from_bytes(&rseed_bytes)).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "rseed not in field")
            })?;
            Rseed::BeforeZip212(data)
        } else {
            Rseed::AfterZip212(rseed_bytes)
        };
        // Finally construct note object
        Ok(Note {
            asset_type,
            value,
            g_d,
            pk_d,
            rseed,
        })
    }
}
/// Enum for note randomness before and after [ZIP 212](https://zips.z.cash/zip-0212).
///
/// Before ZIP 212, the note commitment trapdoor `rcm` must be a scalar value.
/// After ZIP 212, the note randomness `rseed` is a 32-byte sequence, used to derive
/// both the note commitment trapdoor `rcm` and the ephemeral private key `esk`.
#[derive(Copy, Clone, Debug)]
pub enum Rseed {
    BeforeZip212(jubjub::Fr),
    AfterZip212([u8; 32]),
}

/// Typesafe wrapper for nullifier values.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Nullifier(pub [u8; 32]);

impl Nullifier {
    pub fn from_slice(bytes: &[u8]) -> Result<Nullifier, TryFromSliceError> {
        bytes.try_into().map(Nullifier)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}
impl AsRef<[u8]> for Nullifier {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ConstantTimeEq for Nullifier {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NoteValue(u64);

impl TryFrom<u64> for NoteValue {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(NoteValue(value)) // TODO: is a check necessary
    }
}

impl From<NoteValue> for u64 {
    fn from(value: NoteValue) -> u64 {
        value.0
    }
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
            && self.asset_type == other.asset_type
            && self.g_d == other.g_d
            && self.pk_d == other.pk_d
            && self.rcm() == other.rcm()
    }
}

impl Note {
    pub fn uncommitted() -> bls12_381::Scalar {
        // The smallest u-coordinate that is not on the curve
        // is one.
        bls12_381::Scalar::one()
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> jubjub::SubgroupPoint {
        // Calculate the note contents, as bytes
        let mut note_contents = vec![];

        // Write the asset generator, cofactor not cleared
        note_contents.extend_from_slice(&self.asset_type.asset_generator().to_bytes());

        // Writing the value in little endian
        (&mut note_contents)
            .write_u64::<LittleEndian>(self.value)
            .unwrap();

        // Write g_d
        note_contents.extend_from_slice(&self.g_d.to_bytes());

        // Write pk_d
        note_contents.extend_from_slice(&self.pk_d.to_bytes());

        assert_eq!(note_contents.len(), 32 + 32 + 32 + 8);

        // Compute the Pedersen hash of the note contents
        let hash_of_contents = pedersen_hash(
            Personalization::NoteCommitment,
            note_contents
                .into_iter()
                .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
        );

        // Compute final commitment
        (constants::NOTE_COMMITMENT_RANDOMNESS_GENERATOR * self.rcm()) + hash_of_contents
    }

    /// Computes the nullifier given the viewing key and
    /// note position
    pub fn nf(&self, viewing_key: &ViewingKey, position: u64) -> Nullifier {
        // Compute rho = cm + position.G
        let rho = self.cm_full_point()
            + (constants::NULLIFIER_POSITION_GENERATOR * jubjub::Fr::from(position));

        // Compute nf = BLAKE2s(nk | rho)
        Nullifier::from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::PRF_NF_PERSONALIZATION)
                .to_state()
                .update(&viewing_key.nk.to_bytes())
                .update(&rho.to_bytes())
                .finalize()
                .as_bytes(),
        )
        .unwrap()
    }

    /// Computes the note commitment
    pub fn cmu(&self) -> bls12_381::Scalar {
        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the u-coordinate is an injective encoding.
        jubjub::ExtendedPoint::from(self.cm_full_point())
            .to_affine()
            .get_u()
    }

    pub fn rcm(&self) -> jubjub::Fr {
        match self.rseed {
            Rseed::BeforeZip212(rcm) => rcm,
            Rseed::AfterZip212(rseed) => {
                jubjub::Fr::from_bytes_wide(prf_expand(&rseed, &[0x04]).as_array())
            }
        }
    }

    pub fn generate_or_derive_esk<R: RngCore + CryptoRng>(&self, rng: &mut R) -> jubjub::Fr {
        self.generate_or_derive_esk_internal(rng)
    }

    pub(crate) fn generate_or_derive_esk_internal<R: RngCore>(&self, rng: &mut R) -> jubjub::Fr {
        use ff::Field;
        match self.derive_esk() {
            None => jubjub::Fr::random(rng),
            Some(esk) => esk,
        }
    }

    /// Returns the derived `esk` if this note was created after ZIP 212 activated.
    pub fn derive_esk(&self) -> Option<jubjub::Fr> {
        match self.rseed {
            Rseed::BeforeZip212(_) => None,
            Rseed::AfterZip212(rseed) => Some(jubjub::Fr::from_bytes_wide(
                prf_expand(&rseed, &[0x05]).as_array(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        primitives::Note,
        sapling::testing::{arb_note, arb_positive_note_value},
        transaction::amount::MAX_MONEY,
    };
    use borsh::{BorshDeserialize, BorshSerialize};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn note_serialization(note in arb_positive_note_value(MAX_MONEY as u64).prop_flat_map(arb_note)) {
            // BorshSerialize
            let borsh = note.try_to_vec().unwrap();
            // BorshDeserialize
            let de_note: Note = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            prop_assert_eq!(note, de_note);
        }
    }
}

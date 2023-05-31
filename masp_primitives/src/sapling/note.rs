use crate::asset_type::AssetType;
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use rand_core::{CryptoRng, RngCore};
use std::io::{self};

use blake2s_simd::Params as Blake2sParams;

use crate::{
    constants::{self},
    keys::prf_expand,
};
use ff::{Field, PrimeField};
use group::{Curve, GroupEncoding};

use crate::sapling::{
    pedersen_hash::{pedersen_hash, Personalization},
    Node, Nullifier, NullifierDerivingKey,
};

pub mod commitment;
pub mod nullifier;

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

#[derive(Clone, Debug, Copy)]
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
        note_contents.write_u64::<LittleEndian>(self.value).unwrap();

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

    /// Computes the nullifier given the nullifier deriving key and
    /// note position
    pub fn nf(&self, nk: &NullifierDerivingKey, position: u64) -> Nullifier {
        // Compute rho = cm + position.G
        let rho = self.cm_full_point()
            + (constants::NULLIFIER_POSITION_GENERATOR * jubjub::Fr::from(position));

        // Compute nf = BLAKE2s(nk | rho)
        Nullifier::from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::PRF_NF_PERSONALIZATION)
                .to_state()
                .update(&nk.0.to_bytes())
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

    /// Returns [`self.cmu`] in the correct representation for inclusion in the Sapling
    /// note commitment tree.
    pub fn commitment(&self) -> Node {
        Node {
            repr: self.cmu().to_repr(),
        }
    }
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
        let g_d = Option::from(jubjub::SubgroupPoint::from_bytes(&g_d_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "g_d not in field"))?;
        // Read diversified transmission key
        let pk_d_bytes = <[u8; 32]>::deserialize(buf)?;
        let pk_d = Option::from(jubjub::SubgroupPoint::from_bytes(&pk_d_bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "pk_d not in field"))?;
        // Read note plaintext lead byte
        let rseed_type = buf.read_u8()?;
        // Read rseed
        let rseed_bytes = <[u8; 32]>::deserialize(buf)?;
        let rseed = if rseed_type == 0x01 {
            let data = Option::from(jubjub::Fr::from_bytes(&rseed_bytes))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "rseed not in field"))?;
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

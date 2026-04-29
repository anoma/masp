use crate::{
    constants::{ASSET_IDENTIFIER_LENGTH, ASSET_IDENTIFIER_PERSONALIZATION, GH_FIRST_BLOCK},
    sapling::ValueCommitment,
    sapling::poseidon_hash,
};
use blake2b_simd::Params as Blake2bParams;
use borsh::BorshSchema;
use borsh::{BorshDeserialize, BorshSerialize};
use ff::Field;
use ff::PrimeField;
use group::{Group, cofactor::CofactorGroup};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
};

#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, BorshSerialize, BorshDeserialize, Clone, Copy, Eq, BorshSchema)]
pub struct AssetType {
    identifier: [u8; ASSET_IDENTIFIER_LENGTH], // canonical asset-id bytes
    nonce: Option<u8>,
}

// Abstract type representing an asset
impl AssetType {
    /// Create a new AsstType from a unique asset name
    /// Not constant-time, uses rejection sampling
    pub fn new(name: &[u8]) -> Result<AssetType, ()> {
        let mut nonce = 0u8;
        loop {
            if let Some(asset_type) = AssetType::new_with_nonce(name, nonce) {
                return Ok(asset_type);
            }
            nonce = nonce.checked_add(1).ok_or(())?;
        }
    }

    /// Attempt to create a new AssetType from a unique asset name and fixed nonce
    /// Not yet constant-time; assume not-constant-time
    pub fn new_with_nonce(name: &[u8], nonce: u8) -> Option<AssetType> {
        // Check the personalization is acceptable length
        assert_eq!(ASSET_IDENTIFIER_PERSONALIZATION.len(), 8);

        // Create a new BLAKE2b state for deriving the asset-id scalar.
        let h = Blake2bParams::new()
            .hash_length(64)
            .to_state()
            .update(ASSET_IDENTIFIER_PERSONALIZATION)
            .update(GH_FIRST_BLOCK)
            .update(name)
            .update(&[nonce])
            .finalize();

        let asset_id = reduce_wide_le(h.as_array());
        let identifier = asset_id.to_repr();

        // If the hash state maps to a valid asset generator, use it
        if AssetType::hash_to_point_from_asset_id(asset_id).is_some() {
            Some(AssetType {
                identifier,
                nonce: Some(nonce),
            })
        } else {
            None
        }
    }

    // Attempt to map an asset-id encoding to a curve point.
    fn hash_to_point(identifier: &[u8; ASSET_IDENTIFIER_LENGTH]) -> Option<jubjub::ExtendedPoint> {
        let asset_id = Option::from(bls12_381::Scalar::from_repr(*identifier))?;
        Self::hash_to_point_from_asset_id(asset_id)
    }

    fn hash_to_point_from_asset_id(asset_id: bls12_381::Scalar) -> Option<jubjub::ExtendedPoint> {
        assert_eq!(bls12_381::Scalar::NUM_BITS, 255);

        let v = poseidon_hash::hash_scalars(poseidon_hash::Domain::AssetGen, &[asset_id]);
        let v2 = v.square();
        let mut numerator = v2;
        numerator -= bls12_381::Scalar::ONE;
        let mut denominator = v2;
        denominator *= jubjub_edwards_d();
        denominator += bls12_381::Scalar::ONE;

        let inv = denominator.invert();
        if bool::from(inv.is_none()) {
            return None;
        }

        let u2 = numerator * inv.unwrap();
        let sqrt = u2.sqrt();
        if bool::from(sqrt.is_none()) {
            return None;
        }

        let mut u = sqrt.unwrap();
        if bool::from(u.is_odd()) != bool::from(v.is_odd()) {
            u = -u;
        }

        let p: jubjub::ExtendedPoint = jubjub::AffinePoint::from_raw_unchecked(u, v).into();
        let p_prime = CofactorGroup::clear_cofactor(&p);
        if p_prime.is_identity().into() {
            None
        } else {
            Some(p)
        }
    }

    /// Return the canonical asset-id bytes for this asset type.
    pub fn get_identifier(&self) -> &[u8; ASSET_IDENTIFIER_LENGTH] {
        &self.identifier
    }

    pub fn asset_id(&self) -> bls12_381::Scalar {
        bls12_381::Scalar::from_repr(self.identifier)
            .expect("AssetType internal identifier state inconsistent")
    }

    /// Attempt to construct an asset type from an existing asset-id encoding.
    pub fn from_identifier(identifier: &[u8; ASSET_IDENTIFIER_LENGTH]) -> Option<AssetType> {
        // Attempt to hash to point
        if AssetType::hash_to_point(identifier).is_some() {
            Some(AssetType {
                identifier: *identifier,
                nonce: None,
            })
        } else {
            None // invalid asset-id encoding
        }
    }

    /// Produces an asset generator without cofactor cleared
    pub fn asset_generator(&self) -> jubjub::ExtendedPoint {
        AssetType::hash_to_point_from_asset_id(self.asset_id())
            .expect("AssetType internal identifier state inconsistent")
    }

    /// Produces a value commitment generator with cofactor cleared
    pub fn value_commitment_generator(&self) -> jubjub::SubgroupPoint {
        CofactorGroup::clear_cofactor(&self.asset_generator())
    }

    /// Construct a value commitment from given value and randomness
    pub fn value_commitment(&self, value: u64, randomness: jubjub::Fr) -> ValueCommitment {
        ValueCommitment {
            asset_generator: self.asset_generator(),
            value,
            randomness,
        }
    }

    pub fn get_nonce(&self) -> Option<u8> {
        self.nonce
    }

    /// Deserialize an AssetType object
    pub fn read<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut atype = [0; crate::constants::ASSET_IDENTIFIER_LENGTH];
        reader.read_exact(&mut atype)?;
        AssetType::from_identifier(&atype).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid asset type")
        })
    }
}

fn jubjub_edwards_d() -> bls12_381::Scalar {
    bls12_381::Scalar::from_u64s_le(&[
        0x0106_5fd6_d634_3eb1,
        0x292d_7f6d_3757_9d26,
        0xf5fd_9207_e6bd_7fd4,
        0x2a93_18e7_4bfa_2b48,
    ])
    .unwrap()
}

fn reduce_wide_le(bytes: &[u8; 64]) -> bls12_381::Scalar {
    let mut acc = bls12_381::Scalar::ZERO;
    for byte in bytes.iter().rev() {
        acc *= bls12_381::Scalar::from(256u64);
        acc += bls12_381::Scalar::from(*byte as u64);
    }
    acc
}

impl PartialEq for AssetType {
    fn eq(&self, other: &Self) -> bool {
        self.get_identifier() == other.get_identifier()
    }
}

impl Display for AssetType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(self.get_identifier()))
    }
}

impl Hash for AssetType {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_identifier().hash(state)
    }
}

impl PartialOrd for AssetType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssetType {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_identifier().cmp(other.get_identifier())
    }
}

impl std::str::FromStr for AssetType {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(|x| Self::Err::new(std::io::ErrorKind::InvalidData, x))?;
        Self::from_identifier(
            &vec.try_into()
                .map_err(|_| Self::Err::from(std::io::ErrorKind::InvalidData))?,
        )
        .ok_or_else(|| Self::Err::from(std::io::ErrorKind::InvalidData))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    prop_compose! {
        pub fn arb_asset_type()(name in proptest::collection::vec(prop::num::u8::ANY, 0..64)) -> super::AssetType {
            super::AssetType::new(&name).unwrap()
        }
    }
}

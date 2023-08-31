use crate::{
    constants::{
        ASSET_IDENTIFIER_LENGTH, ASSET_IDENTIFIER_PERSONALIZATION, GH_FIRST_BLOCK,
        VALUE_COMMITMENT_GENERATOR_PERSONALIZATION,
    },
    sapling::ValueCommitment,
};
use blake2s_simd::Params as Blake2sParams;
use borsh::{BorshDeserialize, BorshSerialize};
use group::{cofactor::CofactorGroup, Group, GroupEncoding};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
};

#[derive(Debug, BorshSerialize, BorshDeserialize, Clone, Copy, Eq)]
pub struct AssetType {
    identifier: [u8; ASSET_IDENTIFIER_LENGTH], //32 byte asset type preimage
    #[borsh_skip]
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
        use std::slice::from_ref;

        // Check the personalization is acceptable length
        assert_eq!(ASSET_IDENTIFIER_PERSONALIZATION.len(), 8);

        // Create a new BLAKE2s state for deriving the asset identifier
        let h = Blake2sParams::new()
            .hash_length(ASSET_IDENTIFIER_LENGTH)
            .personal(ASSET_IDENTIFIER_PERSONALIZATION)
            .to_state()
            .update(GH_FIRST_BLOCK)
            .update(name)
            .update(from_ref(&nonce))
            .finalize();

        // If the hash state is a valid asset identifier, use it
        if AssetType::hash_to_point(h.as_array()).is_some() {
            Some(AssetType {
                identifier: *h.as_array(),
                nonce: Some(nonce),
            })
        } else {
            None
        }
    }

    // Attempt to hash an identifier to a curve point
    fn hash_to_point(identifier: &[u8; ASSET_IDENTIFIER_LENGTH]) -> Option<jubjub::ExtendedPoint> {
        // Check the personalization is acceptable length
        assert_eq!(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION.len(), 8);

        // Check to see that scalar field is 255 bits
        use ff::PrimeField;
        assert_eq!(bls12_381::Scalar::NUM_BITS, 255);

        let h = Blake2sParams::new()
            .hash_length(32)
            .personal(VALUE_COMMITMENT_GENERATOR_PERSONALIZATION)
            .to_state()
            .update(identifier)
            .finalize();

        // Check to see if the BLAKE2s hash of the identifier is on the curve
        let p = jubjub::ExtendedPoint::from_bytes(h.as_array());
        if p.is_some().into() {
            // <ExtendedPoint as CofactorGroup>::clear_cofactor is implemented using
            // ExtendedPoint::mul_by_cofactor in the jubjub crate.
            let p = p.unwrap();
            let p_prime = CofactorGroup::clear_cofactor(&p);

            if p_prime.is_identity().into() {
                None
            } else {
                // If not small order, return *without* clearing the cofactor
                Some(p)
            }
        } else {
            None // invalid asset identifier
        }
    }

    /// Return the identifier of this asset type
    pub fn get_identifier(&self) -> &[u8; ASSET_IDENTIFIER_LENGTH] {
        &self.identifier
    }

    /// Attempt to construct an asset type from an existing asset identifier
    pub fn from_identifier(identifier: &[u8; ASSET_IDENTIFIER_LENGTH]) -> Option<AssetType> {
        // Attempt to hash to point
        if AssetType::hash_to_point(identifier).is_some() {
            Some(AssetType {
                identifier: *identifier,
                nonce: None,
            })
        } else {
            None // invalid asset identifier
        }
    }

    /// Produces an asset generator without cofactor cleared
    pub fn asset_generator(&self) -> jubjub::ExtendedPoint {
        AssetType::hash_to_point(self.get_identifier())
            .expect("AssetType internal identifier state inconsistent")
    }

    /// Produces a value commitment generator with cofactor cleared
    pub fn value_commitment_generator(&self) -> jubjub::SubgroupPoint {
        CofactorGroup::clear_cofactor(&self.asset_generator())
    }

    /// Get the asset identifier as a vector of bools
    pub fn identifier_bits(&self) -> Vec<Option<bool>> {
        self.get_identifier()
            .iter()
            .flat_map(|&v| (0..8).map(move |i| Some((v >> i) & 1 == 1)))
            .collect()
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
        self.get_identifier().partial_cmp(other.get_identifier())
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

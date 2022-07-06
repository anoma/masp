use crate::asset_type::AssetType;
use crate::pedersen_hash::{pedersen_hash, Personalization};
use crate::primitives::ValueCommitment;
use crate::transaction::components::Amount;
use group::{Curve, GroupEncoding};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::ops::AddAssign;

#[derive(Clone, Debug, PartialEq)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    pub assets: Amount,
    /// Memorize generator because it's expensive to recompute
    generator: jubjub::ExtendedPoint,
}

impl AllowedConversion {
    pub fn new(values: Vec<(AssetType, i64)>) -> Self {
        let assets = Amount(BTreeMap::from_iter(values));
        let generator = asset_generator_internal(&assets);
        Self { assets, generator }
    }

    pub fn uncommitted() -> bls12_381::Scalar {
        // The smallest u-coordinate that is not on the curve
        // is one.
        bls12_381::Scalar::one()
    }

    /// Computes the note commitment, returning the full point.
    fn cm_full_point(&self) -> jubjub::SubgroupPoint {
        // Calculate the note contents, as bytes
        let mut asset_generator_bytes = vec![];

        // Write the asset generator, cofactor not cleared
        asset_generator_bytes.extend_from_slice(&self.asset_generator().to_bytes());

        assert_eq!(asset_generator_bytes.len(), 32);

        // Compute the Pedersen hash of the note contents
        pedersen_hash(
            Personalization::NoteCommitment,
            asset_generator_bytes
                .into_iter()
                .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
        )
    }

    /// Computes the note commitment
    pub fn cmu(&self) -> bls12_381::Scalar {
        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the u-coordinate is an injective encoding.
        jubjub::ExtendedPoint::from(self.cm_full_point())
            .to_affine()
            .get_u()
    }

    /// Produces an asset generator without cofactor cleared
    pub fn asset_generator(&self) -> jubjub::ExtendedPoint {
        asset_generator_internal(&self.assets)
    }

    /// Computes the value commitment for a given amount and randomness
    pub fn value_commitment(&self, value: u64, randomness: jubjub::Fr) -> ValueCommitment {
        ValueCommitment {
            asset_generator: self.asset_generator(),
            value,
            randomness,
        }
    }
}

fn asset_generator_internal(assets: &Amount) -> jubjub::ExtendedPoint {
    let mut asset_generator = jubjub::ExtendedPoint::identity();
    for (asset, value) in assets.components() {
        // Compute the absolute value (failing if -i64::MAX is
        // the value)
        let abs = match value.checked_abs() {
            Some(a) => a as u64,
            None => panic!("invalid conversion"),
        };

        // Is it negative? We'll have to negate later if so.
        let is_negative = value.is_negative();

        // Compute it in the exponent
        let mut value_balance = asset.asset_generator() * jubjub::Fr::from(abs);

        // Negate if necessary
        if is_negative {
            value_balance = -value_balance;
        }

        // Add to asset generator
        asset_generator += value_balance;
    }
    asset_generator
}

impl From<Amount> for AllowedConversion {
    fn from(assets: Amount) -> AllowedConversion {
        let generator = asset_generator_internal(&assets);
        AllowedConversion { assets, generator }
    }
}

impl AddAssign for AllowedConversion {
    fn add_assign(&mut self, rhs: Self) {
        self.assets += rhs.assets;
        self.generator += rhs.generator;
    }
}
use crate::asset_type::AssetType;
use crate::pedersen_hash::{pedersen_hash, Personalization};
use crate::primitives::ValueCommitment;
use group::{Curve, GroupEncoding};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    pub assets: BTreeMap<AssetType, i64>,
}

impl AllowedConversion {
    pub fn new(values: Vec<(AssetType, i64)>) -> Self {
        let mut assets = BTreeMap::new();
        for (atype, v) in values {
            assets.insert(atype, v);
        }
        Self { assets }
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
        let mut asset_generator = jubjub::ExtendedPoint::identity();
        for (asset, value) in self.assets.iter() {
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

    /// Computes the value commitment for a given amount and randomness
    pub fn value_commitment(&self, value: u64, randomness: jubjub::Fr) -> ValueCommitment {
        ValueCommitment {
            asset_generator: self.asset_generator(),
            value,
            randomness,
        }
    }
}

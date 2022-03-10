use crate::asset_type::AssetType;
use crate::pedersen_hash::{pedersen_hash, Personalization};
use crate::primitives::ValueCommitment;
use group::{Curve, GroupEncoding};

#[derive(Clone, Debug)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    pub spend_asset: AssetType,
    pub spend_value: u64,

    pub output_asset: AssetType,
    pub output_value: u64,

    pub mint_asset: AssetType,
    pub mint_value: u64,
}

impl PartialEq for AllowedConversion {
    fn eq(&self, other: &Self) -> bool {
        self.spend_asset == other.spend_asset
            && self.output_asset == other.output_asset
            && self.mint_asset == other.mint_asset
    }
}

impl AllowedConversion {
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
        -self.spend_asset.asset_generator() * jubjub::Fr::from(self.spend_value)
            + self.output_asset.asset_generator() * jubjub::Fr::from(self.output_value)
            + self.mint_asset.asset_generator() * jubjub::Fr::from(self.mint_value)
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

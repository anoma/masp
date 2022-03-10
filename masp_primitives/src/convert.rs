
use crate::pedersen_hash::{pedersen_hash, Personalization};
use crate::{asset_type::AssetType};
use group::{ Curve,  GroupEncoding};


#[derive(Clone, Debug)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    pub spend_asset: AssetType,
    pub output_asset: AssetType,
    pub mint_asset: AssetType,
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
        let mut note_contents = vec![];

        // Write the asset generator, cofactor not cleared
        note_contents.extend_from_slice(&self.spend_asset.asset_generator().to_bytes());

                // Write the asset generator, cofactor not cleared
                note_contents.extend_from_slice(&self.output_asset.asset_generator().to_bytes());
                        // Write the asset generator, cofactor not cleared
        note_contents.extend_from_slice(&self.mint_asset.asset_generator().to_bytes());

        assert_eq!(note_contents.len(), 32 + 32 + 32);

        // Compute the Pedersen hash of the note contents
        let hash_of_contents = pedersen_hash(
            Personalization::NoteCommitment,
            note_contents
                .into_iter()
                .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
        );

        // Compute final commitment
        hash_of_contents
    }

    /// Computes the note commitment
    pub fn cmu(&self) -> bls12_381::Scalar {
        // The commitment is in the prime order subgroup, so mapping the
        // commitment to the u-coordinate is an injective encoding.
        jubjub::ExtendedPoint::from(self.cm_full_point())
            .to_affine()
            .get_u()
    }
}
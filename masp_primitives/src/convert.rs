use crate::{
    sapling::{
        pedersen_hash::{pedersen_hash, Personalization},
        ValueCommitment,
    },
    transaction::components::amount::Amount,
};
use borsh::{BorshDeserialize, BorshSerialize};
use group::{Curve, GroupEncoding};
use std::{
    io::{self, Write},
    iter::Sum,
    ops::{Add, AddAssign, Sub, SubAssign},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    assets: Amount,
    /// Memorize generator because it's expensive to recompute
    generator: jubjub::ExtendedPoint,
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
        asset_generator_bytes.extend_from_slice(&self.generator.to_bytes());

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

    /// Computes the value commitment for a given amount and randomness
    pub fn value_commitment(&self, value: u64, randomness: jubjub::Fr) -> ValueCommitment {
        ValueCommitment {
            asset_generator: self.generator,
            value,
            randomness,
        }
    }
}

impl From<AllowedConversion> for Amount {
    fn from(allowed_conversion: AllowedConversion) -> Amount {
        allowed_conversion.assets
    }
}

impl From<Amount> for AllowedConversion {
    /// Produces an asset generator without cofactor cleared
    fn from(assets: Amount) -> Self {
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
        AllowedConversion {
            assets,
            generator: asset_generator,
        }
    }
}

impl BorshSerialize for AllowedConversion {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.assets.write(writer)?;
        writer.write_all(&self.generator.to_bytes())?;
        Ok(())
    }
}

impl BorshDeserialize for AllowedConversion {
    /// This deserialization is unsafe because it does not do the expensive
    /// computation of checking whether the asset generator corresponds to the
    /// deserialized amount.
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let assets = Amount::read(buf)?;
        let gen_bytes =
            <<jubjub::ExtendedPoint as GroupEncoding>::Repr as BorshDeserialize>::deserialize(buf)?;
        let generator = Option::from(jubjub::ExtendedPoint::from_bytes(&gen_bytes))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(AllowedConversion { assets, generator })
    }
}

impl Add for AllowedConversion {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            assets: self.assets + rhs.assets,
            generator: self.generator + rhs.generator,
        }
    }
}

impl AddAssign for AllowedConversion {
    fn add_assign(&mut self, rhs: Self) {
        self.assets += rhs.assets;
        self.generator += rhs.generator;
    }
}

impl Sub for AllowedConversion {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            assets: self.assets - rhs.assets,
            generator: self.generator - rhs.generator,
        }
    }
}

impl SubAssign for AllowedConversion {
    fn sub_assign(&mut self, rhs: Self) {
        self.assets -= rhs.assets;
        self.generator -= rhs.generator;
    }
}

impl Sum for AllowedConversion {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(AllowedConversion::from(Amount::zero()), Add::add)
    }
}

#[cfg(test)]
mod tests {
    use crate::asset_type::AssetType;
    use crate::convert::AllowedConversion;
    use crate::transaction::components::amount::Amount;

    /// Generate ZEC asset type
    fn zec() -> AssetType {
        AssetType::new(b"ZEC").unwrap()
    }
    /// Generate BTC asset type
    fn btc() -> AssetType {
        AssetType::new(b"BTC").unwrap()
    }
    /// Generate XAN asset type
    fn xan() -> AssetType {
        AssetType::new(b"XAN").unwrap()
    }
    #[test]
    fn test_homomorphism() {
        // Left operand
        let a = Amount::from_pair(zec(), 5).unwrap()
            + Amount::from_pair(btc(), 6).unwrap()
            + Amount::from_pair(xan(), 7).unwrap();
        // Right operand
        let b = Amount::from_pair(zec(), 2).unwrap() + Amount::from_pair(xan(), 10).unwrap();
        // Test homomorphism
        assert_eq!(
            AllowedConversion::from(a.clone() + b.clone()),
            AllowedConversion::from(a) + AllowedConversion::from(b)
        );
    }
    #[test]
    fn test_serialization() {
        // Make conversion
        let a: AllowedConversion = (Amount::from_pair(zec(), 5).unwrap()
            + Amount::from_pair(btc(), 6).unwrap()
            + Amount::from_pair(xan(), 7).unwrap())
        .into();
        // Serialize conversion
        let mut data = Vec::new();
        use borsh::BorshSerialize;
        a.serialize(&mut data).unwrap();
        // Deserialize conversion
        let mut ptr = &data[..];
        use borsh::BorshDeserialize;
        let b = AllowedConversion::deserialize(&mut ptr).unwrap();
        // Check that all bytes have been finished
        assert!(
            ptr.is_empty(),
            "AllowedConversion bytes should be exhausted"
        );
        // Test that serializing then deserializing produces same object
        assert_eq!(
            a, b,
            "serialization followed by deserialization changes value"
        );
    }
}

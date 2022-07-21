use crate::asset_type::AssetType;
use crate::pedersen_hash::{pedersen_hash, Personalization};
use crate::primitives::ValueCommitment;
use crate::transaction::Amount;
use group::{Curve, GroupEncoding};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use borsh::{BorshSerialize, BorshDeserialize};
use std::io::Write;
use borsh::maybestd::io::{Error, ErrorKind};
use derive_more::{Add, AddAssign};

#[derive(Clone, Debug, PartialEq, Add, AddAssign)]
pub struct AllowedConversion {
    /// The asset type that the note represents
    assets: Amount,
    /// Memorize generator because it's expensive to recompute
    generator: jubjub::ExtendedPoint,
}

impl AllowedConversion {
    pub fn new(values: Vec<(AssetType, i64)>) -> Self {
        let assets = Amount::new(BTreeMap::from_iter(values));
        let generator = Self::asset_generator_internal(&assets);
        Self { assets, generator }
    }

    pub fn uncommitted() -> bls12_381::Scalar {
        // The smallest u-coordinate that is not on the curve
        // is one.
        bls12_381::Scalar::one()
    }

    pub fn assets(&self) -> Amount {
        self.assets.clone()
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

    /// Produces an asset generator without cofactor cleared
    pub fn asset_generator(&self) -> jubjub::ExtendedPoint {
        Self::asset_generator_internal(&self.assets)
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

impl From<Amount> for AllowedConversion {
    fn from(assets: Amount) -> AllowedConversion {
        let generator = Self::asset_generator_internal(&assets);
        AllowedConversion { assets, generator }
    }
}

impl BorshSerialize for AllowedConversion {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.assets.write(writer)?;
        writer.write(&self.generator.to_bytes())?;
        Ok(())
    }
}

impl BorshDeserialize for AllowedConversion {
    /// This deserialization is unsafe because it does not do the expensive
    /// computation of checking whether the asset generator corresponds to the
    /// deserialized amount.
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let assets = Amount::read(buf)?;
        let gen_bytes = <<jubjub::ExtendedPoint as GroupEncoding>::Repr as BorshDeserialize>::deserialize(buf)?;
        let generator = Option::from(jubjub::ExtendedPoint::from_bytes(&gen_bytes))
            .ok_or_else(|| Error::from(ErrorKind::InvalidData))?;
        Ok(AllowedConversion { assets, generator })
    }
}

#[cfg(test)]
mod tests {
    use crate::asset_type::AssetType;
    use crate::transaction::descriptions::Amount;
    use crate::convert::AllowedConversion;
    use borsh::{BorshSerialize, BorshDeserialize};

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
        let a = Amount::from_pair(zec(), 5).unwrap() +
            Amount::from_pair(btc(), 6).unwrap() +
            Amount::from_pair(xan(), 7).unwrap();
        // Right operand
        let b = Amount::from_pair(zec(), 2).unwrap() +
            Amount::from_pair(xan(), 10).unwrap();
        // Test homomorphism
        assert_eq!(
            AllowedConversion::from(a.clone() + b.clone()),
            AllowedConversion::from(a.clone()) + AllowedConversion::from(b.clone())
        );
    }
    #[test]
    fn test_serialization() {

        // Make conversion	
        let a: AllowedConversion = (	
            Amount::from_pair(zec(), 5).unwrap() +	
                Amount::from_pair(btc(), 6).unwrap() +	
                Amount::from_pair(xan(), 7).unwrap()).into();	
        // Serialize conversion	
        let mut data = Vec::new();	
        a.serialize(&mut data).unwrap();	
        // Deserialize conversion	
        let mut ptr = &data[..];	
        let b = AllowedConversion::deserialize(&mut ptr).unwrap();	
        // Check that all bytes have been finished	
        assert!(ptr.is_empty(), "AllowedConversion bytes should be exhausted");	
        // Test that serializing then deserializing produces same object	
        assert_eq!(a, b, "serialization followed by deserialization changes value");	
    }	
}	

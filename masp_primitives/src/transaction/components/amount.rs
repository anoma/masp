use crate::asset_type::AssetType;
use borsh::schema::add_definition;
use borsh::schema::Fields;
use borsh::schema::{Declaration, Definition};
use borsh::BorshSchema;
use borsh::{BorshDeserialize, BorshSerialize};
use num_traits::{CheckedAdd, CheckedMul, CheckedNeg, CheckedSub, One};
use std::cmp::Ordering;
use std::collections::btree_map::Keys;
use std::collections::btree_map::{IntoIter, Iter};
use std::collections::BTreeMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign};
use zcash_encoding::Vector;

pub const MAX_MONEY: u64 = u64::MAX;
lazy_static::lazy_static! {
pub static ref DEFAULT_FEE: U64Sum = ValueSum::from_pair(zec(), 1000).unwrap();
}
/// A type-safe representation of some quantity of Zcash.
///
/// An ValueSum can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = i64::MAX).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid ValueSums together to obtain an invalid ValueSum. It is the user's
/// responsibility to handle the result of serializing potentially-invalid ValueSums. In
/// particular, a `Transaction` containing serialized invalid ValueSums will be rejected
/// by the network consensus rules.
///

pub type I8Sum = ValueSum<AssetType, i8>;

pub type U8Sum = ValueSum<AssetType, u8>;

pub type I16Sum = ValueSum<AssetType, i16>;

pub type U16Sum = ValueSum<AssetType, u16>;

pub type I32Sum = ValueSum<AssetType, i32>;

pub type U32Sum = ValueSum<AssetType, u32>;

pub type I64Sum = ValueSum<AssetType, i64>;

pub type U64Sum = ValueSum<AssetType, u64>;

pub type I128Sum = ValueSum<AssetType, i128>;

pub type U128Sum = ValueSum<AssetType, u128>;

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash)]
pub struct ValueSum<
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq,
>(BTreeMap<Unit, Value>);

impl<Unit, Value> memuse::DynamicUsage for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        unimplemented!()
        //self.0.dynamic_usage()
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        unimplemented!()
        //self.0.dynamic_usage_bounds()
    }
}

impl<Unit, Value> ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    /// Creates a non-negative ValueSum from a Value.
    pub fn from_nonnegative(atype: Unit, amount: Value) -> Result<Self, ()> {
        if amount == Value::default() {
            Ok(Self::zero())
        } else if Value::default() <= amount {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(ValueSum(ret))
        } else {
            Err(())
        }
    }
}

impl<Unit, Value> ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default,
{
    /// Creates an ValueSum from a Value.
    pub fn from_pair(atype: Unit, amount: Value) -> Result<Self, ()> {
        if amount == Value::default() {
            Ok(Self::zero())
        } else {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(ValueSum(ret))
        }
    }

    /// Filters out everything but the given AssetType from this ValueSum
    pub fn project(&self, index: Unit) -> Self {
        let val = self.0.get(&index).copied().unwrap_or_default();
        Self::from_pair(index, val).unwrap()
    }

    /// Get the given AssetType within this ValueSum
    pub fn get(&self, index: &Unit) -> Value {
        *self.0.get(index).unwrap_or(&Value::default())
    }
}

impl<Unit, Value> ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
{
    /// Returns a zero-valued ValueSum.
    pub fn zero() -> Self {
        ValueSum(BTreeMap::new())
    }

    /// Check if ValueSum is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns an iterator over the amount's non-zero asset-types
    pub fn asset_types(&self) -> Keys<'_, Unit, Value> {
        self.0.keys()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn components(&self) -> Iter<'_, Unit, Value> {
        self.0.iter()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn into_components(self) -> IntoIter<Unit, Value> {
        self.0.into_iter()
    }

    /// Filters out the given AssetType from this ValueSum
    pub fn reject(&self, index: Unit) -> Self {
        let mut val = self.clone();
        val.0.remove(&index);
        val
    }
}

impl<Unit, Value> BorshSerialize for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
{
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec: Vec<_> = self.components().collect();
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            elt.0.serialize(writer)?;
            elt.1.serialize(writer)?;
            Ok(())
        })
    }
}

impl<Unit, Value> BorshDeserialize for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq,
{
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let atype = Unit::deserialize_reader(reader)?;
            let value = Value::deserialize_reader(reader)?;
            Ok((atype, value))
        })?;
        Ok(Self(vec.into_iter().collect()))
    }
}

impl<Unit, Value> BorshSchema for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + BorshSchema,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + BorshSchema,
{
    fn add_definitions_recursively(definitions: &mut BTreeMap<Declaration, Definition>) {
        let definition = Definition::Enum {
            tag_width: 1,
            variants: vec![
                (253, "u16".into(), u16::declaration()),
                (254, "u32".into(), u32::declaration()),
                (255, "u64".into(), u64::declaration()),
            ],
        };
        add_definition(
            format!("{}::CompactSize", Self::declaration()),
            definition,
            definitions,
        );
        let definition = Definition::Sequence {
            length_width: 0,
            length_range: u64::MIN..=u64::MAX,
            elements: <(Unit, Value)>::declaration(),
        };
        add_definition(
            format!("{}::Sequence", Self::declaration()),
            definition,
            definitions,
        );
        let definition = Definition::Struct {
            fields: Fields::UnnamedFields(vec![
                format!("{}::CompactSize", Self::declaration()),
                format!("{}::Sequence", Self::declaration()),
            ]),
        };
        add_definition(Self::declaration(), definition, definitions);
        u16::add_definitions_recursively(definitions);
        u32::add_definitions_recursively(definitions);
        u64::add_definitions_recursively(definitions);
        <(Unit, Value)>::add_definitions_recursively(definitions);
    }

    fn declaration() -> Declaration {
        format!(
            r#"ValueSum<{}, {}>"#,
            Unit::declaration(),
            Value::declaration()
        )
    }
}

impl ValueSum<AssetType, i32> {
    /// Deserialize an ValueSum object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let atype = AssetType::read(reader)?;
            let mut value = [0; 4];
            reader.read_exact(&mut value)?;
            Ok((atype, i32::from_le_bytes(value)))
        })?;
        let mut ret = Self::zero();
        for (atype, amt) in vec {
            ret += Self::from_pair(atype, amt).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "amount out of range")
            })?;
        }
        Ok(ret)
    }

    /// Serialize an ValueSum object into a list of amounts denominated by
    /// distinct asset types
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec: Vec<_> = self.components().collect();
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            writer.write_all(elt.0.get_identifier())?;
            writer.write_all(elt.1.to_le_bytes().as_ref())?;
            Ok(())
        })
    }
}

impl ValueSum<AssetType, i64> {
    /// Deserialize an ValueSum object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let atype = AssetType::read(reader)?;
            let mut value = [0; 8];
            reader.read_exact(&mut value)?;
            Ok((atype, i64::from_le_bytes(value)))
        })?;
        let mut ret = Self::zero();
        for (atype, amt) in vec {
            ret += Self::from_pair(atype, amt).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "amount out of range")
            })?;
        }
        Ok(ret)
    }

    /// Serialize an ValueSum object into a list of amounts denominated by
    /// distinct asset types
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec: Vec<_> = self.components().collect();
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            writer.write_all(elt.0.get_identifier())?;
            writer.write_all(elt.1.to_le_bytes().as_ref())?;
            Ok(())
        })
    }
}

impl ValueSum<AssetType, i128> {
    /// Deserialize an ValueSum object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let atype = AssetType::read(reader)?;
            let mut value = [0; 16];
            reader.read_exact(&mut value)?;
            Ok((atype, i128::from_le_bytes(value)))
        })?;
        let mut ret = Self::zero();
        for (atype, amt) in vec {
            ret += Self::from_pair(atype, amt).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "amount out of range")
            })?;
        }
        Ok(ret)
    }

    /// Serialize an ValueSum object into a list of amounts denominated by
    /// distinct asset types
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec: Vec<_> = self.components().collect();
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            writer.write_all(elt.0.get_identifier())?;
            writer.write_all(elt.1.to_le_bytes().as_ref())?;
            Ok(())
        })
    }
}

impl<Unit, Value> From<Unit> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + One,
{
    fn from(atype: Unit) -> Self {
        let mut ret = BTreeMap::new();
        ret.insert(atype, Value::one());
        ValueSum(ret)
    }
}

impl<Unit, Value> PartialOrd for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    /// One ValueSum is more than or equal to another if each corresponding
    /// coordinate is more than or equal to the other's.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let zero = Value::default();
        let mut ordering = Some(Ordering::Equal);
        for k in self.0.keys().chain(other.0.keys()) {
            let v1 = self.0.get(k).unwrap_or(&zero);
            let v2 = other.0.get(k).unwrap_or(&zero);
            match (v1.partial_cmp(v2), ordering) {
                // Sums cannot be compared if even a single coordinate cannot be
                // compared
                (None, _) => ordering = None,
                // If sums are uncomparable, less, greater, or equal, another
                // equal coordinate will not change that
                (Some(Ordering::Equal), _) => {}
                // A lesser coordinate is inconsistent with the sum being
                // greater, and vice-versa
                (Some(Ordering::Less), Some(Ordering::Greater) | None) => ordering = None,
                (Some(Ordering::Greater), Some(Ordering::Less) | None) => ordering = None,
                // It only takes one lesser coordinate, to make a sum that
                // otherwise would have been equal, to be lesser
                (Some(Ordering::Less), Some(Ordering::Less | Ordering::Equal)) => {
                    ordering = Some(Ordering::Less)
                }
                (Some(Ordering::Greater), Some(Ordering::Greater | Ordering::Equal)) => {
                    ordering = Some(Ordering::Greater)
                }
            }
        }
        ordering
    }
}

macro_rules! impl_index {
    ($struct_type:ty) => {
        impl<Unit> Index<&Unit> for ValueSum<Unit, $struct_type>
        where
            Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
        {
            type Output = $struct_type;
            /// Query how much of the given asset this amount contains
            fn index(&self, index: &Unit) -> &Self::Output {
                self.0.get(index).unwrap_or(&0)
            }
        }
    };
}

impl_index!(i8);

impl_index!(u8);

impl_index!(i16);

impl_index!(u16);

impl_index!(i32);

impl_index!(u32);

impl_index!(i64);

impl_index!(u64);

impl_index!(i128);

impl_index!(u128);

impl<Unit, Value> MulAssign<Value> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedMul,
{
    fn mul_assign(&mut self, rhs: Value) {
        *self = self.clone() * rhs;
    }
}

impl<Unit, Value> Mul<Value> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedMul,
{
    type Output = ValueSum<Unit, Value>;

    fn mul(self, rhs: Value) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter() {
            comps.insert(
                atype.clone(),
                amount.checked_mul(&rhs).expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Value::default());
        ValueSum(comps)
    }
}

impl<Unit, Value> AddAssign<&ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    fn add_assign(&mut self, rhs: &ValueSum<Unit, Value>) {
        *self = self.clone() + rhs;
    }
}

impl<Unit, Value> AddAssign<ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    fn add_assign(&mut self, rhs: ValueSum<Unit, Value>) {
        *self += &rhs
    }
}

impl<Unit, Value> Add<&ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    type Output = ValueSum<Unit, Value>;

    fn add(self, rhs: &ValueSum<Unit, Value>) -> Self::Output {
        self.checked_add(rhs).expect("overflow detected")
    }
}

impl<Unit, Value> Add<ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    type Output = ValueSum<Unit, Value>;

    fn add(self, rhs: ValueSum<Unit, Value>) -> Self::Output {
        self + &rhs
    }
}

impl<Unit, Value> CheckedAdd for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    fn checked_add(&self, v: &Self) -> Option<Self> {
        let mut comps = self.0.clone();
        for (atype, amount) in v.components() {
            comps.insert(atype.clone(), self.get(atype).checked_add(amount)?);
        }
        comps.retain(|_, v| *v != Value::default());
        Some(ValueSum(comps))
    }
}

impl<Unit, Value> SubAssign<&ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedSub,
{
    fn sub_assign(&mut self, rhs: &ValueSum<Unit, Value>) {
        *self = self.clone() - rhs
    }
}

impl<Unit, Value> SubAssign<ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedSub,
{
    fn sub_assign(&mut self, rhs: ValueSum<Unit, Value>) {
        *self -= &rhs
    }
}

impl<Unit, Value> Neg for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedNeg,
{
    type Output = ValueSum<Unit, Value>;

    fn neg(mut self) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter_mut() {
            comps.insert(
                atype.clone(),
                amount.checked_neg().expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Value::default());
        ValueSum(comps)
    }
}

impl<Unit, Value> Sub<&ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = ValueSum<Unit, Value>;

    fn sub(self, rhs: &ValueSum<Unit, Value>) -> Self::Output {
        self.checked_sub(rhs).expect("underflow detected")
    }
}

impl<Unit, Value> Sub<ValueSum<Unit, Value>> for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = ValueSum<Unit, Value>;

    fn sub(self, rhs: ValueSum<Unit, Value>) -> Self::Output {
        self - &rhs
    }
}

impl<Unit, Value> CheckedSub for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    fn checked_sub(&self, v: &Self) -> Option<Self> {
        let mut comps = self.0.clone();
        for (atype, amount) in v.components() {
            comps.insert(atype.clone(), self.get(atype).checked_sub(amount)?);
        }
        comps.retain(|_, v| *v != Value::default());
        Some(ValueSum(comps))
    }
}

impl<Unit, Value> Sum for ValueSum<Unit, Value>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
    Self: Add<Output = Self>,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

impl<Unit, Output> ValueSum<Unit, Output>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Output: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default,
{
    pub fn try_from_sum<Value>(
        x: ValueSum<Unit, Value>,
    ) -> Result<Self, <Output as TryFrom<Value>>::Error>
    where
        Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
        Output: TryFrom<Value>,
    {
        let mut comps = BTreeMap::new();
        for (atype, amount) in x.0 {
            comps.insert(atype, amount.try_into()?);
        }
        comps.retain(|_, v| *v != Output::default());
        Ok(Self(comps))
    }

    pub fn from_sum<Value>(x: ValueSum<Unit, Value>) -> Self
    where
        Value: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
        Output: From<Value>,
    {
        let mut comps = BTreeMap::new();
        for (atype, amount) in x.0 {
            comps.insert(atype, amount.into());
        }
        comps.retain(|_, v| *v != Output::default());
        Self(comps)
    }
}

/// A type for balance violations in amount addition and subtraction
/// (overflow and underflow of allowed ranges)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BalanceError {
    Overflow,
    Underflow,
}

impl std::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            BalanceError::Overflow => {
                write!(
                    f,
                    "ValueSum addition resulted in a value outside the valid range."
                )
            }
            BalanceError::Underflow => write!(
                f,
                "ValueSum subtraction resulted in a value outside the valid range."
            ),
        }
    }
}

pub fn zec() -> AssetType {
    AssetType::new(b"ZEC").unwrap()
}

pub fn default_fee() -> ValueSum<AssetType, i64> {
    ValueSum::from_pair(zec(), 10000).unwrap()
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::prop_compose;

    use super::{I128Sum, I64Sum, U64Sum, ValueSum, MAX_MONEY};
    use crate::asset_type::testing::arb_asset_type;

    prop_compose! {
        pub fn arb_i64_sum()(asset_type in arb_asset_type(), amt in i64::MIN..i64::MAX) -> I64Sum {
            ValueSum::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_i128_sum()(asset_type in arb_asset_type(), amt in i128::MIN..i128::MAX) -> I128Sum {
            ValueSum::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_nonnegative_amount()(asset_type in arb_asset_type(), amt in 0u64..MAX_MONEY) -> U64Sum {
            ValueSum::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_positive_amount()(asset_type in arb_asset_type(), amt in 1u64..MAX_MONEY) -> U64Sum {
            ValueSum::from_pair(asset_type, amt).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{zec, I128Sum, I32Sum, I64Sum, ValueSum, MAX_MONEY};

    #[test]
    fn amount_in_range() {
        let mut bytes = Vec::with_capacity(100);

        macro_rules! test_vector {
            ($amount:ident) => {{
                bytes.clear();
                $amount.write(&mut bytes).unwrap();
                format!(
                    "b\"{}\",\n",
                    std::str::from_utf8(
                        &bytes
                            .iter()
                            .flat_map(|b| std::ascii::escape_default(*b))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
                )
            }};
        }
        macro_rules! value_amount {
            ($t:ty, $val:expr) => {{
                let mut amount = <$t>::from_pair(zec(), 1).unwrap();
                *amount.0.get_mut(&zec()).unwrap() = $val;
                amount
            }};
        }

        let test_amounts_i32 = [
            value_amount!(I32Sum, 0), // zec() asset with value 0
            I32Sum::from_pair(zec(), -1).unwrap(),
            I32Sum::from_pair(zec(), i32::MAX).unwrap(),
            I32Sum::from_pair(zec(), -i32::MAX).unwrap(),
        ];

        let test_amounts_i64 = [
            value_amount!(I64Sum, 0), // zec() asset with value 0
            I64Sum::from_pair(zec(), -1).unwrap(),
            I64Sum::from_pair(zec(), i64::MAX).unwrap(),
            I64Sum::from_pair(zec(), -i64::MAX).unwrap(),
        ];

        let test_amounts_i128 = [
            value_amount!(I128Sum, 0), // zec() asset with value 0
            I128Sum::from_pair(zec(), MAX_MONEY as i128).unwrap(),
            value_amount!(I128Sum, MAX_MONEY as i128 + 1),
            I128Sum::from_pair(zec(), -(MAX_MONEY as i128)).unwrap(),
            value_amount!(I128Sum, -(MAX_MONEY as i128 - 1)),
        ];

        println!(
            "let test_vectors_i32 = [{}];",
            test_amounts_i32
                .iter()
                .map(|a| test_vector!(a))
                .collect::<String>()
        );
        println!(
            "let test_vectors_i64 = [{}];",
            test_amounts_i64
                .iter()
                .map(|a| test_vector!(a))
                .collect::<String>()
        );

        println!(
            "let test_vectors_i128 = [{}];",
            test_amounts_i128
                .iter()
                .map(|a| test_vector!(a))
                .collect::<String>()
        );

        let zero = b"\x00";
        let test_vectors_i32 = [b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\x7f",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x00\x00\x80",
        ];
        let test_vectors_i64 = [b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\x7f",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x00\x00\x00\x00\x00\x00\x80",
        ];
        let test_vectors_i128 = [b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x02\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
        ];

        assert_eq!(
            I32Sum::read(&mut test_vectors_i32[0].as_ref()).unwrap(),
            ValueSum::zero()
        );
        assert_eq!(
            I64Sum::read(&mut test_vectors_i64[0].as_ref()).unwrap(),
            ValueSum::zero()
        );
        assert_eq!(
            I128Sum::read(&mut test_vectors_i128[0].as_ref()).unwrap(),
            ValueSum::zero()
        );

        assert_eq!(I32Sum::read(&mut zero.as_ref()).unwrap(), ValueSum::zero());
        assert_eq!(I64Sum::read(&mut zero.as_ref()).unwrap(), ValueSum::zero());
        assert_eq!(I128Sum::read(&mut zero.as_ref()).unwrap(), ValueSum::zero());

        test_vectors_i32
            .iter()
            .skip(1)
            .zip(test_amounts_i32.iter().skip(1))
            .for_each(|(tv, ta)| assert_eq!(I32Sum::read(&mut tv.as_ref()).unwrap(), *ta));
        test_vectors_i64
            .iter()
            .skip(1)
            .zip(test_amounts_i64.iter().skip(1))
            .for_each(|(tv, ta)| assert_eq!(I64Sum::read(&mut tv.as_ref()).unwrap(), *ta));
        test_vectors_i128
            .iter()
            .skip(1)
            .zip(test_amounts_i128.iter().skip(1))
            .for_each(|(tv, ta)| assert_eq!(I128Sum::read(&mut tv.as_ref()).unwrap(), *ta));
    }

    #[test]
    #[should_panic]
    fn add_panics_on_overflow() {
        let v = ValueSum::from_pair(zec(), MAX_MONEY).unwrap();
        let _sum = v + ValueSum::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = ValueSum::from_pair(zec(), MAX_MONEY).unwrap();
        a += ValueSum::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_panics_on_underflow() {
        let v = ValueSum::from_pair(zec(), 0u64).unwrap();
        let _diff = v - ValueSum::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = ValueSum::from_pair(zec(), 0u64).unwrap();
        a -= ValueSum::from_pair(zec(), 1).unwrap();
    }
}

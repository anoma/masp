use crate::asset_type::AssetType;
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
/// An Amount can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = i64::MAX).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid Amounts together to obtain an invalid Amount. It is the user's
/// responsibility to handle the result of serializing potentially-invalid Amounts. In
/// particular, a `Transaction` containing serialized invalid Amounts will be rejected
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

#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Hash)]
pub struct ValueSum<
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq,
>(pub BTreeMap<Unit, Magnitude>);

impl<Unit, Magnitude> memuse::DynamicUsage for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
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

impl<Unit, Magnitude> ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    /// Creates a non-negative Amount from a Magnitude.
    pub fn from_nonnegative(atype: Unit, amount: Magnitude) -> Result<Self, ()> {
        if amount == Magnitude::default() {
            Ok(Self::zero())
        } else if Magnitude::default() <= amount {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(ValueSum(ret))
        } else {
            Err(())
        }
    }
}

impl<Unit, Magnitude> ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default,
{
    /// Creates an Amount from a Magnitude.
    pub fn from_pair(atype: Unit, amount: Magnitude) -> Result<Self, ()> {
        if amount == Magnitude::default() {
            Ok(Self::zero())
        } else {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(ValueSum(ret))
        }
    }

    /// Filters out everything but the given AssetType from this Amount
    pub fn project(&self, index: Unit) -> Self {
        let val = self.0.get(&index).copied().unwrap_or_default();
        Self::from_pair(index, val).unwrap()
    }

    /// Get the given AssetType within this Amount
    pub fn get(&self, index: &Unit) -> Magnitude {
        *self.0.get(index).unwrap_or(&Magnitude::default())
    }
}

impl<Unit, Magnitude> ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
{
    /// Returns a zero-valued Amount.
    pub fn zero() -> Self {
        ValueSum(BTreeMap::new())
    }

    /// Returns an iterator over the amount's non-zero asset-types
    pub fn asset_types(&self) -> Keys<'_, Unit, Magnitude> {
        self.0.keys()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn components(&self) -> Iter<'_, Unit, Magnitude> {
        self.0.iter()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn into_components(self) -> IntoIter<Unit, Magnitude> {
        self.0.into_iter()
    }

    /// Filters out the given AssetType from this Amount
    pub fn reject(&self, index: Unit) -> Self {
        let mut val = self.clone();
        val.0.remove(&index);
        val
    }
}

impl ValueSum<AssetType, i32> {
    /// Deserialize an Amount object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let mut atype = [0; 32];
            let mut value = [0; 4];
            reader.read_exact(&mut atype)?;
            reader.read_exact(&mut value)?;
            let atype = AssetType::from_identifier(&atype).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid asset type")
            })?;
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

    /// Serialize an Amount object into a list of amounts denominated by
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
    /// Deserialize an Amount object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let mut atype = [0; 32];
            let mut value = [0; 8];
            reader.read_exact(&mut atype)?;
            reader.read_exact(&mut value)?;
            let atype = AssetType::from_identifier(&atype).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid asset type")
            })?;
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

    /// Serialize an Amount object into a list of amounts denominated by
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
    /// Deserialize an Amount object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let mut atype = [0; 32];
            let mut value = [0; 16];
            reader.read_exact(&mut atype)?;
            reader.read_exact(&mut value)?;
            let atype = AssetType::from_identifier(&atype).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid asset type")
            })?;
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

    /// Serialize an Amount object into a list of amounts denominated by
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

impl<Unit, Magnitude> From<Unit> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + One,
{
    fn from(atype: Unit) -> Self {
        let mut ret = BTreeMap::new();
        ret.insert(atype, Magnitude::one());
        ValueSum(ret)
    }
}

impl<Unit, Magnitude> PartialOrd for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    /// One ValueSum is more than or equal to another if each corresponding
    /// coordinate is more than or equal to the other's.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let zero = Magnitude::default();
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

impl<Unit, Magnitude> MulAssign<Magnitude> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedMul,
{
    fn mul_assign(&mut self, rhs: Magnitude) {
        *self = self.clone() * rhs;
    }
}

impl<Unit, Magnitude> Mul<Magnitude> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedMul,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn mul(self, rhs: Magnitude) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter() {
            comps.insert(
                atype.clone(),
                amount.checked_mul(&rhs).expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        ValueSum(comps)
    }
}

impl<Unit, Magnitude> AddAssign<&ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    fn add_assign(&mut self, rhs: &ValueSum<Unit, Magnitude>) {
        *self = self.clone() + rhs;
    }
}

impl<Unit, Magnitude> AddAssign<ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    fn add_assign(&mut self, rhs: ValueSum<Unit, Magnitude>) {
        *self += &rhs
    }
}

impl<Unit, Magnitude> Add<&ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn add(self, rhs: &ValueSum<Unit, Magnitude>) -> Self::Output {
        let mut comps = self.0.clone();
        for (atype, amount) in rhs.components() {
            comps.insert(
                atype.clone(),
                self.get(atype)
                    .checked_add(amount)
                    .expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        ValueSum(comps)
    }
}

impl<Unit, Magnitude> Add<ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedAdd,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn add(self, rhs: ValueSum<Unit, Magnitude>) -> Self::Output {
        self + &rhs
    }
}

impl<Unit, Magnitude> SubAssign<&ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedSub,
{
    fn sub_assign(&mut self, rhs: &ValueSum<Unit, Magnitude>) {
        *self = self.clone() - rhs
    }
}

impl<Unit, Magnitude> SubAssign<ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedSub,
{
    fn sub_assign(&mut self, rhs: ValueSum<Unit, Magnitude>) {
        *self -= &rhs
    }
}

impl<Unit, Magnitude> Neg for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize
        + BorshDeserialize
        + PartialEq
        + Eq
        + Copy
        + Default
        + PartialOrd
        + CheckedNeg,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn neg(mut self) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter_mut() {
            comps.insert(
                atype.clone(),
                amount.checked_neg().expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        ValueSum(comps)
    }
}

impl<Unit, Magnitude> Sub<&ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn sub(self, rhs: &ValueSum<Unit, Magnitude>) -> Self::Output {
        let mut comps = self.0.clone();
        for (atype, amount) in rhs.components() {
            comps.insert(
                atype.clone(),
                self.get(atype)
                    .checked_sub(amount)
                    .expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        ValueSum(comps)
    }
}

impl<Unit, Magnitude> Sub<ValueSum<Unit, Magnitude>> for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = ValueSum<Unit, Magnitude>;

    fn sub(self, rhs: ValueSum<Unit, Magnitude>) -> Self::Output {
        self - &rhs
    }
}

impl<Unit, Magnitude> Sum for ValueSum<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
    Self: Add<Output = Self>,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
    }
}

/// Workaround for the blanket implementation of TryFrom
pub struct TryFromNt<X>(pub X);

impl<Unit, Magnitude, Output> TryFrom<TryFromNt<ValueSum<Unit, Magnitude>>>
    for ValueSum<Unit, Output>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
    Output: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + TryFrom<Magnitude>,
{
    type Error = <Output as TryFrom<Magnitude>>::Error;

    fn try_from(x: TryFromNt<ValueSum<Unit, Magnitude>>) -> Result<Self, Self::Error> {
        let mut comps = BTreeMap::new();
        for (atype, amount) in x.0 .0 {
            comps.insert(atype, amount.try_into()?);
        }
        Ok(Self(comps))
    }
}

/// Workaround for the blanket implementation of TryFrom
pub struct FromNt<X>(pub X);

impl<Unit, Magnitude, Output> From<FromNt<ValueSum<Unit, Magnitude>>> for ValueSum<Unit, Output>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
    Output: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + From<Magnitude>,
{
    fn from(x: FromNt<ValueSum<Unit, Magnitude>>) -> Self {
        let mut comps = BTreeMap::new();
        for (atype, amount) in x.0 .0 {
            comps.insert(atype, amount.into());
        }
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
                    "Amount addition resulted in a value outside the valid range."
                )
            }
            BalanceError::Underflow => write!(
                f,
                "Amount subtraction resulted in a value outside the valid range."
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
            ValueSum::from_pair(asset_type, amt as i128).unwrap()
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
    use super::{zec, I64Sum, ValueSum, MAX_MONEY};

    #[test]
    fn amount_in_range() {
        let zero = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(I64Sum::read(&mut zero.as_ref()).unwrap(), ValueSum::zero());

        let neg_one = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\xff";
        assert_eq!(
            I64Sum::read(&mut neg_one.as_ref()).unwrap(),
            I64Sum::from_pair(zec(), -1).unwrap()
        );

        let max_money = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\x7f";

        assert_eq!(
            I64Sum::read(&mut max_money.as_ref()).unwrap(),
            I64Sum::from_pair(zec(), i64::MAX).unwrap()
        );

        //let max_money_p1 = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x40\x07\x5a\xf0\x75\x07\x00";
        //assert!(Amount::read(&mut max_money_p1.as_ref()).is_err());

        //let mut neg_max_money = [0u8; 41];
        //let mut amount = Amount::from_pair(zec(), -MAX_MONEY).unwrap();
        //*amount.0.get_mut(&zec()).unwrap() = i64::MIN;
        //amount.write(&mut neg_max_money.as_mut());
        //dbg!(std::str::from_utf8(&neg_max_money.as_ref().iter().map(|b| std::ascii::escape_default(*b)).flatten().collect::<Vec<_>>()).unwrap());

        let neg_max_money = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x01\x00\x00\x00\x00\x00\x00\x80";
        assert_eq!(
            I64Sum::read(&mut neg_max_money.as_ref()).unwrap(),
            I64Sum::from_pair(zec(), -i64::MAX).unwrap()
        );
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

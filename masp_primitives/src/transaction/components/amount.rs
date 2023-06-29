use crate::asset_type::AssetType;
use borsh::{BorshDeserialize, BorshSerialize};
use num_traits::{CheckedAdd, CheckedMul, CheckedNeg, CheckedSub};
use std::cmp::Ordering;
use std::collections::btree_map::Keys;
use std::collections::btree_map::{IntoIter, Iter};
use std::collections::BTreeMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign};
use zcash_encoding::Vector;

pub const MAX_MONEY: i64 = i64::MAX;
pub const MIN_MONEY: i64 = i64::MIN;
lazy_static::lazy_static! {
pub static ref DEFAULT_FEE: Amount<AssetType, i64> = Amount::from_pair(zec(), 1000).unwrap();
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

pub type I64Amt = Amount<AssetType, i64>;

pub type U64Amt = Amount<AssetType, u64>;

pub type I128Amt = Amount<AssetType, i128>;

#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Hash)]
pub struct Amount<
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq,
>(pub BTreeMap<Unit, Magnitude>);

impl<Unit, Magnitude> memuse::DynamicUsage for Amount<Unit, Magnitude>
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

impl<Unit, Magnitude> Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
{
    /// Creates a non-negative Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative(atype: Unit, amount: Magnitude) -> Result<Self, ()> {
        if amount == Magnitude::default() {
            Ok(Self::zero())
        } else if Magnitude::default() <= amount {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }
}

impl<Unit, Magnitude> Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default,
{
    /// Creates an Amount from a type convertible to i64.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub fn from_pair(atype: Unit, amount: Magnitude) -> Result<Self, ()> {
        if amount == Magnitude::default() {
            Ok(Self::zero())
        } else {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
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

impl<Unit, Magnitude> Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
{
    /// Returns a zero-valued Amount.
    pub fn zero() -> Self {
        Amount(BTreeMap::new())
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

impl Amount<AssetType, i64> {
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

impl<Unit, Magnitude> From<Unit> for Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + From<bool>,
{
    fn from(atype: Unit) -> Self {
        let mut ret = BTreeMap::new();
        ret.insert(atype, true.into());
        Amount(ret)
    }
}

impl<Unit, Magnitude> PartialOrd for Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + PartialOrd,
    Self: Sub<Self, Output = Self>,
{
    /// One Amount is more than or equal to another if each corresponding
    /// coordinate is more than the other's.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let diff = other.clone() - self.clone();
        if diff.0.values().all(|x| *x == Default::default()) {
            Some(Ordering::Equal)
        } else if diff.0.values().all(|x| *x >= Default::default()) {
            Some(Ordering::Less)
        } else if diff.0.values().all(|x| *x <= Default::default()) {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

macro_rules! impl_index {
    ($struct_type:ty) => {
        impl<Unit> Index<&Unit> for Amount<Unit, $struct_type>
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

impl_index!(i64);

impl_index!(u64);

impl_index!(i128);

impl<Unit, Magnitude> MulAssign<Magnitude> for Amount<Unit, Magnitude>
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

impl<Unit, Magnitude> Mul<Magnitude> for Amount<Unit, Magnitude>
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
    type Output = Amount<Unit, Magnitude>;

    fn mul(self, rhs: Magnitude) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter() {
            comps.insert(
                atype.clone(),
                amount.checked_mul(&rhs).expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        Amount(comps)
    }
}

impl<Unit, Magnitude> AddAssign<&Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    fn add_assign(&mut self, rhs: &Amount<Unit, Magnitude>) {
        *self = self.clone() + rhs;
    }
}

impl<Unit, Magnitude> AddAssign<Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    fn add_assign(&mut self, rhs: Amount<Unit, Magnitude>) {
        *self += &rhs
    }
}

impl<Unit, Magnitude> Add<&Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    type Output = Amount<Unit, Magnitude>;

    fn add(self, rhs: &Amount<Unit, Magnitude>) -> Self::Output {
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
        Amount(comps)
    }
}

impl<Unit, Magnitude> Add<Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    type Output = Amount<Unit, Magnitude>;

    fn add(self, rhs: Amount<Unit, Magnitude>) -> Self::Output {
        self + &rhs
    }
}

impl<Unit, Magnitude> SubAssign<&Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    fn sub_assign(&mut self, rhs: &Amount<Unit, Magnitude>) {
        *self = self.clone() - rhs
    }
}

impl<Unit, Magnitude> SubAssign<Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
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
    fn sub_assign(&mut self, rhs: Amount<Unit, Magnitude>) {
        *self -= &rhs
    }
}

impl<Unit, Magnitude> Neg for Amount<Unit, Magnitude>
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
    type Output = Amount<Unit, Magnitude>;

    fn neg(mut self) -> Self::Output {
        let mut comps = BTreeMap::new();
        for (atype, amount) in self.0.iter_mut() {
            comps.insert(
                atype.clone(),
                amount.checked_neg().expect("overflow detected"),
            );
        }
        comps.retain(|_, v| *v != Magnitude::default());
        Amount(comps)
    }
}

impl<Unit, Magnitude> Sub<&Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = Amount<Unit, Magnitude>;

    fn sub(self, rhs: &Amount<Unit, Magnitude>) -> Self::Output {
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
        Amount(comps)
    }
}

impl<Unit, Magnitude> Sub<Amount<Unit, Magnitude>> for Amount<Unit, Magnitude>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + Default + CheckedSub,
{
    type Output = Amount<Unit, Magnitude>;

    fn sub(self, rhs: Amount<Unit, Magnitude>) -> Self::Output {
        self - &rhs
    }
}

impl<Unit, Magnitude> Sum for Amount<Unit, Magnitude>
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

impl<Unit, Magnitude, Output> TryFrom<TryFromNt<Amount<Unit, Magnitude>>> for Amount<Unit, Output>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
    Output: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + TryFrom<Magnitude>,
{
    type Error = <Output as TryFrom<Magnitude>>::Error;

    fn try_from(x: TryFromNt<Amount<Unit, Magnitude>>) -> Result<Self, Self::Error> {
        let mut comps = BTreeMap::new();
        for (atype, amount) in x.0 .0 {
            comps.insert(atype, amount.try_into()?);
        }
        Ok(Self(comps))
    }
}

/// Workaround for the blanket implementation of TryFrom
pub struct FromNt<X>(pub X);

impl<Unit, Magnitude, Output> From<FromNt<Amount<Unit, Magnitude>>> for Amount<Unit, Output>
where
    Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone,
    Magnitude: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy,
    Output: BorshSerialize + BorshDeserialize + PartialEq + Eq + Copy + From<Magnitude>,
{
    fn from(x: FromNt<Amount<Unit, Magnitude>>) -> Self {
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

pub fn default_fee() -> Amount<AssetType, i64> {
    Amount::from_pair(zec(), 10000).unwrap()
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::prop_compose;

    use super::{Amount, I64Amt, MAX_MONEY};
    use crate::asset_type::testing::arb_asset_type;

    prop_compose! {
        pub fn arb_amount()(asset_type in arb_asset_type(), amt in -MAX_MONEY..MAX_MONEY) -> I64Amt {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_nonnegative_amount()(asset_type in arb_asset_type(), amt in 0i64..MAX_MONEY) -> I64Amt {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_positive_amount()(asset_type in arb_asset_type(), amt in 1i64..MAX_MONEY) -> I64Amt {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{zec, Amount, MAX_MONEY, MIN_MONEY};

    #[test]
    fn amount_in_range() {
        let zero = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Amount::read(&mut zero.as_ref()).unwrap(), Amount::zero());

        let neg_one = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\xff";
        assert_eq!(
            Amount::read(&mut neg_one.as_ref()).unwrap(),
            Amount::from_pair(zec(), -1).unwrap()
        );

        let max_money = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\xff\xff\xff\xff\xff\xff\xff\x7f";

        assert_eq!(
            Amount::read(&mut max_money.as_ref()).unwrap(),
            Amount::from_pair(zec(), MAX_MONEY).unwrap()
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
            Amount::read(&mut neg_max_money.as_ref()).unwrap(),
            Amount::from_pair(zec(), -MAX_MONEY).unwrap()
        );
    }

    #[test]
    #[should_panic]
    fn add_panics_on_overflow() {
        let v = Amount::from_pair(zec(), MAX_MONEY).unwrap();
        let _sum = v + Amount::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = Amount::from_pair(zec(), MAX_MONEY).unwrap();
        a += Amount::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_panics_on_underflow() {
        let v = Amount::from_pair(zec(), MIN_MONEY).unwrap();
        let _diff = v - Amount::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = Amount::from_pair(zec(), MIN_MONEY).unwrap();
        a -= Amount::from_pair(zec(), 1).unwrap();
    }
}

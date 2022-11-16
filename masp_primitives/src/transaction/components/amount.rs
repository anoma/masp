use crate::asset_type::AssetType;
use borsh::{BorshDeserialize, BorshSerialize};
use std::cmp::Ordering;
use std::collections::btree_map::Keys;
use std::collections::btree_map::{IntoIter, Iter};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::hash::Hash;
use std::io::{Read, Write};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign};
use zcash_encoding::Vector;

pub const MAX_MONEY: i64 = i64::MAX;
lazy_static::lazy_static! {
pub static ref DEFAULT_FEE: Amount = Amount::from_pair(zec(), 1000).unwrap();
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
#[derive(Clone, Default, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Hash)]
pub struct Amount<Unit: Hash + Ord + BorshSerialize + BorshDeserialize = AssetType>(
    pub BTreeMap<Unit, i64>,
);

// TODO
impl memuse::DynamicUsage for Amount {
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        0
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Amount<Unit> {
    /// Returns a zero-valued Amount.
    pub fn zero() -> Self {
        Amount(BTreeMap::new())
    }

    /// Creates a non-negative Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative<Amt: TryInto<i64>>(atype: Unit, amount: Amt) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Self::zero())
        } else if 0 <= amount && amount <= MAX_MONEY {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }
    /// Creates an Amount from a type convertible to i64.
    ///
    /// Returns an error if the amount is outside the range `{-MAX_MONEY..MAX_MONEY}`.
    pub fn from_pair<Amt: TryInto<i64>>(atype: Unit, amount: Amt) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Self::zero())
        } else if -MAX_MONEY <= amount && amount <= MAX_MONEY {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }

    /// Returns an iterator over the amount's non-zero asset-types
    pub fn asset_types(&self) -> Keys<'_, Unit, i64> {
        self.0.keys()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn components(&self) -> Iter<'_, Unit, i64> {
        self.0.iter()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn into_components(self) -> IntoIter<Unit, i64> {
        self.0.into_iter()
    }

    /// Filters out everything but the given AssetType from this Amount
    pub fn project(&self, index: Unit) -> Self {
        let val = self.0.get(&index).copied().unwrap_or(0);
        Self::from_pair(index, val).unwrap()
    }

    /// Filters out the given AssetType from this Amount
    pub fn reject(&self, index: Unit) -> Self {
        self.clone() - self.project(index)
    }
}

impl Amount<AssetType> {
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

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize> From<Unit> for Amount<Unit> {
    fn from(atype: Unit) -> Self {
        let mut ret = BTreeMap::new();
        ret.insert(atype, 1);
        Amount(ret)
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> PartialOrd for Amount<Unit> {
    /// One Amount is more than or equal to another if each corresponding
    /// coordinate is more than the other's.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut diff = other.clone();
        for (atype, amount) in self.components() {
            let ent = diff[atype] - amount;
            if ent == 0 {
                diff.0.remove(atype);
            } else {
                diff.0.insert(atype.clone(), ent);
            }
        }
        if diff.0.values().all(|x| *x == 0) {
            Some(Ordering::Equal)
        } else if diff.0.values().all(|x| *x >= 0) {
            Some(Ordering::Less)
        } else if diff.0.values().all(|x| *x <= 0) {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize> Index<&Unit> for Amount<Unit> {
    type Output = i64;
    /// Query how much of the given asset this amount contains
    fn index(&self, index: &Unit) -> &Self::Output {
        self.0.get(index).unwrap_or(&0)
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> MulAssign<i64> for Amount<Unit> {
    fn mul_assign(&mut self, rhs: i64) {
        for (_atype, amount) in self.0.iter_mut() {
            let ent = *amount * rhs;
            if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                *amount = ent;
            } else {
                panic!("multiplication should remain in range");
            }
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Mul<i64> for Amount<Unit> {
    type Output = Self;

    fn mul(mut self, rhs: i64) -> Self {
        self *= rhs;
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> AddAssign<&Amount<Unit>>
    for Amount<Unit>
{
    fn add_assign(&mut self, rhs: &Self) {
        for (atype, amount) in rhs.components() {
            let ent = self[atype] + amount;
            if ent == 0 {
                self.0.remove(atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                self.0.insert(atype.clone(), ent);
            } else {
                panic!("addition should remain in range");
            }
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> AddAssign<Amount<Unit>>
    for Amount<Unit>
{
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Add<&Amount<Unit>>
    for Amount<Unit>
{
    type Output = Self;

    fn add(mut self, rhs: &Self) -> Self {
        self += rhs;
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Add<Amount<Unit>>
    for Amount<Unit>
{
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self {
        self += &rhs;
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> SubAssign<&Amount<Unit>>
    for Amount<Unit>
{
    fn sub_assign(&mut self, rhs: &Self) {
        for (atype, amount) in rhs.components() {
            let ent = self[atype] - amount;
            if ent == 0 {
                self.0.remove(atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                self.0.insert(atype.clone(), ent);
            } else {
                panic!("subtraction should remain in range");
            }
        }
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> SubAssign<Amount<Unit>>
    for Amount<Unit>
{
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs
    }
}

impl Neg for Amount {
    type Output = Self;

    fn neg(mut self) -> Self {
        for (_, amount) in self.0.iter_mut() {
            *amount = -*amount;
        }
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Sub<&Amount<Unit>>
    for Amount<Unit>
{
    type Output = Self;

    fn sub(mut self, rhs: &Self) -> Self {
        self -= rhs;
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Sub<Amount<Unit>>
    for Amount<Unit>
{
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self {
        self -= &rhs;
        self
    }
}

impl<Unit: Hash + Ord + BorshSerialize + BorshDeserialize + Clone> Sum for Amount<Unit> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::zero(), Add::add)
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

pub fn default_fee() -> Amount {
    Amount::from_pair(zec(), 10000).unwrap()
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::prop_compose;

    use super::{Amount, MAX_MONEY};
    use crate::asset_type::testing::arb_asset_type;

    prop_compose! {
        pub fn arb_amount()(asset_type in arb_asset_type(), amt in -MAX_MONEY..MAX_MONEY) -> Amount {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_nonnegative_amount()(asset_type in arb_asset_type(), amt in 0i64..MAX_MONEY) -> Amount {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_positive_amount()(asset_type in arb_asset_type(), amt in 1i64..MAX_MONEY) -> Amount {
            Amount::from_pair(asset_type, amt).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{zec, Amount, MAX_MONEY};

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

        let neg_max_money_m1 = b"\x01\x94\xf3O\xfdd\xef\n\xc3i\x08\xfd\xdf\xec\x05hX\x06)\xc4Vq\x0f\xa1\x86\x83\x12\xa8\x7f\xbf\n\xa5\t\x00\x00\x00\x00\x00\x00\x00\x80";
        assert!(Amount::read(&mut neg_max_money_m1.as_ref()).is_err());
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
        let v = Amount::from_pair(zec(), -MAX_MONEY).unwrap();
        let _diff = v - Amount::from_pair(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = Amount::from_pair(zec(), -MAX_MONEY).unwrap();
        a -= Amount::from_pair(zec(), 1).unwrap();
    }
}

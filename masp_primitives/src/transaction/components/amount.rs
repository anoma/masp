use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::iter::Sum;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::collections::BTreeMap;
use crate::transaction::AssetType;
use std::iter::FromIterator;
use crate::serialize::Vector;
use std::io::Read;
use std::io::Write;
use std::convert::TryInto;
use std::ops::Index;
use std::collections::btree_map::Keys;
use std::collections::btree_map::Iter;

const COIN: i64 = 1_0000_0000;
const MAX_MONEY: i64 = 21_000_000 * COIN;

pub fn zec() -> AssetType {
    AssetType::new("ZEC".as_bytes()).unwrap()
}

pub fn default_fee() -> Amount {
    Amount::from(zec(), 10000).unwrap()
}

/// A type-safe representation of some quantity of Zcash.
///
/// An Amount can only be constructed from an integer that is within the valid monetary
/// range of `{-MAX_MONEY..MAX_MONEY}` (where `MAX_MONEY` = 21,000,000 × 10⁸ zatoshis).
/// However, this range is not preserved as an invariant internally; it is possible to
/// add two valid Amounts together to obtain an invalid Amount. It is the user's
/// responsibility to handle the result of serializing potentially-invalid Amounts. In
/// particular, a [`Transaction`] containing serialized invalid Amounts will be rejected
/// by the network consensus rules.
///
/// [`Transaction`]: crate::transaction::Transaction
#[derive(
    Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialOrd, Eq, Ord, Hash
)]
pub struct Amount(BTreeMap<AssetType, i64>);

impl Amount {
    /// Returns a zero-valued Amount.
    pub fn zero() -> Self {
        Amount(BTreeMap::new())
    }

    /// Creates a non-negative Amount from an i64.
    ///
    /// Returns an error if the amount is outside the range `{0..MAX_MONEY}`.
    pub fn from_nonnegative<Amt: TryInto<i64>>(
        atype: AssetType,
        amount: Amt
    ) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Amount::zero())
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
    pub fn from<Amt: TryInto<i64>>(
        atype: AssetType,
        amount: Amt
    ) -> Result<Self, ()> {
        let amount = amount.try_into().map_err(|_| ())?;
        if amount == 0 {
            Ok(Amount::zero())
        } else if -MAX_MONEY <= amount && amount <= MAX_MONEY {
            let mut ret = BTreeMap::new();
            ret.insert(atype, amount);
            Ok(Amount(ret))
        } else {
            Err(())
        }
    }

    /// Deserialize an Amount object from a list of amounts denominated by
    /// different assets
    pub fn read<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        let vec = Vector::read(reader, |reader| {
            let mut atype = [0; 32];
            let mut value = [0; 8];
            reader.read_exact(&mut atype)?;
            reader.read_exact(&mut value)?;
            let atype = AssetType::from_identifier(&atype)
                .ok_or_else(|| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid asset type"
                ))?;
            Ok((atype, i64::from_le_bytes(value)))
        })?;
        let mut ret = Amount::zero();
        for (atype, amt) in vec {
            ret += Amount::from(atype, amt)
                .map_err(|_| std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "amount out of range"
                ))?;
        }
        Ok(ret)
    }

    /// Serialize an Amount object into a list of amounts denominated by
    /// distinct asset types
    pub fn write<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec = Vec::<(AssetType, i64)>::from(self.clone());
        Vector::write(writer, vec.as_ref(), |writer, elt| {
            writer.write_all(elt.0.get_identifier())?;
            writer.write_all(elt.1.to_le_bytes().as_ref())?;
            Ok(())
        })
    }

    /// Returns `true` iff `self` has a positive component
    pub fn has_positive(&self) -> bool {
        self.0.values().any(|x| x.is_positive())
    }

    /// Returns `true` iff `self` has a negative component
    pub fn has_negative(&self) -> bool {
        self.0.values().any(|x| x.is_negative())
    }

    /// Returns an iterator over the amount's non-zero asset-types
    pub fn asset_types(&self) -> Keys<'_, AssetType, i64> {
        self.0.keys()
    }

    /// Returns an iterator over the amount's non-zero components
    pub fn components(&self) -> Iter<'_, AssetType, i64> {
        self.0.iter()
    }
}

impl Index<&AssetType> for Amount {
    type Output = i64;
    /// Query how much of the given asset this amount contains
    fn index(&self, index: &AssetType) -> &Self::Output {
        if let Some(val) = self.0.get(index) {
            val
        } else {
            &0
        }
    }
}

impl From<Amount> for Vec<(AssetType, i64)> {
    fn from(amount: Amount) -> Vec<(AssetType, i64)> {
        Vec::from_iter(amount.0.into_iter())
    }
}

impl Add<Amount> for Amount {
    type Output = Amount;

    fn add(self, rhs: Amount) -> Amount {
        let mut ret = self.clone();
        for (atype, amount) in rhs.0 {
            ret.0.entry(atype).or_insert(0);
            let ent = ret.0[&atype] + amount;
            if ent == 0 {
                ret.0.remove(&atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                ret.0.insert(atype, ent);
            } else {
                panic!("addition should remain in range");
            }
        }
        ret
    }
}

impl AddAssign<Amount> for Amount {
    fn add_assign(&mut self, rhs: Amount) {
        *self = self.clone() + rhs
    }
}

impl Sub<Amount> for Amount {
    type Output = Amount;

    fn sub(self, rhs: Amount) -> Amount {
        let mut ret = self.clone();
        for (atype, amount) in rhs.0 {
            ret.0.entry(atype).or_insert(0);
            let ent = ret.0[&atype] - amount;
            if ent == 0 {
                ret.0.remove(&atype);
            } else if -MAX_MONEY <= ent && ent <= MAX_MONEY {
                ret.0.insert(atype, ent);
            } else {
                panic!("subtraction should remain in range");
            }
        }
        ret
    }
}

impl SubAssign<Amount> for Amount {
    fn sub_assign(&mut self, rhs: Amount) {
        *self = self.clone() - rhs
    }
}

impl Sum for Amount {
    fn sum<I: Iterator<Item = Amount>>(iter: I) -> Amount {
        iter.fold(Amount::zero(), Add::add)
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, MAX_MONEY, zec};

    /*#[test]
    fn amount_in_range() {
        let zero = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Amount::from_u64_le_bytes(zero.clone()).unwrap(), Amount(0));
        assert_eq!(
            Amount::from_nonnegative_i64_le_bytes(zero.clone()).unwrap(),
            Amount(0)
        );
        assert_eq!(Amount::from_i64_le_bytes(zero.clone()).unwrap(), Amount(0));

        let neg_one = b"\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(Amount::from_u64_le_bytes(neg_one.clone()).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(neg_one.clone()).is_err());
        assert_eq!(
            Amount::from_i64_le_bytes(neg_one.clone()).unwrap(),
            Amount(-1)
        );

        let max_money = b"\x00\x40\x07\x5a\xf0\x75\x07\x00";
        assert_eq!(
            Amount::from_u64_le_bytes(max_money.clone()).unwrap(),
            Amount(MAX_MONEY)
        );
        assert_eq!(
            Amount::from_nonnegative_i64_le_bytes(max_money.clone()).unwrap(),
            Amount(MAX_MONEY)
        );
        assert_eq!(
            Amount::from_i64_le_bytes(max_money.clone()).unwrap(),
            Amount(MAX_MONEY)
        );

        let max_money_p1 = b"\x01\x40\x07\x5a\xf0\x75\x07\x00";
        assert!(Amount::from_u64_le_bytes(max_money_p1.clone()).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(max_money_p1.clone()).is_err());
        assert!(Amount::from_i64_le_bytes(max_money_p1.clone()).is_err());

        let neg_max_money = b"\x00\xc0\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::from_u64_le_bytes(neg_max_money.clone()).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(neg_max_money.clone()).is_err());
        assert_eq!(
            Amount::from_i64_le_bytes(neg_max_money.clone()).unwrap(),
            Amount(-MAX_MONEY)
        );

        let neg_max_money_m1 = b"\xff\xbf\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::from_u64_le_bytes(neg_max_money_m1.clone()).is_err());
        assert!(Amount::from_nonnegative_i64_le_bytes(neg_max_money_m1.clone()).is_err());
        assert!(Amount::from_i64_le_bytes(neg_max_money_m1.clone()).is_err());
    }*/

    #[test]
    #[should_panic]
    fn add_panics_on_overflow() {
        let v = Amount::from(zec(), MAX_MONEY).unwrap();
        let _sum = v + Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn add_assign_panics_on_overflow() {
        let mut a = Amount::from(zec(), MAX_MONEY).unwrap();
        a += Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_panics_on_underflow() {
        let v = Amount::from(zec(), -MAX_MONEY).unwrap();
        let _diff = v - Amount::from(zec(), 1).unwrap();
    }

    #[test]
    #[should_panic]
    fn sub_assign_panics_on_underflow() {
        let mut a = Amount::from(zec(), -MAX_MONEY).unwrap();
        a -= Amount::from(zec(), 1).unwrap();
    }
}

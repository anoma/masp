//! Types and functions for building transparent transaction components.

use crate::{
    asset_type::AssetType,
    transaction::{
        components::{
            amount::{Amount, BalanceError, MAX_MONEY},
            transparent::{fees, Authorization, Authorized, Bundle, TxOut},
        },
        sighash::TransparentAuthorizingContext,
        TransparentAddress,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
    InvalidAsset,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::InvalidAsset => write!(f, "Invalid asset"),
        }
    }
}

pub struct TransparentBuilder {
    vout: Vec<TxOut>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Unauthorized {}

impl Authorization for Unauthorized {
    type TransparentSig = ();
}

impl TransparentBuilder {
    /// Constructs a new TransparentBuilder
    pub fn empty() -> Self {
        TransparentBuilder { vout: vec![] }
    }

    /// Returns the transparent outputs that will be produced by the transaction being constructed.
    pub fn outputs(&self) -> &[impl fees::OutputView] {
        &self.vout
    }

    pub fn add_output(
        &mut self,
        transparent_address: &TransparentAddress,
        asset_type: AssetType,
        value: i64,
    ) -> Result<(), Error> {
        if value < -MAX_MONEY || value > MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        self.vout.push(TxOut {
            asset_type,
            value,
            transparent_address: *transparent_address,
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Result<Amount, BalanceError> {
        let output_sum = self
            .vout
            .iter()
            .map(|vo| {
                Amount::from_pair(vo.asset_type, -vo.value).map_err(|_| BalanceError::Underflow)
            })
            .sum::<Result<Amount, _>>();

        output_sum
    }

    pub fn build(self) -> Option<Bundle<Unauthorized>> {
        if self.vout.is_empty() {
            None
        } else {
            Some(Bundle {
                vout: self.vout,
                authorization: Unauthorized {},
            })
        }
    }
}

impl TransparentAuthorizingContext for Unauthorized {}
impl Bundle<Unauthorized> {
    pub fn apply_signatures(self) -> Bundle<Authorized> {
        Bundle {
            vout: self.vout,
            authorization: Authorized,
        }
    }
}

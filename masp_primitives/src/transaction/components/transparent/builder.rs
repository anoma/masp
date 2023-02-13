//! Types and functions for building transparent transaction components.

use std::fmt;

use crate::{
    asset_type::AssetType,
    transaction::{
        components::{
            amount::{Amount, BalanceError, MAX_MONEY},
            transparent::{self, fees, Authorization, Authorized, Bundle, TxIn, TxOut},
        },
        sighash::TransparentAuthorizingContext,
        OutPoint, TransparentAddress,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};

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

/// An uninhabited type that allows the type of [`TransparentBuilder::inputs`]
/// to resolve when the transparent-inputs feature is not turned on.
#[cfg(not(feature = "transparent-inputs"))]
enum InvalidTransparentInput {}

#[cfg(not(feature = "transparent-inputs"))]
impl fees::InputView for InvalidTransparentInput {
    fn coin(&self) -> &TxOut {
        panic!("transparent-inputs feature flag is not enabled.");
    }
}

#[cfg(feature = "transparent-inputs")]
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct TransparentInputInfo {
    coin: TxOut,
}

#[cfg(feature = "transparent-inputs")]
impl fees::InputView for TransparentInputInfo {
    fn coin(&self) -> &TxOut {
        &self.coin
    }
}

pub struct TransparentBuilder {
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
    vout: Vec<TxOut>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Unauthorized {
    #[cfg(feature = "transparent-inputs")]
    inputs: Vec<TransparentInputInfo>,
}

impl Authorization for Unauthorized {
    type TransparentSig = ();
}

impl TransparentBuilder {
    /// Constructs a new TransparentBuilder
    pub fn empty() -> Self {
        TransparentBuilder {
            #[cfg(feature = "transparent-inputs")]
            inputs: vec![],
            vout: vec![],
        }
    }

    /// Returns the list of transparent inputs that will be consumed by the transaction being
    /// constructed.
    pub fn inputs(&self) -> &[impl fees::InputView] {
        #[cfg(feature = "transparent-inputs")]
        return &self.inputs;

        #[cfg(not(feature = "transparent-inputs"))]
        {
            let invalid: &[InvalidTransparentInput] = &[];
            return invalid;
        }
    }

    /// Returns the transparent outputs that will be produced by the transaction being constructed.
    pub fn outputs(&self) -> &[impl fees::OutputView] {
        &self.vout
    }

    /// Adds a coin (the output of a previous transaction) to be spent to the transaction.
    #[cfg(feature = "transparent-inputs")]
    pub fn add_input(
        &mut self,
        coin: TxOut,
    ) -> Result<(), Error> {
        if coin.value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        self.inputs.push(TransparentInputInfo {
            coin,
        });

        Ok(())
    }

    pub fn add_output(
        &mut self,
        to: &TransparentAddress,
        asset_type: AssetType,
        value: i64,
    ) -> Result<(), Error> {
        if value < 0 || value > MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        self.vout.push(TxOut {
            asset_type,
            value,
            transparent_address: *to,
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Result<Amount, BalanceError> {
        #[cfg(feature = "transparent-inputs")]
        let input_sum = self
            .inputs
            .iter()
            .map(|input| {
                if input.coin.value >= 0 {
                    Amount::from_pair(input.coin.asset_type, input.coin.value)
                } else {
                    Err(())
                }
            })
            .sum::<Result<Amount, ()>>()
            .map_err(|_| BalanceError::Overflow)?;

        #[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Amount::zero();

        let output_sum = self
            .vout
            .iter()
            .map(|vo| {
                if vo.value >= 0 {
                    Amount::from_pair(vo.asset_type, vo.value)
                } else {
                    Err(())
                }
            })
            .sum::<Result<Amount, ()>>()
            .map_err(|_| BalanceError::Overflow)?;

        // Cannot panic when subtracting two positive i64
        Ok(input_sum - output_sum)
    }

    pub fn build(self) -> Option<transparent::Bundle<Unauthorized>> {
        #[cfg(feature = "transparent-inputs")]
        let vin: Vec<TxIn> = self
            .inputs
            .iter()
            .map(|i| TxIn { asset_type: i.coin.asset_type, value: i.coin.value } )
            .collect();

        #[cfg(not(feature = "transparent-inputs"))]
        let vin: Vec<TxIn> = vec![];

        if vin.is_empty() && self.vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout: self.vout,
                authorization: Unauthorized {
                    #[cfg(feature = "transparent-inputs")]
                    inputs: self.inputs,
                },
            })
        }
    }
}

#[cfg(not(feature = "transparent-inputs"))]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<Amount> {
        vec![]
    }
}

#[cfg(feature = "transparent-inputs")]
impl TransparentAuthorizingContext for Unauthorized {
    fn input_amounts(&self) -> Vec<Result<Amount, ()>> {
        return self.inputs.iter().map(|txin| Amount::from_pair(txin.coin.asset_type, txin.coin.value)).collect();
    }

}

impl Bundle<Unauthorized> {
    pub fn apply_signatures(self) -> Bundle<Authorized> {
        transparent::Bundle {
            vin: self.vin,
            vout: self.vout,
            authorization: Authorized,
        }
    }
}

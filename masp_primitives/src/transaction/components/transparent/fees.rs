//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use super::TxOut;
use crate::transaction::{components::amount::Amount, TransparentAddress};

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView {
    /// The previous output being spent.
    fn coin(&self) -> &TxOut;
}

/// This trait provides a minimized view of a transparent output suitable for use in
/// fee and change computation.
pub trait OutputView {
    /// Returns the value of the output being created.
    fn value(&self) -> Amount;
    /// Returns the script corresponding to the newly created output.
    fn transparent_address(&self) -> &TransparentAddress;
}

impl OutputView for TxOut {
    fn value(&self) -> Amount {
        Amount::from_pair(self.asset_type, self.value).unwrap()
    }

    fn transparent_address(&self) -> &TransparentAddress {
        &self.address
    }
}

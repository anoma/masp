//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use super::TxOut;
use crate::asset_type::AssetType;
use crate::transaction::TransparentAddress;

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
    fn value(&self) -> i128;
    /// Returns the asset type of the output being created.
    fn asset_type(&self) -> AssetType;
    /// Returns the script corresponding to the newly created output.
    fn transparent_address(&self) -> &TransparentAddress;
}

impl OutputView for TxOut {
    fn value(&self) -> i128 {
        self.value
    }

    fn asset_type(&self) -> AssetType {
        self.asset_type
    }

    fn transparent_address(&self) -> &TransparentAddress {
        &self.address
    }
}

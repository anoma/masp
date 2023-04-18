//! Types related to computation of fees and change related to the Sapling components
//! of a transaction.

use crate::asset_type::AssetType;
use crate::sapling::PaymentAddress;

/// A trait that provides a minimized view of a Sapling input suitable for use in
/// fee and change calculation.
pub trait InputView<NoteRef, Key> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> u64;
    /// The asset type of the input being spent.
    fn asset_type(&self) -> AssetType;
    /// The spend/view key of the input being spent.
    fn key(&self) -> &Key;
}

/// A trait that provides a minimized view of a Sapling output suitable for use in
/// fee and change calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> u64;
    /// The asset type of the output being produced.
    fn asset_type(&self) -> AssetType;
    /// The destination of this output
    fn address(&self) -> PaymentAddress;
}

//! Types related to computation of fees and change related to the Sapling components
//! of a transaction.

use crate::asset_type::AssetType;

/// A trait that provides a minimized view of a Sapling input suitable for use in
/// fee and change calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> u64;
    /// The asset type of the input being spent.
    fn asset_type(&self) -> AssetType;
}

/// A trait that provides a minimized view of a Sapling output suitable for use in
/// fee and change calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> u64;
    /// The asset type of the output being produced.
    fn asset_type(&self) -> AssetType;
}

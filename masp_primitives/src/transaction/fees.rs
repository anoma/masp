//! Abstractions and types related to fee calculations.

use crate::{
    consensus::{self, BlockHeight},
    transaction::components::{amount::I64Amt, transparent::fees as transparent},
};

pub mod fixed;

/// A trait that represents the ability to compute the fees that must be paid
/// by a transaction having a specified set of inputs and outputs.
pub trait FeeRule {
    type Error;

    /// Computes the total fee required for a transaction given the provided inputs and outputs.
    ///
    /// Implementations of this method should compute the fee amount given exactly the inputs and
    /// outputs specified, and should NOT compute speculative fees given any additional change
    /// outputs that may need to be created in order for inputs and outputs to balance.
    fn fee_required<P: consensus::Parameters>(
        &self,
        params: &P,
        target_height: BlockHeight,
        transparent_outputs: &[impl transparent::OutputView],
        sapling_input_count: usize,
        sapling_output_count: usize,
    ) -> Result<I64Amt, Self::Error>;
}

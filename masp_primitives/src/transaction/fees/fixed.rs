use crate::{
    consensus::{self, BlockHeight},
    transaction::components::{
        amount::{Amount, DEFAULT_FEE},
        transparent::fees as transparent,
    },
};

/// A fee rule that always returns a fixed fee, irrespective of the structure of
/// the transaction being constructed.
#[derive(Clone, Debug)]
pub struct FeeRule {
    fixed_fee: Amount,
}

impl FeeRule {
    /// Creates a new nonstandard fixed fee rule with the specified fixed fee.
    pub fn non_standard(fixed_fee: Amount) -> Self {
        Self { fixed_fee }
    }

    /// Creates a new fixed fee rule with the standard default fee.
    pub fn standard() -> Self {
        Self {
            fixed_fee: DEFAULT_FEE.clone(),
        }
    }

    /// Returns the fixed fee amount which which this rule was configured.
    pub fn fixed_fee(&self) -> Amount {
        self.fixed_fee.clone()
    }
}

impl super::FeeRule for FeeRule {
    type Error = std::convert::Infallible;

    fn fee_required<P: consensus::Parameters>(
        &self,
        _params: &P,
        _target_height: BlockHeight,
        _transparent_outputs: &[impl transparent::OutputView],
        _sapling_input_count: usize,
        _sapling_output_count: usize,
    ) -> Result<Amount, Self::Error> {
        Ok(self.fixed_fee.clone())
    }
}

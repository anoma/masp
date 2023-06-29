//! Structs representing the components within Zcash transactions.

pub mod amount;
pub mod sapling;
pub mod transparent;
pub use self::{
    amount::{Amount, I64Amt},
    sapling::{ConvertDescription, OutputDescription, SpendDescription},
    transparent::{TxIn, TxOut},
};

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

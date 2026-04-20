//! Helpers for creating MASP Sapling proofs.

use masp_primitives::asset_type::AssetType;

mod prover;
mod verifier;

pub use self::prover::{SaplingProvingContext, append_proof};
pub use self::verifier::{
    BatchValidator, SaplingVerificationContext, SaplingVerificationContextInner,
};

// This function computes `value` in the exponent of the value commitment base
fn masp_compute_value_balance(asset_type: AssetType, value: i128) -> jubjub::ExtendedPoint {
    // Compute the absolute value
    let abs = if value >= 0 {
        value as u128
    } else {
        (-(value + 1)) as u128
    };
    // Compute it in the exponent
    let mut abs_bytes = [0u8; 32];
    abs_bytes[0..16].copy_from_slice(&abs.to_le_bytes());
    let abs_scalar = jubjub::Fr::from_bytes(&abs_bytes).unwrap();
    // Negate if necessary
    let scalar = if value >= 0 {
        abs_scalar
    } else {
        -abs_scalar - jubjub::Fr::one()
    };
    let value_balance =
        asset_type.value_commitment_generator() * scalar;

    // Convert to unknown order point
    value_balance.into()
}

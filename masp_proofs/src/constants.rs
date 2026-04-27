//! Various constants used for the MASP proofs.

use bls12_381::Scalar;
use group::Curve;
use group::ff::Field;
use lazy_static::lazy_static;

/// The `d` constant of the twisted Edwards curve.
pub(crate) fn edward_d() -> Scalar {
    Scalar::from_u64s_le(&[
        0x0106_5fd6_d634_3eb1,
        0x292d_7f6d_3757_9d26,
        0xf5fd_9207_e6bd_7fd4,
        0x2a93_18e7_4bfa_2b48,
    ])
    .unwrap()
}

/// The `A` constant of the birationally equivalent Montgomery curve.
pub(crate) fn montgomery_a() -> Scalar {
    Scalar::from_u64s_le(&[
        0x0000_0000_0000_a002,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ])
    .unwrap()
}

/// The scaling factor used for conversion to and from the Montgomery form.
pub(crate) fn montgomery_scale() -> Scalar {
    Scalar::from_u64s_le(&[
        0x8f45_35f7_cf82_b8d9,
        0xce40_6970_3da8_8abd,
        0x31de_341e_77d7_64e5,
        0x2762_de61_e862_645e,
    ])
    .unwrap()
}

/// The number of chunks needed to represent a full scalar during fixed-base
/// exponentiation.
const FIXED_BASE_CHUNKS_PER_GENERATOR: usize = 84;

/// Reference to a circuit version of a generator for fixed-base salar multiplication.
pub type FixedGenerator = &'static [Vec<(Scalar, Scalar)>];

/// Circuit version of a generator for fixed-base salar multiplication.
pub type FixedGeneratorOwned = Vec<Vec<(Scalar, Scalar)>>;

lazy_static! {
    pub static ref PROOF_GENERATION_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::proof_generation_key_generator());
    pub static ref VALUE_COMMITMENT_RANDOMNESS_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(
            masp_primitives::constants::value_commitment_randomness_generator()
        );
    pub static ref SPENDING_KEY_GENERATOR: FixedGeneratorOwned =
        generate_circuit_generator(masp_primitives::constants::spending_key_generator());
}

/// Creates the 3-bit window table `[0, 1, ..., 8]` for different magnitudes of a fixed
/// generator.
pub fn generate_circuit_generator(mut r#gen: jubjub::SubgroupPoint) -> FixedGeneratorOwned {
    let mut windows = vec![];

    for _ in 0..FIXED_BASE_CHUNKS_PER_GENERATOR {
        let mut coeffs = vec![(Scalar::ZERO, Scalar::ONE)];
        let mut g = r#gen;
        for _ in 0..7 {
            let g_affine = jubjub::ExtendedPoint::from(g).to_affine();
            coeffs.push((g_affine.get_u(), g_affine.get_v()));
            g += r#gen;
        }
        windows.push(coeffs);

        // r#gen = r#gen * 8
        r#gen = g;
    }

    windows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `d` constant of the twisted Edwards curve.
    pub(crate) fn edwards_d() -> Scalar {
        Scalar::from_u64s_le(&[
            0x0106_5fd6_d634_3eb1,
            0x292d_7f6d_3757_9d26,
            0xf5fd_9207_e6bd_7fd4,
            0x2a93_18e7_4bfa_2b48,
        ])
        .unwrap()
    }

    #[test]
    fn test_edwards_d() {
        assert_eq!(
            -Scalar::from(10240) * Scalar::from(10241).invert().unwrap(),
            edwards_d()
        );
    }

    #[test]
    fn test_montgomery_scale() {
        assert_eq!(
            montgomery_scale().square() * (-Scalar::ONE - edwards_d()),
            Scalar::from(4),
        );
    }
}

//! Various constants used by the Zcash primitives.

use jubjub::SubgroupPoint;

/// First 64 bytes of the BLAKE2s input during group hash.
/// This is chosen to be some random string that we couldn't have anticipated when we designed
/// the algorithm, for rigidity purposes.
/// We deliberately use an ASCII hex string of 32 bytes here.
pub const GH_FIRST_BLOCK: &[u8; 64] =
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

// Group hash personalizations
/// BLAKE2s Personalization for the group hash for key diversification
pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"MASP__gd";

/// BLAKE2s Personalization for the spending key base point
pub const SPENDING_KEY_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__G_";

/// BLAKE2s Personalization for the proof generation key base point
pub const PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__H_";

pub const VALUE_COMMITMENT_RANDOMNESS_PERSONALIZATION: &[u8; 8] = b"MASP__r_";

/// BLAKE2s Personalization for the nullifier position generator (for computing rho)
pub const NULLIFIER_POSITION_IN_TREE_GENERATOR_PERSONALIZATION: &[u8; 8] = b"MASP__J_";

/// Length in bytes of the canonical asset-id encoding
pub const ASSET_IDENTIFIER_LENGTH: usize = 32;

/// Personalization prefix for deriving asset id from asset name
pub const ASSET_IDENTIFIER_PERSONALIZATION: &[u8; 8] = b"MASP__t_";

/// The prover will demonstrate knowledge of discrete log with respect to this base when
/// they are constructing a proof, in order to authorize proof construction.
pub fn proof_generation_key_generator() -> SubgroupPoint {
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_u64s_le(&[
            0x5f3c_723a_a253_1b66,
            0x1e24_f832_67f1_5abd,
            0x4ba1_f065_e719_fd03,
            0x4caa_eaca_af28_ed4b,
        ])
        .unwrap(),
        bls12_381::Scalar::from_u64s_le(&[
            0xfe6f_96be_c575_bff8,
            0x36b4_9c71_a2af_0708,
            0xc654_dfdd_3600_4de9,
            0x0093_0d67_d690_6365,
        ])
        .unwrap(),
    )
}

/// The value commitment is randomized over this generator, for privacy.
pub fn value_commitment_randomness_generator() -> SubgroupPoint {
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_u64s_le(&[
            0xdd93d364cb8cec7e,
            0x91cc3e3835675450,
            0xcfa86026b8d99be9,
            0x1c6da0ce9a5e5fdb,
        ])
        .unwrap(),
        bls12_381::Scalar::from_u64s_le(&[
            0x28e5fce99ce692d0,
            0xf94c2daa360302fe,
            0xbc900cd4b8ae1150,
            0x555f11f9b720d50b,
        ])
        .unwrap(),
    )
}

/// The spender proves discrete log with respect to this base at spend time.
pub fn spending_key_generator() -> SubgroupPoint {
    SubgroupPoint::from_raw_unchecked(
        bls12_381::Scalar::from_u64s_le(&[
            0xec75293d81248452,
            0x39f5b03380af6020,
            0xf831c2b19fec6026,
            0x5b389522a9e81532,
        ])
        .unwrap(),
        bls12_381::Scalar::from_u64s_le(&[
            0x14b62623a186b4b1,
            0x2012d031f624fd52,
            0x75defecff1f49ef2,
            0x0cbc5f9f1e52e0ab,
        ])
        .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use group::Group;
    use jubjub::SubgroupPoint;

    use super::*;
    use crate::sapling::group_hash::group_hash;

    fn find_group_hash(m: &[u8], personalization: &[u8; 8]) -> SubgroupPoint {
        let mut tag = m.to_vec();
        let i = tag.len();
        tag.push(0u8);

        loop {
            let gh = group_hash(&tag, personalization);

            // We don't want to overflow and start reusing generators
            assert!(tag[i] != u8::MAX);
            tag[i] += 1;

            if let Some(gh) = gh {
                break gh;
            }
        }
    }

    #[test]
    fn test_proof_generation_key_base_generator() {
        assert_eq!(
            find_group_hash(&[], PROOF_GENERATION_KEY_BASE_GENERATOR_PERSONALIZATION),
            proof_generation_key_generator(),
        );
    }

    #[test]
    fn test_value_commitment_randomness_generator() {
        assert_eq!(
            find_group_hash(b"r", VALUE_COMMITMENT_RANDOMNESS_PERSONALIZATION),
            value_commitment_randomness_generator(),
        );
    }

    #[test]
    fn test_spending_key_generator() {
        assert_eq!(
            find_group_hash(&[], SPENDING_KEY_GENERATOR_PERSONALIZATION),
            spending_key_generator(),
        );
    }

    #[test]
    fn no_duplicate_fixed_base_generators() {
        let fixed_base_generators = [
            proof_generation_key_generator(),
            value_commitment_randomness_generator(),
            spending_key_generator(),
        ];

        // Check for duplicates, far worse than spec inconsistencies!
        for (i, p1) in fixed_base_generators.iter().enumerate() {
            if p1.is_identity().into() {
                panic!("Neutral element!");
            }

            for p2 in fixed_base_generators.iter().skip(i + 1) {
                if p1 == p2 {
                    panic!("Duplicate generator!");
                }
            }
        }
    }
}

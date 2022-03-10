//! The Sapling circuits.

use bellman::{Circuit, ConstraintSystem, SynthesisError};

use masp_primitives::primitives::ValueCommitment;

use super::pedersen_hash;
use crate::circuit::sapling::expose_value_commitment;
use zcash_proofs::circuit::ecc;

use bellman::gadgets::boolean;
use bellman::gadgets::num;
use bellman::gadgets::Assignment;

use itertools::multizip;

pub const TREE_DEPTH: usize = zcash_primitives::sapling::SAPLING_COMMITMENT_TREE_DEPTH;

/// This is an instance of the `Spend` circuit.
pub struct Convert {
    /// Pedersen commitment to the value being spent (conversion input)
    pub spend_value_commitment: Option<ValueCommitment>,

    /// Pedersen commitment to the value being output (conversion output)
    pub output_value_commitment: Option<ValueCommitment>,

    /// Pedersen commitment to the value being minted (conversion minted)
    pub mint_value_commitment: Option<ValueCommitment>,

    /// The authentication path of the commitment in the tree
    pub auth_path: Vec<Option<(bls12_381::Scalar, bool)>>,

    /// The anchor of the allowable convert-and-mints; the root of the tree.
    pub anchor: Option<bls12_381::Scalar>,
}

impl Circuit<bls12_381::Scalar> for Convert {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Compute note contents:
        // asset_generator, then value (in big endian) followed by g_d and pk_d
        let mut note_contents = vec![];

        // Handle the value; we'll need it later for the
        // dummy input check.
        let mut value_num = num::Num::zero();
        {
            // Get the value in little-endian bit order
            let (spend_asset_generator_bits, spend_value_bits) = expose_value_commitment(
                cs.namespace(|| "spend value commitment"),
                self.spend_value_commitment,
            )?;

            // Place the asset generator in the note
            note_contents.extend(spend_asset_generator_bits);

            // Get the value in little-endian bit order
            let (output_asset_generator_bits, output_value_bits) = expose_value_commitment(
                cs.namespace(|| "output value commitment"),
                self.output_value_commitment,
            )?;

            // Place the asset generator in the note
            note_contents.extend(output_asset_generator_bits);

            // Get the value in little-endian bit order
            let (mint_asset_generator_bits, mint_value_bits) = expose_value_commitment(
                cs.namespace(|| "mint value commitment"),
                self.mint_value_commitment,
            )?;

            // Place the asset generator in the note
            note_contents.extend(mint_asset_generator_bits);

            for (i, spend_value_bit, output_value_bit, mint_value_bit) in multizip((
                0..256,
                &spend_value_bits,
                &output_value_bits,
                &mint_value_bits,
            )) {
                boolean::Boolean::enforce_equal(
                    cs.namespace(|| format!("integrity of output value bit {}", i)),
                    spend_value_bit,
                    output_value_bit,
                )?;
                boolean::Boolean::enforce_equal(
                    cs.namespace(|| format!("integrity of mint value bit {}", i)),
                    spend_value_bit,
                    mint_value_bit,
                )?;
            }
        }

        assert_eq!(
            note_contents.len(),
            256 * 3 // asset_generator bits
        );

        // Compute the hash of the note contents
        let mut cm = pedersen_hash::pedersen_hash(
            cs.namespace(|| "note content hash"),
            pedersen_hash::Personalization::NoteCommitment,
            &note_contents,
        )?;

        // This will store (least significant bit first)
        // the position of the note in the tree, for use
        // in nullifier computation.
        let mut position_bits = vec![];

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = cm.get_u().clone();

        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                cs.namespace(|| "position bit"),
                e.map(|e| e.1),
            )?);

            // Push this boolean for nullifier computation later
            position_bits.push(cur_is_right.clone());

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(e.get()?.0))?;

            // Swap the two if the current subtree is on the right
            let (ul, ur) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                &cur_is_right,
            )?;

            // We don't need to be strict, because the function is
            // collision-resistant. If the prover witnesses a congruency,
            // they will be unable to find an authentication path in the
            // tree with high probability.
            let mut preimage = vec![];
            preimage.extend(ul.to_bits_le(cs.namespace(|| "ul into bits"))?);
            preimage.extend(ur.to_bits_le(cs.namespace(|| "ur into bits"))?);

            // Compute the new subtree value
            cur = pedersen_hash::pedersen_hash(
                cs.namespace(|| "computation of pedersen hash"),
                pedersen_hash::Personalization::MerkleTree(i),
                &preimage,
            )?
            .get_u()
            .clone(); // Injective encoding
        }

        {
            let real_anchor_value = self.anchor;

            // Allocate the "real" anchor that will be exposed.
            let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional anchor"), || {
                Ok(*real_anchor_value.get()?)
            })?;

            // (cur - rt) * value = 0
            // if value is zero, cur and rt can be different
            // if value is nonzero, they must be equal
            cs.enforce(
                || "conditionally enforce correct root",
                |lc| lc + cur.get_variable() - rt.get_variable(),
                |lc| lc + &value_num.lc(bls12_381::Scalar::one()),
                |lc| lc,
            );

            // Expose the anchor
            rt.inputize(cs.namespace(|| "anchor"))
        }
    }
}

#[test]
fn test_convert_circuit_with_bls12_381() {
    use bellman::gadgets::test::*;
    use ff::{Field, PrimeField, PrimeFieldBits};
    use group::Curve;
    use masp_primitives::{asset_type::AssetType, convert::AllowedConversion, pedersen_hash};
    use rand_core::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let tree_depth = 32;

    for i in 0..400u32 {
        let spend_asset = AssetType::new(format!("asset {}", i).as_bytes()).unwrap();
        let output_asset = AssetType::new(format!("asset {}", i + 1).as_bytes()).unwrap();
        let mint_asset = AssetType::new(b"reward").unwrap();

        let value = rng.next_u64();
        let spend_value_commitment =
            spend_asset.value_commitment(value, jubjub::Fr::random(&mut rng));
        let output_value_commitment =
            output_asset.value_commitment(value, jubjub::Fr::random(&mut rng));
        let mint_value_commitment =
            mint_asset.value_commitment(value, jubjub::Fr::random(&mut rng));

        let auth_path =
            vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); tree_depth];

        {
            let expected_spend_value_commitment =
                jubjub::ExtendedPoint::from(spend_value_commitment.commitment()).to_affine();
            let expected_output_value_commitment =
                jubjub::ExtendedPoint::from(output_value_commitment.commitment()).to_affine();
            let expected_mint_value_commitment =
                jubjub::ExtendedPoint::from(mint_value_commitment.commitment()).to_affine();

            let note = AllowedConversion {
                spend_asset,
                output_asset,
                mint_asset,
            };

            let mut position = 0u64;
            let cmu = note.cmu();
            let mut cur = cmu;

            for (i, val) in auth_path.clone().into_iter().enumerate() {
                let (uncle, b) = val.unwrap();

                let mut lhs = cur;
                let mut rhs = uncle;

                if b {
                    ::std::mem::swap(&mut lhs, &mut rhs);
                }

                let lhs = lhs.to_le_bits();
                let rhs = rhs.to_le_bits();

                cur = jubjub::ExtendedPoint::from(pedersen_hash::pedersen_hash(
                    pedersen_hash::Personalization::MerkleTree(i),
                    lhs.iter()
                        .by_val()
                        .take(bls12_381::Scalar::NUM_BITS as usize)
                        .chain(
                            rhs.iter()
                                .by_val()
                                .take(bls12_381::Scalar::NUM_BITS as usize),
                        ),
                ))
                .to_affine()
                .get_u();

                if b {
                    position |= 1 << i;
                }
            }

            let mut cs = TestConstraintSystem::new();

            let instance = Convert {
                spend_value_commitment: Some(spend_value_commitment.clone()),
                output_value_commitment: Some(output_value_commitment.clone()),
                mint_value_commitment: Some(mint_value_commitment.clone()),
                auth_path: auth_path.clone(),
                anchor: Some(cur),
            };

            instance.synthesize(&mut cs).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(cs.num_constraints(), 53734);
            assert_eq!(
                cs.hash(),
                "51c3073c251bab715eb4adc20e0ee75b54cd73614d82253f071e26287232fbff"
            );

            assert_eq!(cs.num_inputs(), 8);
            assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::one());
            assert_eq!(
                cs.get_input(
                    1,
                    "spend value commitment/commitment point/u/input variable"
                ),
                expected_spend_value_commitment.get_u()
            );
            assert_eq!(
                cs.get_input(
                    2,
                    "spend value commitment/commitment point/v/input variable"
                ),
                expected_spend_value_commitment.get_v()
            );
            assert_eq!(
                cs.get_input(
                    3,
                    "output value commitment/commitment point/u/input variable"
                ),
                expected_output_value_commitment.get_u()
            );
            assert_eq!(
                cs.get_input(
                    4,
                    "output value commitment/commitment point/v/input variable"
                ),
                expected_output_value_commitment.get_v()
            );
            assert_eq!(
                cs.get_input(5, "mint value commitment/commitment point/u/input variable"),
                expected_mint_value_commitment.get_u()
            );
            assert_eq!(
                cs.get_input(6, "mint value commitment/commitment point/v/input variable"),
                expected_mint_value_commitment.get_v()
            );
            assert_eq!(cs.get_input(7, "anchor/input variable"), cur);
        }
    }
}

use crate::circuit::pedersen_hash;
use bellman::Circuit;
use bellman::ConstraintSystem;
use bellman::LinearCombination;
use bellman::SynthesisError;
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::gadgets::{Assignment, num};
use bls12_381::Scalar;
use group::ff::Field;
use masp_primitives::merkle_tree::Hashable;
use masp_primitives::sapling::Node;
use masp_primitives::sapling::SAPLING_COMMITMENT_TREE_DEPTH;

pub const TREE_DEPTH: usize = SAPLING_COMMITMENT_TREE_DEPTH;
pub const BATCH_SIZE: usize = 32;

pub struct Append {
    /// Current size of the Merkle tree
    pub old_size: Option<bls12_381::Scalar>,

    /// The authentication path of the blank at old_size
    pub auth_path: Vec<Option<bls12_381::Scalar>>,

    /// The notes being added to the Merkle tree
    pub new_cmus: Vec<Option<bls12_381::Scalar>>,
}

// Constrain the given value to have the given bit width. Return
// booleans in little endian order equal to the bits of the input.
pub fn constrain_to_boolean_vec_le<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: &mut CS,
    val: num::AllocatedNum<bls12_381::Scalar>,
    bit_width: u8,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = vec![];
    // First allocate bits to represent the given number
    match val.get_value() {
        // Propagate knowledge of the larger number into the bits
        Some(value) => {
            let bytes = value.to_bytes_le();
            let bit_width: usize = bit_width.into();
            // Bits beyond the given bit width not allowed
            if bytes[bit_width / 8] >> (bit_width % 8) != 0 {
                return Err(SynthesisError::Unsatisfiable);
            }
            // Bytes beyond the given bit width not allowed
            for byte in bytes.iter().skip((bit_width + 7) / 8) {
                if *byte != 0 {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            // Finally allocate bits within the bit width
            for i in 0..bit_width {
                let mask = 1 << (i % 8);
                let bit = bytes[i / 8] & mask != 0;
                bits.push(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    Some(bit),
                )?);
            }
        }

        None => {
            // Allocate bits within the bit width
            for i in 0..bit_width {
                bits.push(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    None,
                )?);
            }
        }
    }
    // Then constrain the bits to equal the value
    let mut lc = LinearCombination::zero();
    let mut coeff = bls12_381::Scalar::ONE;

    for bit in bits.iter() {
        lc = lc + (coeff, bit.get_variable());

        coeff = coeff.double();
    }

    lc = lc - val.get_variable();

    cs.enforce(|| "unpacking constraint", |lc| lc, |lc| lc, |_| lc);

    Ok(bits.into_iter().map(Boolean::from).collect())
}

// If condition is true, select consequent otherwise alternate
pub fn ternary_constraint<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    condition: &Boolean,
    consequent: &num::AllocatedNum<bls12_381::Scalar>,
    alternate: &num::AllocatedNum<bls12_381::Scalar>,
) -> Result<num::AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    // The variable that will hold result of evaluating ternary expression
    let ternary = num::AllocatedNum::alloc(cs.namespace(|| "ternary"), || {
        Ok(*if *condition.get_value().get()? {
            consequent
        } else {
            alternate
        }
        .get_value()
        .get()?)
    })?;
    let lca = condition.lc(CS::one(), bls12_381::Scalar::ONE);
    let lcb =
        LinearCombination::from_variable(consequent.get_variable()) - alternate.get_variable();
    let lcc = LinearCombination::from_variable(ternary.get_variable()) - alternate.get_variable();
    // ternary = condition*consequent + (1-condition)*input
    cs.enforce(|| "ternary constraint", |_| lca, |_| lcb, |_| lcc);
    Ok(ternary)
}

// Takes the given level and shifts it to the right by cur_is_right,
// where cur_is_right is interpreted as an integer. If we are shifting
// by 1, then fill the new leaf on the left with prev. If we are not
// shifting, then fill the leaf on the right with an empty root. Return
// the conditionally shifted level and the prev variable that this
// function was called with.
pub fn conditionally_shift_leaves<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    cur_is_right: &Boolean,
    mut prev: num::AllocatedNum<bls12_381::Scalar>,
    level: Vec<num::AllocatedNum<bls12_381::Scalar>>,
    empty_root: num::AllocatedNum<bls12_381::Scalar>,
) -> Result<
    (
        Vec<num::AllocatedNum<bls12_381::Scalar>>,
        num::AllocatedNum<bls12_381::Scalar>,
    ),
    SynthesisError,
> {
    let mut shifted_level = vec![];
    // Make a shifted level
    for (i, input) in level
        .into_iter()
        .chain(std::iter::once(empty_root))
        .enumerate()
    {
        let shifted_input = ternary_constraint(
            cs.namespace(|| format!("shift constraint {}", i)),
            cur_is_right,
            &prev,
            &input,
        )?;
        // Expand the shifted level
        shifted_level.push(shifted_input);
        // If the row is shifted, then current element will need to feed into next iteration
        prev = input;
    }
    Ok((shifted_level, prev))
}

// Allocate a variable that is hardwired to equal the empty root at the
// given altitude
pub fn alloc_empty_root<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    alt: usize,
) -> Result<num::AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    // Get a scalar equal to the empty root at the given altitude
    let empty_root = Scalar::from(Node::empty_root(alt));
    // Allocate a variable to hold the empty root
    let alloc = num::AllocatedNum::alloc(
        cs.namespace(|| format!("empty root altitude {}", alt)),
        || Ok(empty_root),
    )?;
    // Force our new variable to equal to the empty root scalar
    let lc = LinearCombination::from_variable(alloc.get_variable()) - (empty_root, CS::one());
    cs.enforce(|| "ensure empty leaf 0", |lc| lc, |lc| lc, |_| lc);
    Ok(alloc)
}

impl Circuit<bls12_381::Scalar> for Append {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // First verify that the authentication path is valid. I.e. it places
        // an empty node at the position size into the old root
        // Allocate the tree size that will be exposed.
        let old_size =
            num::AllocatedNum::alloc_input(cs.namespace(|| "old Merkle tree size"), || {
                Ok(*self.old_size.get()?)
            })?;
        // Convert the tree size to bits
        let depth = self
            .auth_path
            .len()
            .try_into()
            .expect("tree depth should fit in u8");
        let old_size_bits = constrain_to_boolean_vec_le(cs, old_size, depth)?;

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = alloc_empty_root(cs.namespace(|| "empty root to compute old root"), 0)?;
        let mut path_elements = vec![];
        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("old merkle tree hash {}", i));
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[i];
            // Witness the authentication path element adjacent
            // at this depth.
            let path_element =
                num::AllocatedNum::alloc(cs.namespace(|| "path element"), || Ok(*e.get()?))?;

            // Swap the two if the current subtree is on the right
            let (ul, ur) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                cur_is_right,
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
            // Store path element for the computation of new root
            path_elements.push(path_element);
        }

        // Expose the old root
        cur.inputize(cs.namespace(|| "old root"))?;

        // Build the first level of the tree from the public inputs
        let mut prev_level = vec![];
        let mut new_cmus = vec![];
        for (i, e) in self.new_cmus.into_iter().enumerate() {
            let input =
                num::AllocatedNum::alloc(
                    cs.namespace(|| format!("input {}", i)),
                    || Ok(*e.get()?),
                )?;
            new_cmus.push(input);
        }
        let mut level = new_cmus.clone();

        let mut height = 0;
        // Build more tree levels until we hit a subtree containing all the new cmus
        while level.len() > 1 && !path_elements.is_empty() {
            let cs = &mut cs.namespace(|| format!("build level {}", height));
            // The previous element in the level
            let prev = path_elements.remove(0);
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[height];
            // If the previous level has 3 elements, and we know that the left
            // subtree (and therefore also the right subtree) are empty, then we
            // know that the third element is a blank. Then we know that the
            // second entry of the current level is the hash of the concatenation
            // of two empty roots. In this case, replace this second entry with
            // the corresponding entry from the authentication path.
            if prev_level.len() == 3 {
                // Determines if the previous subtree is the "right" leaf at this
                // depth of the tree.
                let prev_is_right = &old_size_bits[height - 1];
                let condition = Boolean::and(
                    cs.namespace(|| format!("overwrite last hash in level {}", height)),
                    &cur_is_right.not(),
                    &prev_is_right.not(),
                )?;
                level[1] = ternary_constraint(
                    cs.namespace(|| format!("computation of last hash in level {}", height)),
                    &condition,
                    &prev,
                    &level[1],
                )?;
            }
            // Make a variable hard wired to the empty root
            let mut empty_root_alloc = alloc_empty_root(
                cs.namespace(|| format!("empty root to compute level {}", height)),
                height,
            )?;
            // Conditionally shift the level
            (prev_level, empty_root_alloc) = conditionally_shift_leaves(
                cs.namespace(|| "conditionally shifting of nodes"),
                cur_is_right,
                prev,
                std::mem::take(&mut level),
                empty_root_alloc,
            )?;
            // Finally, hash pairs of elements
            for (j, pair) in prev_level.chunks(2).enumerate() {
                let ur = pair.get(1).unwrap_or(&empty_root_alloc);
                // We don't need to be strict, because the function is
                // collision-resistant. If the prover witnesses a congruency,
                // they will be unable to find an authentication path in the
                // tree with high probability.
                let mut preimage = vec![];
                preimage
                    .extend(pair[0].to_bits_le(cs.namespace(|| format!("ul {} into bits", j)))?);
                preimage.extend(ur.to_bits_le(cs.namespace(|| format!("ur {} into bits", j)))?);

                // Compute the new subtree value
                let cur = pedersen_hash::pedersen_hash(
                    cs.namespace(|| format!("computation of pedersen hash {}", j)),
                    pedersen_hash::Personalization::MerkleTree(height),
                    &preimage,
                )?
                .get_u()
                .clone(); // Injective encoding
                // Build up the next level
                level.push(cur);
            }
            // Start working on the next level of the Merkle tree
            height += 1;
        }
        // Push to next level in case it's empty before the removal
        level.push(alloc_empty_root(
            cs.namespace(|| format!("empty root to compute level {}", height)),
            height,
        )?);
        // The first element is the first root containing all the new cmus
        cur = level.remove(0);
        // Finally compute the new root by ascending the remaining merkle
        // tree authentication path
        for path_element in path_elements {
            let cs = &mut cs.namespace(|| format!("new merkle tree hash {}", height));
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[height];

            // Swap the two if the current subtree is on the right
            let (ul, ur) = num::AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                &path_element,
                cur_is_right,
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
                pedersen_hash::Personalization::MerkleTree(height),
                &preimage,
            )?
            .get_u()
            .clone(); // Injective encoding
            height += 1;
        }
        // Expose the new root
        cur.inputize(cs.namespace(|| "new root"))?;
        // Evaluate a polynomial on the root hash
        // Start evaluating polynomial on challenge point
        let mut cmu_response =
            num::AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(bls12_381::Scalar::from(0)))?;
        // evaluation = 0
        cs.enforce(
            || "",
            |lc| lc,
            |lc| lc,
            |_| LinearCombination::from_variable(cmu_response.get_variable()),
        );
        for (i, cmu) in new_cmus.iter().enumerate().rev() {
            // new_evaluation = evaluation*challenge + cmu
            let partial_cmu_response = num::AllocatedNum::alloc(
                cs.namespace(|| format!("partial cmu response {}", i)),
                || {
                    Ok(cmu_response.get_value().get()? * cur.get_value().get()?
                        + cmu.get_value().get()?)
                },
            )?;
            let la = LinearCombination::from_variable(cmu_response.get_variable());
            let lb = LinearCombination::from_variable(cur.get_variable());
            let lc = LinearCombination::from_variable(partial_cmu_response.get_variable())
                - cmu.get_variable();
            cs.enforce(
                || format!("partial cmu response constraint {}", i),
                |_| la,
                |_| lb,
                |_| lc,
            );
            cmu_response = partial_cmu_response;
        }
        // Make the cmu response public
        cmu_response.inputize(cs.namespace(|| "cmu response"))?;
        Ok(())
    }
}

#[test]
fn test_append_circuit_with_bls12_381() {
    use bellman::gadgets::test::*;
    use group::ff::Field;

    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::sapling::Node;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    for i in 0..64u32 {
        let mut leaves = vec![];

        for _j in 0..i {
            leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
        }
        let old_tree = FrozenCommitmentTree::new(&leaves);
        let old_root = old_tree.root();
        let old_size = leaves.len();
        let old_size_scalar = bls12_381::Scalar::from(old_size as u64);
        let auth_path = old_tree.path(leaves.len());
        for _j in 0..BATCH_SIZE {
            leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
        }
        let new_tree = FrozenCommitmentTree::new(&leaves);
        let new_root = new_tree.root();

        {
            let mut cs = TestConstraintSystem::new();
            let auth_path: Vec<_> = auth_path
                .auth_path
                .iter()
                .map(|x| Some(bls12_381::Scalar::from(x.0)))
                .collect();
            let k = i as usize;

            let instance = Append {
                old_size: Some(old_size_scalar),
                auth_path: auth_path.clone(),
                new_cmus: leaves[k..(k + BATCH_SIZE)]
                    .iter()
                    .map(|x| Some(bls12_381::Scalar::from(*x)))
                    .collect(),
            };

            instance.synthesize(&mut cs).unwrap();

            assert!(cs.is_satisfied());
            assert_eq!(cs.num_constraints(), 168609);
            assert_eq!(
                cs.hash(),
                "e47757c56fe90372ba85bca37ff23e9c8989c190f19775276d21e53f5c879c0f"
            );

            for (m, elt) in auth_path.iter().enumerate() {
                assert_eq!(
                    cs.get(&format!("old merkle tree hash {}/path element/num", m)),
                    elt.unwrap()
                );
            }
            assert_eq!(cs.num_inputs(), 5);
            assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::ONE);
            assert_eq!(
                cs.get_input(1, "old Merkle tree size/input num"),
                old_size_scalar
            );
            assert_eq!(
                cs.get_input(2, "old root/input variable"),
                bls12_381::Scalar::from(old_root)
            );
            assert_eq!(
                cs.get_input(3, "new root/input variable"),
                bls12_381::Scalar::from(new_root)
            );
            let mut response = bls12_381::Scalar::ZERO;
            for m in (0..BATCH_SIZE).rev() {
                response *= bls12_381::Scalar::from(new_root);
                response += bls12_381::Scalar::from(leaves[old_size + m]);
            }
            assert_eq!(cs.get_input(4, "cmu response/input variable"), response);
        }
    }
}

#[test]
fn test_variable_sized_append_circuit_with_bls12_381() {
    use bellman::gadgets::test::*;
    use group::ff::Field;

    use masp_primitives::merkle_tree::FrozenCommitmentTree;
    use masp_primitives::sapling::Node;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    let mut rng = XorShiftRng::from_seed([
        0x58, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let old_size = 11;
    let old_size_scalar = bls12_381::Scalar::from(old_size as u64);

    for i in 0..32u32 {
        let mut leaves = vec![];

        for _j in 0..old_size {
            leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
        }
        let old_tree = FrozenCommitmentTree::new(&leaves);
        let old_root = old_tree.root();
        let auth_path = old_tree.path(leaves.len());
        for _j in 0..i {
            leaves.push(Node::from_scalar(bls12_381::Scalar::random(&mut rng)));
        }
        let new_tree = FrozenCommitmentTree::new(&leaves);
        let new_root = new_tree.root();

        {
            let mut cs = TestConstraintSystem::new();
            let auth_path: Vec<_> = auth_path
                .auth_path
                .iter()
                .map(|x| Some(bls12_381::Scalar::from(x.0)))
                .collect();

            let instance = Append {
                old_size: Some(old_size_scalar),
                auth_path: auth_path.clone(),
                new_cmus: leaves[old_size..(old_size + (i as usize))]
                    .iter()
                    .map(|x| Some(bls12_381::Scalar::from(*x)))
                    .collect(),
            };

            instance.synthesize(&mut cs).unwrap();

            assert!(cs.is_satisfied());

            for (m, elt) in auth_path.iter().enumerate() {
                assert_eq!(
                    cs.get(&format!("old merkle tree hash {}/path element/num", m)),
                    elt.unwrap()
                );
            }
            assert_eq!(cs.num_inputs(), 5);
            assert_eq!(cs.get_input(0, "ONE"), bls12_381::Scalar::ONE);
            assert_eq!(
                cs.get_input(1, "old Merkle tree size/input num"),
                old_size_scalar
            );
            assert_eq!(
                cs.get_input(2, "old root/input variable"),
                bls12_381::Scalar::from(old_root)
            );
            assert_eq!(
                cs.get_input(3, "new root/input variable"),
                bls12_381::Scalar::from(new_root)
            );
            let mut response = bls12_381::Scalar::ZERO;
            for m in (0..i).rev() {
                response *= bls12_381::Scalar::from(new_root);
                response += bls12_381::Scalar::from(leaves[old_size + (m as usize)]);
            }
            assert_eq!(cs.get_input(4, "cmu response/input variable"), response);
        }
    }
}

use bellman::SynthesisError;
use bellman::ConstraintSystem;
use bellman::gadgets::{Assignment, num};
use bellman::Circuit;
use bellman::gadgets::boolean::{AllocatedBit, Boolean};
use bellman::LinearCombination;
use bls12_381::Scalar;
use group::ff::Field;
use masp_primitives::sapling::Node;
use masp_primitives::merkle_tree::Hashable;
use crate::circuit::pedersen_hash;
use masp_primitives::sapling::SAPLING_COMMITMENT_TREE_DEPTH;

pub const TREE_DEPTH: usize = SAPLING_COMMITMENT_TREE_DEPTH;
pub const BATCH_SIZE: u8 = 32;

pub struct Append {
    /// Current size of the Merkle tree
    pub old_size: Option<bls12_381::Scalar>,

    /// The authentication path of the blank at old_size
    pub auth_path: Vec<Option<bls12_381::Scalar>>,

    /// The notes being added to the Merkle tree
    pub new_cmus: Vec<Option<bls12_381::Scalar>>,
}

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
            if bytes[bit_width/8] >> (bit_width % 8) != 0 {
                return Err(SynthesisError::Unsatisfiable)
            }
            // Bytes beyond the given bit width not allowed
            for i in ((bit_width+7)/8)..32 {
                if bytes[i] != 0 {
                    return Err(SynthesisError::Unsatisfiable)
                }
            }
            // Finally allocate bits within the bit width
            for i in 0..bit_width {
                let mask = 1 << (i%8);
                let bit = bytes[i/8] & mask != 0;
                bits.push(AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), Some(bit))?);
            }
        },
        
        None => {
            // Allocate bits within the bit width
            for i in 0..bit_width {
                bits.push(AllocatedBit::alloc(cs.namespace(|| format!("bit {}", i)), None)?);
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
) -> Result<(Vec<num::AllocatedNum<bls12_381::Scalar>>, num::AllocatedNum<bls12_381::Scalar>), SynthesisError> {
    let mut shifted_level = vec![];
    // Make a shifted level
    for (i, input) in level.into_iter().chain(std::iter::once(empty_root)).enumerate() {
        let shifted_input = num::AllocatedNum::alloc_input(
            cs.namespace(|| format!("shifted input {}", i)),
            || Ok(*if *cur_is_right.get_value().get()? { &prev } else { &input }.get_value().get()?),
        )?;
        let lca = cur_is_right.lc(CS::one(), bls12_381::Scalar::ONE);
        let lcb = LinearCombination::from_variable(prev.get_variable()) - input.get_variable();
        let lcc = LinearCombination::from_variable(shifted_input.get_variable()) - input.get_variable();
        // shifted_input = curr_is_right*prev + (1-curr_is_right)*input
        cs.enforce(|| "shift constraint", |_| lca, |_| lcb, |_| lcc);
        // Expand the shifted level
        shifted_level.push(shifted_input);
        // If the row is shifted, then current element will need to feed into next iteration
        prev = input;
    }
    Ok((shifted_level, prev))
}

impl Circuit<bls12_381::Scalar> for Append {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // First verify that the authentication path is valid. I.e. it places
        // an empty node at the position size into the old root
        // Allocate the tree size that will be exposed.
        let old_size = num::AllocatedNum::alloc_input(cs.namespace(|| "old Merkle tree size"), || {
            Ok(*self.old_size.get()?)
        })?;
        // Convert the tree size to bits
        let depth = self.auth_path.len().try_into().expect("tree depth should fit in u8");
        let old_size_bits = constrain_to_boolean_vec_le(cs, old_size, depth)?;

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let empty_root = Scalar::from(Node::empty_root(0));
        let mut cur = num::AllocatedNum::alloc(cs.namespace(|| "empty leaf"), || Ok(empty_root))?;
        let lc = LinearCombination::from_variable(cur.get_variable()) - (empty_root, CS::one());
        cs.enforce(|| "empty leaf", |lc| lc, |lc| lc, |_| lc);
        let mut path_elements = vec![];
        // Ascend the merkle tree authentication path
        for (i, e) in self.auth_path.into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));
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
            // Store path element for the computation of new root
            path_elements.push(path_element);
        }

        // Expose the old root
        cur.inputize(cs.namespace(|| "old root"))?;

        // Make a variable hard wired to the empty root
        let empty_root_alloc = num::AllocatedNum::alloc(cs.namespace(|| "empty root"), || Ok(empty_root))?;
        let lc = LinearCombination::from_variable(empty_root_alloc.get_variable()) - (empty_root, CS::one());
        cs.enforce(|| "empty leaf", |lc| lc, |lc| lc, |_| lc);
        
        // Build the first level of the tree from the public inputs
        let (mut level, mut empty_root_alloc) = {
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[0];
            // The previous element in the level
            let prev = path_elements.remove(0);
            // Build up the bottom level of the tree
            let mut level = vec![];
            for (i, e) in self.new_cmus.into_iter().enumerate() {
                let input = num::AllocatedNum::alloc_input(cs.namespace(|| format!("input {}", i)), || Ok(*e.get()?))?;
                level.push(input);
            }
            // Conditionally shift the level
            conditionally_shift_leaves(
                cs.namespace(|| "conditionally shifting of nodes"),
                cur_is_right,
                prev,
                level,
                empty_root_alloc,
            )?
        };
        let mut height = 0;
        // Build more tree levels until we hit a subtree containing all the public inputs
        loop {
            let mut next_level = vec![];
            for pair in level.chunks(2) {
                let ur = pair.get(1).unwrap_or(&empty_root_alloc);
                // We don't need to be strict, because the function is
                // collision-resistant. If the prover witnesses a congruency,
                // they will be unable to find an authentication path in the
                // tree with high probability.
                let mut preimage = vec![];
                preimage.extend(pair[0].to_bits_le(cs.namespace(|| "ul into bits"))?);
                preimage.extend(ur.to_bits_le(cs.namespace(|| "ur into bits"))?);

                // Compute the new subtree value
                let cur = pedersen_hash::pedersen_hash(
                    cs.namespace(|| "computation of pedersen hash"),
                    pedersen_hash::Personalization::MerkleTree(height),
                    &preimage,
                )?
                    .get_u()
                    .clone(); // Injective encoding
                // Build up the next level
                next_level.push(cur);
            }
            height += 1;
            // If we've finally found a single root, then stop this aggregation
            if level.len() == 1 { break; }
            // The previous element in the level
            let prev = path_elements.remove(0);
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[height];
            // Conditionally shift the level
            (level, empty_root_alloc) = conditionally_shift_leaves(
                cs.namespace(|| "conditionally shifting of nodes"),
                cur_is_right,
                prev,
                next_level,
                empty_root_alloc,
            )?;
        }
        // After computing a Merkle root from the public inputs
        assert_eq!(level.len(), 1);
        cur = level.remove(0);
        // Finally compute the new root by ascending the remaining merkle
        // tree authentication path
        for e in path_elements {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", height));
            // Determines if the current subtree is the "right" leaf at this
            // depth of the tree.
            let cur_is_right = &old_size_bits[height];
            // Witness the authentication path element adjacent
            // at this depth.
            let path_element = e;
            
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
                pedersen_hash::Personalization::MerkleTree(height),
                &preimage,
            )?
            .get_u()
                .clone(); // Injective encoding
            height += 1;
        }
        // Expose the new root
        cur.inputize(cs.namespace(|| "new root"))?;
        Ok(())
    }
}

use bellman::gadgets::boolean::Boolean;
use bellman::gadgets::num::{AllocatedNum, Num};
use bellman::{ConstraintSystem, SynthesisError};
use group::ff::Field;
pub use masp_primitives::sapling::poseidon_hash::Domain;
use masp_primitives::sapling::poseidon_hash::POSEIDON_CHUNK_BITS;
use poseidon2_r1cs_bls12_381::gadget::compress_allocated;

pub fn alloc_constant<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    value: bls12_381::Scalar,
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let allocated = AllocatedNum::alloc(cs.namespace(|| "allocate constant"), || Ok(value))?;
    cs.enforce(
        || "enforce constant",
        |lc| lc + allocated.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + (value, CS::one()),
    );
    Ok(allocated)
}

pub fn pack_bits_le<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let packed = AllocatedNum::alloc(cs.namespace(|| "packed bits"), || {
        let mut value = bls12_381::Scalar::ZERO;
        let mut coeff = bls12_381::Scalar::ONE;
        for bit in bits {
            if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                value += coeff;
            }
            coeff = coeff.double();
        }
        Ok(value)
    })?;

    let mut num = Num::zero();
    let mut coeff = bls12_381::Scalar::ONE;
    for bit in bits {
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);
        coeff = coeff.double();
    }

    cs.enforce(
        || "pack bits constraint",
        |lc| lc + packed.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + &num.lc(bls12_381::Scalar::ONE),
    );

    Ok(packed)
}

pub fn hash_bits<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    domain: Domain,
    bits: &[Boolean],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    hash_bits_with_suffix_scalars(cs, domain, bits, &[])
}

pub fn hash_bits_with_suffix_scalars<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    domain: Domain,
    bits: &[Boolean],
    suffix_scalars: &[AllocatedNum<bls12_381::Scalar>],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let domain = alloc_constant(cs.namespace(|| "domain"), domain.as_scalar())?;
    let bit_len = alloc_constant(
        cs.namespace(|| "bit length"),
        bls12_381::Scalar::from(bits.len() as u64),
    )?;
    let mut acc = compress_allocated(cs.namespace(|| "init"), &domain, &bit_len)?;

    for (chunk_idx, chunk) in bits.chunks(POSEIDON_CHUNK_BITS).enumerate() {
        let packed = pack_bits_le(cs.namespace(|| format!("chunk {chunk_idx} pack")), chunk)?;
        acc = compress_allocated(
            cs.namespace(|| format!("chunk {chunk_idx} compress")),
            &acc,
            &packed,
        )?;
    }

    for (idx, scalar) in suffix_scalars.iter().enumerate() {
        acc = compress_allocated(
            cs.namespace(|| format!("suffix scalar {idx}")),
            &acc,
            scalar,
        )?;
    }

    Ok(acc)
}

pub fn hash_allocated_scalars<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    domain: Domain,
    scalars: &[AllocatedNum<bls12_381::Scalar>],
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let domain = alloc_constant(cs.namespace(|| "domain"), domain.as_scalar())?;
    let len = alloc_constant(
        cs.namespace(|| "scalar length"),
        bls12_381::Scalar::from(scalars.len() as u64),
    )?;
    let mut acc = compress_allocated(cs.namespace(|| "init"), &domain, &len)?;
    for (idx, scalar) in scalars.iter().enumerate() {
        acc = compress_allocated(cs.namespace(|| format!("scalar {idx}")), &acc, scalar)?;
    }
    Ok(acc)
}

pub fn merkle_hash<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    depth: usize,
    left: &AllocatedNum<bls12_381::Scalar>,
    right: &AllocatedNum<bls12_381::Scalar>,
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let inner = compress_allocated(cs.namespace(|| "inner"), left, right)?;
    let depth = alloc_constant(
        cs.namespace(|| "depth"),
        bls12_381::Scalar::from(depth as u64),
    )?;
    compress_allocated(cs.namespace(|| "outer"), &depth, &inner)
}

pub fn nullifier_rho<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    cmu: &AllocatedNum<bls12_381::Scalar>,
    position: &AllocatedNum<bls12_381::Scalar>,
) -> Result<AllocatedNum<bls12_381::Scalar>, SynthesisError> {
    let inner = compress_allocated(cs.namespace(|| "inner"), cmu, position)?;
    let domain = alloc_constant(cs.namespace(|| "domain"), Domain::NullifierRho.as_scalar())?;
    compress_allocated(cs.namespace(|| "outer"), &domain, &inner)
}

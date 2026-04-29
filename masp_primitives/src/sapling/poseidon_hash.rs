use ff::Field;
use poseidon2_r1cs_bls12_381::compress;

pub const POSEIDON_CHUNK_BITS: usize = 248;

#[derive(Copy, Clone)]
pub enum Domain {
    NoteCommitment,
    AllowedConversion,
    NullifierRho,
    CRHIvk,
    PRFNf,
    AssetGen,
}

impl Domain {
    pub fn as_scalar(self) -> bls12_381::Scalar {
        match self {
            Domain::NoteCommitment => bls12_381::Scalar::from(1u64),
            Domain::AllowedConversion => bls12_381::Scalar::from(2u64),
            Domain::NullifierRho => bls12_381::Scalar::from(3u64),
            Domain::CRHIvk => bls12_381::Scalar::from(4u64),
            Domain::PRFNf => bls12_381::Scalar::from(5u64),
            Domain::AssetGen => bls12_381::Scalar::from(6u64),
        }
    }
}

pub fn hash_bits<I>(domain: Domain, bits: I) -> bls12_381::Scalar
where
    I: IntoIterator<Item = bool>,
{
    hash_bits_with_suffix_scalars(domain, bits, &[])
}

pub fn hash_bits_with_suffix_scalars<I>(
    domain: Domain,
    bits: I,
    suffix_scalars: &[bls12_381::Scalar],
) -> bls12_381::Scalar
where
    I: IntoIterator<Item = bool>,
{
    let bits: Vec<bool> = bits.into_iter().collect();
    let bit_len = bls12_381::Scalar::from(bits.len() as u64);

    let mut acc = compress(domain.as_scalar(), bit_len);
    for chunk in bits.chunks(POSEIDON_CHUNK_BITS) {
        let packed = pack_bits_le(chunk.iter().copied());
        acc = compress(acc, packed);
    }

    for scalar in suffix_scalars {
        acc = compress(acc, *scalar);
    }

    acc
}

pub fn hash_scalars(domain: Domain, scalars: &[bls12_381::Scalar]) -> bls12_381::Scalar {
    let mut acc = compress(
        domain.as_scalar(),
        bls12_381::Scalar::from(scalars.len() as u64),
    );
    for scalar in scalars {
        acc = compress(acc, *scalar);
    }
    acc
}

pub fn merkle_hash(
    depth: usize,
    lhs: bls12_381::Scalar,
    rhs: bls12_381::Scalar,
) -> bls12_381::Scalar {
    let inner = compress(lhs, rhs);
    compress(bls12_381::Scalar::from(depth as u64), inner)
}

pub fn nullifier_rho(cmu: bls12_381::Scalar, position: u64) -> bls12_381::Scalar {
    let inner = compress(cmu, bls12_381::Scalar::from(position));
    compress(Domain::NullifierRho.as_scalar(), inner)
}

fn pack_bits_le<I>(bits: I) -> bls12_381::Scalar
where
    I: IntoIterator<Item = bool>,
{
    let mut value = bls12_381::Scalar::ZERO;
    let mut coeff = bls12_381::Scalar::ONE;

    for bit in bits {
        if bit {
            value += coeff;
        }
        coeff = coeff.double();
    }

    value
}

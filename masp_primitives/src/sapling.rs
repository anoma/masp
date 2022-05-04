//! Structs and constants specific to the Sapling shielded pool.

use crate::{
    constants::SPENDING_KEY_GENERATOR,
    merkle_tree::{HashSer, Hashable},
    pedersen_hash::{pedersen_hash, Personalization},
    primitives::Note,
    redjubjub::{PrivateKey, PublicKey, Signature},
};
use bitvec::{order::Lsb0, view::AsBits};
use ff::PrimeField;
use group::{Curve, GroupEncoding};
use incrementalmerkletree::{self, Altitude};
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
use std::io::{self, Read, Write};

pub const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(lhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(rhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .copied()
            .take(bls12_381::Scalar::NUM_BITS as usize)
            .chain(
                rhs.iter()
                    .copied()
                    .take(bls12_381::Scalar::NUM_BITS as usize),
            ),
    ))
    .to_affine()
    .get_u()
    .to_repr()
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    repr: [u8; 32],
}

impl Node {
    pub fn new(repr: [u8; 32]) -> Self {
        Node { repr }
    }
}

impl incrementalmerkletree::Hashable for Node {
    fn empty_leaf() -> Self {
        Node {
            repr: Note::uncommitted().to_repr(),
        }
    }

    fn combine(altitude: Altitude, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(altitude.into(), &lhs.repr, &rhs.repr),
        }
    }

    fn empty_root(altitude: Altitude) -> Self {
        EMPTY_ROOTS[<usize>::from(altitude)]
    }
}

impl HashSer for Node {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        Ok(Node::new(repr))
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.repr.as_ref())
    }
}

impl From<Node> for bls12_381::Scalar {
    fn from(node: Node) -> Self {
        // Tree nodes should be in the prime field.
        bls12_381::Scalar::from_repr(node.repr).unwrap()
    }
}

lazy_static! {
    static ref EMPTY_ROOTS: Vec<Node> = {
        let mut v = vec![Node::blank()];
        for d in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            let next = Node::combine(d, &v[d], &v[d]);
            v.push(next);
        }
        v
    };
}

/// Create the spendAuthSig for a Sapling SpendDescription.
pub fn spend_sig<R: RngCore + CryptoRng>(
    ask: PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    spend_sig_internal(ask, ar, sighash, rng)
}

pub(crate) fn spend_sig_internal<R: RngCore>(
    ask: PrivateKey,
    ar: jubjub::Fr,
    sighash: &[u8; 32],
    rng: &mut R,
) -> Signature {
    // We compute `rsk`...
    let rsk = ask.randomize(ar);

    // We compute `rk` from there (needed for key prefixing)
    let rk = PublicKey::from_private(&rsk, SPENDING_KEY_GENERATOR);

    // Compute the signature's message for rk/spend_auth_sig
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&rk.0.to_bytes());
    (&mut data_to_be_signed[32..64]).copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(&data_to_be_signed, rng, SPENDING_KEY_GENERATOR)
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use crate::zip32::testing::arb_extended_spending_key;
    use proptest::prelude::*;
    use std::cmp::min;
    use std::convert::TryFrom;

    use super::Node;
    use crate::primitives::{Note, NoteValue, PaymentAddress, Rseed};

    prop_compose! {
        pub fn arb_note_value()(value in 0u64..=u64::MAX as u64) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    prop_compose! {
        /// The
        pub fn arb_positive_note_value(bound: u64)(
            value in 1u64..=(min(bound, u64::MAX as u64))
        ) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    pub fn arb_payment_address() -> impl Strategy<Value = PaymentAddress> {
        arb_extended_spending_key().prop_map(|sk| sk.default_address().1)
    }
    prop_compose! {
        pub fn arb_node()(value in prop::array::uniform32(prop::num::u8::ANY)) -> Node {
            Node::new(value)
        }
    }

    prop_compose! {
        pub fn arb_note(value: NoteValue)(
            asset_type in crate::asset_type::testing::arb_asset_type(),
            addr in arb_payment_address(),
            rseed in prop::array::uniform32(prop::num::u8::ANY).prop_map(Rseed::AfterZip212)
                ) -> Note {
            Note {
                value: value.into(),
                g_d: addr.g_d().unwrap(), // this unwrap is safe because arb_payment_address always generates an address with a valid g_d
                pk_d: *addr.pk_d(),
                rseed,
                asset_type
            }
        }
    }
}

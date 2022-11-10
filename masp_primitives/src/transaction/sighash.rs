use std::convert::TryInto;

use blake2b_simd::Hash as Blake2bHash;

use super::{
    TransparentAddress, GrothProofBytes,
    //components::{
        sapling::{self, },
        builder::transparent, amount::Amount,
    //},
    //sighash_v4::v4_signature_hash,
    sighash_v5::v5_signature_hash,
    Authorization, TransactionData, TxDigests,
};

#[cfg(feature = "zfuture")]
use crate::extensions::transparent::Precondition;

pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_MASK: u8 = 0x1f;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;

pub enum SignableInput {
    Shielded,
    Transparent {
        hash_type: u8,
        index: usize,
        value: Amount,
    },
}

impl SignableInput {
    pub fn hash_type(&self) -> u8 {
        match self {
            SignableInput::Shielded => SIGHASH_ALL,
            SignableInput::Transparent { hash_type, .. } => *hash_type,
        }
    }
}

pub struct SignatureHash(Blake2bHash);

impl AsRef<[u8; 32]> for SignatureHash {
    fn as_ref(&self) -> &[u8; 32] {
        self.0.as_ref().try_into().unwrap()
    }
}

/// Additional context that is needed to compute signature hashes
/// for transactions that include transparent inputs or outputs.
pub trait TransparentAuthorizingContext: transparent::Authorization {
    /// Returns the list of all transparent input amounts, provided
    /// so that wallets can commit to the transparent input breakdown
    /// without requiring the full data of the previous transactions
    /// providing these inputs.
    fn input_amounts(&self) -> Vec<Amount>;
    /// Returns the list of all transparent input scriptPubKeys, provided
    /// so that wallets can commit to the transparent input breakdown
    /// without requiring the full data of the previous transactions
    /// providing these inputs.
    fn input_scriptpubkeys(&self) -> Vec<TransparentAddress>;
}

/// Computes the signature hash for an input to a transaction, given
/// the full data of the transaction, the input being signed, and the
/// set of precomputed hashes produced in the construction of the
/// transaction ID.
pub fn signature_hash<
    'a,
    //TA: TransparentAuthorizingContext,
    SA: sapling::Authorization<Proof = GrothProofBytes>,
    A: Authorization<SaplingAuth = SA>, //TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> SignatureHash {
    SignatureHash( v5_signature_hash(tx, signable_input, txid_parts)
    )
}

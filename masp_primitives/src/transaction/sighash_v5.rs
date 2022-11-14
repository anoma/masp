use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use byteorder::{LittleEndian, WriteBytesExt};
use zcash_encoding::Array;

use crate::transaction::{
    builder::transparent::{self, TxOut},
    sighash::{
        SignableInput, TransparentAuthorizingContext, SIGHASH_ANYONECANPAY, SIGHASH_MASK,
        SIGHASH_NONE, SIGHASH_SINGLE,
    },
    txid::{
        hash_transparent_txid_data, to_hash, transparent_outputs_hash,
        ZCASH_TRANSPARENT_HASH_PERSONALIZATION,
    },
    Authorization, TransactionData, TransparentDigests, TxDigests,
};

#[cfg(feature = "zfuture")]
use zcash_encoding::{CompactSize, Vector};

#[cfg(feature = "zfuture")]
use crate::transaction::{components::tze, TzeDigests};

const ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash___TxInHash";
const ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrAmountsHash";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxTrScriptsHash";

#[cfg(feature = "zfuture")]
const ZCASH_TZE_INPUT_HASH_PERSONALIZATION: &[u8; 16] = b"Zcash__TzeInHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Implements [ZIP 244 section S.2](https://zips.z.cash/zip-0244#s-2-transparent-sig-digest).
fn transparent_sig_digest<A: transparent::Authorization>(
    //<A: TransparentAuthorizingContext>(
    tx_data: Option<(&transparent::Bundle<A>, &TransparentDigests<Blake2bHash>)>,
    input: &SignableInput,
) -> Blake2bHash {
    match tx_data {
        // No transparent inputs or outputs.
        None => hash_transparent_txid_data(None),
        // No transparent inputs, or coinbase.
        //Some((bundle, txid_digests)) if bundle.is_coinbase() || bundle.vin.is_empty() => {
        //    hash_transparent_txid_data(Some(txid_digests))
        // }
        // Some transparent inputs, and not coinbase.
        Some((bundle, txid_digests)) => {
            let hash_type = input.hash_type();
            let flag_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;
            let flag_single = hash_type & SIGHASH_MASK == SIGHASH_SINGLE;
            let flag_none = hash_type & SIGHASH_MASK == SIGHASH_NONE;

            let outputs_digest = if let SignableInput::Transparent { index, .. } = input {
                if flag_single {
                    if *index < bundle.vout.len() {
                        transparent_outputs_hash(&[&bundle.vout[*index]])
                    } else {
                        transparent_outputs_hash::<TxOut>(&[])
                    }
                } else if flag_none {
                    transparent_outputs_hash::<TxOut>(&[])
                } else {
                    txid_digests.outputs_digest
                }
            } else {
                txid_digests.outputs_digest
            };

            let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
            h.write_all(&[hash_type]).unwrap();
            h.write_all(outputs_digest.as_bytes()).unwrap();
            h.finalize()
        }
    }
}

/// Implements the [Signature Digest section of ZIP 244](https://zips.z.cash/zip-0244#signature-digest)
pub fn v5_signature_hash<
    //TA: TransparentAuthorizingContext,
    A: Authorization, //<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    // The caller must provide the transparent digests if and only if the transaction has a
    // transparent component.
    assert_eq!(
        tx.transparent_bundle.is_some(),
        txid_parts.transparent_digests.is_some()
    );

    to_hash(
        transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
    )
}

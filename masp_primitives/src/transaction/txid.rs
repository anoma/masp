use std::borrow::Borrow;
use std::convert::TryFrom;
use std::io::Write;

use blake2b_simd::{Hash as Blake2bHash, Params, State};
use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::GroupEncoding;

use crate::consensus::{BlockHeight, BranchId};

use super::{
    sapling::{self, ConvertDescription, OutputDescription, SpendDescription},
    transparent::{self, TxIn, TxOut},
    Authorization, Authorized, TransactionDigest, TransparentDigests, TxDigests, TxId, TxVersion,
};

/// TxId tree root personalization
const ZCASH_TX_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZcashTxHash_";

// TxId level 1 node personalization
const ZCASH_HEADERS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdHeadersHash";
pub(crate) const ZCASH_TRANSPARENT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdTranspaHash";
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSaplingHash";

// TxId transparent level 2 node personalization
const ZCASH_INPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdInputs_Hash";
const ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdOutputsHash";

// TxId sapling level 2 node personalization
const ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendsHash";
const ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendCHash";
const ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSSpendNHash";

const ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdConvertHash";

const ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutputHash";
const ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutC__Hash";
const ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutM__Hash";
const ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxIdSOutN__Hash";

const ZCASH_AUTH_PERSONALIZATION_PREFIX: &[u8; 12] = b"ZTxAuthHash_";
const ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTransHash";
const ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION: &[u8; 16] = b"ZTxAuthSapliHash";

fn hasher(personal: &[u8; 16]) -> State {
    Params::new().hash_length(32).personal(personal).to_state()
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by ZCASH_OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_outputs_hash<T: Borrow<TxOut>>(vout: &[T]) -> Blake2bHash {
    let mut h = hasher(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
    for t_out in vout {
        t_out.borrow().write(&mut h).unwrap();
    }
    h.finalize()
}

/// Sequentially append the full serialized value of each transparent input
/// to a hash personalized by ZCASH_INPUTS_HASH_PERSONALIZATION.
/// In the case that no inputs are provided, this produces a default
/// hash from just the personalization string.
pub(crate) fn transparent_inputs_hash<
    TransparentAuth: transparent::Authorization,
    T: Borrow<TxIn<TransparentAuth>>,
>(
    vin: &[T],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_INPUTS_HASH_PERSONALIZATION);
    for t_in in vin {
        let t_in = t_in.borrow();
        h.write_all(t_in.asset_type.get_identifier()).unwrap();
        h.write_all(&t_in.value.to_le_bytes()).unwrap();
        h.write_all(&t_in.address.0).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3a](https://zips.z.cash/zip-0244#t-3a-sapling-spends-digest)
///
/// Write disjoint parts of each Sapling shielded spend to a pair of hashes:
/// * \[nullifier*\] - personalized with ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION
/// * \[(cv, anchor, rk, zkproof)*\] - personalized with ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized by ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_spends<A: sapling::Authorization + PartialEq>(
    shielded_spends: &[SpendDescription<A>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
    if !shielded_spends.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_spend in shielded_spends {
            // we build the hash of nullifiers separately for compact blocks.
            ch.write_all(s_spend.nullifier.as_ref()).unwrap();

            nh.write_all(&s_spend.cv.to_bytes()).unwrap();
            nh.write_all(&s_spend.anchor.to_repr()).unwrap();
            s_spend.rk.write(&mut nh).unwrap();
        }

        let compact_digest = ch.finalize();
        h.write_all(compact_digest.as_bytes()).unwrap();
        let noncompact_digest = nh.finalize();
        h.write_all(noncompact_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Implements ZIP 244-like hashing of MASP convert descriptions.
///
/// Write disjoint parts of each MASP shielded convert to a hash:
/// * \[(cv, anchor)*\] - personalized with ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION
///
pub(crate) fn hash_sapling_converts<Proof: Clone + PartialEq>(
    shielded_converts: &[ConvertDescription<Proof>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_CONVERTS_HASH_PERSONALIZATION);
    if !shielded_converts.is_empty() {
        for s_convert in shielded_converts {
            h.write_all(&s_convert.cv.to_bytes()).unwrap();
            h.write_all(&s_convert.anchor.to_repr()).unwrap();
        }
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3b](https://zips.z.cash/zip-0244#t-3b-sapling-outputs-digest)
///
/// Write disjoint parts of each Sapling shielded output as 3 separate hashes:
/// * \[(cmu, epk, enc_ciphertext\[..52\])*\] personalized with ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION
/// * \[enc_ciphertext\[52..564\]*\] (memo ciphertexts) personalized with ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION
/// * \[(cv, enc_ciphertext\[564..\], out_ciphertext, zkproof)*\] personalized with ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION
///
/// Then, hash these together personalized with ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION
pub(crate) fn hash_sapling_outputs<Proof: Clone>(
    shielded_outputs: &[OutputDescription<Proof>],
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);
    if !shielded_outputs.is_empty() {
        let mut ch = hasher(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);
        let mut mh = hasher(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);
        let mut nh = hasher(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);
        for s_out in shielded_outputs {
            ch.write_all(s_out.cmu.to_repr().as_ref()).unwrap();
            ch.write_all(s_out.ephemeral_key.as_ref()).unwrap();
            ch.write_all(&s_out.enc_ciphertext[..masp_note_encryption::COMPACT_NOTE_SIZE])
                .unwrap();

            mh.write_all(
                &s_out.enc_ciphertext[masp_note_encryption::COMPACT_NOTE_SIZE
                    ..masp_note_encryption::NOTE_PLAINTEXT_SIZE],
            )
            .unwrap();

            nh.write_all(&s_out.cv.to_bytes()).unwrap();
            nh.write_all(&s_out.enc_ciphertext[masp_note_encryption::NOTE_PLAINTEXT_SIZE..])
                .unwrap();
            nh.write_all(&s_out.out_ciphertext).unwrap();
        }

        h.write_all(ch.finalize().as_bytes()).unwrap();
        h.write_all(mh.finalize().as_bytes()).unwrap();
        h.write_all(nh.finalize().as_bytes()).unwrap();
    }
    h.finalize()
}

/// The txid commits to the hash of all transparent outputs. The
/// prevout and sequence_hash components of txid
fn transparent_digests<A: transparent::Authorization>(
    bundle: &transparent::Bundle<A>,
) -> TransparentDigests<Blake2bHash> {
    TransparentDigests {
        inputs_digest: transparent_inputs_hash(&bundle.vin),
        outputs_digest: transparent_outputs_hash(&bundle.vout),
    }
}
/// Implements [ZIP 244 section T.1](https://zips.z.cash/zip-0244#t-1-header-digest)
fn hash_header_txid_data(
    version: TxVersion,
    // we commit to the consensus branch ID with the header
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_HEADERS_HASH_PERSONALIZATION);

    h.write_u32::<LittleEndian>(version.header()).unwrap();
    h.write_u32::<LittleEndian>(version.version_group_id())
        .unwrap();
    h.write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();
    h.write_u32::<LittleEndian>(lock_time).unwrap();
    h.write_u32::<LittleEndian>(expiry_height.into()).unwrap();

    h.finalize()
}

/// Implements [ZIP 244 section T.2](https://zips.z.cash/zip-0244#t-2-transparent-digest)
pub(crate) fn hash_transparent_txid_data(
    t_digests: Option<&TransparentDigests<Blake2bHash>>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);
    if let Some(d) = t_digests {
        h.write_all(d.inputs_digest.as_bytes()).unwrap();
        h.write_all(d.outputs_digest.as_bytes()).unwrap();
    }
    h.finalize()
}

/// Implements [ZIP 244 section T.3](https://zips.z.cash/zip-0244#t-3-sapling-digest)
fn hash_sapling_txid_data<
    A: sapling::Authorization + PartialEq + BorshSerialize + BorshDeserialize,
>(
    bundle: &sapling::Bundle<A>,
) -> Blake2bHash {
    let mut h = hasher(ZCASH_SAPLING_HASH_PERSONALIZATION);
    if !(bundle.shielded_spends.is_empty()
        && bundle.shielded_converts.is_empty()
        && bundle.shielded_outputs.is_empty())
    {
        h.write_all(hash_sapling_spends(&bundle.shielded_spends).as_bytes())
            .unwrap();
        h.write_all(hash_sapling_converts(&bundle.shielded_converts).as_bytes())
            .unwrap();
        h.write_all(hash_sapling_outputs(&bundle.shielded_outputs).as_bytes())
            .unwrap();

        bundle.value_balance.serialize(&mut h).unwrap();
    }
    h.finalize()
}

fn hash_sapling_txid_empty() -> Blake2bHash {
    hasher(ZCASH_SAPLING_HASH_PERSONALIZATION).finalize()
}

/// A TransactionDigest implementation that commits to all of the effecting
/// data of a transaction to produce a nonmalleable transaction identifier.
///
/// This expects and relies upon the existence of canonical encodings for
/// each effecting component of a transaction.
///
/// This implements the [TxId Digest section of ZIP 244](https://zips.z.cash/zip-0244#txid-digest)
pub struct TxIdDigester;

impl<A: Authorization> TransactionDigest<A> for TxIdDigester {
    type HeaderDigest = Blake2bHash;
    type TransparentDigest = Option<TransparentDigests<Blake2bHash>>;
    type SaplingDigest = Option<Blake2bHash>;

    type Digest = TxDigests<Blake2bHash>;

    fn digest_header(
        &self,
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        hash_header_txid_data(version, consensus_branch_id, lock_time, expiry_height)
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<A::TransparentAuth>>,
    ) -> Self::TransparentDigest {
        transparent_bundle.map(transparent_digests)
    }

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<A::SaplingAuth>>,
    ) -> Self::SaplingDigest {
        sapling_bundle.map(hash_sapling_txid_data)
    }

    fn combine(
        &self,
        header_digest: Self::HeaderDigest,
        transparent_digests: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
    ) -> Self::Digest {
        TxDigests {
            header_digest,
            transparent_digests,
            sapling_digest,
        }
    }
}

pub(crate) fn to_hash(
    _txversion: TxVersion,
    consensus_branch_id: BranchId,
    header_digest: Blake2bHash,
    transparent_digest: Blake2bHash,
    sapling_digest: Option<Blake2bHash>,
) -> Blake2bHash {
    let mut personal = [0; 16];
    personal[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
    (&mut personal[12..])
        .write_u32::<LittleEndian>(consensus_branch_id.into())
        .unwrap();
    println!("Personalization Prefix: {}", hex::encode(ZCASH_TX_PERSONALIZATION_PREFIX));
    println!("Consensus Branch ID: {:?}", consensus_branch_id);
    println!("Consensus Branch ID: {:?}", u32::from(consensus_branch_id));
    println!("Personal: {}", hex::encode(personal));

    let mut h = hasher(&personal);
    println!("Header Digest: {:?}", header_digest);
    h.write_all(header_digest.as_bytes()).unwrap();
    println!("Transparent Digest: {:?}", transparent_digest);
    h.write_all(transparent_digest.as_bytes()).unwrap();
    println!("Sapling Digest: {}", hex::encode(sapling_digest
            .unwrap_or_else(hash_sapling_txid_empty)
            .as_bytes()));
    h.write_all(
        sapling_digest
            .unwrap_or_else(hash_sapling_txid_empty)
            .as_bytes(),
    )
        .unwrap();

    h.finalize()
}

pub fn to_txid(
    txversion: TxVersion,
    consensus_branch_id: BranchId,
    digests: &TxDigests<Blake2bHash>,
) -> TxId {
    let txid_digest = to_hash(
        txversion,
        consensus_branch_id,
        digests.header_digest,
        hash_transparent_txid_data(digests.transparent_digests.as_ref()),
        digests.sapling_digest,
    );
    println!("TxId Digest: {}\n", TxId(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap()));

    TxId(<[u8; 32]>::try_from(txid_digest.as_bytes()).unwrap())
}

/// Digester which constructs a digest of only the witness data.
/// This does not internally commit to the txid, so if that is
/// desired it should be done using the result of this digest
/// function.
pub struct BlockTxCommitmentDigester;

impl TransactionDigest<Authorized> for BlockTxCommitmentDigester {
    /// We use the header digest to pass the transaction ID into
    /// where it needs to be used for personalization string construction.
    type HeaderDigest = BranchId;
    type TransparentDigest = Blake2bHash;
    type SaplingDigest = Blake2bHash;

    type Digest = Blake2bHash;

    fn digest_header(
        &self,
        _version: TxVersion,
        consensus_branch_id: BranchId,
        _lock_time: u32,
        _expiry_height: BlockHeight,
    ) -> Self::HeaderDigest {
        consensus_branch_id
    }

    fn digest_transparent(
        &self,
        transparent_bundle: Option<&transparent::Bundle<transparent::Authorized>>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
        if let Some(bundle) = transparent_bundle {
            for txout in &bundle.vout {
                h.write_all(txout.asset_type.get_identifier()).unwrap();
                h.write_all(&txout.value.to_le_bytes()).unwrap();
                h.write_all(&txout.address.0).unwrap();
            }
        }
        h.finalize()
    }

    fn digest_sapling(
        &self,
        sapling_bundle: Option<&sapling::Bundle<sapling::Authorized>>,
    ) -> Blake2bHash {
        let mut h = hasher(ZCASH_SAPLING_SIGS_HASH_PERSONALIZATION);
        if let Some(bundle) = sapling_bundle {
            for spend in &bundle.shielded_spends {
                h.write_all(&spend.zkproof).unwrap();
            }

            for spend in &bundle.shielded_spends {
                spend.spend_auth_sig.write(&mut h).unwrap();
            }

            for convert in &bundle.shielded_converts {
                h.write_all(&convert.zkproof).unwrap();
            }

            for output in &bundle.shielded_outputs {
                h.write_all(&output.zkproof).unwrap();
            }

            bundle.authorization.binding_sig.write(&mut h).unwrap();
        }
        h.finalize()
    }

    fn combine(
        &self,
        consensus_branch_id: Self::HeaderDigest,
        transparent_digest: Self::TransparentDigest,
        sapling_digest: Self::SaplingDigest,
    ) -> Self::Digest {
        let digests = [transparent_digest, sapling_digest];

        let mut personal = [0; 16];
        personal[..12].copy_from_slice(ZCASH_AUTH_PERSONALIZATION_PREFIX);
        (&mut personal[12..])
            .write_u32::<LittleEndian>(consensus_branch_id.into())
            .unwrap();

        let mut h = hasher(&personal);
        for digest in &digests {
            h.write_all(digest.as_bytes()).unwrap();
        }

        h.finalize()
    }
}

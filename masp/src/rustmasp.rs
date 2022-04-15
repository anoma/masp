//! FFI between the C++ zcashd codebase and the Rust Zcash crates.
//!
//! This is internal to zcashd and is not an officially-supported API.

// Catch documentation errors caused by code changes.
//#![deny(rustdoc::broken_intra_doc_links)]
#![deny(broken_intra_doc_links)]
// Clippy has a default-deny lint to prevent dereferencing raw pointer arguments
// in a non-unsafe function. However, declaring a function as unsafe has the
// side-effect that the entire function body is treated as an unsafe {} block,
// and rustc will not enforce full safety checks on the parts of the function
// that would otherwise be safe.
//
// The functions in this crate are all for FFI usage, so it's obvious to the
// caller (which is only ever zcashd) that the arguments must satisfy the
// necessary assumptions. We therefore ignore this lint to retain the benefit of
// explicitly annotating the parts of each function that must themselves satisfy
// assumptions of underlying code.
//
// See https://github.com/rust-lang/rfcs/pull/2585 for more background.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use bellman::groth16::{Parameters, PreparedVerifyingKey, Proof};
use blake2s_simd::Params as Blake2sParams;
use bls12_381::Bls12;
use group::{cofactor::CofactorGroup, GroupEncoding};
use libc::{c_uchar, size_t};
use rand_core::{OsRng, RngCore};
use std::path::Path;
use std::slice;
use subtle::CtOption;

#[cfg(not(target_os = "windows"))]
use std::ffi::OsStr;
#[cfg(not(target_os = "windows"))]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

use zcash_primitives::sapling::{note_encryption::sapling_ka_agree, Rseed};

use masp_primitives::{
    asset_type::AssetType,
    constants::{
        ASSET_IDENTIFIER_LENGTH, CRH_IVK_PERSONALIZATION, PROOF_GENERATION_KEY_GENERATOR,
        SPENDING_KEY_GENERATOR,
    },
    primitives::{Diversifier, Note, PaymentAddress, ProofGenerationKey, ViewingKey},
    redjubjub::{self, Signature},
    sapling::{merkle_hash, spend_sig},
    zip32,
};
use masp_proofs::{
    circuit::sapling::TREE_DEPTH as SAPLING_TREE_DEPTH,
    load_parameters,
    sapling::{SaplingProvingContext, SaplingVerificationContext},
};
use zcash_primitives::merkle_tree::MerklePath;

#[cfg(test)]
mod tests;

static mut SAPLING_SPEND_VK: Option<PreparedVerifyingKey<Bls12>> = None;
static mut SAPLING_OUTPUT_VK: Option<PreparedVerifyingKey<Bls12>> = None;

static mut SAPLING_SPEND_PARAMS: Option<Parameters<Bls12>> = None;
static mut SAPLING_OUTPUT_PARAMS: Option<Parameters<Bls12>> = None;

/// Converts CtOption<t> into Option<T>
fn de_ct<T>(ct: CtOption<T>) -> Option<T> {
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

/// Reads an FsRepr from a [u8; 32]
/// and multiplies it by the given base.
fn fixed_scalar_mult(from: &[u8; 32], p_g: &jubjub::SubgroupPoint) -> jubjub::SubgroupPoint {
    // We only call this with `from` being a valid jubjub::Scalar.
    let f = jubjub::Scalar::from_bytes(from).unwrap();

    p_g * f
}

/// Loads the zk-SNARK parameters into memory and saves paths as necessary.
/// Only called once.
#[cfg(not(target_os = "windows"))]
#[no_mangle]
pub extern "C" fn libmasp_init_zksnark_params(
    spend_path: *const u8,
    spend_path_len: usize,
    output_path: *const u8,
    output_path_len: usize,
    convert_path: *const u8,
    convert_path_len: usize,
) {
    let spend_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(spend_path, spend_path_len)
    }));
    let output_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(output_path, output_path_len)
    }));
    let convert_path = Path::new(OsStr::from_bytes(unsafe {
        slice::from_raw_parts(convert_path, convert_path_len)
    }));

    init_zksnark_params(spend_path, output_path, convert_path)
}

/// Loads the zk-SNARK parameters into memory and saves paths as necessary.
/// Only called once.
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "C" fn libmasp_init_zksnark_params(
    spend_path: *const u16,
    spend_path_len: usize,
    output_path: *const u16,
    output_path_len: usize,
) {
    let spend_path =
        OsString::from_wide(unsafe { slice::from_raw_parts(spend_path, spend_path_len) });
    let output_path =
        OsString::from_wide(unsafe { slice::from_raw_parts(output_path, output_path_len) });

    init_zksnark_params(Path::new(&spend_path), Path::new(&output_path))
}

fn init_zksnark_params(spend_path: &Path, output_path: &Path, convert_path: &Path) {
    // Load params
    let p = load_parameters(spend_path, output_path, convert_path);

    // Caller is responsible for calling this function once, so
    // these global mutations are safe.
    unsafe {
        SAPLING_SPEND_PARAMS = Some(p.spend_params);
        SAPLING_OUTPUT_PARAMS = Some(p.output_params);

        SAPLING_SPEND_VK = Some(p.spend_vk);
        SAPLING_OUTPUT_VK = Some(p.output_vk);
    }
}

/// Writes the "uncommitted" note value for empty leaves of the Merkle tree.
///
/// `result` must be a valid pointer to 32 bytes which will be written.
#[no_mangle]
pub extern "C" fn libmasp_tree_uncommitted(result: *mut [c_uchar; 32]) {
    let tmp = Note::uncommitted().to_bytes();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };
    *result = tmp;
}

/// Computes a merkle tree hash for a given depth. The `depth` parameter should
/// not be larger than 62.
///
/// `a` and `b` each must be of length 32, and must each be scalars of BLS12-381.
///
/// The result of the merkle tree hash is placed in `result`, which must also be
/// of length 32.
#[no_mangle]
pub extern "C" fn libmasp_merkle_hash(
    depth: size_t,
    a: *const [c_uchar; 32],
    b: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    // Should be okay, because caller is responsible for ensuring
    // the pointers are valid pointers to 32 bytes.
    let tmp = merkle_hash(depth, unsafe { &*a }, unsafe { &*b });

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };
    *result = tmp;
}

#[no_mangle] // ToScalar
pub extern "C" fn libmasp_to_scalar(input: *const [c_uchar; 64], result: *mut [c_uchar; 32]) {
    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    let scalar = jubjub::Scalar::from_bytes_wide(unsafe { &*input });

    let result = unsafe { &mut *result };

    *result = scalar.to_bytes();
}

#[no_mangle]
pub extern "C" fn libmasp_ask_to_ak(ask: *const [c_uchar; 32], result: *mut [c_uchar; 32]) {
    let ask = unsafe { &*ask };
    let ak = fixed_scalar_mult(ask, &SPENDING_KEY_GENERATOR);

    let result = unsafe { &mut *result };

    *result = ak.to_bytes();
}

#[no_mangle]
pub extern "C" fn libmasp_nsk_to_nk(nsk: *const [c_uchar; 32], result: *mut [c_uchar; 32]) {
    let nsk = unsafe { &*nsk };
    let nk = fixed_scalar_mult(nsk, &PROOF_GENERATION_KEY_GENERATOR);

    let result = unsafe { &mut *result };

    *result = nk.to_bytes();
}

#[no_mangle]
pub extern "C" fn libmasp_crh_ivk(
    ak: *const [c_uchar; 32],
    nk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) {
    let ak = unsafe { &*ak };
    let nk = unsafe { &*nk };

    let mut h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    h.update(ak);
    h.update(nk);
    let mut h = h.finalize().as_ref().to_vec();

    // Drop the last five bits, so it can be interpreted as a scalar.
    h[31] &= 0b0000_0111;

    let result = unsafe { &mut *result };

    result.copy_from_slice(&h);
}

#[no_mangle]
pub extern "C" fn libmasp_check_diversifier(diversifier: *const [c_uchar; 11]) -> bool {
    let diversifier = Diversifier(unsafe { *diversifier });
    diversifier.g_d().is_some()
}

#[no_mangle]
pub extern "C" fn libmasp_check_asset_identifier(
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
) -> bool {
    AssetType::from_identifier(&unsafe { *asset_identifier }).is_some()
}

#[no_mangle]
pub extern "C" fn libmasp_ivk_to_pkd(
    ivk: *const [c_uchar; 32],
    diversifier: *const [c_uchar; 11],
    result: *mut [c_uchar; 32],
) -> bool {
    let ivk = de_ct(jubjub::Scalar::from_bytes(unsafe { &*ivk }));
    let diversifier = Diversifier(unsafe { *diversifier });
    if let (Some(ivk), Some(g_d)) = (ivk, diversifier.g_d()) {
        let pk_d = g_d * ivk;

        let result = unsafe { &mut *result };

        *result = pk_d.to_bytes();

        true
    } else {
        false
    }
}

/// Test generation of commitment randomness
#[test]
fn test_gen_r() {
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];

    // Verify different r values are generated
    libmasp_sapling_generate_r(&mut r1);
    libmasp_sapling_generate_r(&mut r2);
    assert_ne!(r1, r2);

    // Verify r values are valid in the field
    let _ = jubjub::Scalar::from_bytes(&r1).unwrap();
    let _ = jubjub::Scalar::from_bytes(&r2).unwrap();
}

/// Generate uniformly random scalar in Jubjub. The result is of length 32.
#[no_mangle]
pub extern "C" fn libmasp_sapling_generate_r(result: *mut [c_uchar; 32]) {
    // create random 64 byte buffer
    let mut rng = OsRng;
    let mut buffer = [0u8; 64];
    rng.fill_bytes(&mut buffer);

    // reduce to uniform value
    let r = jubjub::Scalar::from_bytes_wide(&buffer);
    let result = unsafe { &mut *result };
    *result = r.to_bytes();
}

// Private utility function to get Note from C parameters
fn priv_get_note(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
    value: u64,
    rcm: *const [c_uchar; 32],
) -> Result<Note, ()> {
    let diversifier = Diversifier(unsafe { *diversifier });
    let g_d = diversifier.g_d().ok_or(())?;

    let pk_d = de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*pk_d })).ok_or(())?;

    let pk_d = de_ct(pk_d.into_subgroup()).ok_or(())?;

    let asset_type = AssetType::from_identifier(&unsafe { *asset_identifier }).ok_or(())?;

    // Deserialize randomness
    // If this is after ZIP 212, the caller has calculated rcm, and we don't need to call
    // Note::derive_esk, so we just pretend the note was using this rcm all along.
    let rseed = Rseed::BeforeZip212(de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })).ok_or(())?);

    let note = Note {
        asset_type,
        value,
        g_d,
        pk_d,
        rseed,
    };

    Ok(note)
}

/// Compute a Sapling nullifier.
///
/// The `diversifier` parameter must be 11 bytes in length.
/// The `pk_d`, `r`, `ak` and `nk` parameters must be of length 32.
/// The result is also of length 32 and placed in `result`.
/// Returns false if `diversifier` or `pk_d` is not valid.
#[no_mangle]
pub extern "C" fn libmasp_sapling_compute_nf(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
    value: u64,
    rcm: *const [c_uchar; 32],
    ak: *const [c_uchar; 32],
    nk: *const [c_uchar; 32],
    position: u64,
    result: *mut [c_uchar; 32],
) -> bool {
    let note = match priv_get_note(diversifier, pk_d, &unsafe { *asset_identifier }, value, rcm) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let ak = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*ak })) {
        Some(p) => p,
        None => return false,
    };

    let ak = match de_ct(ak.into_subgroup()) {
        Some(ak) => ak,
        None => return false,
    };

    let nk = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*nk })) {
        Some(p) => p,
        None => return false,
    };

    let nk = match de_ct(nk.into_subgroup()) {
        Some(nk) => nk,
        None => return false,
    };

    let vk = ViewingKey { ak, nk };
    let nf = note.nf(&vk, position);
    let result = unsafe { &mut *result };
    result.copy_from_slice(&nf.0);

    true
}

/// Compute a Sapling commitment.
///
/// The `diversifier` parameter must be 11 bytes in length.
/// The `pk_d` and `r` parameters must be of length 32.
/// The result is also of length 32 and placed in `result`.
/// Returns false if `diversifier` or `pk_d` is not valid.
#[no_mangle]
pub extern "C" fn libmasp_sapling_compute_cmu(
    diversifier: *const [c_uchar; 11],
    pk_d: *const [c_uchar; 32],
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
    value: u64,
    rcm: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    let note = match priv_get_note(diversifier, pk_d, &unsafe { *asset_identifier }, value, rcm) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let result = unsafe { &mut *result };
    *result = note.cmu().to_bytes();

    true
}

/// Computes \[sk\] \[8\] P for some 32-byte point P, and 32-byte Fs.
///
/// If P or sk are invalid, returns false. Otherwise, the result is written to
/// the 32-byte `result` buffer.
#[no_mangle]
pub extern "C" fn libmasp_sapling_ka_agree(
    p: *const [c_uchar; 32],
    sk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    // Deserialize p
    let p = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*p })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize sk
    let sk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*sk })) {
        Some(p) => p,
        None => return false,
    };

    // Compute key agreement
    let ka = sapling_ka_agree(&sk, &p);

    // Produce result
    let result = unsafe { &mut *result };
    *result = ka.to_bytes();

    true
}

/// Compute g_d = GH(diversifier) and returns false if the diversifier is
/// invalid. Computes \[esk\] g_d and writes the result to the 32-byte `result`
/// buffer. Returns false if `esk` is not a valid scalar.
#[no_mangle]
pub extern "C" fn libmasp_sapling_ka_derivepublic(
    diversifier: *const [c_uchar; 11],
    esk: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
) -> bool {
    let diversifier = Diversifier(unsafe { *diversifier });

    // Compute g_d from the diversifier
    let g_d = match diversifier.g_d() {
        Some(g) => g,
        None => return false,
    };

    // Deserialize esk
    let esk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*esk })) {
        Some(p) => p,
        None => return false,
    };

    let p = g_d * esk;

    let result = unsafe { &mut *result };
    *result = p.to_bytes();

    true
}

/// Creates a Sapling verification context. Please free this when you're done.
#[no_mangle]
pub extern "C" fn libmasp_sapling_verification_ctx_init() -> *mut SaplingVerificationContext {
    let ctx = Box::new(SaplingVerificationContext::new());

    Box::into_raw(ctx)
}

/// Frees a Sapling verification context returned from
/// [`libmasp_sapling_verification_ctx_init`].
#[no_mangle]
pub extern "C" fn libmasp_sapling_verification_ctx_free(ctx: *mut SaplingVerificationContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C

/// Check the validity of a Sapling Spend description, accumulating the value
/// commitment into the context.
#[no_mangle]
pub extern "C" fn libmasp_sapling_check_spend(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    anchor: *const [c_uchar; 32],
    nullifier: *const [c_uchar; 32],
    rk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
    spend_auth_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    // Deserialize the value commitment
    let cv = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the anchor, which should be an element
    // of Fr.
    let anchor = match de_ct(bls12_381::Scalar::from_bytes(unsafe { &*anchor })) {
        Some(a) => a,
        None => return false,
    };

    // Deserialize rk
    let rk = match redjubjub::PublicKey::read(&(unsafe { &*rk })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Deserialize the signature
    let spend_auth_sig = match Signature::read(&(unsafe { &*spend_auth_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Deserialize the proof
    let zkproof = match Proof::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    unsafe { &mut *ctx }.check_spend(
        cv,
        anchor,
        unsafe { &*nullifier },
        rk,
        unsafe { &*sighash_value },
        spend_auth_sig,
        zkproof,
        unsafe { SAPLING_SPEND_VK.as_ref() }.unwrap(),
    )
}

/// Check the validity of a Sapling Output description, accumulating the value
/// commitment into the context.
#[no_mangle]
pub extern "C" fn libmasp_sapling_check_output(
    ctx: *mut SaplingVerificationContext,
    cv: *const [c_uchar; 32],
    cm: *const [c_uchar; 32],
    epk: *const [c_uchar; 32],
    zkproof: *const [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Deserialize the value commitment
    let cv = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*cv })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the commitment, which should be an element
    // of Fr.
    let cm = match de_ct(bls12_381::Scalar::from_bytes(unsafe { &*cm })) {
        Some(a) => a,
        None => return false,
    };

    // Deserialize the ephemeral key
    let epk = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*epk })) {
        Some(p) => p,
        None => return false,
    };

    // Deserialize the proof
    let zkproof = match Proof::read(&(unsafe { &*zkproof })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    unsafe { &mut *ctx }.check_output(
        cv,
        cm,
        epk,
        zkproof,
        unsafe { SAPLING_OUTPUT_VK.as_ref() }.unwrap(),
    )
}

/// Finally checks the validity of the entire Sapling transaction given
/// valueBalance and the binding signature.
#[no_mangle]
pub extern "C" fn libmasp_sapling_final_check(
    ctx: *mut SaplingVerificationContext,
    asset_identifiers: *const c_uchar,
    value_balances: *const i64,
    asset_count: size_t,
    binding_sig: *const [c_uchar; 64],
    sighash_value: *const [c_uchar; 32],
) -> bool {
    // Collect the asset identifiers and values
    let assets_and_values =
        match collect_assets_and_values(asset_identifiers, value_balances, asset_count) {
            Some(a) => a,
            None => return false,
        };

    // Deserialize the signature
    let binding_sig = match Signature::read(&(unsafe { &*binding_sig })[..]) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    unsafe { &*ctx }.final_check(
        &assets_and_values[..],
        unsafe { &*sighash_value },
        binding_sig,
    )
}

/// This function (using the proving context) constructs an Output proof given
/// the necessary witness information. It outputs `cv` and the `zkproof`.
#[no_mangle]
pub extern "C" fn libmasp_sapling_output_proof(
    ctx: *mut SaplingProvingContext,
    esk: *const [c_uchar; 32],
    payment_address: *const [c_uchar; 43],
    rcm: *const [c_uchar; 32],
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
    value: u64,
    cv: *mut [c_uchar; 32],
    zkproof: *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `esk`, which the caller should have constructed for the DH key exchange.
    let esk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*esk })) {
        Some(p) => p,
        None => return false,
    };

    // Grab the payment address from the caller
    let payment_address = match PaymentAddress::from_bytes(unsafe { &*payment_address }) {
        Some(pa) => pa,
        None => return false,
    };

    // The caller provides the commitment randomness for the output note
    let rcm = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })) {
        Some(p) => p,
        None => return false,
    };

    let asset_type = match AssetType::from_identifier(&unsafe { *asset_identifier }) {
        Some(a) => a,
        None => return false,
    };

    // Create proof
    let (proof, value_commitment) = unsafe { &mut *ctx }.output_proof(
        esk,
        payment_address,
        rcm,
        asset_type,
        value,
        unsafe { SAPLING_OUTPUT_PARAMS.as_ref() }.unwrap(),
    );

    // Write the proof out to the caller
    proof
        .write(&mut (unsafe { &mut *zkproof })[..])
        .expect("should be able to serialize a proof");

    // Write the value commitment to the caller
    *unsafe { &mut *cv } = value_commitment.to_bytes();

    true
}

/// Computes the signature for each Spend description, given the key `ask`, the
/// re-randomization `ar`, the 32-byte sighash `sighash`, and an output `result`
/// buffer of 64-bytes for the signature.
///
/// This function will fail if the provided `ask` or `ar` are invalid.
#[no_mangle]
pub extern "C" fn libmasp_sapling_spend_sig(
    ask: *const [c_uchar; 32],
    ar: *const [c_uchar; 32],
    sighash: *const [c_uchar; 32],
    result: *mut [c_uchar; 64],
) -> bool {
    // The caller provides the re-randomization of `ak`.
    let ar = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*ar })) {
        Some(p) => p,
        None => return false,
    };

    // The caller provides `ask`, the spend authorizing key.
    let ask = match redjubjub::PrivateKey::read(&(unsafe { &*ask })[..]) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Initialize secure RNG
    let mut rng = OsRng;

    // Do the signing
    let sig = spend_sig(ask, ar, unsafe { &*sighash }, &mut rng);

    // Write out the signature
    sig.write(&mut (unsafe { &mut *result })[..])
        .expect("result should be 64 bytes");

    true
}

/// Collect an array of asset identifiers and array of
/// asset values into a vector of asset types and values
fn collect_assets_and_values(
    asset_identifiers: *const c_uchar,
    value_balances: *const i64,
    asset_count: size_t,
) -> Option<Vec<(AssetType, i64)>> {
    use std::convert::TryInto;
    unsafe { std::slice::from_raw_parts(asset_identifiers, asset_count * ASSET_IDENTIFIER_LENGTH) }
        .chunks_exact(ASSET_IDENTIFIER_LENGTH)
        .zip(unsafe { std::slice::from_raw_parts(value_balances, asset_count) })
        .map(|(asset_identifier, value)| {
            AssetType::from_identifier(asset_identifier.try_into().expect("invalid asset id chunk"))
                .map(|id| (id, *value))
        })
        .collect()
}

/// This function (using the proving context) constructs a binding signature.
///
/// You must provide the intended valueBalance so that we can internally check
/// consistency.
#[no_mangle]
pub extern "C" fn libmasp_sapling_binding_sig(
    ctx: *const SaplingProvingContext,
    asset_identifiers: *const c_uchar,
    value_balances: *const i64,
    asset_count: size_t,
    sighash: *const [c_uchar; 32],
    result: *mut [c_uchar; 64],
) -> bool {
    // Collect the asset identifiers and values
    let assets_and_values =
        match collect_assets_and_values(asset_identifiers, value_balances, asset_count) {
            Some(a) => a,
            None => return false,
        };

    // Sign
    let sig = match unsafe { &*ctx }.binding_sig(&assets_and_values[..], unsafe { &*sighash }) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Write out signature
    sig.write(&mut (unsafe { &mut *result })[..])
        .expect("result should be 64 bytes");

    true
}

/// This function (using the proving context) constructs a Spend proof given the
/// necessary witness information. It outputs `cv` (the value commitment) and
/// `rk` (so that you don't have to compute it) along with the proof.
#[no_mangle]
pub extern "C" fn libmasp_sapling_spend_proof(
    ctx: *mut SaplingProvingContext,
    ak: *const [c_uchar; 32],
    nsk: *const [c_uchar; 32],
    diversifier: *const [c_uchar; 11],
    rcm: *const [c_uchar; 32],
    ar: *const [c_uchar; 32],
    asset_identifier: *const [c_uchar; ASSET_IDENTIFIER_LENGTH],
    value: u64,
    anchor: *const [c_uchar; 32],
    merkle_path: *const [c_uchar; 1 + 33 * SAPLING_TREE_DEPTH + 8],
    cv: *mut [c_uchar; 32],
    rk_out: *mut [c_uchar; 32],
    zkproof: *mut [c_uchar; GROTH_PROOF_SIZE],
) -> bool {
    // Grab `ak` from the caller, which should be a point.
    let ak = match de_ct(jubjub::ExtendedPoint::from_bytes(unsafe { &*ak })) {
        Some(p) => p,
        None => return false,
    };

    // `ak` should be prime order.
    let ak = match de_ct(ak.into_subgroup()) {
        Some(p) => p,
        None => return false,
    };

    // Grab `nsk` from the caller
    let nsk = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*nsk })) {
        Some(p) => p,
        None => return false,
    };

    // Construct the proof generation key
    let proof_generation_key = ProofGenerationKey { ak, nsk };

    // Grab the diversifier from the caller
    let diversifier = Diversifier(unsafe { *diversifier });

    // The caller chooses the note randomness
    // If this is after ZIP 212, the caller has calculated rcm, and we don't need to call
    // Note::derive_esk, so we just pretend the note was using this rcm all along.
    let rseed = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*rcm })) {
        Some(p) => Rseed::BeforeZip212(p),
        None => return false,
    };

    // The caller also chooses the re-randomization of ak
    let ar = match de_ct(jubjub::Scalar::from_bytes(unsafe { &*ar })) {
        Some(p) => p,
        None => return false,
    };

    // We need to compute the anchor of the Spend.
    let anchor = match de_ct(bls12_381::Scalar::from_bytes(unsafe { &*anchor })) {
        Some(p) => p,
        None => return false,
    };

    // Parse the Merkle path from the caller
    let merkle_path = match MerklePath::from_slice(unsafe { &(&*merkle_path)[..] }) {
        Ok(w) => w,
        Err(_) => return false,
    };

    let asset_type = match AssetType::from_identifier(&unsafe { *asset_identifier }) {
        Some(a) => a,
        None => return false,
    };

    // Create proof
    let (proof, value_commitment, rk) = unsafe { &mut *ctx }
        .spend_proof(
            proof_generation_key,
            diversifier,
            rseed,
            ar,
            asset_type,
            value,
            anchor,
            merkle_path,
            unsafe { SAPLING_SPEND_PARAMS.as_ref() }.unwrap(),
            unsafe { SAPLING_SPEND_VK.as_ref() }.unwrap(),
        )
        .expect("proving should not fail");

    // Write value commitment to caller
    *unsafe { &mut *cv } = value_commitment.to_bytes();

    // Write proof out to caller
    proof
        .write(&mut (unsafe { &mut *zkproof })[..])
        .expect("should be able to serialize a proof");

    // Write out `rk` to the caller
    rk.write(&mut unsafe { &mut *rk_out }[..])
        .expect("should be able to write to rk_out");

    true
}

/// Creates a Sapling proving context. Please free this when you're done.
#[no_mangle]
pub extern "C" fn libmasp_sapling_proving_ctx_init() -> *mut SaplingProvingContext {
    let ctx = Box::new(SaplingProvingContext::new());

    Box::into_raw(ctx)
}

/// Frees a Sapling proving context returned from
/// [`libmasp_sapling_proving_ctx_init`].
#[no_mangle]
pub extern "C" fn libmasp_sapling_proving_ctx_free(ctx: *mut SaplingProvingContext) {
    drop(unsafe { Box::from_raw(ctx) });
}

/// Derive the master ExtendedSpendingKey from a seed.
#[no_mangle]
pub extern "C" fn libmasp_zip32_xsk_master(
    seed: *const c_uchar,
    seedlen: size_t,
    xsk_master: *mut [c_uchar; 169],
) {
    let seed = unsafe { std::slice::from_raw_parts(seed, seedlen) };

    let xsk = zip32::ExtendedSpendingKey::master(seed);

    xsk.write(&mut (unsafe { &mut *xsk_master })[..])
        .expect("should be able to serialize an ExtendedSpendingKey");
}

/// Derive a child ExtendedSpendingKey from a parent.
#[no_mangle]
pub extern "C" fn libmasp_zip32_xsk_derive(
    xsk_parent: *const [c_uchar; 169],
    i: u32,
    xsk_i: *mut [c_uchar; 169],
) {
    let xsk_parent = zip32::ExtendedSpendingKey::read(&unsafe { *xsk_parent }[..])
        .expect("valid ExtendedSpendingKey");
    let i = zip32::ChildIndex::from_index(i);

    let xsk = xsk_parent.derive_child(i);

    xsk.write(&mut (unsafe { &mut *xsk_i })[..])
        .expect("should be able to serialize an ExtendedSpendingKey");
}

/// Derive a child ExtendedFullViewingKey from a parent.
#[no_mangle]
pub extern "C" fn libmasp_zip32_xfvk_derive(
    xfvk_parent: *const [c_uchar; 169],
    i: u32,
    xfvk_i: *mut [c_uchar; 169],
) -> bool {
    let xfvk_parent = zip32::ExtendedFullViewingKey::read(&unsafe { *xfvk_parent }[..])
        .expect("valid ExtendedFullViewingKey");
    let i = zip32::ChildIndex::from_index(i);

    let xfvk = match xfvk_parent.derive_child(i) {
        Ok(xfvk) => xfvk,
        Err(_) => return false,
    };

    xfvk.write(&mut (unsafe { &mut *xfvk_i })[..])
        .expect("should be able to serialize an ExtendedFullViewingKey");

    true
}

/// Derive a PaymentAddress from an ExtendedFullViewingKey.
#[no_mangle]
pub extern "C" fn libmasp_zip32_xfvk_address(
    xfvk: *const [c_uchar; 169],
    j: *const [c_uchar; 11],
    j_ret: *mut [c_uchar; 11],
    addr_ret: *mut [c_uchar; 43],
) -> bool {
    let xfvk = zip32::ExtendedFullViewingKey::read(&unsafe { *xfvk }[..])
        .expect("valid ExtendedFullViewingKey");
    let j = zip32::DiversifierIndex(unsafe { *j });

    let addr = match xfvk.find_address(j) {
        Some(addr) => addr,
        None => return false,
    };

    let j_ret = unsafe { &mut *j_ret };
    let addr_ret = unsafe { &mut *addr_ret };

    j_ret.copy_from_slice(&(addr.0).0);
    addr_ret.copy_from_slice(&addr.1.to_bytes());

    true
}

/// Derives an asset identifier without a starting nonce
/// Not constant-time as it uses rejection sampling
#[no_mangle]
pub extern "C" fn libmasp_new_asset_identifier(
    name: *const c_uchar,
    name_length: size_t,
    identifier_result: *mut [c_uchar; ASSET_IDENTIFIER_LENGTH],
    nonce_result: *mut u8,
) -> bool {
    let asset_type = match AssetType::new(unsafe { std::slice::from_raw_parts(name, name_length) })
    {
        Ok(asset_type) => asset_type,
        Err(_) => return false,
    };

    let identifier_result = unsafe { &mut *identifier_result };
    identifier_result.copy_from_slice(asset_type.get_identifier());

    if let Some(nonce) = asset_type.get_nonce() {
        unsafe { *nonce_result = nonce };
        return true;
    }

    false
}

/// Derives an asset identifier from an existing nonce; can fail if nonce is invalid
#[no_mangle]
pub extern "C" fn libmasp_asset_from_name_and_nonce(
    name: *const c_uchar,
    name_length: size_t,
    nonce: u8,
    result: *mut [c_uchar; ASSET_IDENTIFIER_LENGTH],
) -> bool {
    if let Some(asset_type) = AssetType::new_with_nonce(
        unsafe { std::slice::from_raw_parts(name, name_length) },
        nonce,
    ) {
        let identifier_result = unsafe { &mut *result };
        identifier_result.copy_from_slice(asset_type.get_identifier());
        return true;
    }
    false
}

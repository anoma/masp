//! Implementation of in-band secret distribution for MASP transactions.
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};
use byteorder::{LittleEndian, WriteBytesExt};
use ff::PrimeField;
use group::{cofactor::CofactorGroup, GroupEncoding, WnafBase, WnafScalar};
use jubjub::{AffinePoint, ExtendedPoint};
use memuse::DynamicUsage;
use std::convert::TryInto;

use crate::asset_type::AssetType;
use masp_note_encryption::{
    try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ock,
    try_output_recovery_with_ovk, BatchDomain, Domain, EphemeralKeyBytes, NoteEncryption,
    NotePlaintextBytes, OutPlaintextBytes, OutgoingCipherKey, ShieldedOutput, COMPACT_NOTE_SIZE,
    ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE, OUT_PLAINTEXT_SIZE,
};

use crate::{
    consensus::{self, BlockHeight, NetworkUpgrade::MASP},
    memo::MemoBytes,
    sapling::{keys::OutgoingViewingKey, Diversifier, Note, PaymentAddress, Rseed, SaplingIvk},
    transaction::{components::sapling::OutputDescription, GrothProofBytes},
};

pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"MASP__SaplingKDF";
pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"MASP__Derive_ock";

const PREPARED_WINDOW_SIZE: usize = 4;
type PreparedBase = WnafBase<jubjub::ExtendedPoint, PREPARED_WINDOW_SIZE>;
type PreparedBaseSubgroup = WnafBase<jubjub::SubgroupPoint, PREPARED_WINDOW_SIZE>;
type PreparedScalar = WnafScalar<jubjub::Scalar, PREPARED_WINDOW_SIZE>;

/// A Sapling incoming viewing key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedIncomingViewingKey(PreparedScalar);

impl DynamicUsage for PreparedIncomingViewingKey {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl PreparedIncomingViewingKey {
    /// Performs the necessary precomputations to use a `SaplingIvk` for note decryption.
    pub fn new(ivk: &SaplingIvk) -> Self {
        Self(PreparedScalar::new(&ivk.0))
    }
}

/// A Sapling ephemeral public key that has been precomputed for trial decryption.
#[derive(Clone, Debug)]
pub struct PreparedEphemeralPublicKey(PreparedBase);

/// Sapling key agreement for note encryption.
///
/// Implements section 5.4.4.3 of the Zcash Protocol Specification.
pub fn sapling_ka_agree(esk: &jubjub::Fr, pk_d: &jubjub::ExtendedPoint) -> jubjub::SubgroupPoint {
    sapling_ka_agree_prepared(&PreparedScalar::new(esk), &PreparedBase::new(*pk_d))
}

fn sapling_ka_agree_prepared(esk: &PreparedScalar, pk_d: &PreparedBase) -> jubjub::SubgroupPoint {
    // [8 esk] pk_d
    // <ExtendedPoint as CofactorGroup>::clear_cofactor is implemented using
    // ExtendedPoint::mul_by_cofactor in the jubjub crate.

    (pk_d * esk).clear_cofactor()
}

/// Sapling KDF for note encryption.
///
/// Implements section 5.4.4.4 of the Zcash Protocol Specification.
fn kdf_sapling(dhsecret: jubjub::SubgroupPoint, ephemeral_key: &EphemeralKeyBytes) -> Blake2bHash {
    Blake2bParams::new()
        .hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION)
        .to_state()
        .update(&dhsecret.to_bytes())
        .update(ephemeral_key.as_ref())
        .finalize()
}

/// Sapling PRF^ock.
///
/// Implemented per section 5.4.2 of the Zcash Protocol Specification.
pub fn prf_ock(
    ovk: &OutgoingViewingKey,
    cv: &jubjub::ExtendedPoint,
    cmu_bytes: &[u8; 32],
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Blake2bParams::new()
            .hash_length(32)
            .personal(PRF_OCK_PERSONALIZATION)
            .to_state()
            .update(&ovk.0)
            .update(&cv.to_bytes())
            .update(cmu_bytes)
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn epk_bytes(epk: &jubjub::ExtendedPoint) -> EphemeralKeyBytes {
    EphemeralKeyBytes(epk.to_bytes())
}

fn sapling_parse_note_plaintext_without_memo<F, P: consensus::Parameters>(
    domain: &SaplingDomain<P>,
    plaintext: &[u8],
    get_validated_pk_d: F,
) -> Option<(Note, PaymentAddress)>
where
    F: FnOnce(&Diversifier) -> Option<jubjub::SubgroupPoint>,
{
    assert!(plaintext.len() >= COMPACT_NOTE_SIZE);

    // Check note plaintext version
    if !plaintext_version_is_valid(&domain.params, domain.height, plaintext[0]) {
        return None;
    }

    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier(plaintext[1..12].try_into().unwrap());
    let value = u64::from_le_bytes(plaintext[12..20].try_into().unwrap());
    let asset_type = AssetType::from_identifier(plaintext[20..52].try_into().unwrap())?;
    let r: [u8; 32] = plaintext[52..COMPACT_NOTE_SIZE].try_into().unwrap();

    let rseed = if plaintext[0] == 0x01 {
        let rcm = Option::from(jubjub::Fr::from_repr(r))?;
        Rseed::BeforeZip212(rcm)
    } else {
        Rseed::AfterZip212(r)
    };

    let pk_d = get_validated_pk_d(&diversifier)?;

    let to = PaymentAddress::from_parts(diversifier, pk_d)?;
    let note = to.create_note(asset_type, value.into(), rseed);
    Some((note, to))
}

pub struct SaplingDomain<P: consensus::Parameters> {
    params: P,
    height: BlockHeight,
}

impl<P: consensus::Parameters + DynamicUsage> DynamicUsage for SaplingDomain<P> {
    fn dynamic_usage(&self) -> usize {
        self.params.dynamic_usage() + self.height.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let (params_lower, params_upper) = self.params.dynamic_usage_bounds();
        let (height_lower, height_upper) = self.height.dynamic_usage_bounds();
        (
            params_lower + height_lower,
            params_upper.zip(height_upper).map(|(a, b)| a + b),
        )
    }
}

impl<P: consensus::Parameters> SaplingDomain<P> {
    pub fn for_height(params: P, height: BlockHeight) -> Self {
        Self { params, height }
    }
}

impl<P: consensus::Parameters> Domain for SaplingDomain<P> {
    type EphemeralSecretKey = jubjub::Scalar;
    // It is acceptable for this to be a point rather than a byte array, because we
    // enforce by consensus that points must not be small-order, and all points with
    // non-canonical serialization are small-order.
    type EphemeralPublicKey = jubjub::ExtendedPoint;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = jubjub::SubgroupPoint;
    type SymmetricKey = Blake2bHash;
    type Note = Note;
    type Recipient = PaymentAddress;
    type DiversifiedTransmissionKey = jubjub::SubgroupPoint;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = jubjub::ExtendedPoint;
    type ExtractedCommitment = bls12_381::Scalar;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = MemoBytes;

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        note.derive_esk()
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey(PreparedBase::new(epk))
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        // epk is an element of jubjub's prime-order subgroup,
        // but Self::EphemeralPublicKey is a full group element
        // for efficiency of encryption. The conversion here is fine
        // because the output of this function is only used for
        // encoding and the byte encoding is unaffected by the conversion.
        (note.recipient().g_d().unwrap() * esk).into()
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        sapling_ka_agree(esk, pk_d.into())
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        sapling_ka_agree_prepared(&ivk.0, &epk.0)
    }

    /// Sapling KDF for note encryption.
    ///
    /// Implements section 5.4.4.4 of the Zcash Protocol Specification.
    fn kdf(dhsecret: jubjub::SubgroupPoint, epk: &EphemeralKeyBytes) -> Blake2bHash {
        kdf_sapling(dhsecret, epk)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        // Note plaintext encoding is defined in section 5.5 of the Zcash Protocol
        // Specification.
        let mut input = [0; NOTE_PLAINTEXT_SIZE];
        input[0] = match note.rseed {
            Rseed::BeforeZip212(_) => 1,
            Rseed::AfterZip212(_) => 2,
        };
        input[1..12].copy_from_slice(&note.recipient().diversifier().0);
        (&mut input[12..20])
            .write_u64::<LittleEndian>(note.value().inner())
            .unwrap();

        input[20..52].copy_from_slice(note.asset_type.get_identifier());
        match note.rseed {
            Rseed::BeforeZip212(rcm) => {
                input[52..COMPACT_NOTE_SIZE].copy_from_slice(rcm.to_repr().as_ref());
            }
            Rseed::AfterZip212(rseed) => {
                input[52..COMPACT_NOTE_SIZE].copy_from_slice(&rseed);
            }
        }

        input[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE].copy_from_slice(&memo.as_array()[..]);

        NotePlaintextBytes(input)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmu_bytes: &Self::ExtractedCommitmentBytes,
        epk: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock(ovk, cv, cmu_bytes, epk)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut input = [0u8; OUT_PLAINTEXT_SIZE];
        input[0..32].copy_from_slice(&note.recipient().pk_d.to_bytes());
        input[32..OUT_PLAINTEXT_SIZE].copy_from_slice(esk.to_repr().as_ref());

        OutPlaintextBytes(input)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk_bytes(epk)
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        // ZIP 216: We unconditionally reject non-canonical encodings, because these have
        // always been rejected by consensus (due to small-order checks).
        // https://zips.z.cash/zip-0216#specification
        jubjub::ExtendedPoint::from_bytes(&ephemeral_key.0).into()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(self, plaintext, |diversifier| {
            Some(&PreparedBaseSubgroup::new(diversifier.g_d()?) * &ivk.0)
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &NotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        sapling_parse_note_plaintext_without_memo(self, &plaintext.0, |diversifier| {
            diversifier.g_d().map(|_| *pk_d)
        })
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.cmu()
    }

    fn extract_pk_d(op: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        jubjub::SubgroupPoint::from_bytes(
            op.0[0..32].try_into().expect("slice is the correct length"),
        )
        .into()
    }

    fn extract_esk(op: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        jubjub::Fr::from_repr(
            op.0[32..OUT_PLAINTEXT_SIZE]
                .try_into()
                .expect("slice is the correct length"),
        )
        .into()
    }

    fn extract_memo(&self, plaintext: &NotePlaintextBytes) -> Self::Memo {
        MemoBytes::from_bytes(&plaintext.0[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]).unwrap()
    }
}

impl<P: consensus::Parameters> BatchDomain for SaplingDomain<P> {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        let (shared_secrets, ephemeral_keys): (Vec<_>, Vec<_>) = items.unzip();

        let secrets: Vec<_> = shared_secrets
            .iter()
            .filter_map(|s| s.map(ExtendedPoint::from))
            .collect();
        let mut secrets_affine = vec![AffinePoint::identity(); shared_secrets.len()];
        group::Curve::batch_normalize(&secrets, &mut secrets_affine);

        let mut secrets_affine = secrets_affine.into_iter();
        shared_secrets
            .into_iter()
            .map(|s| s.and_then(|_| secrets_affine.next()))
            .zip(ephemeral_keys.into_iter())
            .map(|(secret, ephemeral_key)| {
                secret.map(|dhsecret| {
                    Blake2bParams::new()
                        .hash_length(32)
                        .personal(KDF_SAPLING_PERSONALIZATION)
                        .to_state()
                        .update(&dhsecret.to_bytes())
                        .update(ephemeral_key.as_ref())
                        .finalize()
                })
            })
            .collect()
    }

    fn batch_epk(
        ephemeral_keys: impl Iterator<Item = EphemeralKeyBytes>,
    ) -> Vec<(Option<Self::PreparedEphemeralPublicKey>, EphemeralKeyBytes)> {
        let ephemeral_keys: Vec<_> = ephemeral_keys.collect();
        let epks = jubjub::AffinePoint::batch_from_bytes(ephemeral_keys.iter().map(|b| b.0));
        epks.into_iter()
            .zip(ephemeral_keys.into_iter())
            .map(|(epk, ephemeral_key)| {
                (
                    epk.map(jubjub::ExtendedPoint::from)
                        .map(Self::prepare_epk)
                        .into(),
                    ephemeral_key,
                )
            })
            .collect()
    }
}

/// Creates a new encryption context for the given note.
///
/// Setting `ovk` to `None` represents the `ovk = ⊥` case, where the note cannot be
/// recovered by the sender.
///
/// NB: the example code here only covers the post-MASP case.
///
/// # Examples
///
/// ```
/// use ff::Field;
/// use rand_core::OsRng;
/// use masp_primitives::{
///     asset_type::AssetType,
///     keys::{OutgoingViewingKey, prf_expand},
///     consensus::{TEST_NETWORK, TestNetwork, NetworkUpgrade, Parameters},
///     memo::MemoBytes,
///     sapling::{
///         note_encryption::sapling_note_encryption,
///         util::generate_random_rseed,
///         Diversifier, PaymentAddress, Rseed, ValueCommitment
///     },
/// };
///
/// let mut rng = OsRng;
///
/// let diversifier = Diversifier([10u8; 11]);
/// let pk_d = diversifier.g_d().unwrap();
/// let to = PaymentAddress::from_parts(diversifier, pk_d).unwrap();
/// let ovk = Some(OutgoingViewingKey([0; 32]));
///
/// let value = 1000;
/// let rcv = jubjub::Fr::random(&mut rng);
/// let asset_type = AssetType::new(b"note_encryption").unwrap();
/// let cv = asset_type.value_commitment(1, jubjub::Fr::random(&mut rng));
///
/// let height = TEST_NETWORK.activation_height(NetworkUpgrade::MASP).unwrap();
/// let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);
/// let note = to.create_note(asset_type, value, rseed);
/// let cmu = note.cmu();
///
/// let mut enc = sapling_note_encryption::<TestNetwork>(ovk, note, MemoBytes::empty());
/// let encCiphertext = enc.encrypt_note_plaintext();
/// let outCiphertext = enc.encrypt_outgoing_plaintext(&cv.commitment().into(), &cmu, &mut rng);
/// ```
pub fn sapling_note_encryption<P: consensus::Parameters>(
    ovk: Option<OutgoingViewingKey>,
    note: Note,
    memo: MemoBytes,
) -> NoteEncryption<SaplingDomain<P>> {
    NoteEncryption::new(ovk, note, memo)
}

#[allow(clippy::if_same_then_else)]
#[allow(clippy::needless_bool)]
pub fn plaintext_version_is_valid<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    leadbyte: u8,
) -> bool {
    if params.is_nu_active(MASP, height) {
        // return false if non-0x02 received when MASP is active
        leadbyte == 0x02
    } else {
        // Pre-ZIP 212 testnet
        // Only used for the TEST_NETWORK prior to MASP activation,
        // because note encryption test vectors use pre-ZIP-212 rseed derivation
        leadbyte == 0x01
    }
}

pub fn try_sapling_note_decryption<
    P: consensus::Parameters,
    Output: ShieldedOutput<SaplingDomain<P>, ENC_CIPHERTEXT_SIZE>,
>(
    params: &P,
    height: BlockHeight,
    ivk: &PreparedIncomingViewingKey,
    output: &Output,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };
    try_note_decryption(&domain, ivk, output)
}

pub fn try_sapling_compact_note_decryption<
    P: consensus::Parameters,
    Output: ShieldedOutput<SaplingDomain<P>, COMPACT_NOTE_SIZE>,
>(
    params: &P,
    height: BlockHeight,
    ivk: &PreparedIncomingViewingKey,
    output: &Output,
) -> Option<(Note, PaymentAddress)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_compact_note_decryption(&domain, ivk, output)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ock`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements part of section 4.19.3 of the Zcash Protocol Specification.
/// For decryption using a Full Viewing Key see [`try_sapling_output_recovery`].
pub fn try_sapling_output_recovery_with_ock<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ock: &OutgoingCipherKey,
    output: &OutputDescription<GrothProofBytes>,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_output_recovery_with_ock(&domain, ock, output, &output.out_ciphertext)
}

/// Recovery of the full note plaintext by the sender.
///
/// Attempts to decrypt and validate the given `enc_ciphertext` using the given `ovk`.
/// If successful, the corresponding Sapling note and memo are returned, along with the
/// `PaymentAddress` to which the note was sent.
///
/// Implements section 4.19.3 of the Zcash Protocol Specification.
#[allow(clippy::too_many_arguments)]
pub fn try_sapling_output_recovery<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    ovk: &OutgoingViewingKey,
    output: &OutputDescription<GrothProofBytes>,
) -> Option<(Note, PaymentAddress, MemoBytes)> {
    let domain = SaplingDomain {
        params: params.clone(),
        height,
    };

    try_output_recovery_with_ovk(&domain, ovk, output, &output.cv, &output.out_ciphertext)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        ChaCha20Poly1305,
    };
    use ff::{Field, PrimeField};
    use group::Group;
    use group::{cofactor::CofactorGroup, GroupEncoding};
    use rand_core::OsRng;
    use rand_core::{CryptoRng, RngCore};
    use std::convert::TryInto;

    use masp_note_encryption::{
        batch, EphemeralKeyBytes, NoteEncryption, OutgoingCipherKey, ENC_CIPHERTEXT_SIZE,
        NOTE_PLAINTEXT_SIZE, OUT_CIPHERTEXT_SIZE, OUT_PLAINTEXT_SIZE,
    };

    use super::{
        epk_bytes, kdf_sapling, prf_ock, sapling_ka_agree, sapling_note_encryption,
        try_sapling_compact_note_decryption, try_sapling_note_decryption,
        try_sapling_output_recovery, try_sapling_output_recovery_with_ock, SaplingDomain,
    };

    use crate::{
        consensus::{
            BlockHeight, NetworkUpgrade::MASP, Parameters, TestNetwork, TEST_NETWORK,
            ZIP212_GRACE_PERIOD,
        },
        keys::OutgoingViewingKey,
        memo::MemoBytes,
        sapling::{
            note_encryption::{AssetType, PreparedIncomingViewingKey},
            util::generate_random_rseed,
        },
        sapling::{Diversifier, PaymentAddress, Rseed, SaplingIvk},
        transaction::components::{
            sapling::{self, CompactOutputDescription, OutputDescription},
            GROTH_PROOF_SIZE,
        },
    };

    fn random_enc_ciphertext<R: RngCore + CryptoRng>(
        height: BlockHeight,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        PreparedIncomingViewingKey,
        OutputDescription<sapling::GrothProofBytes>,
    ) {
        let ivk = SaplingIvk(jubjub::Fr::random(&mut rng));
        let prepared_ivk = PreparedIncomingViewingKey::new(&ivk);

        let (ovk, ock, output) = random_enc_ciphertext_with(height, &ivk, rng);

        assert!(
            try_sapling_note_decryption(&TEST_NETWORK, height, &prepared_ivk, &output).is_some()
        );
        assert!(try_sapling_compact_note_decryption(
            &TEST_NETWORK,
            height,
            &prepared_ivk,
            &CompactOutputDescription::from(output.clone()),
        )
        .is_some());

        let ovk_output_recovery = try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output);

        let ock_output_recovery =
            try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output);
        assert!(ovk_output_recovery.is_some());
        assert!(ock_output_recovery.is_some());
        assert_eq!(ovk_output_recovery, ock_output_recovery);

        (ovk, ock, prepared_ivk, output)
    }

    fn random_enc_ciphertext_with<R: RngCore + CryptoRng>(
        height: BlockHeight,
        ivk: &SaplingIvk,
        mut rng: &mut R,
    ) -> (
        OutgoingViewingKey,
        OutgoingCipherKey,
        OutputDescription<sapling::GrothProofBytes>,
    ) {
        let diversifier = Diversifier([10u8; 11]);
        let pk_d = diversifier.g_d().unwrap() * ivk.0;
        let pa = PaymentAddress::from_parts_unchecked(diversifier, pk_d);

        // Construct the value commitment for the proof instance
        let value = 100u64;

        let asset_type = AssetType::new("BTC".as_bytes()).unwrap();
        let value_commitment = asset_type.value_commitment(value, jubjub::Fr::random(&mut rng));

        let cv = value_commitment.commitment().into();

        let rseed = generate_random_rseed(&TEST_NETWORK, height, &mut rng);

        let note = pa.create_note(asset_type, value.into(), rseed);
        let cmu = note.cmu();

        let ovk = OutgoingViewingKey([0; 32]);
        let ne = sapling_note_encryption::<TestNetwork>(Some(ovk), note, MemoBytes::empty());
        let epk = *ne.epk();
        let ock = prf_ock(&ovk, &cv, &cmu.to_repr(), &epk_bytes(&epk));

        let output = OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes().into(),
            enc_ciphertext: ne.encrypt_note_plaintext(),
            out_ciphertext: ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng),
            zkproof: [0u8; GROTH_PROOF_SIZE],
        };

        (ovk, ock, output)
    }

    fn reencrypt_enc_ciphertext(
        ovk: &OutgoingViewingKey,
        cv: &jubjub::ExtendedPoint,
        cmu: &bls12_381::Scalar,
        ephemeral_key: &EphemeralKeyBytes,
        enc_ciphertext: &mut [u8; ENC_CIPHERTEXT_SIZE],
        out_ciphertext: &[u8; OUT_CIPHERTEXT_SIZE],
        modify_plaintext: impl Fn(&mut [u8; NOTE_PLAINTEXT_SIZE]),
    ) {
        let ock = prf_ock(ovk, cv, &cmu.to_repr(), ephemeral_key);

        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op.copy_from_slice(&out_ciphertext[..OUT_PLAINTEXT_SIZE]);

        ChaCha20Poly1305::new(ock.as_ref().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut op,
                out_ciphertext[OUT_PLAINTEXT_SIZE..].into(),
            )
            .unwrap();

        let pk_d = jubjub::SubgroupPoint::from_bytes(&op[0..32].try_into().unwrap()).unwrap();

        let esk = jubjub::Fr::from_repr(op[32..OUT_PLAINTEXT_SIZE].try_into().unwrap()).unwrap();

        let shared_secret = sapling_ka_agree(&esk, &pk_d.into());
        let key = kdf_sapling(shared_secret, ephemeral_key);

        let mut plaintext = [0; NOTE_PLAINTEXT_SIZE];
        plaintext.copy_from_slice(&enc_ciphertext[..NOTE_PLAINTEXT_SIZE]);

        ChaCha20Poly1305::new(key.as_bytes().into())
            .decrypt_in_place_detached(
                [0u8; 12][..].into(),
                &[],
                &mut plaintext,
                enc_ciphertext[NOTE_PLAINTEXT_SIZE..].into(),
            )
            .unwrap();

        modify_plaintext(&mut plaintext);

        let tag = ChaCha20Poly1305::new(key.as_ref().into())
            .encrypt_in_place_detached([0u8; 12][..].into(), &[], &mut plaintext)
            .unwrap();

        enc_ciphertext[..NOTE_PLAINTEXT_SIZE].copy_from_slice(&plaintext);
        enc_ciphertext[NOTE_PLAINTEXT_SIZE..].copy_from_slice(&tag);
    }

    fn find_invalid_diversifier() -> Diversifier {
        // Find an invalid diversifier
        let mut d = Diversifier([0; 11]);
        loop {
            for k in 0..11 {
                d.0[k] = d.0[k].wrapping_add(1);
                if d.0[k] != 0 {
                    break;
                }
            }
            if d.g_d().is_none() {
                break;
            }
        }
        d
    }

    fn find_valid_diversifier() -> Diversifier {
        // Find a different valid diversifier
        let mut d = Diversifier([0; 11]);
        loop {
            for k in 0..11 {
                d.0[k] = d.0[k].wrapping_add(1);
                if d.0[k] != 0 {
                    break;
                }
            }
            if d.g_d().is_some() {
                break;
            }
        }
        d
    }

    #[test]
    fn decryption_with_invalid_ivk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(&mut rng))),
                    &output
                ),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output,),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            output.cmu = bls12_381::Scalar::random(&mut rng);

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_tag() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            output.enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_version_byte() {
        let mut rng = OsRng;
        let masp_activation_height = TEST_NETWORK.activation_height(MASP).unwrap();
        let heights = [
            masp_activation_height,
            masp_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x01, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
                None
            );
        }
    }

    #[test]
    fn decryption_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
                None
            );
        }
    }

    #[test]
    fn decryption_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );

            assert_eq!(
                try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_ivk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(&mut rng))),
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);
            output.cmu = bls12_381::Scalar::random(&mut rng);

            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_version_byte() {
        let mut rng = OsRng;
        let masp_activation_height = TEST_NETWORK.activation_height(MASP).unwrap();
        let heights = [
            masp_activation_height,
            masp_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x01, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn compact_decryption_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, _, ivk, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_compact_note_decryption(
                    &TEST_NETWORK,
                    height,
                    &ivk,
                    &CompactOutputDescription::from(output)
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_ovk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (mut ovk, _, _, output) = random_enc_ciphertext(height, &mut rng);

            ovk.0[0] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_ock() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (_, _, _, output) = random_enc_ciphertext(height, &mut rng);

            assert_eq!(
                try_sapling_output_recovery_with_ock(
                    &TEST_NETWORK,
                    height,
                    &OutgoingCipherKey([0u8; 32]),
                    &output,
                ),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_cv() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, _, _, mut output) = random_enc_ciphertext(height, &mut rng);
            output.cv = jubjub::ExtendedPoint::random(&mut rng);

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_cmu() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);
            output.cmu = bls12_381::Scalar::random(&mut rng);

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_epk() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);
            output.ephemeral_key = jubjub::ExtendedPoint::random(&mut rng).to_bytes().into();

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );

            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_enc_tag() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            output.enc_ciphertext[ENC_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_out_tag() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            output.out_ciphertext[OUT_CIPHERTEXT_SIZE - 1] ^= 0xff;
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_version_byte() {
        let mut rng = OsRng;
        let masp_activation_height = TEST_NETWORK.activation_height(MASP).unwrap();
        let heights = [
            masp_activation_height,
            masp_activation_height + ZIP212_GRACE_PERIOD,
        ];
        let leadbytes = [0x01, 0x01];

        for (&height, &leadbyte) in heights.iter().zip(leadbytes.iter()) {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[0] = leadbyte,
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_invalid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_incorrect_diversifier() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let (ovk, ock, _, mut output) = random_enc_ciphertext(height, &mut rng);

            reencrypt_enc_ciphertext(
                &ovk,
                &output.cv,
                &output.cmu,
                &output.ephemeral_key,
                &mut output.enc_ciphertext,
                &output.out_ciphertext,
                |pt| pt[1..12].copy_from_slice(&find_valid_diversifier().0),
            );
            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn recovery_with_invalid_pk_d() {
        let mut rng = OsRng;
        let heights = [TEST_NETWORK.activation_height(MASP).unwrap()];

        for &height in heights.iter() {
            let ivk = SaplingIvk(jubjub::Fr::zero());
            let (ovk, ock, output) = random_enc_ciphertext_with(height, &ivk, &mut rng);

            assert_eq!(
                try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output,),
                None
            );
            assert_eq!(
                try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output,),
                None
            );
        }
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::make_test_vectors();

        macro_rules! read_bls12_381_scalar {
            ($field:expr) => {{
                bls12_381::Scalar::from_repr($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_jubjub_scalar {
            ($field:expr) => {{
                jubjub::Fr::from_repr($field[..].try_into().unwrap()).unwrap()
            }};
        }

        macro_rules! read_point {
            ($field:expr) => {
                jubjub::ExtendedPoint::from_bytes(&$field).unwrap()
            };
        }
        // We must use height 0 here because the note encryption test vectors
        // use  pre-ZIP-212 rseed, while all MASP tx always use ZIP-212
        let height = crate::consensus::H0;

        let asset_type = AssetType::from_identifier(b"testtesttesttesttesttesttesttest").unwrap();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            let ivk = PreparedIncomingViewingKey::new(&SaplingIvk(read_jubjub_scalar!(tv.ivk)));
            let pk_d = read_point!(tv.default_pk_d).into_subgroup().unwrap();
            let rcm = read_jubjub_scalar!(tv.rcm);
            let cv = read_point!(tv.cv);
            let cmu = read_bls12_381_scalar!(tv.cmu);
            let esk = read_jubjub_scalar!(tv.esk);
            let ephemeral_key = EphemeralKeyBytes(tv.epk);

            //
            // Test the individual components
            //

            let shared_secret = sapling_ka_agree(&esk, &pk_d.into());
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = kdf_sapling(shared_secret, &ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ovk = OutgoingViewingKey(tv.ovk);
            let ock = prf_ock(&ovk, &cv, &cmu.to_repr(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let to = PaymentAddress::from_parts(Diversifier(tv.default_d), pk_d).unwrap();
            let note = to.create_note(asset_type, tv.v, Rseed::BeforeZip212(rcm));
            assert_eq!(note.cmu(), cmu);

            let output = OutputDescription {
                cv,
                cmu,
                ephemeral_key,
                enc_ciphertext: tv.c_enc,
                out_ciphertext: tv.c_out,
                zkproof: [0u8; GROTH_PROOF_SIZE],
            };

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            match try_sapling_note_decryption(&TEST_NETWORK, height, &ivk, &output) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_sapling_compact_note_decryption(
                &TEST_NETWORK,
                height,
                &ivk,
                &CompactOutputDescription::from(output.clone()),
            ) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_sapling_output_recovery(&TEST_NETWORK, height, &ovk, &output) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            match &batch::try_note_decryption(
                &[ivk.clone()],
                &[(
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    output.clone(),
                )],
            )[..]
            {
                [Some(((decrypted_note, decrypted_to, decrypted_memo), i))] => {
                    assert_eq!(decrypted_note, &note);
                    assert_eq!(decrypted_to, &to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                    assert_eq!(*i, 0);
                }
                _ => panic!("Note decryption failed"),
            }

            match &batch::try_compact_note_decryption(
                &[ivk.clone()],
                &[(
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    CompactOutputDescription::from(output.clone()),
                )],
            )[..]
            {
                [Some(((decrypted_note, decrypted_to), i))] => {
                    assert_eq!(decrypted_note, &note);
                    assert_eq!(decrypted_to, &to);
                    assert_eq!(*i, 0);
                }
                _ => panic!("Note decryption failed"),
            }

            match try_sapling_output_recovery_with_ock(&TEST_NETWORK, height, &ock, &output) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, to);
                    assert_eq!(&decrypted_memo.as_array()[..], &tv.memo[..]);
                }
                None => panic!("Output recovery with ock failed"),
            }

            //
            // Test encryption
            //

            let ne = NoteEncryption::<SaplingDomain<TestNetwork>>::new_with_esk(
                esk,
                Some(ovk),
                note,
                MemoBytes::from_bytes(&tv.memo).unwrap(),
            );

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv, &cmu, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }

    #[test]
    fn batching() {
        let mut rng = OsRng;
        let height = TEST_NETWORK.activation_height(MASP).unwrap();

        // Test batch trial-decryption with multiple IVKs and outputs.
        let invalid_ivk = PreparedIncomingViewingKey::new(&SaplingIvk(jubjub::Fr::random(rng)));
        let valid_ivk = SaplingIvk(jubjub::Fr::random(rng));
        let outputs: Vec<_> = (0..10)
            .map(|_| {
                (
                    SaplingDomain::for_height(TEST_NETWORK, height),
                    random_enc_ciphertext_with(height, &valid_ivk, &mut rng).2,
                )
            })
            .collect();
        let valid_ivk = PreparedIncomingViewingKey::new(&valid_ivk);

        // Check that batched trial decryptions with invalid_ivk fails.
        let res = batch::try_note_decryption(&[invalid_ivk.clone()], &outputs);
        assert_eq!(res.len(), 10);
        assert_eq!(&res[..], &vec![None; 10][..]);

        // Check that batched trial decryptions with valid_ivk succeeds.
        let res = batch::try_note_decryption(&[invalid_ivk, valid_ivk.clone()], &outputs);
        assert_eq!(res.len(), 10);
        for (result, (_, output)) in res.iter().zip(outputs.iter()) {
            // Confirm the successful batched trial decryptions gave the same result.
            // In all cases, the index of the valid ivk is returned.
            assert!(result.is_some());
            assert_eq!(
                result,
                &try_sapling_note_decryption(&TEST_NETWORK, height, &valid_ivk, output)
                    .map(|r| (r, 1))
            );
        }
    }
}

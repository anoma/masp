//! Types and functions for building Sapling transaction components.

use crate::{
    asset_type::AssetType,
    consensus::{self, BlockHeight, H0, MAIN_NETWORK},
    convert::AllowedConversion,
    keys::OutgoingViewingKey,
    merkle_tree::MerklePath,
    note_encryption::sapling_note_encryption,
    primitives::{Diversifier, Note, Nullifier, PaymentAddress},
    prover::{TxProver, GROTH_PROOF_SIZE},
    redjubjub::{self, PrivateKey, PublicKey, Signature},
    sapling::{spend_sig_internal, Node},
    transaction::{
        //Bundle,
        amount::{Amount, MAX_MONEY},
        builder::Progress,
        //components::{
        //    amount::Amount,
        //    sapling::{
        //        fees, Authorization, Authorized, Bundle, GrothProofBytes, OutputDescription,
        //        SpendDescription,
        //    },
        //},
        memo::MemoBytes,
        GrothProofBytes,
        SaplingDomain,
        TransactionData,
    },
    util::generate_random_rseed_internal,
    zip32::ExtendedSpendingKey,
};
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use ff::{Field, PrimeField};
use group::GroupEncoding;
use masp_note_encryption::{
    EphemeralKeyBytes, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};
use memuse::DynamicUsage;
use rand::{seq::SliceRandom, RngCore};
use std::convert::TryInto;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::sync::mpsc::Sender;

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    InvalidAddress,
    InvalidAmount,
    SpendProof,
    ConvertProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AnchorMismatch => {
                write!(f, "Anchor mismatch (anchors for all spends must be equal)")
            }
            Error::BindingSig => write!(f, "Failed to create bindingSig"),
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::SpendProof => write!(f, "Failed to create MASP spend proof"),
            Error::ConvertProof => write!(f, "Failed to create MASP convert proof"),
        }
    }
}

pub trait Authorization: Debug {
    type Proof: Clone + Debug + PartialEq + Hash;
    type AuthSig: Clone + Debug + PartialEq;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Unproven;

impl Authorization for Unproven {
    type Proof = ();
    type AuthSig = ();
}

#[derive(Debug, Copy, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Authorized {
    pub binding_sig: redjubjub::Signature,
}

impl Authorization for Authorized {
    type Proof = GrothProofBytes;
    type AuthSig = redjubjub::Signature;
}
#[derive(Clone, PartialEq, Eq)]
pub struct SpendDescription<A: Authorization + PartialEq> {
    pub cv: jubjub::ExtendedPoint,
    pub anchor: bls12_381::Scalar,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
    pub zkproof: A::Proof,
    pub spend_auth_sig: A::AuthSig,
}

impl<A: Authorization + PartialEq> std::fmt::Debug for SpendDescription<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "SpendDescription(cv = {:?}, anchor = {:?}, nullifier = {:?}, rk = {:?}, spend_auth_sig = {:?})",
            self.cv, self.anchor, self.nullifier, self.rk, self.spend_auth_sig
        )
    }
}
/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced here.
/// - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
///   (located in zcash_proofs::sapling::verifier).
pub fn read_point<R: Read>(mut reader: R, field: &str) -> io::Result<jubjub::ExtendedPoint> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let point = jubjub::ExtendedPoint::from_bytes(&bytes);

    if point.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {}", field),
        ))
    } else {
        Ok(point.unwrap())
    }
}

/// Consensus rules (§7.3) & (§7.4):
/// - Canonical encoding is enforced here
pub fn read_base<R: Read>(mut reader: R, field: &str) -> io::Result<bls12_381::Scalar> {
    let mut f = [0u8; 32];
    reader.read_exact(&mut f)?;
    Option::from(bls12_381::Scalar::from_repr(f)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} not in field", field),
        )
    })
}

/// Consensus rules (§4.4) & (§4.5):
/// - Canonical encoding is enforced by the API of SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output() due to the need to parse this into a
///   bellman::groth16::Proof.
/// - Proof validity is enforced in SaplingVerificationContext::check_spend()
///   and SaplingVerificationContext::check_output()
pub fn read_zkproof<R: Read>(mut reader: R) -> io::Result<GrothProofBytes> {
    let mut zkproof = [0u8; GROTH_PROOF_SIZE];
    reader.read_exact(&mut zkproof)?;
    Ok(zkproof)
}

impl SpendDescription<Authorized> {
    pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
        let mut nullifier = Nullifier([0u8; 32]);
        reader.read_exact(&mut nullifier.0)?;
        Ok(nullifier)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - "Not small order" is enforced in SaplingVerificationContext::check_spend()
    pub fn read_rk<R: Read>(mut reader: R) -> io::Result<PublicKey> {
        PublicKey::read(&mut reader)
    }

    /// Consensus rules (§4.4):
    /// - Canonical encoding is enforced here.
    /// - Signature validity is enforced in SaplingVerificationContext::check_spend()
    pub fn read_spend_auth_sig<R: Read>(mut reader: R) -> io::Result<Signature> {
        Signature::read(&mut reader)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        // Consensus rules (§4.4) & (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;
        // Consensus rules (§7.3) & (§7.4):
        // - Canonical encoding is enforced here
        let anchor = read_base(&mut reader, "anchor")?;
        let nullifier = Self::read_nullifier(&mut reader)?;
        let rk = Self::read_rk(&mut reader)?;
        let zkproof = read_zkproof(&mut reader)?;
        let spend_auth_sig = Self::read_spend_auth_sig(&mut reader)?;

        Ok(SpendDescription {
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.anchor.to_repr().as_ref())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)?;
        writer.write_all(&self.zkproof)?;
        self.spend_auth_sig.write(&mut writer)
    }

    pub fn write_v5_without_witness_data<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(&self.nullifier.0)?;
        self.rk.write(&mut writer)
    }
}

#[derive(Clone)]
pub struct SpendDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub nullifier: Nullifier,
    pub rk: PublicKey,
}

impl SpendDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let nullifier = SpendDescription::read_nullifier(&mut reader)?;
        let rk = SpendDescription::read_rk(&mut reader)?;

        Ok(SpendDescriptionV5 { cv, nullifier, rk })
    }

    pub fn into_spend_description(
        self,
        anchor: bls12_381::Scalar,
        zkproof: GrothProofBytes,
        spend_auth_sig: Signature,
    ) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor,
            nullifier: self.nullifier,
            rk: self.rk,
            zkproof,
            spend_auth_sig,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ConvertDescription<Proof: PartialEq> {
    pub cv: jubjub::ExtendedPoint,
    pub anchor: bls12_381::Scalar,
    pub zkproof: Proof,
}

impl<Proof: Clone + PartialOrd> PartialOrd for ConvertDescription<Proof> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (
            self.cv.to_bytes(),
            self.anchor.to_bytes(),
            self.zkproof.clone(),
        )
            .partial_cmp(&(
                other.cv.to_bytes(),
                other.anchor.to_bytes(),
                other.zkproof.clone(),
            ))
    }
}

impl<Proof: PartialEq + Hash> Hash for ConvertDescription<Proof> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.cv.to_bytes().hash(state);
        self.anchor.to_bytes().hash(state);
        self.zkproof.hash(state);
    }
}
impl<Proof: PartialEq> std::fmt::Debug for ConvertDescription<Proof> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "ConvertDescription(cv = {:?}, anchor = {:?})",
            self.cv, self.anchor
        )
    }
}
impl ConvertDescription<GrothProofBytes> {
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        // Consensus rules (§4.4) & (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::(check_spend()/check_output())
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;
        // Consensus rules (§7.3) & (§7.4):
        // - Canonical encoding is enforced here
        let anchor = read_base(&mut reader, "anchor")?;
        let zkproof = read_zkproof(&mut reader)?;

        Ok(ConvertDescription {
            cv,
            anchor,
            zkproof,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.anchor.to_repr().as_ref())?;
        writer.write_all(&self.zkproof)
    }
}

#[derive(Clone, PartialEq)]
pub struct OutputDescription<Proof: Clone> {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: EphemeralKeyBytes,
    pub enc_ciphertext: [u8; 580 + 32],
    pub out_ciphertext: [u8; 80],
    pub zkproof: Proof,
}

impl<Proof: Clone + DynamicUsage> DynamicUsage for OutputDescription<Proof> {
    fn dynamic_usage(&self) -> usize {
        self.zkproof.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.zkproof.dynamic_usage_bounds()
    }
}

impl<Proof: Clone + PartialOrd> PartialOrd for OutputDescription<Proof> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        (
            self.cv.to_bytes(),
            self.cmu.to_bytes(),
            self.ephemeral_key.clone(),
            self.enc_ciphertext,
            self.out_ciphertext,
            self.zkproof.clone(),
        )
            .partial_cmp(&(
                other.cv.to_bytes(),
                other.cmu.to_bytes(),
                other.ephemeral_key.clone(),
                other.enc_ciphertext,
                other.out_ciphertext,
                other.zkproof.clone(),
            ))
    }
}

impl<Proof: Clone + Hash> Hash for OutputDescription<Proof> {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.cv.to_bytes().hash(state);
        self.cmu.to_bytes().hash(state);
        self.ephemeral_key.hash(state);
        self.enc_ciphertext.hash(state);
        self.out_ciphertext.hash(state);
        self.zkproof.hash(state);
    }
}

impl<P: consensus::Parameters, Proof: Clone> ShieldedOutput<SaplingDomain<P>, ENC_CIPHERTEXT_SIZE>
    for OutputDescription<Proof>
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.enc_ciphertext
    }
}

impl<Proof> std::fmt::Debug for OutputDescription<Proof>
where
    Proof: Clone + PartialEq,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "OutputDescription(cv = {:?}, cmu = {:?}, ephemeral_key = {:?})",
            self.cv, self.cmu, self.ephemeral_key
        )
    }
}

impl OutputDescription<GrothProofBytes> {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        // Consensus rules (§4.5):
        // - Canonical encoding is enforced here.
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        //   (located in zcash_proofs::sapling::verifier).
        let cv = read_point(&mut reader, "cv")?;

        // Consensus rule (§7.4): Canonical encoding is enforced here
        let cmu = read_base(&mut reader, "cmu")?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580 + 32];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        let zkproof = read_zkproof(&mut reader)?;

        Ok(OutputDescription {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        })
    }

    pub fn write_v4<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(self.ephemeral_key.as_ref())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)?;
        writer.write_all(&self.zkproof)
    }

    pub fn write_v5_without_proof<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.cv.to_bytes())?;
        writer.write_all(self.cmu.to_repr().as_ref())?;
        writer.write_all(self.ephemeral_key.as_ref())?;
        writer.write_all(&self.enc_ciphertext)?;
        writer.write_all(&self.out_ciphertext)
    }
}

#[derive(Clone)]
pub struct OutputDescriptionV5 {
    pub cv: jubjub::ExtendedPoint,
    pub cmu: bls12_381::Scalar,
    pub ephemeral_key: EphemeralKeyBytes,
    pub enc_ciphertext: [u8; 580 + 32],
    pub out_ciphertext: [u8; 80],
}

impl OutputDescriptionV5 {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let cv = read_point(&mut reader, "cv")?;
        let cmu = read_base(&mut reader, "cmu")?;

        // Consensus rules (§4.5):
        // - Canonical encoding is enforced in librustzcash_sapling_check_output by zcashd
        // - "Not small order" is enforced in SaplingVerificationContext::check_output()
        let mut ephemeral_key = EphemeralKeyBytes([0u8; 32]);
        reader.read_exact(&mut ephemeral_key.0)?;

        let mut enc_ciphertext = [0u8; 580 + 32];
        let mut out_ciphertext = [0u8; 80];
        reader.read_exact(&mut enc_ciphertext)?;
        reader.read_exact(&mut out_ciphertext)?;

        Ok(OutputDescriptionV5 {
            cv,
            cmu,
            ephemeral_key,
            enc_ciphertext,
            out_ciphertext,
        })
    }

    pub fn into_output_description(
        self,
        zkproof: GrothProofBytes,
    ) -> OutputDescription<GrothProofBytes> {
        OutputDescription {
            cv: self.cv,
            cmu: self.cmu,
            ephemeral_key: self.ephemeral_key,
            enc_ciphertext: self.enc_ciphertext,
            out_ciphertext: self.out_ciphertext,
            zkproof,
        }
    }
}

pub struct CompactOutputDescription {
    pub ephemeral_key: EphemeralKeyBytes,
    pub cmu: bls12_381::Scalar,
    pub enc_ciphertext: [u8; COMPACT_NOTE_SIZE],
}

impl<Proof: Clone> From<OutputDescription<Proof>> for CompactOutputDescription {
    fn from(out: OutputDescription<Proof>) -> CompactOutputDescription {
        CompactOutputDescription {
            ephemeral_key: out.ephemeral_key,
            cmu: out.cmu,
            enc_ciphertext: out.enc_ciphertext[..COMPACT_NOTE_SIZE].try_into().unwrap(),
        }
    }
}

impl<P: consensus::Parameters> ShieldedOutput<SaplingDomain<P>, COMPACT_NOTE_SIZE>
    for CompactOutputDescription
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.ephemeral_key.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_repr()
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.enc_ciphertext
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpendDescriptionInfo {
    extsk: ExtendedSpendingKey,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath<Node>,
}
/*
impl fees::InputView for SpendDescriptionInfo {
    fn value(&self) -> Amount {
        // An existing note to be spent must have a valid
        // amount value.
        Amount::from_u64(self.note.value).unwrap()
    }
}*/

/// A struct containing the information required in order to construct a
/// MASP conversion in a transaction.
#[derive(Clone)]
pub struct ConvertDescriptionInfo {
    allowed: AllowedConversion,
    value: u64,
    merkle_path: MerklePath<Node>,
}

/// A struct containing the information required in order to construct a
/// MASP output to a transaction.
#[derive(Clone)]
pub struct SaplingOutputInfo {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: MemoBytes,
}

impl SaplingOutputInfo {
    fn new_internal<R: RngCore>(
        rng: &mut R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<Self, Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value > MAX_MONEY.try_into().unwrap() {
            return Err(Error::InvalidAmount);
        }

        let rseed = generate_random_rseed_internal(&crate::consensus::MAIN_NETWORK, H0, rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value: value.into(),
            rseed,
            asset_type,
        };

        Ok(SaplingOutputInfo {
            ovk,
            to,
            note,
            memo,
        })
    }

    fn build<P: consensus::Parameters, Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
    ) -> OutputDescription<GrothProofBytes> {
        let encryptor = sapling_note_encryption::<R, P>(
            self.ovk,
            self.note.clone(),
            self.to.clone(),
            self.memo,
            rng,
        );

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            self.to,
            self.note.rcm(),
            self.note.asset_type,
            self.note.value,
        );

        let cmu = self.note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, rng);

        let epk = *encryptor.epk();

        OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes().into(),
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        }
    }
}
/*
impl fees::OutputView for SaplingOutputInfo {
    fn value(&self) -> Amount {
        Amount::from_u64(self.note.value).expect("Note values should be checked at construction.")
    }
}*/

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SaplingMetadata {
    spend_indices: Vec<usize>,
    convert_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl SaplingMetadata {
    pub fn empty() -> Self {
        SaplingMetadata {
            spend_indices: vec![],
            convert_indices: vec![],
            output_indices: vec![],
        }
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`SaplingBuilder::add_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
    /// Returns the index within the transaction of the [`ConvertDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_convert`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`ConvertDescription`] in the transaction.
    pub fn convert_index(&self, n: usize) -> Option<usize> {
        self.convert_indices.get(n).copied()
    }
}

pub struct SaplingBuilder {
    anchor: Option<bls12_381::Scalar>,
    value_balance: Amount,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

#[derive(Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Unauthorized {
    tx_metadata: SaplingMetadata,
}

impl std::fmt::Debug for Unauthorized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "Unauthorized")
    }
}

impl Authorization for Unauthorized {
    type Proof = GrothProofBytes;
    type AuthSig = SpendDescriptionInfo;
}

impl SaplingBuilder {
    pub fn new() -> Self {
        SaplingBuilder {
            anchor: None,
            value_balance: Amount::zero(),
            convert_anchor: None,
            spends: vec![],
            converts: vec![],
            outputs: vec![],
        }
    }

    /// Returns the list of Sapling inputs that will be consumed by the transaction being
    /// constructed.
    //pub fn inputs(&self) -> &[impl fees::InputView] {
    pub fn inputs(&self) -> &[SpendDescriptionInfo] {
        &self.spends
    }

    pub fn converts(&self) -> &[ConvertDescriptionInfo] {
        &self.converts
    }
    /// Returns the Sapling outputs that will be produced by the transaction being constructed
    //pub fn outputs(&self) -> &[impl fees::OutputView] {
    pub fn outputs(&self) -> &[SaplingOutputInfo] {
        &self.outputs
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) -> Amount {
        self.value_balance.clone()
    }
}

impl SaplingBuilder {
    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_spend<R: RngCore>(
        &mut self,
        mut rng: R,
        extsk: ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one
        let cmu = Node::new(note.cmu().into());
        if let Some(anchor) = self.anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.anchor = Some(merkle_path.root(cmu).into())
        }

        let alpha = jubjub::Fr::random(&mut rng);

        self.value_balance +=
            Amount::from_pair(note.asset_type, note.value).map_err(|_| Error::InvalidAmount)?;

        self.spends.push(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            alpha,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    #[allow(clippy::too_many_arguments)]
    pub fn add_output<R: RngCore>(
        &mut self,
        mut rng: R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        let output = SaplingOutputInfo::new_internal(&mut rng, ovk, to, asset_type, value, memo)?;

        self.value_balance -=
            Amount::from_pair(asset_type, value).map_err(|_| Error::InvalidAmount)?;

        self.outputs.push(output);

        Ok(())
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized>>, Error> {
        // Record initial positions of spends and outputs
        let params = crate::consensus::MAIN_NETWORK;
        let mut indexed_spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut indexed_converts: Vec<_> = self.converts.into_iter().enumerate().collect();
        let mut indexed_outputs: Vec<_> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| Some((i, o)))
            .collect();

        // Set up the transaction metadata that will be used to record how
        // inputs and outputs are shuffled.
        let mut tx_metadata = SaplingMetadata::empty();
        tx_metadata.spend_indices.resize(indexed_spends.len(), 0);
        tx_metadata
            .convert_indices
            .resize(indexed_converts.len(), 0);
        tx_metadata.output_indices.resize(indexed_outputs.len(), 0);

        // Pad Sapling outputs
        if !indexed_spends.is_empty() {
            while indexed_outputs.len() < MIN_SHIELDED_OUTPUTS {
                indexed_outputs.push(None);
            }
        }

        // Randomize order of inputs and outputs
        indexed_spends.shuffle(&mut rng);
        indexed_converts.shuffle(&mut rng);
        indexed_outputs.shuffle(&mut rng);

        // Keep track of the total number of steps computed
        let total_progress = indexed_spends.len() as u32 + indexed_outputs.len() as u32;
        let mut progress = 0u32;

        // Create Sapling SpendDescriptions
        let shielded_spends: Vec<SpendDescription<Unauthorized>> = if !indexed_spends.is_empty() {
            let anchor = self
                .anchor
                .expect("Sapling anchor must be set if Sapling spends are present.");

            indexed_spends
                .into_iter()
                .enumerate()
                .map(|(i, (pos, spend))| {
                    let proof_generation_key = spend.extsk.expsk.proof_generation_key();

                    let nullifier = spend.note.nf(
                        &proof_generation_key.to_viewing_key(),
                        spend.merkle_path.position,
                    );

                    let (zkproof, cv, rk) = prover
                        .spend_proof(
                            ctx,
                            proof_generation_key,
                            spend.diversifier,
                            spend.note.rseed,
                            spend.alpha,
                            spend.note.asset_type,
                            spend.note.value,
                            anchor,
                            spend.merkle_path.clone(),
                        )
                        .map_err(|_| Error::SpendProof)?;

                    // Record the post-randomized spend location
                    tx_metadata.spend_indices[pos] = i;

                    // Update progress and send a notification on the channel
                    progress += 1;
                    if let Some(sender) = progress_notifier {
                        // If the send fails, we should ignore the error, not crash.
                        sender
                            .send(Progress::new(progress, Some(total_progress)))
                            .unwrap_or(());
                    }

                    Ok(SpendDescription {
                        cv,
                        anchor,
                        nullifier,
                        rk,
                        zkproof,
                        spend_auth_sig: spend,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            vec![]
        };

        // Create Sapling ConvertDescriptions
        let shielded_converts: Vec<ConvertDescription<GrothProofBytes>> =
            if !indexed_converts.is_empty() {
                let anchor = self
                    .convert_anchor
                    .expect("Sapling convert_anchor must be set if Sapling converts are present.");

                indexed_converts
                    .into_iter()
                    .enumerate()
                    .map(|(i, (pos, convert))| {
                        let (zkproof, cv) = prover
                            .convert_proof(
                                ctx,
                                convert.allowed.clone(),
                                convert.value,
                                anchor,
                                convert.merkle_path.clone(),
                            )
                            .map_err(|_| Error::ConvertProof)?;

                        // Record the post-randomized spend location
                        tx_metadata.convert_indices[pos] = i;

                        // Update progress and send a notification on the channel
                        progress += 1;
                        if let Some(sender) = progress_notifier {
                            // If the send fails, we should ignore the error, not crash.
                            sender
                                .send(Progress::new(progress, Some(total_progress)))
                                .unwrap_or(());
                        }

                        Ok(ConvertDescription {
                            cv,
                            anchor,
                            zkproof,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?
            } else {
                vec![]
            };

        // Create Sapling OutputDescriptions
        let shielded_outputs: Vec<OutputDescription<GrothProofBytes>> = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                let result = if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output
                        .clone()
                        .build::<crate::consensus::MainNetwork, _, _>(prover, ctx, &mut rng)
                } else {
                    // This is a dummy output
                    let (dummy_to, dummy_note) = {
                        let (diversifier, g_d) = {
                            let mut diversifier;
                            let g_d;
                            loop {
                                let mut d = [0; 11];
                                rng.fill_bytes(&mut d);
                                diversifier = Diversifier(d);
                                if let Some(val) = diversifier.g_d() {
                                    g_d = val;
                                    break;
                                }
                            }
                            (diversifier, g_d)
                        };
                        let (pk_d, payment_address) = loop {
                            let dummy_ivk = jubjub::Fr::random(&mut rng);
                            let pk_d = g_d * dummy_ivk;
                            if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d) {
                                break (pk_d, addr);
                            }
                        };

                        let rseed = generate_random_rseed_internal(&params, H0, &mut rng);

                        (
                            payment_address,
                            Note {
                                g_d,
                                pk_d,
                                rseed,
                                value: 0,
                                asset_type: AssetType::new(b"dummy").unwrap(),
                            },
                        )
                    };

                    let esk = dummy_note.generate_or_derive_esk_internal(&mut rng);
                    let epk = dummy_note.g_d * esk;

                    let (zkproof, cv) = prover.output_proof(
                        ctx,
                        esk,
                        dummy_to,
                        dummy_note.rcm(),
                        dummy_note.asset_type,
                        dummy_note.value,
                    );

                    let cmu = dummy_note.cmu();

                    let mut enc_ciphertext = [0u8; 580 + 32];
                    let mut out_ciphertext = [0u8; 80];
                    rng.fill_bytes(&mut enc_ciphertext[..]);
                    rng.fill_bytes(&mut out_ciphertext[..]);

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.to_bytes().into(),
                        enc_ciphertext,
                        out_ciphertext,
                        zkproof,
                    }
                };

                // Update progress and send a notification on the channel
                progress += 1;
                if let Some(sender) = progress_notifier {
                    // If the send fails, we should ignore the error, not crash.
                    sender
                        .send(Progress::new(progress, Some(total_progress)))
                        .unwrap_or(());
                }

                result
            })
            .collect();

        let bundle = if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends,
                shielded_converts,
                shielded_outputs,
                value_balance: self.value_balance,
                authorization: Unauthorized { tx_metadata },
            })
        };

        Ok(bundle)
    }
}

impl SpendDescription<Unauthorized> {
    pub fn apply_signature(&self, spend_auth_sig: Signature) -> SpendDescription<Authorized> {
        SpendDescription {
            cv: self.cv,
            anchor: self.anchor,
            nullifier: self.nullifier,
            rk: self.rk.clone(),
            zkproof: self.zkproof,
            spend_auth_sig,
        }
    }
}

impl Bundle<Unauthorized> {
    pub fn apply_signatures<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        rng: &mut R,
        sighash_bytes: &[u8; 32],
    ) -> Result<(Bundle<Authorized>, SaplingMetadata), Error> {
        let binding_sig = prover
            .binding_sig(ctx, &self.value_balance, sighash_bytes)
            .map_err(|_| Error::BindingSig)?;

        Ok((
            Bundle {
                shielded_spends: self
                    .shielded_spends
                    .iter()
                    .map(|spend| {
                        spend.apply_signature(spend_sig_internal(
                            PrivateKey(spend.spend_auth_sig.extsk.expsk.ask),
                            spend.spend_auth_sig.alpha,
                            sighash_bytes,
                            rng,
                        ))
                    })
                    .collect(),
                shielded_converts: self.shielded_converts,
                shielded_outputs: self.shielded_outputs,
                value_balance: self.value_balance,
                authorization: Authorized { binding_sig },
            },
            self.authorization.tx_metadata,
        ))
    }
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_proof(&self, p: A::Proof) -> B::Proof;
    fn map_auth_sig(&self, s: A::AuthSig) -> B::AuthSig;
    fn map_authorization(&self, a: A) -> B;
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq)]
pub struct Bundle<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> {
    pub shielded_spends: Vec<SpendDescription<A>>,
    pub shielded_converts: Vec<ConvertDescription<A::Proof>>,
    pub shielded_outputs: Vec<OutputDescription<A::Proof>>,
    pub value_balance: Amount,
    pub authorization: A,
}

impl<A: Authorization + PartialEq + BorshSerialize + BorshDeserialize> Bundle<A> {
    pub fn map_authorization<
        B: Authorization + PartialEq + BorshSerialize + BorshDeserialize,
        F: MapAuth<A, B>,
    >(
        self,
        f: F,
    ) -> Bundle<B> {
        Bundle {
            shielded_spends: self
                .shielded_spends
                .into_iter()
                .map(|d| SpendDescription {
                    cv: d.cv,
                    anchor: d.anchor,
                    nullifier: d.nullifier,
                    rk: d.rk,
                    zkproof: f.map_proof(d.zkproof),
                    spend_auth_sig: f.map_auth_sig(d.spend_auth_sig),
                })
                .collect(),
            shielded_converts: self
                .shielded_converts
                .into_iter()
                .map(|c| ConvertDescription {
                    cv: c.cv,
                    anchor: c.anchor,
                    zkproof: f.map_proof(c.zkproof),
                })
                .collect(),
            shielded_outputs: self
                .shielded_outputs
                .into_iter()
                .map(|o| OutputDescription {
                    cv: o.cv,
                    cmu: o.cmu,
                    ephemeral_key: o.ephemeral_key,
                    enc_ciphertext: o.enc_ciphertext,
                    out_ciphertext: o.out_ciphertext,
                    zkproof: f.map_proof(o.zkproof),
                })
                .collect(),
            value_balance: self.value_balance,
            authorization: f.map_authorization(self.authorization),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        consensus::{
            testing::{arb_branch_id, arb_height},
            TEST_NETWORK,
        },
        merkle_tree::{testing::arb_commitment_tree, IncrementalWitness},
        primitives::Diversifier,
        prover::mock::MockTxProver,
        sapling::testing::{arb_node, arb_note, arb_positive_note_value},
        transaction::amount::MAX_MONEY,
        zip32::testing::arb_extended_spending_key,
    };

    use super::{Authorized, Bundle, SaplingBuilder};

    prop_compose! {
        fn arb_bundle()(n_notes in 1..30usize)(
            extsk in arb_extended_spending_key(),
            spendable_notes in vec(
                arb_positive_note_value(MAX_MONEY as u64 / 10000).prop_flat_map(arb_note),
                n_notes
            ),
            commitment_trees in vec(
                arb_commitment_tree(n_notes, arb_node(), 32).prop_map(
                    |t| IncrementalWitness::from_tree(&t).path().unwrap()
                ),
                n_notes
            ),
            diversifiers in vec(prop::array::uniform11(any::<u8>()).prop_map(Diversifier), n_notes),
            rng_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new();
            let mut rng = StdRng::from_seed(rng_seed);

            for ((note, path), diversifier) in spendable_notes.into_iter().zip(commitment_trees.into_iter()).zip(diversifiers.into_iter()) {
                builder.add_spend(
                    &mut rng,
                    extsk.clone(),
                    diversifier,
                    note,
                    path
                ).unwrap();
            }

            let prover = MockTxProver;

            let bundle = builder.build(
                &prover,
                &mut (),
                &mut rng,
                None
            ).unwrap().unwrap();

            let (bundle, _) = bundle.apply_signatures(
                &prover,
                &mut (),
                &mut rng,
                &fake_sighash_bytes,
            ).unwrap();

            bundle
        }
    }
}

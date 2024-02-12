//! Types and functions for building MASP shielded transaction components.

use core::fmt;
use std::sync::mpsc::Sender;

use ff::Field;
use group::GroupEncoding;
use rand::{seq::SliceRandom, RngCore};

use crate::{
    asset_type::AssetType,
    consensus::{self, BlockHeight},
    convert::AllowedConversion,
    keys::OutgoingViewingKey,
    memo::MemoBytes,
    merkle_tree::MerklePath,
    sapling::{
        note_encryption::sapling_note_encryption,
        prover::TxProver,
        redjubjub::{PrivateKey, Signature},
        spend_sig_internal,
        util::generate_random_rseed_internal,
        Diversifier, Node, Note, PaymentAddress,
    },
    transaction::{
        builder::Progress,
        components::{
            amount::{I128Sum, ValueSum, MAX_MONEY},
            sapling::{
                fees, Authorization, Authorized, Bundle, ConvertDescription, GrothProofBytes,
                OutputDescription, SpendDescription,
            },
        },
    },
    zip32::ExtendedSpendingKey,
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::Write;

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

#[derive(Debug, Clone, PartialEq)]
pub struct SpendDescriptionInfo<Key = ExtendedSpendingKey> {
    extsk: Key,
    diversifier: Diversifier,
    note: Note,
    alpha: jubjub::Fr,
    merkle_path: MerklePath<Node>,
}

impl<Key> SpendDescriptionInfo<Key> {
    /// Constructs a [`SpendDescriptionInfo`] from its constituent parts.
    pub fn new(
        extsk: Key,
        diversifier: Diversifier,
        note: Note,
        alpha: jubjub::Fr,
        merkle_path: MerklePath<Node>,
    ) -> Self {
        Self {
            extsk,
            diversifier,
            note,
            alpha,
            merkle_path,
        }
    }
}

impl<Key: BorshSerialize> BorshSerialize for SpendDescriptionInfo<Key> {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.extsk.serialize(writer)?;
        self.diversifier.serialize(writer)?;
        self.note.serialize(writer)?;
        self.alpha.to_bytes().serialize(writer)?;
        self.merkle_path.serialize(writer)
    }
}

impl<Key: BorshDeserialize> BorshDeserialize for SpendDescriptionInfo<Key> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let extsk = Key::deserialize_reader(reader)?;
        let diversifier = Diversifier::deserialize_reader(reader)?;
        let note = Note::deserialize_reader(reader)?;
        let alpha: Option<_> =
            jubjub::Fr::from_bytes(&<[u8; 32]>::deserialize_reader(reader)?).into();
        let alpha = alpha.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        let merkle_path = MerklePath::<Node>::deserialize_reader(reader)?;
        Ok(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            alpha,
            merkle_path,
        })
    }
}

impl<K> fees::InputView<(), K> for SpendDescriptionInfo<K> {
    fn note_id(&self) -> &() {
        // The builder does not make use of note identifiers, so we can just return the unit value.
        &()
    }

    fn value(&self) -> u64 {
        self.note.value
    }

    fn asset_type(&self) -> AssetType {
        self.note.asset_type
    }

    fn key(&self) -> &K {
        &self.extsk
    }
}

/// A struct containing the information required in order to construct a
/// MASP output to a transaction.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SaplingOutputInfo {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: MemoBytes,
}
impl SaplingOutputInfo {
    /// Constructs a [`SaplingOutputInfo`] from its constituent parts.
    pub fn new(
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        note: Note,
        memo: MemoBytes,
    ) -> Self {
        Self { ovk, to, note, memo }
    }
    /// Returns the recipient of the new output.
    pub fn recipient(&self) -> PaymentAddress {
        self.to
    }

    /// Returns the value of the output.
    pub fn note(&self) -> Note {
        self.note
    }

    pub fn ovk(&self) -> Option<OutgoingViewingKey> { self.ovk }

    pub fn memo(&self) -> MemoBytes { self.memo.clone() }
}
impl SaplingOutputInfo {
    #[allow(clippy::too_many_arguments)]
    fn new_internal<P: consensus::Parameters, R: RngCore>(
        params: &P,
        rng: &mut R,
        target_height: BlockHeight,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<Self, Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value > MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        let rseed = generate_random_rseed_internal(params, target_height, rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value,
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
        let encryptor = sapling_note_encryption::<P>(self.ovk, self.note, self.to, self.memo);

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

impl fees::OutputView for SaplingOutputInfo {
    fn value(&self) -> u64 {
        self.note.value
    }

    fn asset_type(&self) -> AssetType {
        self.note.asset_type
    }

    fn address(&self) -> PaymentAddress {
        self.to
    }
}

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

#[derive(Clone, Debug)]
pub struct SaplingBuilder<P, Key = ExtendedSpendingKey> {
    params: P,
    spend_anchor: Option<bls12_381::Scalar>,
    target_height: BlockHeight,
    value_balance: I128Sum,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescriptionInfo<Key>>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

impl<P: BorshSerialize, Key: BorshSerialize> BorshSerialize for SaplingBuilder<P, Key> {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.params.serialize(writer)?;
        self.spend_anchor.map(|x| x.to_bytes()).serialize(writer)?;
        self.target_height.serialize(writer)?;
        self.value_balance.serialize(writer)?;
        self.convert_anchor
            .map(|x| x.to_bytes())
            .serialize(writer)?;
        self.spends.serialize(writer)?;
        self.converts.serialize(writer)?;
        self.outputs.serialize(writer)
    }
}

impl<P: BorshDeserialize, Key: BorshDeserialize> BorshDeserialize for SaplingBuilder<P, Key> {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let params = P::deserialize_reader(reader)?;
        let spend_anchor: Option<Option<_>> = Option::<[u8; 32]>::deserialize_reader(reader)?
            .map(|x| bls12_381::Scalar::from_bytes(&x).into());
        let spend_anchor = spend_anchor
            .map(|x| x.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData)))
            .transpose()?;
        let target_height = BlockHeight::deserialize_reader(reader)?;
        let value_balance = I128Sum::deserialize_reader(reader)?;
        let convert_anchor: Option<Option<_>> = Option::<[u8; 32]>::deserialize_reader(reader)?
            .map(|x| bls12_381::Scalar::from_bytes(&x).into());
        let convert_anchor = convert_anchor
            .map(|x| x.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData)))
            .transpose()?;
        let spends = Vec::<SpendDescriptionInfo<Key>>::deserialize_reader(reader)?;
        let converts = Vec::<ConvertDescriptionInfo>::deserialize_reader(reader)?;
        let outputs = Vec::<SaplingOutputInfo>::deserialize_reader(reader)?;
        Ok(SaplingBuilder {
            params,
            spend_anchor,
            target_height,
            value_balance,
            convert_anchor,
            spends,
            converts,
            outputs,
        })
    }
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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

impl<P, K> SaplingBuilder<P, K> {
    pub fn new(params: P, target_height: BlockHeight) -> Self {
        SaplingBuilder {
            params,
            spend_anchor: None,
            target_height,
            value_balance: ValueSum::zero(),
            convert_anchor: None,
            spends: vec![],
            converts: vec![],
            outputs: vec![],
        }
    }

    /// Returns the list of Sapling inputs that will be consumed by the transaction being
    /// constructed.
    pub fn inputs(&self) -> &[impl fees::InputView<(), K>] {
        &self.spends
    }

    pub fn converts(&self) -> &[impl fees::ConvertView] {
        &self.converts
    }
    /// Returns the Sapling outputs that will be produced by the transaction being constructed
    pub fn outputs(&self) -> &[impl fees::OutputView] {
        &self.outputs
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) -> I128Sum {
        self.value_balance.clone()
    }
}

impl<P: consensus::Parameters> SaplingBuilder<P> {
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
        let node = note.commitment();
        if let Some(anchor) = self.spend_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.spend_anchor = Some(merkle_path.root(node).into())
        }

        let alpha = jubjub::Fr::random(&mut rng);

        self.value_balance += ValueSum::from_pair(note.asset_type, note.value.into())
            .map_err(|_| Error::InvalidAmount)?;

        self.spends.push(SpendDescriptionInfo {
            extsk,
            diversifier,
            note,
            alpha,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a convert note to be applied in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous convert notes.
    pub fn add_convert(
        &mut self,
        allowed: AllowedConversion,
        value: u64,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one

        let node = allowed.commitment();
        if let Some(anchor) = self.convert_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.convert_anchor = Some(merkle_path.root(node).into())
        }

        let allowed_amt: I128Sum = allowed.clone().into();
        self.value_balance += I128Sum::from_sum(allowed_amt) * (value as i128);

        self.converts.push(ConvertDescriptionInfo {
            allowed,
            value,
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
        let output = SaplingOutputInfo::new_internal(
            &self.params,
            &mut rng,
            self.target_height,
            ovk,
            to,
            asset_type,
            value,
            memo,
        )?;

        self.value_balance -=
            ValueSum::from_pair(asset_type, value.into()).map_err(|_| Error::InvalidAmount)?;

        self.outputs.push(output);

        Ok(())
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized>>, Error> {
        // Record initial positions of spends and outputs
        let value_balance = self.value_balance();
        let params = self.params;
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
                .spend_anchor
                .expect("MASP Spend anchor must be set if MASP spends are present.");

            indexed_spends
                .into_iter()
                .enumerate()
                .map(|(i, (pos, spend))| {
                    let proof_generation_key = spend.extsk.expsk.proof_generation_key();

                    let nullifier = spend.note.nf(
                        &proof_generation_key.to_viewing_key().nk,
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
                    .expect("MASP convert_anchor must be set if MASP converts are present.");

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
                                convert.merkle_path,
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

                    output.clone().build::<P, _, _>(prover, ctx, &mut rng)
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

                        let rseed =
                            generate_random_rseed_internal(&params, target_height, &mut rng);

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
                value_balance,
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
            rk: self.rk,
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

/// A struct containing the information required in order to construct a
/// MASP conversion in a transaction.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ConvertDescriptionInfo {
    allowed: AllowedConversion,
    value: u64,
    merkle_path: MerklePath<Node>,
}

impl ConvertDescriptionInfo {
    /// Constructs a [`ConvertDescriptionInfo`] from its constituent parts.
    pub fn new(allowed: AllowedConversion, value: u64, merkle_path: MerklePath<Node>) -> Self {
        Self {
            allowed,
            value,
            merkle_path,
        }
    }

    pub fn allowed(&self) -> AllowedConversion {
        self.allowed.clone()
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn merkle_path(&self) -> MerklePath<Node> {
        self.merkle_path.clone()
    }
}
impl fees::ConvertView for ConvertDescriptionInfo {
    fn value(&self) -> u64 {
        self.value
    }

    fn conversion(&self) -> &AllowedConversion {
        &self.allowed
    }
}

pub trait MapBuilder<P1, K1, P2, K2> {
    fn map_params(&self, s: P1) -> P2;
    fn map_key(&self, s: K1) -> K2;
}

impl<P1, K1> SaplingBuilder<P1, K1> {
    pub fn map_builder<P2, K2, F: MapBuilder<P1, K1, P2, K2>>(
        self,
        f: F,
    ) -> SaplingBuilder<P2, K2> {
        SaplingBuilder::<P2, K2> {
            params: f.map_params(self.params),
            spend_anchor: self.spend_anchor,
            target_height: self.target_height,
            value_balance: self.value_balance,
            convert_anchor: self.convert_anchor,
            converts: self.converts,
            outputs: self.outputs,
            spends: self
                .spends
                .into_iter()
                .map(|x| SpendDescriptionInfo {
                    extsk: f.map_key(x.extsk),
                    diversifier: x.diversifier,
                    note: x.note,
                    alpha: x.alpha,
                    merkle_path: x.merkle_path,
                })
                .collect(),
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
        sapling::{
            prover::mock::MockTxProver,
            testing::{arb_node, arb_note, arb_positive_note_value},
            Diversifier,
        },
        transaction::components::{
            amount::MAX_MONEY,
            sapling::{Authorized, Bundle},
        },
        zip32::sapling::testing::arb_extended_spending_key,
    };

    use super::SaplingBuilder;

    prop_compose! {
        fn arb_bundle()(n_notes in 1..30usize)(
            extsk in arb_extended_spending_key(),
            spendable_notes in vec(
                arb_positive_note_value(MAX_MONEY / 10000).prop_flat_map(arb_note),
                n_notes
            ),
            commitment_trees in vec(
                arb_commitment_tree(n_notes, arb_node(), 32).prop_map(
                    |t| IncrementalWitness::from_tree(&t).path().unwrap()
                ),
                n_notes
            ),
            diversifiers in vec(prop::array::uniform11(any::<u8>()).prop_map(Diversifier), n_notes),
            target_height in arb_branch_id().prop_flat_map(|b| arb_height(b, &TEST_NETWORK)),
            rng_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new(TEST_NETWORK, target_height.unwrap());
            let mut rng = StdRng::from_seed(rng_seed);

            for ((note, path), diversifier) in spendable_notes.into_iter().zip(commitment_trees.into_iter()).zip(diversifiers.into_iter()) {
                builder.add_spend(
                    &mut rng,
                    extsk,
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
                target_height.unwrap(),
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

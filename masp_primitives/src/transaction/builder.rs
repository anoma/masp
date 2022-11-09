//! Types and functions for building Sapling transaction components.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::mpsc::Sender;

use bitvec::index;
use ff::Field;
use group::GroupEncoding;
use rand::{seq::SliceRandom, CryptoRng, RngCore};

use crate::{
    asset_type::AssetType,
    consensus::{self, BlockHeight},
    convert::AllowedConversion,
    keys::OutgoingViewingKey,
    merkle_tree::MerklePath,
    note_encryption::sapling_note_encryption,
    primitives::{Diversifier, Note, PaymentAddress},
    prover::TxProver,
    redjubjub::{PrivateKey, Signature},
    sapling::{spend_sig_internal, Node},
    transaction::{
        amount::Amount, memo::MemoBytes, Authorization, Authorized, Bundle, GrothProofBytes,
        OutputDescription, SpendDescription, ConvertDescription,
    },
    util::generate_random_rseed,
    zip32::ExtendedSpendingKey,
};
use borsh::{BorshDeserialize, BorshSerialize};

/// If there are any shielded inputs, always have at least two shielded outputs, padding
/// with dummy outputs if necessary. See <https://github.com/zcash/zcash/issues/3615>.
const MIN_SHIELDED_OUTPUTS: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    AnchorMismatch,
    BindingSig,
    ChangeIsNegative(Amount),
    InvalidAddress,
    InvalidAmount,
    NoChangeAddress,
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
            Error::ChangeIsNegative(amount) => {
                write!(f, "Change is negative ({:?} zatoshis)", amount)
            }
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
            Error::NoChangeAddress => write!(f, "No change address specified or discoverable"),
            Error::SpendProof => write!(f, "Failed to create Sapling spend proof"),
            Error::ConvertProof => write!(f, "Failed to create convert proof"),
        }
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

#[derive(Clone)]
struct ConvertDescriptionInfo {
    allowed: AllowedConversion,
    value: u64,
    merkle_path: MerklePath<Node>,
}

#[derive(Clone)]
struct SaplingOutput {
    /// `None` represents the `ovk = ⊥` case.
    ovk: Option<OutgoingViewingKey>,
    to: PaymentAddress,
    note: Note,
    memo: MemoBytes,
}

impl SaplingOutput {
    #[allow(clippy::too_many_arguments)]
    fn new_internal<P: consensus::Parameters, R: RngCore + CryptoRng>(
        params: &P,
        rng: &mut R,
        //target_height: BlockHeight,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<Self, Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value.is_negative() {
            return Err(Error::InvalidAmount);
        }

        let rseed = generate_random_rseed(params, crate::consensus::H0, rng);

        let note = Note {
            asset_type,
            g_d,
            pk_d: *to.pk_d(),
            value: value.into(),
            rseed,
        };

        Ok(SaplingOutput {
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
        let encryptor =
            sapling_note_encryption::<R, P>(self.ovk, self.note, self.to, self.memo, rng);

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

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SaplingMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl SaplingMetadata {
    pub fn empty() -> Self {
        SaplingMetadata {
            spend_indices: vec![],
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
}

pub struct SaplingBuilder<P> {
    params: P,
    anchor: Option<bls12_381::Scalar>,
    value_balance: Amount,
    spends: Vec<SpendDescriptionInfo>,
    convert_anchor: Option<bls12_381::Scalar>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutput>,
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

impl<P: consensus::Parameters> SaplingBuilder<P> {
    pub fn new(params: P) -> Self {
        SaplingBuilder {
            params,
            anchor: None,
            value_balance: Amount::zero(),
            spends: vec![],
            convert_anchor: None,
            converts: vec![],
            outputs: vec![],
        }
    }

    /// Returns the net value represented by the spends and outputs added to this builder.
    pub fn value_balance(&self) ->  Amount {
        self.value_balance.clone()
    }

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
        let cmu = Node::new(allowed.cmu().into());
        if let Some(anchor) = self.convert_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.convert_anchor = Some(merkle_path.root(cmu).into())
        }

        let allowed_amt: Amount = allowed.clone().into();
        self.value_balance += allowed_amt * value.try_into().unwrap();

        self.converts.push(ConvertDescriptionInfo {
            allowed,
            value,
            merkle_path,
        });

        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    #[allow(clippy::too_many_arguments)]
    pub fn add_output<R: RngCore + CryptoRng>(
        &mut self,
        mut rng: R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        let output = SaplingOutput::new_internal(
            &self.params,
            &mut rng,
            ovk,
            to,
            asset_type,
            value,
            memo,
        )?;

        self.value_balance -=
            Amount::from_pair(asset_type, value).map_err(|_| Error::InvalidAmount)?;
        self.outputs.push(output);

        Ok(())
    }

    /// Send change to the specified change address. If no change address
    /// was set, send change to the first Sapling address given as input.
    pub fn get_candidate_change_address(&self) -> Option<(OutgoingViewingKey, PaymentAddress)> {
        self.spends.first().and_then(|spend| {
            PaymentAddress::from_parts(spend.diversifier, spend.note.pk_d)
                .map(|addr| (spend.extsk.expsk.ovk, addr))
        })
    }

    pub fn build<Pr: TxProver, R: RngCore + CryptoRng>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) -> Result<Option<Bundle<Unauthorized>>, Error> {
        // Record initial positions of spends and outputs
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
        let total_progress = indexed_spends.len() as u32
            + indexed_converts.len() as u32
            + indexed_outputs.len() as u32;
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
        // Create ConvertDescriptions
        let shielded_converts = if !indexed_converts.is_empty() {
            let anchor = self
                .convert_anchor
                .expect("convert anchor was set if converts were added");
            indexed_converts
                .into_iter()
                .enumerate()
                .map(|(i, (pos, convert))| {
                    let (zkproof, cv) = prover
                        .convert_proof(
                            &mut ctx,
                            convert.allowed.clone(),
                            convert.value,
                            anchor,
                            convert.merkle_path.clone(),
                        )
                        .map_err(|_| Error::ConvertProof)?;

                    // Record the post-randomized spend location
                    tx_metadata.convert_indices[*pos] = i;

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
        } else { vec![] };
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

                        let rseed = generate_random_rseed(&params, target_height, &mut rng);

                        (
                            payment_address,
                            Note {
                                asset_type: AssetType::new(b"dummy").unwrap(),
                                g_d,
                                pk_d,
                                rseed,
                                value: 0,
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
        use std::convert::TryFrom;

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
                shielded_outputs: self.shielded_outputs,
                value_balance: self.value_balance,
                authorization: Authorized { binding_sig },
            },
            self.authorization.tx_metadata,
        ))
    }
}
/// Reports on the progress made by the builder towards building a transaction.
pub struct Progress {
    /// The number of steps completed.
    cur: u32,
    /// The expected total number of steps (as of this progress update), if known.
    end: Option<u32>,
}

impl Progress {
    pub fn new(cur: u32, end: Option<u32>) -> Self {
        Self { cur, end }
    }

    /// Returns the number of steps completed so far while building the transaction.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn cur(&self) -> u32 {
        self.cur
    }

    /// Returns the total expected number of steps before this transaction will be ready,
    /// or `None` if the end is unknown as of this progress update.
    ///
    /// Note that each step may not be of the same complexity/duration.
    pub fn end(&self) -> Option<u32> {
        self.end
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        consensus::{self, 
            testing::{arb_branch_id, arb_height},
            TEST_NETWORK, TestNetwork,
        },
        merkle_tree::{testing::arb_commitment_tree, IncrementalWitness},
        primitives::Diversifier,
        prover::{mock::MockTxProver, TxProver},
        sapling::testing::{arb_node, arb_note, arb_positive_note_value},
        transaction::{amount::{Amount, MAX_MONEY}, Authorized, Bundle},
        zip32::{ExtendedSpendingKey, ExtendedFullViewingKey, testing::arb_extended_spending_key},
    };

    use super::SaplingBuilder;

    #[test]
    fn fails_on_negative_change() {
        let mut rng = rand_core::OsRng;

        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        {
            let builder = SaplingBuilder::<TestNetwork>::new(0);
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(super::Error::ChangeIsNegative(Amount::from_pair(zec(), -10000).unwrap()))
            );
        } 
        let extfvk = ExtendedFullViewingKey::from(&extsk);
        let ovk = Some(extfvk.fvk.ovk);
        let to = extfvk.default_address().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = SaplingBuilder::<TestNetwork>::new(0);
            builder
                .add_output(
                    ovk,
                    zec(),
                    50000,
                    None,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(super::Error::ChangeIsNegative(Amount::from_pair(zec(), -60000).unwrap()))
            );
        }
        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.0001 t-ZEC fee
        {
            let mut builder = SaplingBuilder::<TestNetwork>::new(0);
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    zec(),
                    50000,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_pair(zec(), -60000).unwrap()))
            );
        }

        let note1 = to
            .create_note(zec(), 59999, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu1 = Node::new(note1.cmu().to_repr());
        let mut tree = CommitmentTree::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.00059999 z-ZEC in
        {
            let mut builder = SaplingBuilder::<TestNetwork>::new(0);
            builder
                .add_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_output(
                    ovk.clone(),
                    to,
                    zec(),
                    30000,
                    None,
                )
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    zec(),
                    20000,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(Error::ChangeIsNegative(Amount::from_pair(zec(), -1).unwrap()))
            );
        } 
        let note2 = to
        .create_note(zec(), 1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
        .unwrap();
    let cmu2 = Node::new(note2.cmu().to_repr());
    tree.append(cmu2).unwrap();
    witness1.append(cmu2).unwrap();
    let witness2 = IncrementalWitness::from_tree(&tree);

    // Succeeds if there is sufficient input
    // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
    //
    // (Still fails because we are using a MockTxProver which doesn't correctly
    // compute bindingSig.)
    {
        let mut builder = SaplingBuilder::<TestNetwork>::new(0);
        builder
            .add_sapling_spend(
                extsk.clone(),
                *to.diversifier(),
                    note1,
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_spend(extsk, *to.diversifier(), note2, witness2.path().unwrap())
                .unwrap();
            builder
                .add_sapling_output(ovk, to, zec(), 30000, None)
                .unwrap();
            builder
                .add_transparent_output(
                    &TransparentAddress::PublicKey([0; 20]),
                    zec(),
                    20000,
                )
                .unwrap();
            assert_eq!(
                builder.build(consensus::BranchId::Sapling, &MockTxProver),
                Err(super::Error::BindingSig)
            )
        }
    }

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
            target_height in arb_branch_id().prop_flat_map(|b| arb_height(b, &TEST_NETWORK)),
            rng_seed in prop::array::uniform32(any::<u8>()),
            fake_sighash_bytes in prop::array::uniform32(any::<u8>()),
        ) -> Bundle<Authorized> {
            let mut builder = SaplingBuilder::new(TEST_NETWORK, target_height.unwrap());
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
            let mut ctx = prover.new_sapling_proving_context();

            let bundle = builder.build(
                &prover,
                &mut ctx,
                &mut rng,
                target_height.unwrap(),
                None
            ).unwrap().unwrap();

            let (bundle, _) = bundle.apply_signatures(
                &prover,
                &mut ctx,
                &mut rng,
                &fake_sighash_bytes,
            ).unwrap();

            bundle
        }
    }
}

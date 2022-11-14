//! Structs for building transactions.

use std::cmp::Ordering;
use std::convert::Infallible;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::sync::mpsc::Sender;

use secp256k1::PublicKey as TransparentAddress;

use rand::{rngs::OsRng, CryptoRng, RngCore};

use crate::asset_type::AssetType;
use crate::{
    consensus::{self, BlockHeight, BranchId},
    keys::OutgoingViewingKey,
    merkle_tree::MerklePath,
    primitives::Note,
    primitives::{Diversifier, PaymentAddress},
    prover::TxProver,
    sapling::Node,
    //legacy::TransparentAddress,
    transaction::memo::MemoBytes,
    transaction::{
        amount::Amount,
        Authorized,
        TransactionData,
        //components::{

        //    sapling::{
        //        self,
        //builder::sapling::{sapling::SaplingBuilder, SaplingMetadata},
        //    },
        //    transparent::{self, builder::transparent::TransparentBuilder},
        //},
        //fees::FeeRule,
        //sighash::{signature_hash, SignableInput},
        //Transaction, TransactionData, TxVersion, Unauthorized,
        Unauthorized,
    },
    zip32::ExtendedSpendingKey,
};

use super::amount::MAX_MONEY;
use super::sighash::signature_hash;
use super::sighash::SignableInput;
use super::txid::TxIdDigester;

const DEFAULT_TX_EXPIRY_DELTA: u32 = 20;

pub mod sapling;
pub mod transparent;
//use sapling::{sapling::SaplingBuilder, SaplingMetadata};

/// Errors that can occur during transaction construction.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Insufficient funds were provided to the transaction builder; the given
    /// additional amount is required in order to construct the transaction.
    InsufficientFunds(Amount),
    /// The transaction has inputs in excess of outputs and fees; the user must
    /// add a change output.
    ChangeRequired(Amount),
    /// An overflow or underflow occurred when computing value balances
    InvalidAmount,
    /// An error occurred in constructing the transparent parts of a transaction.
    TransparentBuild(transparent::Error),
    /// An error occurred in constructing the Sapling parts of a transaction.
    SaplingBuild(sapling::Error),
    /// An error occurred in constructing the TZE parts of a transaction.
    #[cfg(feature = "zfuture")]
    TzeBuild(tze::builder::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InsufficientFunds(amount) => write!(
                f,
                "Insufficient funds for transaction construction; need an additional {:?} zatoshis",
                amount
            ),
            Error::ChangeRequired(amount) => write!(
                f,
                "The transaction requires an additional change output of {:?} zatoshis",
                amount
            ),
            Error::InvalidAmount => write!(f, "Invalid amount (overflow or underflow)"),
            Error::TransparentBuild(err) => err.fmt(f),
            Error::SaplingBuild(err) => err.fmt(f),
            #[cfg(feature = "zfuture")]
            Error::TzeBuild(err) => err.fmt(f),
        }
    }
}

impl error::Error for Error {}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Error {
        unreachable!()
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

/// Generates a [`Transaction`] from its inputs and outputs.
pub struct Builder<R> {
    rng: R,
    transparent_builder: transparent::TransparentBuilder,
    sapling_builder: sapling::SaplingBuilder,
    progress_notifier: Option<Sender<Progress>>,
}
/*
impl<'a, R> Builder<'a, R> {


    /// Returns the set of transparent inputs currently committed to be consumed
    /// by the transaction.
    pub fn transparent_inputs(&self) -> &[impl transparent::fees::InputView] {
        self.transparent_builder.inputs()
    }

    /// Returns the set of transparent outputs currently set to be produced by
    /// the transaction.
    pub fn transparent_outputs(&self) -> &[impl transparent::fees::OutputView] {
        self.transparent_builder.outputs()
    }

    /// Returns the set of Sapling inputs currently committed to be consumed
    /// by the transaction.
    pub fn sapling_inputs(&self) -> &[impl sapling::fees::InputView] {
        self.sapling_builder.inputs()
    }

    /// Returns the set of Sapling outputs currently set to be produced by
    /// the transaction.
    pub fn sapling_outputs(&self) -> &[impl sapling::fees::OutputView] {
        self.sapling_builder.outputs()
    }
}*/

impl<'a> Builder<OsRng> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height,
    /// using default values for general transaction fields and the default OS random.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new() -> Self {
        Builder::new_with_rng(OsRng)
    }
}

impl<'a, R: RngCore + CryptoRng> Builder<R> {
    /// Creates a new `Builder` targeted for inclusion in the block with the given height
    /// and randomness source, using default values for general transaction fields.
    ///
    /// # Default values
    ///
    /// The expiry height will be set to the given height plus the default transaction
    /// expiry delta (20 blocks).
    pub fn new_with_rng(rng: R) -> Builder<R> {
        Self::new_internal(rng)
    }
}

impl<'a, R: RngCore> Builder<R> {
    /// Common utility function for builder construction.
    ///
    /// WARNING: THIS MUST REMAIN PRIVATE AS IT ALLOWS CONSTRUCTION
    /// OF BUILDERS WITH NON-CryptoRng RNGs
    fn new_internal(rng: R) -> Builder<R> {
        Builder {
            rng,
            transparent_builder: transparent::TransparentBuilder::empty(),
            sapling_builder: sapling::SaplingBuilder::new(),
            progress_notifier: None,
        }
    }

    /// Adds a Sapling note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the same anchor as the
    /// paths for previous Sapling notes.
    pub fn add_sapling_spend(
        &mut self,
        extsk: ExtendedSpendingKey,
        diversifier: Diversifier,
        note: Note,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        self.sapling_builder
            .add_spend(&mut self.rng, extsk, diversifier, note, merkle_path)
            .map_err(Error::SaplingBuild)
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        if value > MAX_MONEY.try_into().unwrap() {
            return Err(Error::InvalidAmount);
        }
        self.sapling_builder
            .add_output(&mut self.rng, ovk, to, asset_type, value, memo)
            .map_err(Error::SaplingBuild)
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(
        &mut self,
        to: &TransparentAddress,
        asset_type: AssetType,
        value: i64,
    ) -> Result<(), Error> {
        if value < -MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        self.transparent_builder
            .add_output(to, asset_type, value)
            .map_err(Error::TransparentBuild)
    }

    /// Sets the notifier channel, where progress of building the transaction is sent.
    ///
    /// An update is sent after every Spend or Output is computed, and the `u32` sent
    /// represents the total steps completed so far. It will eventually send number of
    /// spends + outputs. If there's an error building the transaction, the channel is
    /// closed.
    pub fn with_progress_notifier(&mut self, progress_notifier: Sender<Progress>) {
        self.progress_notifier = Some(progress_notifier);
    }

    /// Returns the sum of the transparent, Sapling, and TZE value balances.
    fn value_balance(&self) -> Result<Amount, Error> {
        let value_balances = [
            self.transparent_builder
                .value_balance()
                .ok_or(Error::InvalidAmount)?,
            self.sapling_builder.value_balance(),
        ];

        Ok(value_balances[0].clone() + value_balances[1].clone())
        //.into_iter()
        //.sum::<Amount>()
        //.ok_or(Error::InvalidAmount)
    }

    /// Builds a transaction from the configured spends and outputs.
    ///
    /// Upon success, returns a tuple containing the final transaction, and the
    /// [`SaplingMetadata`] generated during the build process.
    pub fn build(
        self,
        prover: &impl TxProver,
    ) -> Result<(TransactionData<Authorized>, sapling::SaplingMetadata), Error> {
        //
        // Consistency checks
        //

        // After fees are accounted for, the value balance of the transaction must be zero.
        let balance_after_fees = (self.value_balance()?); //.ok_or(Error::InvalidAmount)?;

        /*
        TODO
        match balance_after_fees.cmp(&Amount::zero()) {
            Ordering::Less => {
                return Err(Error::InsufficientFunds(-balance_after_fees));
            }
            Ordering::Greater => {
                return Err(Error::ChangeRequired(balance_after_fees));
            }
            Ordering::Equal => (),
        };*/

        let transparent_bundle = self.transparent_builder.build();

        let mut rng = self.rng;
        let mut ctx = prover.new_sapling_proving_context();
        let sapling_bundle = self
            .sapling_builder
            .build(prover, &mut ctx, &mut rng, self.progress_notifier.as_ref())
            .map_err(Error::SaplingBuild)?;

        let unauthed_tx: TransactionData<Unauthorized> = TransactionData {
            transparent_bundle,
            sapling_bundle,
        };

        //
        // Signatures -- everything but the signatures must already have been added.
        //
        let txid_parts = unauthed_tx.digest(TxIdDigester);

        let transparent_bundle = unauthed_tx
            .transparent_bundle
            .clone()
            .map(|b| b.apply_signatures());

        // the commitment being signed is shared across all Sapling inputs; once
        // V4 transactions are deprecated this should just be the txid, but
        // for now we need to continue to compute it here.
        let shielded_sig_commitment =
            signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

        let (sapling_bundle, tx_metadata) = match unauthed_tx
            .sapling_bundle
            .map(|b| {
                b.apply_signatures(prover, &mut ctx, &mut rng, shielded_sig_commitment.as_ref())
            })
            .transpose()
            .map_err(Error::SaplingBuild)?
        {
            Some((bundle, meta)) => (Some(bundle), meta),
            None => (None, sapling::SaplingMetadata::empty()),
        };

        let authorized_tx = TransactionData {
            transparent_bundle,
            sapling_bundle,
        };

        // The unwrap() here is safe because the txid hashing
        // of freeze() should be infalliable.
        Ok((authorized_tx, tx_metadata))
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
mod testing {
    use rand::RngCore;

    use super::{sapling::SaplingMetadata, Builder, Error};
    use crate::{
        consensus::{self, BlockHeight},
        prover::mock::MockTxProver,
        transaction::{Authorized, TransactionData},
    };

    impl<'a, R: RngCore> Builder<R> {
        /// Creates a new `Builder` targeted for inclusion in the block with the given height
        /// and randomness source, using default values for general transaction fields.
        ///
        /// # Default values
        ///
        /// The expiry height will be set to the given height plus the default transaction
        /// expiry delta (20 blocks).
        ///
        /// WARNING: DO NOT USE IN PRODUCTION
        pub fn test_only_new_with_rng(rng: R) -> Builder<R> {
            Self::new_internal(rng)
        }

        pub fn mock_build(self) -> Result<(TransactionData<Authorized>, SaplingMetadata), Error> {
            self.build(&MockTxProver)
        }
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use rand_core::OsRng;
    use secp256k1::Secp256k1;

    use crate::{
        asset_type::AssetType,
        consensus::{NetworkUpgrade, Parameters, TEST_NETWORK},
        merkle_tree::{CommitmentTree, IncrementalWitness},
        primitives::Rseed,
        transaction::{
            amount::Amount,
            builder::{sapling, transparent},
            //sapling::builder::{self as build_s},
            //transparent::builder::{self as build_t},
            memo::MemoBytes,
            TransparentAddress,
        },
        zip32::ExtendedSpendingKey,
    };

    use super::{Builder, Error};
    /*
    #[test]
    fn fails_on_negative_output() {
        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = dfvk.fvk().ovk;
        let to = dfvk.default_address().1;

        let sapling_activation_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .unwrap();

        let mut builder = Builder::new();
        assert_eq!(
            builder.add_sapling_output(
                Some(ovk),
                to,
                Amount::from_i64(-1).unwrap(),
                MemoBytes::empty()
            ),
            Err(Error::SaplingBuild(build_s::Error::InvalidAmount))
        );
    }*/

    /// Generate ZEC asset type
    fn zec() -> AssetType {
        AssetType::new(b"ZEC").unwrap()
    }

    #[test]
    fn binding_sig_present_if_shielded_spend() {
        let (_, transparent_address) = Secp256k1::new().generate_keypair(&mut OsRng);

        let extsk = ExtendedSpendingKey::master(&[]);
        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let to = dfvk.default_address().1;

        let mut rng = OsRng;

        let note1 = to
            .create_note(
                zec(),
                50000,
                Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
            )
            .unwrap();
        let cmu1 = note1.commitment();
        let mut tree = CommitmentTree::empty();
        tree.append(cmu1).unwrap();
        let witness1 = IncrementalWitness::from_tree(&tree);

        let mut builder = Builder::new();

        // Create a tx with a sapling spend. binding_sig should be present
        builder
            .add_sapling_spend(extsk, *to.diversifier(), note1, witness1.path().unwrap())
            .unwrap();

        builder
            .add_transparent_output(&transparent_address, zec(), 49000)
            .unwrap();

        // Expect a binding signature error, because our inputs aren't valid, but this shows
        // that a binding signature was attempted
        assert_eq!(
            builder.mock_build(),
            Err(Error::SaplingBuild(sapling::Error::BindingSig))
        );
    }

    /*#[test]
    fn fails_on_negative_transparent_output() {
        let transparent_address = &TransparentAddress::from_slice(&[0; 33]).unwrap();
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Canopy)
            .unwrap();
        let mut builder = Builder::new();
        assert_eq!(
            builder.add_transparent_output(
                transparent_address,
                zec(),
                Amount::from_i64(-1).unwrap(),
            ),
            Err(Error::TransparentBuild(transparent::Error::InvalidAmount))
        );
    }*/

    #[test]
    fn fails_on_negative_change() {
        let mut rng = OsRng;

        let DEFAULT_FEE = Amount::zero();
        let (_, transparent_address) = Secp256k1::new().generate_keypair(&mut OsRng);
        // Just use the master key as the ExtendedSpendingKey for this test
        let extsk = ExtendedSpendingKey::master(&[]);
        let tx_height = TEST_NETWORK
            .activation_height(NetworkUpgrade::Canopy)
            .unwrap();

        // Fails with no inputs or outputs
        // 0.0001 t-ZEC fee
        /*{
            let builder = Builder::new();
            assert_eq!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(DEFAULT_FEE))
            );
        }*/

        let dfvk = extsk.to_diversifiable_full_viewing_key();
        let ovk = Some(dfvk.fvk().ovk);
        let to = dfvk.default_address().1;

        // Fail if there is only a Sapling output
        // 0.0005 z-ZEC out, 0.00001 t-ZEC fee
        {
            let mut builder = Builder::new();
            builder
                .add_sapling_output(ovk, to.clone(), zec(), 50000, MemoBytes::empty())
                .unwrap();
            assert_eq!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(
                    (Amount::from_pair(zec(), 50000).unwrap() + &DEFAULT_FEE)
                ))
            );
        }

        // Fail if there is only a transparent output
        // 0.0005 t-ZEC out, 0.00001 t-ZEC fee
        {
            let mut builder = Builder::new();
            builder
                .add_transparent_output(&transparent_address, zec(), 50000)
                .unwrap();
            assert_eq!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(
                    (Amount::from_pair(zec(), 50000).unwrap() + &DEFAULT_FEE)
                ))
            );
        }

        let note1 = to
            .create_note(
                zec(),
                50999,
                Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)),
            )
            .unwrap();
        let cmu1 = note1.commitment();
        let mut tree = CommitmentTree::empty();
        tree.append(cmu1).unwrap();
        let mut witness1 = IncrementalWitness::from_tree(&tree);

        // Fail if there is insufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.00001 t-ZEC fee, 0.00050999 z-ZEC in
        {
            let mut builder = Builder::new();
            builder
                .add_sapling_spend(
                    extsk.clone(),
                    *to.diversifier(),
                    note1.clone(),
                    witness1.path().unwrap(),
                )
                .unwrap();
            builder
                .add_sapling_output(ovk, to.clone(), zec(), 30000, MemoBytes::empty())
                .unwrap();
            builder
                .add_transparent_output(&transparent_address, zec(), 20000)
                .unwrap();
            assert_eq!(
                builder.mock_build(),
                Err(Error::InsufficientFunds(
                    Amount::from_pair(zec(), 1).unwrap()
                ))
            );
        }

        let note2 = to
            .create_note(zec(), 1, Rseed::BeforeZip212(jubjub::Fr::random(&mut rng)))
            .unwrap();
        let cmu2 = note2.commitment();
        tree.append(cmu2).unwrap();
        witness1.append(cmu2).unwrap();
        let witness2 = IncrementalWitness::from_tree(&tree);

        // Succeeds if there is sufficient input
        // 0.0003 z-ZEC out, 0.0002 t-ZEC out, 0.0001 t-ZEC fee, 0.0006 z-ZEC in
        //
        // (Still fails because we are using a MockTxProver which doesn't correctly
        // compute bindingSig.)
        {
            let mut builder = Builder::new();
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
                .add_sapling_output(ovk, to, zec(), 30000, MemoBytes::empty())
                .unwrap();
            builder
                .add_transparent_output(&transparent_address, zec(), 20000)
                .unwrap();
            assert_eq!(
                builder.mock_build(),
                Err(Error::SaplingBuild(sapling::Error::BindingSig))
            )
        }
    }
}

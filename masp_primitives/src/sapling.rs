//! Structs and constants specific to the Sapling shielded pool.

pub mod group_hash;
pub mod keys;
pub mod note;
pub mod note_encryption;
pub mod pedersen_hash;
pub mod prover;
pub mod redjubjub;
pub mod tree;
pub mod util;
pub mod value;

use group::GroupEncoding;
use rand_core::{CryptoRng, RngCore};
use std::convert::TryFrom;

use crate::{constants::SPENDING_KEY_GENERATOR, transaction::components::amount::MAX_MONEY};

use self::redjubjub::{PrivateKey, PublicKey, Signature};

pub use crate::sapling::tree::{Node, SAPLING_COMMITMENT_TREE_DEPTH};

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
    data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

    // Do the signing
    rsk.sign(&data_to_be_signed, rng, SPENDING_KEY_GENERATOR)
}

pub use crate::sapling::keys::{
    Diversifier, NullifierDerivingKey, PaymentAddress, ProofGenerationKey, SaplingIvk, ViewingKey,
};
pub use crate::sapling::value::ValueCommitment;

pub use crate::sapling::note::nullifier::Nullifier;
pub use crate::sapling::note::Rseed;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteValue(u64);

impl TryFrom<u64> for NoteValue {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value <= MAX_MONEY as u64 {
            Ok(NoteValue(value))
        } else {
            Err(())
        }
    }
}

impl From<NoteValue> for u64 {
    fn from(value: NoteValue) -> u64 {
        value.0
    }
}
pub use crate::sapling::note::Note;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;
    use std::cmp::min;

    use crate::transaction::components::amount::MAX_MONEY;

    use super::{
        keys::testing::arb_full_viewing_key, Diversifier, Node, Note, NoteValue, PaymentAddress,
        Rseed, SaplingIvk,
    };

    prop_compose! {
        pub fn arb_note_value()(value in 0u64..=MAX_MONEY as u64) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    prop_compose! {
        /// The
        pub fn arb_positive_note_value(bound: u64)(
            value in 1u64..=(min(bound, MAX_MONEY as u64))
        ) -> NoteValue {
            NoteValue::try_from(value).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_incoming_viewing_key()(fvk in arb_full_viewing_key()) -> SaplingIvk {
            fvk.vk.ivk()
        }
    }

    pub fn arb_payment_address() -> impl Strategy<Value = PaymentAddress> {
        arb_incoming_viewing_key().prop_flat_map(|ivk: SaplingIvk| {
            any::<[u8; 11]>().prop_filter_map(
                "Sampled diversifier must generate a valid Sapling payment address.",
                move |d| ivk.to_payment_address(Diversifier(d)),
            )
        })
    }

    prop_compose! {
        pub fn arb_node()(value in prop::array::uniform32(prop::num::u8::ANY)) -> Node {
            Node {
                repr: value
            }
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

#[cfg(test)]
mod tests {
    use crate::{
        sapling::testing::{arb_note, arb_positive_note_value},
        sapling::Note,
        transaction::components::amount::MAX_MONEY,
    };
    use borsh::{BorshDeserialize, BorshSerialize};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn note_serialization(note in arb_positive_note_value(MAX_MONEY as u64).prop_flat_map(arb_note)) {
            // BorshSerialize
            let borsh = note.try_to_vec().unwrap();
            // BorshDeserialize
            let de_note: Note = BorshDeserialize::deserialize(&mut borsh.as_ref()).unwrap();
            prop_assert_eq!(note, de_note);
        }
    }
}

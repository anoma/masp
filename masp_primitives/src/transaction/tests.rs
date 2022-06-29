use ff::Field;
use rand_core::OsRng;
use super::{Transaction, TransactionData};
use crate::{constants::SPENDING_KEY_GENERATOR, redjubjub::PrivateKey};
use crate::transaction::components::{TxIn as Ti, TxOut as To};
use std::io::{self, Read, Write};
use borsh::{BorshDeserialize, BorshSerialize};
use blake2b_simd;

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Hash, Ord, BorshDeserialize, BorshSerialize)]
pub struct Txin {}

impl Ti for Txin {
    fn read(mut _reader: &mut impl Read) -> io::Result<Self> {
        Ok(Self{})
    }

    fn write(&self, mut _writer: &mut impl Write) -> io::Result<()> {
        Ok(())
    }

    fn write_prevout(&self, _writer: &mut impl Write) -> io::Result<()> {
        Ok(())
    }

    fn sequence(&self) -> u32 {
        0
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Hash, Ord, BorshDeserialize, BorshSerialize)]
pub struct Txout {}

impl To for Txout {
    fn read(mut _reader: &mut impl Read) -> io::Result<Self> {
        Ok(Self{})
    }

    fn write(&self, mut _writer: &mut impl Write) -> io::Result<()> {
        Ok(())
    }

    fn sighash(&self) -> blake2b_simd::Hash {
        let data = vec![];
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"TEST_PERSONALIZATION")
            .hash(&data)
    }
}

#[test]
fn tx_read_write() {
    let data = &self::data::tx_read_write::TX_READ_WRITE;
    let mut rdr = &data[..];
    let tx = Transaction::<Txin, Txout>::read(&mut rdr).unwrap();
    assert_eq!(
        format!("{}", tx.txid()),
        "1a8f89899834a3e7127cd9842707218368e0056b9d488a3248a4b072ac75cb75"
    );

    let mut encoded = Vec::with_capacity(data.len());
    tx.write(&mut encoded).unwrap();
    assert_eq!(&data[..], &encoded[..]);
}

#[test]
fn tx_write_rejects_unexpected_joinsplit_pubkey() {
    // Succeeds without a JoinSplit pubkey
    assert!( TransactionData::<Txin, Txout>::new().freeze().is_ok());

    // Fails with an unexpected JoinSplit pubkey
    {
        let mut tx = TransactionData::<Txin, Txout>::new();
        tx.joinsplit_pubkey = Some([0; 32]);
        assert!(tx.freeze().is_err());
    }
}

#[test]
fn tx_write_rejects_unexpected_joinsplit_sig() {
    // Succeeds without a JoinSplit signature
    assert!( TransactionData::<Txin, Txout>::new().freeze().is_ok());

    // Fails with an unexpected JoinSplit signature
    {
        let mut tx = TransactionData::<Txin, Txout>::new();
        tx.joinsplit_sig = Some([0; 64]);
        assert!(tx.freeze().is_err());
    }
}

#[test]
fn tx_write_rejects_unexpected_binding_sig() {
    // Succeeds without a binding signature
    assert!( TransactionData::<Txin, Txout>::new().freeze().is_ok());

    // Fails with an unexpected binding signature
    {
        let mut rng = OsRng;
        let sk = PrivateKey(jubjub::Fr::random(&mut rng));
        let sig = sk.sign(b"Foo bar", &mut rng, SPENDING_KEY_GENERATOR);

        let mut tx = TransactionData::<Txin, Txout>::new();
        tx.binding_sig = Some(sig);
        assert!(tx.freeze().is_err());
    }
}

mod data;
// #[test]
// fn zip_0143() {
//     for tv in self::data::zip_0143::make_test_vectors() {
//         let mut rdr = &tv.tx[..];
//         let tx =  Transaction::<Txin, Txout>::read(&mut rdr).unwrap();
//         let transparent_input = tv.transparent_input.map(|n| {
//             (
//                 n as usize,
//                 &tv.script_code,
//                 tv.asset_type,
//                 tv.amount as u64,
//             )
//         });

//         assert_eq!(
//             signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, transparent_input),
//             tv.sighash
//         );
//     }
// }

// #[test]
// fn zip_0243() {
//     for tv in self::data::zip_0243::make_test_vectors() {
//         let mut rdr = &tv.tx[..];
//         let tx =  Transaction::<Txin, Txout>::read(&mut rdr).unwrap();
//         let transparent_input = tv.transparent_input.map(|n| {
//             (
//                 n as usize,
//                 &tv.script_code,
//                 tv.asset_type,
//                 tv.amount as u64,
//             )
//         });

//         assert_eq!(
//             signature_hash(&tx, tv.consensus_branch_id, tv.hash_type, transparent_input),
//             tv.sighash
//         );
//     }
// }

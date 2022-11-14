//! Types and functions for building transparent transaction components.

use secp256k1::PublicKey as TransparentAddress;
use std::{fmt, ops::Sub};

use crate::{
    asset_type::AssetType,
    //,
    transaction::{
        amount::{Amount, MAX_MONEY},
        //components::{

        //    transparent::{self, fees, Authorization, Authorized, Bundle, TxIn, TxOut},
        //},
        //sighash::TransparentAuthorizingContext,
        //OutPoint,
        builder::sapling::{ConvertDescriptionInfo, SaplingOutputInfo, SpendDescriptionInfo},
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAddress,
    InvalidAmount,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidAddress => write!(f, "Invalid address"),
            Error::InvalidAmount => write!(f, "Invalid amount"),
        }
    }
}

pub struct TransparentBuilder {
    vout: Vec<TxOut>,
}

pub trait Authorization: fmt::Debug {
    //type ScriptSig: fmt::Debug + Clone + PartialEq;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Authorized;

impl Authorization for Authorized {
    //type ScriptSig = Script;
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    //fn map_script_sig(&self, s: A::ScriptSig) -> B::ScriptSig;
    fn map_authorization(&self, s: A) -> B;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bundle<A: Authorization> {
    pub vout: Vec<TxOut>,
    pub authorization: A,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Unauthorized {}

impl Authorization for Unauthorized {}

impl TransparentBuilder {
    /// Constructs a new TransparentBuilder
    pub fn empty() -> Self {
        TransparentBuilder { vout: vec![] }
    }

    /// Returns the transparent outputs that will be produced by the transaction being constructed.
    pub fn outputs(&self) -> &[TxOut] {
        &self.vout
    }

    pub fn add_output(
        &mut self,
        transparent_address: &TransparentAddress,
        asset_type: AssetType,
        value: i64,
    ) -> Result<(), Error> {
        if value < -MAX_MONEY {
            return Err(Error::InvalidAmount);
        }

        self.vout.push(TxOut {
            asset_type,
            value,
            transparent_address: *transparent_address,
        });

        Ok(())
    }

    pub fn value_balance(&self) -> Option<Amount> {
        //#[cfg(not(feature = "transparent-inputs"))]
        let input_sum = Amount::<AssetType>::zero();

        Some(
            input_sum
                - self
                    .vout
                    .iter()
                    .map(|vo| Amount::from_pair(vo.asset_type, vo.value).unwrap())
                    .sum::<Amount>(),
        )
    }

    pub fn build(self) -> Option<Bundle<Unauthorized>> {
        if self.vout.is_empty() {
            None
        } else {
            Some(Bundle {
                vout: self.vout,
                authorization: Unauthorized {
                    #[cfg(feature = "transparent-inputs")]
                    secp: self.secp,
                    #[cfg(feature = "transparent-inputs")]
                    inputs: self.inputs,
                },
            })
        }
    }
}

impl Bundle<Unauthorized> {
    pub fn apply_signatures(
        self,
        #[cfg(feature = "transparent-inputs")] mtx: &TransactionData<tx::Unauthorized>,
        #[cfg(feature = "transparent-inputs")] txid_parts_cache: &TxDigests<Blake2bHash>,
    ) -> Bundle<Authorized> {
        #[cfg(feature = "transparent-inputs")]
        let script_sigs = self
            .authorization
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                let sighash = signature_hash(
                    mtx,
                    &SignableInput::Transparent {
                        hash_type: SIGHASH_ALL,
                        index,
                        script_code: &info.coin.script_pubkey, // for p2pkh, always the same as script_pubkey
                        script_pubkey: &info.coin.script_pubkey,
                        value: info.coin.value,
                    },
                    txid_parts_cache,
                );

                let msg = secp256k1::Message::from_slice(sighash.as_ref()).expect("32 bytes");
                let sig = self.authorization.secp.sign_ecdsa(&msg, &info.sk);

                // Signature has to have "SIGHASH_ALL" appended to it
                let mut sig_bytes: Vec<u8> = sig.serialize_der()[..].to_vec();
                sig_bytes.extend([SIGHASH_ALL as u8]);

                // P2PKH scriptSig
                Script::default() << &sig_bytes[..] << &info.pubkey[..]
            });

        Bundle {
            vout: self.vout,
            authorization: Authorized,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialOrd, PartialEq, Ord, Eq)]
pub struct TxOut {
    pub asset_type: AssetType,
    pub value: i64,
    pub transparent_address: TransparentAddress,
}

impl TxOut {
    pub fn read<R: Read>(mut reader: &mut R) -> io::Result<Self> {
        let asset_type = {
            let mut tmp = [0u8; 32];
            reader.read_exact(&mut tmp)?;
            AssetType::from_identifier(&tmp)
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))?;
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            i64::from_le_bytes(tmp)
        };

        let mut tmp = [0u8; 33];
        reader.read_exact(&mut tmp)?;
        let transparent_address = TransparentAddress::from_slice(&tmp)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad public key"))?;

        Ok(TxOut {
            asset_type,
            value,
            transparent_address,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.asset_type.get_identifier())?;
        writer.write_all(&self.value.to_le_bytes())?;
        writer.write_all(&self.transparent_address.serialize())
    }
}

impl BorshDeserialize for TxOut {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl BorshSerialize for TxOut {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}

//! Structs representing the components within Zcash transactions.

use borsh::{BorshDeserialize, BorshSerialize};
use secp256k1::PublicKey as TransparentAddress;
use std::fmt::{self, Debug};
use std::io::{self, Read, Write};

use crate::asset_type::AssetType;

use super::amount::{Amount, BalanceError, MAX_MONEY};

pub mod builder;
pub mod fees;

pub trait Authorization: fmt::Debug {
    type TransparentSig: fmt::Debug + Clone + PartialEq;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Authorized;

impl Authorization for Authorized {
    type TransparentSig = ();
}

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_authorization(&self, s: A) -> B;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle<A: Authorization> {
    pub vin: Vec<TxIn>,
    pub vout: Vec<TxOut>,
    pub authorization: A,
}

impl<A: Authorization> Bundle<A> {
    pub fn map_authorization<B: Authorization, F: MapAuth<A, B>>(self, f: F) -> Bundle<B> {
        Bundle {
            vin: self.vin,
            vout: self.vout,
            authorization: f.map_authorization(self.authorization),
        }
    }

    /// The amount of value added to or removed from the transparent pool by the action of this
    /// bundle. A positive value represents that the containing transaction has funds being
    /// transferred out of the transparent pool into shielded pools or to fees; a negative value
    /// means that the containing transaction has funds being transferred into the transparent pool
    /// from the shielded pools.
    pub fn value_balance<E, F>(&self) -> Result<Amount, E>
    where
        E: From<BalanceError>,
    {
        let input_sum = self
            .vin
            .iter()
            .map(|p| {
                if p.value >= 0 {
                    Amount::from_pair(p.asset_type, p.value)
                } else {
                    Err(())
                }
            })
            .sum::<Result<Amount, ()>>()
            .map_err(|_| BalanceError::Overflow)?;

        let output_sum = self
            .vout
            .iter()
            .map(|p| {
                if p.value >= 0 {
                    Amount::from_pair(p.asset_type, p.value)
                } else {
                    Err(())
                }
            })
            .sum::<Result<Amount, ()>>()
            .map_err(|_| BalanceError::Overflow)?;

        // Cannot panic when subtracting two positive i64
        Ok(input_sum - output_sum)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub asset_type: AssetType,
    pub value: i64,
}

impl TxIn {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let asset_type = {
            let mut tmp = [0u8; 32];
            reader.read_exact(&mut tmp)?;
            AssetType::from_identifier(&tmp)
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid asset identifier"))?;
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            i64::from_le_bytes(tmp)
        };
        if value < 0 || value > MAX_MONEY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "value out of range",
            ));
        }

        Ok(TxIn { asset_type, value })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.asset_type.get_identifier())?;
        writer.write_all(&self.value.to_le_bytes())
    }
}

#[derive(Clone, Debug, Hash, PartialOrd, PartialEq, Ord, Eq)]
pub struct TxOut {
    pub asset_type: AssetType,
    pub value: u64,
    pub transparent_address: TransparentAddress,
}

impl TxOut {
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let asset_type = {
            let mut tmp = [0u8; 32];
            reader.read_exact(&mut tmp)?;
            AssetType::from_identifier(&tmp)
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid asset identifier"))?;
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            i64::from_le_bytes(tmp)
        };
        if value < 0 || value > MAX_MONEY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "value out of range",
            ));
        }

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
    /// Returns the address to which the TxOut was sent, if this is a valid P2SH or P2PKH output.
    pub fn recipient_address(&self) -> TransparentAddress {
        self.transparent_address
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

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::transaction::components::amount::testing::arb_nonnegative_amount;

    use super::{Authorized, Bundle, TxIn, TxOut};

    prop_compose! {
        pub fn arb_txin()(amt in arb_nonnegative_amount()) -> TxIn {
            let (asset_type, value) = amt.components().next().unwrap();
            TxIn { asset_type: *asset_type, value: *value }
        }
    }

    prop_compose! {
        pub fn arb_txout()(amt in arb_nonnegative_amount()) -> TxOut {
            let secp = secp256k1::Secp256k1::new();
            let (_, public_key) = secp.generate_keypair(&mut rand_core::OsRng);
            let (asset_type, value) = amt.components().next().unwrap();

            TxOut { asset_type: *asset_type, value: *value, transparent_address : public_key }
        }
    }

    prop_compose! {
        pub fn arb_bundle()(
            vin in vec(arb_txin(), 0..10),
            vout in vec(arb_txout(), 0..10),
        ) -> Option<Bundle<Authorized>> {
            if vout.is_empty() {
                None
            } else {
                Some(Bundle {vin, vout, authorization: Authorized })
            }
        }
    }
}

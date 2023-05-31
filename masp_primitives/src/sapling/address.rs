use super::{
    keys::{Diversifier, DiversifiedTransmissionKey},
    note::{Note, Rseed},
    //value::NoteValue,
};
use crate::asset_type::AssetType;
use borsh::{BorshDeserialize, BorshSerialize};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    io::{self, Write},
    str::FromStr,
};

/// A Sapling payment address.
///
/// # Invariants
///
/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Copy, Debug)]
pub struct PaymentAddress {
    pk_d: DiversifiedTransmissionKey,
    diversifier: Diversifier,
}

impl PartialEq for PaymentAddress {
    fn eq(&self, other: &Self) -> bool {
        self.pk_d == other.pk_d && self.diversifier == other.diversifier
    }
}

impl Eq for PaymentAddress {}

impl PaymentAddress {
    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity.
    pub fn from_parts(diversifier: Diversifier, pk_d: DiversifiedTransmissionKey) -> Option<Self> {
        // Check that the diversifier is valid
        diversifier.g_d()?;

        Self::from_parts_unchecked(diversifier, pk_d)
    }

    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Returns None if `pk_d` is the identity. The caller must check that `diversifier`
    /// is valid for Sapling.
    pub(crate) fn from_parts_unchecked(
        diversifier: Diversifier,
        pk_d: DiversifiedTransmissionKey,
    ) -> Option<Self> {
        if pk_d.is_identity() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Parses a PaymentAddress from bytes.
    pub fn from_bytes(bytes: &[u8; 43]) -> Option<Self> {
        let diversifier = {
            let mut tmp = [0; 11];
            tmp.copy_from_slice(&bytes[0..11]);
            Diversifier(tmp)
        };
        // Check that the diversifier is valid
        diversifier.g_d()?;

        let pk_d = DiversifiedTransmissionKey::from_bytes(bytes[11..43].try_into().unwrap());
        if pk_d.is_some().into() {
            PaymentAddress::from_parts(diversifier, pk_d.unwrap())
        } else {
            None
        }
    }

    /// Returns the byte encoding of this `PaymentAddress`.
    pub fn to_bytes(&self) -> [u8; 43] {
        let mut bytes = [0; 43];
        bytes[0..11].copy_from_slice(&self.diversifier.0);
        bytes[11..].copy_from_slice(&self.pk_d.to_bytes());
        bytes
    }

    /// Returns the [`Diversifier`] for this `PaymentAddress`.
    pub fn diversifier(&self) -> &Diversifier {
        &self.diversifier
    }

    /// Returns `pk_d` for this `PaymentAddress`.
    pub fn pk_d(&self) -> &DiversifiedTransmissionKey {
        &self.pk_d
    }

    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        self.diversifier.g_d()
    }

    pub fn create_note(&self, asset_type: AssetType, value: u64, rseed: Rseed) -> Option<Note> {
        self.g_d().map(|g_d| Note {
            asset_type,
            value,
            rseed,
            g_d,
            pk_d: self.pk_d,
        })
    }
}

impl Display for PaymentAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl FromStr for PaymentAddress {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(|x| io::Error::new(io::ErrorKind::InvalidData, x))?;
        BorshDeserialize::try_from_slice(&vec)
    }
}

impl PartialOrd for PaymentAddress {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}
impl Ord for PaymentAddress {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}
impl Hash for PaymentAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl BorshSerialize for PaymentAddress {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        writer.write(self.to_bytes().as_ref()).and(Ok(()))
    }
}
impl BorshDeserialize for PaymentAddress {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        let data = buf
            .get(..43)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let res = Self::from_bytes(data.try_into().unwrap());
        let pa = res.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
        *buf = &buf[43..];
        Ok(pa)
    }
}

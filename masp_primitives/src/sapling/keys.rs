//! Sapling key components.
//!
//! Implements [section 4.2.2] of the Zcash Protocol Specification.
//!
//! [section 4.2.2]: https://zips.z.cash/protocol/protocol.pdf#saplingkeycomponents

use crate::{
    asset_type::AssetType,
    constants::{self, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    keys::prf_expand,
    sapling::{
        group_hash::group_hash,
        note::{Note, Rseed},
    },
};
use blake2s_simd::Params as Blake2sParams;
use borsh::{BorshDeserialize, BorshSerialize};
use ff::PrimeField;
use group::{Group, GroupEncoding};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
    io::{self, Read, Write},
    str::FromStr,
};
use subtle::CtOption;

/// Errors that can occur in the decoding of Sapling spending keys.
pub enum DecodingError {
    /// The length of the byte slice provided for decoding was incorrect.
    LengthInvalid { expected: usize, actual: usize },
    /// Could not decode the `ask` bytes to a jubjub field element.
    InvalidAsk,
    /// Could not decode the `nsk` bytes to a jubjub field element.
    InvalidNsk,
}

/// An outgoing viewing key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct OutgoingViewingKey(pub [u8; 32]);

/// A Sapling expanded spending key
#[derive(Clone, PartialEq, Eq, Copy)]
pub struct ExpandedSpendingKey {
    pub ask: jubjub::Fr,
    pub nsk: jubjub::Fr,
    pub ovk: OutgoingViewingKey,
}

impl Hash for ExpandedSpendingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ask.to_bytes().hash(state);
        self.nsk.to_bytes().hash(state);
        self.ovk.hash(state);
    }
}

impl ExpandedSpendingKey {
    pub fn from_spending_key(sk: &[u8]) -> Self {
        let ask = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x00]).as_array());
        let nsk = jubjub::Fr::from_bytes_wide(prf_expand(sk, &[0x01]).as_array());
        let mut ovk = OutgoingViewingKey([0u8; 32]);
        ovk.0
            .copy_from_slice(&prf_expand(sk, &[0x02]).as_bytes()[..32]);
        ExpandedSpendingKey { ask, nsk, ovk }
    }

    pub fn proof_generation_key(&self) -> ProofGenerationKey {
        ProofGenerationKey {
            ak: SPENDING_KEY_GENERATOR * self.ask,
            nsk: self.nsk,
        }
    }

    /// Decodes the expanded spending key from its serialized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn from_bytes(b: &[u8]) -> Result<Self, DecodingError> {
        if b.len() != 96 {
            return Err(DecodingError::LengthInvalid {
                expected: 96,
                actual: b.len(),
            });
        }

        let ask = Option::from(jubjub::Fr::from_repr(b[0..32].try_into().unwrap()))
            .ok_or(DecodingError::InvalidAsk)?;
        let nsk = Option::from(jubjub::Fr::from_repr(b[32..64].try_into().unwrap()))
            .ok_or(DecodingError::InvalidNsk)?;
        let ovk = OutgoingViewingKey(b[64..96].try_into().unwrap());

        Ok(ExpandedSpendingKey { ask, nsk, ovk })
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 96];
        reader.read_exact(repr.as_mut())?;
        Self::from_bytes(&repr).map_err(|e| match e {
            DecodingError::InvalidAsk => {
                io::Error::new(io::ErrorKind::InvalidData, "ask not in field")
            }
            DecodingError::InvalidNsk => {
                io::Error::new(io::ErrorKind::InvalidData, "nsk not in field")
            }
            DecodingError::LengthInvalid { .. } => unreachable!(),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.to_bytes())
    }

    /// Encodes the expanded spending key to the its seralized representation
    /// as part of the encoding of the extended spending key as defined in
    /// [ZIP 32](https://zips.z.cash/zip-0032)
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        result[0..32].copy_from_slice(&self.ask.to_repr());
        result[32..64].copy_from_slice(&self.nsk.to_repr());
        result[64..96].copy_from_slice(&self.ovk.0);
        result
    }
}
#[derive(Clone)]
pub struct ProofGenerationKey {
    pub ak: jubjub::SubgroupPoint,
    pub nsk: jubjub::Fr,
}

impl ProofGenerationKey {
    pub fn to_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            ak: self.ak,
            nk: NullifierDerivingKey(constants::PROOF_GENERATION_KEY_GENERATOR * self.nsk),
        }
    }
}

/// A key used to derive the nullifier for a Sapling note.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NullifierDerivingKey(pub jubjub::SubgroupPoint);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ViewingKey {
    pub ak: jubjub::SubgroupPoint,
    pub nk: NullifierDerivingKey,
}

impl Hash for ViewingKey {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.ak.to_bytes().hash(state);
        self.nk.0.to_bytes().hash(state);
    }
}

impl ViewingKey {
    pub fn rk(&self, ar: jubjub::Fr) -> jubjub::SubgroupPoint {
        self.ak + constants::SPENDING_KEY_GENERATOR * ar
    }

    pub fn ivk(&self) -> SaplingIvk {
        let mut h = [0; 32];
        h.copy_from_slice(
            Blake2sParams::new()
                .hash_length(32)
                .personal(constants::CRH_IVK_PERSONALIZATION)
                .to_state()
                .update(&self.ak.to_bytes())
                .update(&self.nk.0.to_bytes())
                .finalize()
                .as_bytes(),
        );

        // Drop the most significant five bits, so it can be interpreted as a scalar.
        h[31] &= 0b0000_0111;

        SaplingIvk(jubjub::Fr::from_repr(h).unwrap())
    }

    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        self.ivk().to_payment_address(diversifier)
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf).and_then(|p| CtOption::new(p, !p.is_identity()))
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = nk.unwrap();

        Ok(ViewingKey {
            ak,
            nk: NullifierDerivingKey(nk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.ak.to_bytes())?;
        writer.write_all(&self.nk.0.to_bytes())?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        self.write(&mut result[..])
            .expect("should be able to serialize a ViewingKey");
        result
    }
}

impl BorshSerialize for ViewingKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::maybestd::io::Result<()> {
        self.write(writer)
    }
}

impl BorshDeserialize for ViewingKey {
    fn deserialize(buf: &mut &[u8]) -> borsh::maybestd::io::Result<Self> {
        Self::read(buf)
    }
}

impl PartialOrd for ViewingKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_bytes().partial_cmp(&other.to_bytes())
    }
}

impl Ord for ViewingKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}
/// A Sapling key that provides the capability to view incoming and outgoing transactions.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct FullViewingKey {
    pub vk: ViewingKey,
    pub ovk: OutgoingViewingKey,
}

impl Display for FullViewingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl FromStr for FullViewingKey {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vec = hex::decode(s).map_err(|x| io::Error::new(std::io::ErrorKind::InvalidData, x))?;
        let mut rdr = vec.as_slice();
        let res = Self::read(&mut rdr)?;
        if !rdr.is_empty() {
            Err(io::Error::from(std::io::ErrorKind::InvalidData))
        } else {
            Ok(res)
        }
    }
}

impl FullViewingKey {
    pub fn from_expanded_spending_key(expsk: &ExpandedSpendingKey) -> Self {
        FullViewingKey {
            vk: ViewingKey {
                ak: SPENDING_KEY_GENERATOR * expsk.ask,
                nk: NullifierDerivingKey(PROOF_GENERATION_KEY_GENERATOR * expsk.nsk),
            },
            ovk: expsk.ovk,
        }
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let ak = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf).and_then(|p| CtOption::new(p, !p.is_identity()))
        };
        let nk = {
            let mut buf = [0u8; 32];
            reader.read_exact(&mut buf)?;
            jubjub::SubgroupPoint::from_bytes(&buf)
        };
        if ak.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ak not of prime order",
            ));
        }
        if nk.is_none().into() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nk not in prime-order subgroup",
            ));
        }
        let ak = ak.unwrap();
        let nk = NullifierDerivingKey(nk.unwrap());

        let mut ovk = [0u8; 32];
        reader.read_exact(&mut ovk)?;

        Ok(FullViewingKey {
            vk: ViewingKey { ak, nk },
            ovk: OutgoingViewingKey(ovk),
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vk.ak.to_bytes())?;
        writer.write_all(&self.vk.nk.0.to_bytes())?;
        writer.write_all(&self.ovk.0)?;

        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut result = [0u8; 96];
        self.write(&mut result[..])
            .expect("should be able to serialize a FullViewingKey");
        result
    }
}

#[derive(Debug, Clone)]
pub struct SaplingIvk(pub jubjub::Fr);

impl SaplingIvk {
    pub fn to_payment_address(&self, diversifier: Diversifier) -> Option<PaymentAddress> {
        diversifier.g_d().and_then(|g_d| {
            let pk_d = g_d * self.0;

            PaymentAddress::from_parts(diversifier, pk_d)
        })
    }

    pub fn to_repr(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct Diversifier(pub [u8; 11]);

impl Diversifier {
    pub fn g_d(&self) -> Option<jubjub::SubgroupPoint> {
        group_hash(&self.0, constants::KEY_DIVERSIFICATION_PERSONALIZATION)
    }
}

/// A Sapling payment address.
///
/// # Invariants
///
/// `pk_d` is guaranteed to be prime-order (i.e. in the prime-order subgroup of Jubjub,
/// and not the identity).
#[derive(Clone, Copy, Debug)]
pub struct PaymentAddress {
    pk_d: jubjub::SubgroupPoint,
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
    pub fn from_parts(diversifier: Diversifier, pk_d: jubjub::SubgroupPoint) -> Option<Self> {
        if pk_d.is_identity().into() {
            None
        } else {
            Some(PaymentAddress { pk_d, diversifier })
        }
    }

    /// Constructs a PaymentAddress from a diversifier and a Jubjub point.
    ///
    /// Only for test code, as this explicitly bypasses the invariant.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn from_parts_unchecked(
        diversifier: Diversifier,
        pk_d: jubjub::SubgroupPoint,
    ) -> Self {
        PaymentAddress { pk_d, diversifier }
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

        let pk_d = jubjub::SubgroupPoint::from_bytes(bytes[11..43].try_into().unwrap());
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
    pub fn pk_d(&self) -> &jubjub::SubgroupPoint {
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
#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::vec;
    use proptest::prelude::{any, prop_compose};
    use std::fmt::{self, Debug, Formatter};

    use super::{ExpandedSpendingKey, FullViewingKey};

    impl Debug for ExpandedSpendingKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "Spending keys cannot be Debug-formatted.")
        }
    }

    use crate::sapling::PaymentAddress;
    use crate::zip32::testing::arb_extended_spending_key;
    use crate::zip32::ExtendedFullViewingKey;

    prop_compose! {
        pub fn arb_expanded_spending_key()(v in vec(any::<u8>(), 32..252)) -> ExpandedSpendingKey {
            ExpandedSpendingKey::from_spending_key(&v)
        }
    }

    prop_compose! {
        pub fn arb_full_viewing_key()(sk in arb_expanded_spending_key()) -> FullViewingKey {
            FullViewingKey::from_expanded_spending_key(&sk)
        }
    }

    prop_compose! {
        pub fn arb_shielded_addr()(extsk in arb_extended_spending_key()) -> PaymentAddress {
            let extfvk = ExtendedFullViewingKey::from(&extsk);
            extfvk.default_address().1
        }
    }
}

#[cfg(test)]
mod tests {
    use group::{Group, GroupEncoding};

    use super::FullViewingKey;
    use crate::constants::SPENDING_KEY_GENERATOR;

    #[test]
    fn ak_must_be_prime_order() {
        let mut buf = [0; 96];
        let identity = jubjub::SubgroupPoint::identity();

        // Set both ak and nk to the identity.
        buf[0..32].copy_from_slice(&identity.to_bytes());
        buf[32..64].copy_from_slice(&identity.to_bytes());

        // ak is not allowed to be the identity.
        assert_eq!(
            FullViewingKey::read(&buf[..]).unwrap_err().to_string(),
            "ak not of prime order"
        );

        // Set ak to a basepoint.
        let basepoint = SPENDING_KEY_GENERATOR;
        buf[0..32].copy_from_slice(&basepoint.to_bytes());

        // nk is allowed to be the identity.
        assert!(FullViewingKey::read(&buf[..]).is_ok());
    }
}

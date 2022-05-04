//! Consensus logic and parameters.

use std::cmp::{Ord, Ordering};
use std::convert::TryFrom;
use std::fmt;
use std::ops::{Add, Bound, RangeBounds, Sub};

/// A wrapper type representing blockchain heights. Safe conversion from
/// various integer types, as well as addition and subtraction, are provided.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockHeight(u32);

pub const H0: BlockHeight = BlockHeight(0);

impl BlockHeight {
    pub const fn from_u32(v: u32) -> BlockHeight {
        BlockHeight(v)
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Ord for BlockHeight {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for BlockHeight {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u32> for BlockHeight {
    fn from(value: u32) -> Self {
        BlockHeight(value)
    }
}

impl From<BlockHeight> for u32 {
    fn from(value: BlockHeight) -> u32 {
        value.0
    }
}

impl TryFrom<u64> for BlockHeight {
    type Error = std::num::TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        u32::try_from(value).map(BlockHeight)
    }
}

impl From<BlockHeight> for u64 {
    fn from(value: BlockHeight) -> u64 {
        value.0 as u64
    }
}

impl TryFrom<i32> for BlockHeight {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        u32::try_from(value).map(BlockHeight)
    }
}

impl TryFrom<i64> for BlockHeight {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u32::try_from(value).map(BlockHeight)
    }
}

impl From<BlockHeight> for i64 {
    fn from(value: BlockHeight) -> i64 {
        value.0 as i64
    }
}

impl Add<u32> for BlockHeight {
    type Output = Self;

    fn add(self, other: u32) -> Self {
        BlockHeight(self.0 + other)
    }
}

impl Add for BlockHeight {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self + other.0
    }
}

impl Sub<u32> for BlockHeight {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        if other > self.0 {
            panic!("Subtraction resulted in negative block height.");
        }

        BlockHeight(self.0 - other)
    }
}

impl Sub for BlockHeight {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self - other.0
    }
}

/// MASP consensus parameters.
pub trait Parameters: Clone {
    /// Returns the activation height for a particular network upgrade,
    /// if an activation height has been set.
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight>;

    /// Determines whether the specified network upgrade is active as of the
    /// provided block height on the network to which this Parameters value applies.
    fn is_nu_active(&self, nu: NetworkUpgrade, height: BlockHeight) -> bool {
        self.activation_height(nu).map_or(false, |h| h <= height)
    }
}

/// Marker struct for the production network.
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct MainNetwork;

pub const MAIN_NETWORK: MainNetwork = MainNetwork;

impl Parameters for MainNetwork {
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Canopy => Some(BlockHeight(419_200)),
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => None,
        }
    }
}

/// Marker struct for the test network.
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct TestNetwork;

pub const TEST_NETWORK: TestNetwork = TestNetwork;

impl Parameters for TestNetwork {
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Canopy => Some(BlockHeight(280_000)),
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => None,
        }
    }
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Network {
    MainNetwork,
    TestNetwork,
}

impl Parameters for Network {
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::MainNetwork => MAIN_NETWORK.activation_height(nu),
            Network::TestNetwork => TEST_NETWORK.activation_height(nu),
        }
    }
}

/// An event that occurs at a specified height on the Zcash chain, at which point the
/// consensus rules enforced by the network are altered.
///
/// See [ZIP 200](https://zips.z.cash/zip-0200) for more details.
#[derive(Clone, Copy, Debug)]
pub enum NetworkUpgrade {
    /// The [Canopy] network upgrade.
    ///
    /// [Canopy]: https://z.cash/upgrade/canopy/
    Canopy,
    /// The ZFUTURE network upgrade.
    ///
    /// This upgrade is expected never to activate on mainnet;
    /// it is intended for use in integration testing of functionality
    /// that is a candidate for integration in a future network upgrade.
    #[cfg(feature = "zfuture")]
    ZFuture,
}

impl fmt::Display for NetworkUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkUpgrade::Canopy => write!(f, "Canopy"),
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => write!(f, "ZFUTURE"),
        }
    }
}

impl NetworkUpgrade {
    fn branch_id(self) -> BranchId {
        match self {
            NetworkUpgrade::Canopy => BranchId::Canopy,
            #[cfg(feature = "zfuture")]
            NetworkUpgrade::ZFuture => BranchId::ZFuture,
        }
    }
}

/// The network upgrades on the Zcash chain in order of activation.
///
/// This order corresponds to the activation heights, but because Rust enums are
/// full-fledged algebraic data types, we need to define it manually.
const UPGRADES_IN_ORDER: &[NetworkUpgrade] = &[NetworkUpgrade::Canopy];

pub const ZIP212_GRACE_PERIOD: u32 = 32256;

/// A globally-unique identifier for a set of consensus rules within the Zcash chain.
///
/// Each branch ID in this enum corresponds to one of the epochs between a pair of Zcash
/// network upgrades. For example, `BranchId::Overwinter` corresponds to the blocks
/// starting at Overwinter activation, and ending the block before Sapling activation.
///
/// The main use of the branch ID is in signature generation: transactions commit to a
/// specific branch ID by including it as part of signature_hash. This ensures
/// two-way replay protection for transactions across network upgrades.
///
/// See [ZIP 200](https://zips.z.cash/zip-0200) for more details.
///
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BranchId {
    /// The consensus rules deployed by [`NetworkUpgrade::Canopy`].
    Canopy,
    /// Candidates for future consensus rules; this branch will never
    /// activate on mainnet.
    #[cfg(feature = "zfuture")]
    ZFuture,
}

impl TryFrom<u32> for BranchId {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0xe9ff_75a6 => Ok(BranchId::Canopy),
            #[cfg(feature = "zfuture")]
            0xffff_ffff => Ok(BranchId::ZFuture),
            _ => Err("Unknown consensus branch ID"),
        }
    }
}

impl From<BranchId> for u32 {
    fn from(consensus_branch_id: BranchId) -> u32 {
        match consensus_branch_id {
            BranchId::Canopy => 0xe9ff_75a6,
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture => 0xffff_ffff,
        }
    }
}

impl BranchId {
    /// Returns the branch ID corresponding to the consensus rule set that is active at
    /// the given height.
    ///
    /// This is the branch ID that should be used when creating transactions.
    pub fn for_height<P: Parameters>(parameters: &P, height: BlockHeight) -> Self {
        for nu in UPGRADES_IN_ORDER.iter().rev() {
            if parameters.is_nu_active(*nu, height) {
                return nu.branch_id();
            }
        }

        // Sapling rules apply before any network upgrade
        BranchId::Canopy
    }

    /// Returns the range of heights for the consensus epoch associated with this branch id.
    ///
    /// The resulting tuple implements the [`RangeBounds<BlockHeight>`] trait.
    pub fn height_range<P: Parameters>(&self, params: &P) -> Option<impl RangeBounds<BlockHeight>> {
        self.height_bounds(params).map(|(lower, upper)| {
            (
                Bound::Included(lower),
                upper.map_or(Bound::Unbounded, Bound::Excluded),
            )
        })
    }

    /// Returns the range of heights for the consensus epoch associated with this branch id.
    ///
    /// The return type of this value is slightly more precise than [`Self::height_range`]:
    /// - `Some((x, Some(y)))` means that the consensus rules corresponding to this branch id
    ///   are in effect for the range `x..y`
    /// - `Some((x, None))` means that the consensus rules corresponding to this branch id are
    ///   in effect for the range `x..`
    /// - `None` means that the consensus rules corresponding to this branch id are never in effect.
    pub fn height_bounds<P: Parameters>(
        &self,
        params: &P,
    ) -> Option<(BlockHeight, Option<BlockHeight>)> {
        match self {
            BranchId::Canopy => params
                .activation_height(NetworkUpgrade::Canopy)
                .map(|lower| {
                    #[cfg(feature = "zfuture")]
                    let upper = params.activation_height(NetworkUpgrade::ZFuture);
                    #[cfg(not(feature = "zfuture"))]
                    let upper = None;
                    (lower, upper)
                }),
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture => params
                .activation_height(NetworkUpgrade::ZFuture)
                .map(|lower| (lower, None)),
        }
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::sample::select;
    use proptest::strategy::{Just, Strategy};

    use super::{BlockHeight, BranchId, Parameters};

    pub fn arb_branch_id() -> impl Strategy<Value = BranchId> {
        select(vec![
            BranchId::Canopy,
            #[cfg(feature = "zfuture")]
            BranchId::ZFuture,
        ])
    }

    pub fn arb_height<P: Parameters>(
        branch_id: BranchId,
        params: &P,
    ) -> impl Strategy<Value = Option<BlockHeight>> {
        branch_id
            .height_bounds(params)
            .map_or(Strategy::boxed(Just(None)), |(lower, upper)| {
                Strategy::boxed(
                    (lower.0..upper.map_or(std::u32::MAX, |u| u.0))
                        .prop_map(|h| Some(BlockHeight(h))),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::{
        BlockHeight, BranchId, NetworkUpgrade, Parameters, MAIN_NETWORK, UPGRADES_IN_ORDER,
    };

    #[test]
    fn nu_ordering() {
        for i in 1..UPGRADES_IN_ORDER.len() {
            let nu_a = UPGRADES_IN_ORDER[i - 1];
            let nu_b = UPGRADES_IN_ORDER[i];
            match (
                MAIN_NETWORK.activation_height(nu_a),
                MAIN_NETWORK.activation_height(nu_b),
            ) {
                (Some(a), Some(b)) if a < b => (),
                (Some(_), None) => (),
                (None, None) => (),
                _ => panic!(
                    "{} should not be before {} in UPGRADES_IN_ORDER",
                    nu_a, nu_b
                ),
            }
        }
    }

    #[test]
    fn nu_is_active() {
        //assert!(!MAIN_NETWORK.is_nu_active(NetworkUpgrade::Canopy, BlockHeight(0)));
        //assert!(!MAIN_NETWORK.is_nu_active(NetworkUpgrade::Overwinter, BlockHeight(347_499)));
        assert!(MAIN_NETWORK.is_nu_active(NetworkUpgrade::Canopy, BlockHeight(347_500)));
    }

    #[test]
    fn branch_id_from_u32() {
        assert_eq!(BranchId::try_from(0), Ok(BranchId::Canopy));
        assert!(BranchId::try_from(1).is_err());
    }

    #[test]
    fn branch_id_for_height() {
        assert_eq!(
            BranchId::for_height(&MAIN_NETWORK, BlockHeight(419_200)),
            BranchId::Canopy,
        );
    }
}

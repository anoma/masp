use sha3::Keccak256;
use sha3::Digest;

use crate::consensus::{self, BlockHeight, NetworkUpgrade};

use super::Rseed;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

pub fn hash_to_scalar(persona: &[u8], a: &[u8], b: &[u8]) -> jubjub::Fr {
    // The 64 byte hash that we are computing
    let mut hash = [0u8; 64];
    // Compute the first half of the hash
    let mut hasher0 = Keccak256::new_with_prefix(persona);
    // The first half's subdomain
    hasher0.update(&[0]);
    hasher0.update(a);
    hasher0.update(b);
    hasher0.finalize_into((&mut hash[0..32]).try_into().unwrap());
    // Compute the second half of the hash
    let mut hasher1 = Keccak256::new_with_prefix(persona);
    // The second half's subdomain
    hasher1.update(&[1]);
    hasher1.update(a);
    hasher1.update(b);
    hasher1.finalize_into((&mut hash[32..64]).try_into().unwrap());
    // Turn the combined hash into a scalar
    jubjub::Fr::from_bytes_wide(&hash)
}

pub fn generate_random_rseed<P: consensus::Parameters, R: RngCore + CryptoRng>(
    params: &P,
    height: BlockHeight,
    rng: &mut R,
) -> Rseed {
    if params.is_nu_active(NetworkUpgrade::MASP, height) {
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        Rseed::AfterZip212(buffer)
    } else {
        Rseed::BeforeZip212(jubjub::Fr::random(rng))
    }
}

pub(crate) fn generate_random_rseed_internal<P: consensus::Parameters>(
    params: &P,
    height: BlockHeight,
    before: jubjub::Fr,
    after: [u8; 32],
) -> Rseed {
    if params.is_nu_active(NetworkUpgrade::MASP, height) {
        Rseed::AfterZip212(after)
    } else {
        Rseed::BeforeZip212(before)
    }
}

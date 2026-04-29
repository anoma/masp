#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) const POSEIDON_FIXTURES_JSON: &str = include_str!("test_vectors/poseidon_vectors.json");

#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) const SAPLING_ZIP32_IVK_FIXTURES_JSON: &str =
    include_str!("test_vectors/sapling_zip32_ivk_vectors.json");

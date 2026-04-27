#[cfg(any(test, feature = "test-dependencies"))]
pub(crate) const POSEIDON_FIXTURES_JSON: &str = include_str!("test_vectors/poseidon_vectors.json");

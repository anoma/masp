# Findings & Decisions

## Requirements
- Replace Pedersen hash usage in MASP primitives/circuits with Poseidon2 v0.1.0 from git repo `https://github.com/heliaxdev/poseidon2-r1cs-bls12-381` (not crates.io).
- Migration is intentionally protocol-breaking to start a new shielded pool.
- Merkle tree node hashing should encode depth as: `compress(height, compress(left, right))`.
- Remove all Pedersen-related code from repository code paths.
- Regenerate vectors around Merkle node encoding semantics (depth-inclusive Poseidon formulation).
- Remove trusted-setup-specific data that no longer applies to modified circuits.

## Research Findings
- Existing Pedersen hash surfaces are concentrated in:
  - `masp_primitives/src/sapling/pedersen_hash.rs`
  - `masp_proofs/src/circuit/pedersen_hash.rs`
  - callsites in `masp_primitives/src/sapling.rs`, `masp_primitives/src/convert.rs`, `masp_proofs/src/circuit/sapling.rs`, `masp_proofs/src/circuit/convert.rs`
  - Pedersen constants/precompute tables in `masp_primitives/src/constants.rs` and `masp_proofs/src/constants.rs`.
- Poseidon2 crate (`v0.1.0`) API supports:
  - native: `compress(left, right) -> Scalar`
  - gadget: `gadget::compress_allocated(cs, left, right) -> AllocatedNum<Scalar>`
  - fixed width t=2, feed-forward output, no built-in personalization/chunking format.
- Current proof parameter validation uses hardcoded `MASP_*_HASH` and `MASP_*_BYTES` in `masp_proofs/src/lib.rs`; these become stale after circuit change.
- Final Poseidon scheme implemented:
  - Merkle parent: `compress(depth_scalar, compress(left, right))`
  - Domain-separated bit hashing for note/convert preimages via chunked packing (`248` bits/chunk).
  - Note commitment now includes `rcm` directly in the hash preimage and outputs a scalar `cmu`.
  - Nullifier preimage now uses scalar `rho` encoding (`to_repr`) for BLAKE2s input.
  - Nullifier rho construction is domain + inner structured as `compress(Domain::NullifierRho, compress(cmu, position))` in both primitives and circuit gadget.
- OPT-005a landed end-to-end in code:
  - `ViewingKey::ivk()` now uses Poseidon scalar hashing over point u-coordinates.
  - `Note::nf()` now uses Poseidon with `rho` as suffix scalar.
  - Nullifier migrated to scalar-backed type with canonical serialization.
  - Spend circuit nullifier is now a direct scalar public input (`num_inputs: 8 -> 7`).
  - ZIP32 ivk coverage was restored using JSON fixture-backed assertions for `ivk` and `internal_ivk`.
- OPT-005b implementation landed end-to-end:
  - Added `Domain::AssetGen` in Poseidon domain enum.
  - `AssetType` now derives `asset_id` via BLAKE2b(512) with full-width reduction to Fr and maps generator with Poseidon v-binding + Edwards reconstruction.
  - Output circuit now witnesses scalar `asset_id`, enforces `generator.v == Poseidon(asset_id)`, and applies sign-convention check (`u_lsb == v_lsb`).
  - Output witness path updated in prover (`asset_id` instead of identifier bits).
  - Output constraints re-pinned from `31047` to `11401`.
  - Poseidon fixture JSON regenerated to keep encryption/decryption vectors aligned.
  - External commitment test vectors in `masp_proofs` were restored (not removed) and updated to new expected values.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| Use Poseidon scalar nodes end-to-end | Removes need for Pedersen point outputs and reduces migration complexity |
| Merkle hash uses two-step compress with explicit depth | Provides level binding and deterministic structure |
| Full Pedersen removal (no compatibility shim) | Requested by user and consistent with protocol break |
| Remove trusted setup fingerprints | Circuit modifications invalidate existing canonical artifacts |
| Replace legacy ignored vectors with JSON fixtures | New pool semantics are now captured in canonical fixture files and active tests |
| Split OPT-005 into 005a (ivk/nf) and 005b (asset_generator) | OPT-005b requires hash-to-curve design which is a separate concern from PRF/CRH replacement |
| OPT-005a: ivk uses `hash_scalars` not `hash_bits` | Feeding ak_u, nk_u as scalars costs fewer compress calls (3 vs 5) than 512 bits via hash_bits |
| OPT-005a: ivk NOT bit-truncated from 255→251 | Bit truncation of Poseidon output is unsound (doesn't equal mod reduction). Feed all 255 bits to `g_d.mul()`; group structure ensures `g_d * s = g_d * (s mod r_jubjub)`. Primitives reduce mod r_jubjub for jubjub::Fr — same result. |
| OPT-005a: nf as direct scalar public input (not multipack) | Poseidon outputs a scalar; multipack was needed for BLAKE2s 256-bit output. Saves 1 public input (8→7). |
| OPT-005a superseded note | Earlier plan kept Output asset-generator BLAKE2s for safety; superseded by scalar `asset_id` + Poseidon v-binding design in OPT-005b. |
| OPT-005b: BLAKE2b hash-to-field + Poseidon hash-to-curve | BLAKE2b(name\|\|nonce) full 512-bit digest reduced mod Fr (deterministic byte-order semantics), then Poseidon(DomainAssetGen, [asset_id]) for v-coordinate; try-and-increment until QR + not small-order. |
| OPT-005b: Circuit verifies (not computes) hash-to-curve | Compute `v = Poseidon(asset_id)` in-circuit; constrain `generator.v == v`; sign convention on u. Curve equation already checked by `EdwardsPoint::interpret`. ~1.3k constraints vs BLAKE2s ~13k. |
| OPT-005b: Note commitment uses extended (pre-cofactor-cleared) point | Cofactor clearing would destroy injectivity of AssetType→generator (multiple extended points cofactor-clear to same subgroup point). Value commitment path cofactor-clears + asserts nonzero, catching small-order generators. |
| OPT-005b: Non-uniformity from sign convention is acceptable | Choosing u vs -u based on convention excludes half the valid points. Acceptable for collision resistance + binding; IRO not required for this use case. Must be documented. |
| Migrate nullifier end-to-end to scalar | User explicitly requested scalar migration across APIs and wire-facing code; enables direct public input in Spend and removes multipack overhead. |
| BLAKE2b asset-id derivation uses full 512-bit reduction mod Fr | Cleaner than truncation and avoids decode-failure ambiguity with canonical scalar parsers. |
| `from_repr` is decode, not reduction | Prevents unsound assumption in ivk and asset-id scalar conversion logic. |
| OPT-005a revised estimate | Spend expected reduction: `-22k..-27k` constraints (from `83807` to `~56800..61800`). |
| OPT-005b revised estimate | Output expected reduction: `-4.8k..-10.5k` constraints (from `31047` to `~20500..26200`). |
| Convert unaffected by OPT-005 | No direct BLAKE2s random-oracle path in Convert; expected delta `0`. |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| `session-catchup.py` produced no output | Treated as no prior unsynced context; proceeded with fresh planning files |
| Broad patch accidentally deleted `masp_proofs/src/lib.rs` | Restored immediately and resumed with smaller scoped edits |
| Assumption that 255-bit truncation always decodes as Fr | Corrected: canonical decode may fail when value >= Fr modulus; use explicit reduction or 254-bit mask if decode-guarantee is needed |
| Assumption that `jubjub::Fr::from_repr` performs modular reduction | Corrected: it performs canonical decoding only |
| ZIP32 ivk assertions were temporarily removed during migration | Reintroduced by adding `sapling_zip32_ivk_vectors.json` fixture and asserting against regenerated ivk/internal_ivk values |

## Resources
- Poseidon2 repo: `https://github.com/heliaxdev/poseidon2-r1cs-bls12-381`
- Poseidon2 tag `v0.1.0` Cargo manifest and source paths (fetched):
  - `src/lib.rs`
  - `src/native.rs`
  - `src/gadget/mod.rs`
  - `src/gadget/compress.rs`
- New/updated key files in this migration:
  - `masp_primitives/src/sapling/poseidon_hash.rs`
  - `masp_proofs/src/circuit/poseidon_hash.rs`
  - `masp_primitives/src/sapling.rs`
  - `masp_proofs/src/circuit/sapling.rs`
  - `masp_proofs/src/circuit/convert.rs`
  - `masp_proofs/src/lib.rs`
  - `masp_primitives/src/test_vectors/sapling_zip32_ivk_vectors.json`
  - `masp_primitives/examples/dump_zip32_ivk_vectors.rs`

## Visual/Browser Findings
- None in this planning step.

## Current Soundness Checklist (Scalar-Only Revision)
- ivk circuit path uses full 255 Poseidon bits in `g_d.mul()` (no truncation).
- Primitive ivk conversion uses explicit reduction semantics, not `from_repr` decode as reduction.
- Nullifier is scalar-native across primitive, circuit, prover, verifier, serialization.
- Nullifier encoding is canonical and unique on read/write boundaries.
- Asset id is derived by reducing full BLAKE2b(512) digest mod Fr.
- Output circuit enforces Poseidon(asset_id) v-binding and sign convention.
- Small-order generator rejection is preserved.

---
*Update this file after every 2 view/browser/search operations*
*This prevents visual information from being lost*

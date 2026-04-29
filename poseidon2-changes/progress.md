# Progress Log

## Session: 2026-04-27

### Refinement Replan: 2026-04-27
- **Status:** in_progress
- Actions taken:
  - Captured new user constraints for refinement pass:
    - maintain circuit soundness during optimization,
    - primitives-first de-duplication policy,
    - move/remove test-only Montgomery helper from `masp_proofs/src/constants.rs`,
    - defer final circuit constraint count pinning to the end,
    - use JSON fixtures for canonical vectors/tests.
  - Wrote full revised execution plan to `task_plan.md` to avoid context loss.
- Files created/modified:
  - `task_plan.md` (updated with full revised plan)
  - `progress.md` (this entry)

### Refinement Completion: 2026-04-27
- **Status:** complete
- Actions taken:
  - Investigated remaining spend test failures and identified a native/circuit mismatch in nullifier rho framing.
  - Added dedicated gadget helper `nullifier_rho` in `masp_proofs/src/circuit/poseidon_hash.rs` using `compress(Domain::NullifierRho, compress(cmu, position))`.
  - Updated spend circuit nullifier path to use `poseidon_hash::nullifier_rho(...)`.
  - Recomputed and pinned final spend constraint count to `92519` in both spend tests.
  - Re-ran targeted proofs tests and full workspace test suite; all tests now pass.
- Files created/modified:
  - `masp_proofs/src/circuit/poseidon_hash.rs`
  - `masp_proofs/src/circuit/sapling.rs`
  - `task_plan.md`
  - `findings.md`
  - `progress.md`

### Phase 1: Scope Lock and Spec
- **Status:** complete
- **Started:** 2026-04-27
- Actions taken:
  - Loaded `planning-with-files` skill.
  - Ran session catchup script for repository root.
  - Reviewed planning templates from skill directory.
  - Initialized project planning files: `task_plan.md`, `findings.md`, `progress.md`.
  - Captured agreed migration direction: protocol-breaking Poseidon scalar nodes and full Pedersen removal.
- Files created/modified:
  - `task_plan.md` (created)
  - `findings.md` (created)
  - `progress.md` (created)

### Phase 2: Dependency and Hash API Migration
- **Status:** complete
- Actions taken:
  - Added git dependency `poseidon2-r1cs-bls12-381` (`v0.1.0`) in `masp_primitives/Cargo.toml` and `masp_proofs/Cargo.toml`.
  - Added native Poseidon hash module `masp_primitives/src/sapling/poseidon_hash.rs`.
  - Added circuit Poseidon gadget adapter `masp_proofs/src/circuit/poseidon_hash.rs`.
  - Switched module exports from `pedersen_hash` to `poseidon_hash` in proofs circuit module.
- Files created/modified:
  - `masp_primitives/Cargo.toml`
  - `masp_proofs/Cargo.toml`
  - `masp_primitives/src/sapling/poseidon_hash.rs`
  - `masp_proofs/src/circuit/poseidon_hash.rs`
  - `masp_proofs/src/circuit.rs`

### Phase 3: Primitives Refactor
- **Status:** complete
- Actions taken:
  - Replaced Sapling note/merkle/nullifier hashing paths with Poseidon scalar hashing in `masp_primitives/src/sapling.rs`.
  - Replaced AllowedConversion commitment hashing path in `masp_primitives/src/convert.rs`.
  - Removed Pedersen hash constants/tables and related tests from `masp_primitives/src/constants.rs`.
  - Removed Pedersen hash module file and vector module linkage.
- Files created/modified:
  - `masp_primitives/src/sapling.rs`
  - `masp_primitives/src/convert.rs`
  - `masp_primitives/src/constants.rs`
  - `masp_primitives/src/test_vectors.rs`
  - `masp_primitives/src/merkle_tree.rs`
  - `masp_primitives/src/sapling/note_encryption.rs`
  - Deleted: `masp_primitives/src/sapling/pedersen_hash.rs`
  - Deleted: `masp_primitives/src/test_vectors/pedersen_hash_vectors.rs`

### Phase 4: Circuit Refactor
- **Status:** complete
- Actions taken:
  - Migrated Spend/Output/Convert circuits to Poseidon gadgets and scalar-node Merkle hashing.
  - Removed Pedersen circuit gadget and Pedersen circuit precompute constants.
  - Adjusted rho/nullifier wiring to scalar representation compatible with new primitive logic.
- Files created/modified:
  - `masp_proofs/src/circuit/sapling.rs`
  - `masp_proofs/src/circuit/convert.rs`
  - `masp_proofs/src/circuit/gadgets.rs`
  - `masp_proofs/src/circuit/ecc.rs`
  - `masp_proofs/src/constants.rs`
  - Deleted: `masp_proofs/src/circuit/pedersen_hash.rs`

### Phase 5: Tests and Vectors Update
- **Status:** complete
- Actions taken:
  - Updated circuit tests to remove Pedersen-specific constraint hash/count pins.
  - Reworked Merkle empty-root assertions to structural derivation checks under new hash function.
  - Marked legacy vector tests as ignored where vectors intentionally pin old pool semantics.
- Files created/modified:
  - `masp_proofs/src/circuit/sapling.rs`
  - `masp_proofs/src/circuit/convert.rs`
  - `masp_primitives/src/merkle_tree.rs`
  - `masp_primitives/src/sapling/note_encryption.rs`

### Phase 6: Trusted Setup Data Cleanup
- **Status:** complete
- Actions taken:
  - Removed hardcoded trusted-setup fingerprint constants (`MASP_*_HASH`, `MASP_*_BYTES`).
  - Simplified parameter download/load/parse verification flow to stop enforcing stale hash/size checks.
- Files created/modified:
  - `masp_proofs/src/lib.rs`

### Phase 7: Validation and Cleanup
- **Status:** complete
- Actions taken:
  - Ran `cargo check` and full `cargo test` successfully.
  - Confirmed no Pedersen references remain in active Rust source paths (excluding planning artifacts and historical coverage XML).
- Files created/modified:
  - `task_plan.md`
  - `findings.md`
  - `progress.md`

## Test Results
| Test | Input | Expected | Actual | Status |
|------|-------|----------|--------|--------|
| Planning init | Create planning files only | Files present with scoped plan | Created `task_plan.md`, `findings.md`, `progress.md` | pass |
| Workspace build | `cargo check` | Successful compilation | Success | pass |
| Proofs tests | `cargo test -p masp_proofs --lib` | Circuit tests updated and passing | Success (15 passed) | pass |
| Full tests | `cargo test` | Workspace tests pass with intentional legacy ignores | Success (all pass, 3 ignored) | pass |
| Full tests (refinement complete) | `cargo test` | Workspace tests pass | Success (all pass, 0 ignored) | pass |

## Error Log
| Timestamp | Error | Attempt | Resolution |
|-----------|-------|---------|------------|
| 2026-04-27 | Catchup script returned no output | 1 | Treated as no unsynced session data |
| 2026-04-27 | `masp_proofs/src/lib.rs` accidentally deleted by broad patch | 1 | Restored with `git checkout -- masp_proofs/src/lib.rs`, reapplied scoped edits |
| 2026-04-27 | Spend test nullifier packed input mismatch | 1 | Fixed rho framing mismatch between primitives and circuit with dedicated nullifier gadget |

## 5-Question Reboot Check
| Question | Answer |
|----------|--------|
| Where am I? | OPT-001 and OPT-002 implemented; OPT-005 planned in detail |
| Where am I going? | Implement OPT-005 (replace BLAKE2s with Poseidon for ivk/nf/asset_generator) |
| What's the goal? | Minimize R1CS constraints by eliminating remaining BLAKE2s calls from circuits |
| What have I learned? | BLAKE2s costs ~13k constraints per 512-bit hash; Poseidon scalar hashing costs ~2.5k for same. Output asset_generator BLAKE2s is redundant (already constrained by value commitment). Spend nullifier can be 1 scalar public input instead of 2 packed. |
| What have I done? | Implemented OPT-001 (packed equality, -254 Output), OPT-002 (gadget linear-layer, -8712 Spend / -726 Output / -8107 Convert); planned OPT-005 in full detail in OPTS.md |

### OPT-001 Implementation: 2026-04-27
- **Status:** complete
- Actions taken:
  - Replaced 256 per-bit equality checks with 2 packed 128-bit chunk equality constraints in Output circuit.
  - Output: `32027` → `31773` (`-254`).
- Files modified:
  - `masp_proofs/src/circuit/sapling.rs`
  - `OPTS.md`

### OPT-002 Implementation (v0.2.0): 2026-04-27
- **Status:** complete
- Actions taken:
  - Added `alloc_linear_combination` to `poseidon2-r1cs-bls12-381` gadget; collapsed matmul_external (3→2 constraints), matmul_internal (4→2), feed-forward (unchanged).
  - Released as `poseidon2-r1cs-bls12-381` v0.2.0. Updated masp deps to v0.2.0.
  - Per-compress: `540` → `419` (`-121`).
  - Spend: `92519` → `83807` (`-8712`). Output: `31773` → `31047` (`-726`). Convert: `39005` → `30898` (`-8107`).
- Files modified:
  - `poseidon2-r1cs-bls12-381/src/gadget/arith.rs`
  - `poseidon2-r1cs-bls12-381/src/gadget/round.rs`
  - `poseidon2-r1cs-bls12-381/src/gadget/compress.rs`
  - `poseidon2-r1cs-bls12-381/tests/compress_vectors.rs`
  - `masp_proofs/Cargo.toml` (v0.1.0 → v0.2.0)
  - `masp_primitives/Cargo.toml` (v0.1.0 → v0.2.0)
  - `masp_proofs/src/circuit/sapling.rs` (re-pinned counts)
  - `masp_proofs/src/circuit/convert.rs` (re-pinned counts)
  - `OPTS.md`

### OPT-005 Planning: 2026-04-27
- **Status:** planned (not yet implemented)
- Actions taken:
  - Analyzed constraint breakdown: BLAKE2s costs ~26k in Spend, ~6k in Output.
  - Identified 3 BLAKE2s call sites: ivk (Spend), nf (Spend), asset_generator (Output).
  - Designed replacement: Poseidon `hash_bits` for ivk/nf; remove asset_generator BLAKE2s entirely (redundant).
  - Designed public input change: Spend nullifier 2 packed → 1 direct scalar (8→7 inputs).
  - Wrote full step-by-step plan with files affected and soundness analysis.
- Files modified:
  - `OPTS.md` (added OPT-005 with full plan)
  - `task_plan.md` (added Phase 8)
  - `progress.md` (this entry)

### OPT-005 Soundness Audit + Design Refinement: 2026-04-29
- **Status:** complete (planning only, no code changes)
- Actions taken:
  - Audited OPT-005a (ivk/nf) for soundness issues. Found CRITICAL: bit truncation of Poseidon output (255→251 bits) is unsound — doesn't equal mod reduction. Resolution: feed all 255 bits to `g_d.mul()`, rely on group structure for correctness.
  - Decided ivk should use `hash_scalars` (ak_u, nk_u as scalars) instead of `hash_bits` (512 bits) — fewer constraints, same soundness.
  - Decided nf should use `hash_bits_with_suffix_scalars` with rho as suffix scalar — avoids 256 boolean allocations for rho.
  - Audited OPT-005b (asset_generator). Found: removing BLAKE2s entirely loses identifier→generator binding. A prover could use an arbitrary curve point. Decided to keep BLAKE2s in Output circuit for now, split into OPT-005b with proper Poseidon hash-to-curve design.
  - Designed OPT-005b: BLAKE2b hash-to-field + Poseidon hash-to-curve. BLAKE2b(name||nonce) → truncate to 255-bit scalar (always succeeds). Poseidon(DomainAssetGen, [asset_id]) → v-coordinate. Circuit constrains `generator.v == v` + sign convention on u. ~1.3k constraints vs BLAKE2s ~13k.
  - Noted: note commitment uses extended (pre-cofactor-cleared) point for injectivity; cofactor clearing + assert_nonzero in expose_value_commitment catches small-order generators.
  - Noted: sign convention makes distribution non-uniform; acceptable for collision resistance + binding, IRO not required.
  - Noted: try-and-increment nonce must be serialized in AssetType (currently `borsh(skip)`).
- Files modified:
  - `OPTS.md` (rewrote OPT-005a with soundness analysis; rewrote OPT-005b with full BLAKE2b+Poseidon design; updated prioritized execution order; updated estimated counts)
  - `task_plan.md` (updated Phase 8 with soundness-critical notes; added Phase 9 for OPT-005b)
  - `findings.md` (added 8 new technical decisions from soundness audit)
  - `progress.md` (this entry)

### Scalar-Only Plan Revision + Estimate Refresh: 2026-04-29
- **Status:** complete (planning only, no code changes)
- Actions taken:
  - Incorporated user decision to migrate nullifier and asset identifier flows fully to scalar semantics.
  - Re-estimated constraint impact by circuit under scalar-only design:
    - Spend: `83807 -> ~56800..61800` (`-22k..-27k`)
    - Output: `31047 -> ~20500..26200` (`-4.8k..-10.5k`)
    - Convert: unchanged (`30898`)
  - Revised soundness guidance:
    - `from_repr` is canonical decode only (not modular reduction).
    - `asset_id` must be derived by reducing full 512-bit BLAKE2b digest mod Fr.
    - Spend ivk circuit must use all 255 bits in scalar multiplication (no truncation).
    - Scalar nullifier serialization must be canonical across transaction boundaries.
  - Rewrote planning files to reflect new scope and sequence (Phase A/B/C).
- Files modified:
  - `task_plan.md`
  - `findings.md`
  - `OPTS.md`
  - `progress.md` (this entry)

### Planning Consistency Pass: 2026-04-29
- **Status:** complete (planning only, no code changes)
- Actions taken:
  - Removed stale OPT-005b truncation language from findings and aligned on full BLAKE2b(512) reduction mod Fr.
  - Marked historical "keep Output BLAKE2s" decision as superseded by scalar `asset_id` + Poseidon v-binding plan.
  - Aligned OPT-005a estimate in `OPTS.md` with scalar-only range (`~56,800..61,800`).
  - Aligned `group_hash` scoping by marking it explicitly out-of-scope for OPT-005b implementation phase unless separately approved.
  - Added canonical encoding rules section to `OPTS.md` for nullifier/asset-id serialization and BLAKE2b reduction byte-order determinism.
- Files modified:
  - `findings.md`
  - `OPTS.md`
  - `progress.md` (this entry)

### OPT-005a Implementation + ZIP32 ivk Fixture Migration: 2026-04-29
- **Status:** complete
- Actions taken:
  - Implemented OPT-005a in primitives/proofs:
    - Added Poseidon domains `CRHIvk` and `PRFNf`.
    - Replaced primitive `ViewingKey::ivk()` and `Note::nf()` BLAKE2s paths with Poseidon scalar paths.
    - Migrated nullifier to scalar-backed type with canonical read/write.
    - Updated Spend circuit ivk/nf to Poseidon and removed nullifier multipack in favor of direct scalar input.
    - Updated prover/verifier Spend public input wiring and signatures (`8 -> 7` circuit inputs).
  - Updated Spend circuit expectations:
    - `num_inputs` set to `7`.
    - Spend constraint count re-pinned to `44009`.
  - Restored ZIP32 ivk verification:
    - Added generator example `masp_primitives/examples/dump_zip32_ivk_vectors.rs`.
    - Added JSON fixture `masp_primitives/src/test_vectors/sapling_zip32_ivk_vectors.json`.
    - Updated ZIP32 tests to assert `ivk` and `internal_ivk` against fixture values.
  - Created a single commit from staged implementation files only:
    - `764871d` `Migrate Spend ivk/nullifier to Poseidon scalars and restore ZIP32 ivk vectors`
  - Verified with tests:
    - `cargo test -p masp_proofs --lib` pass
    - `cargo test -p masp_primitives --lib` pass
    - `cargo test` pass
- Files modified:
  - `masp_primitives/src/sapling.rs`
  - `masp_primitives/src/sapling/poseidon_hash.rs`
  - `masp_primitives/src/transaction/components/sapling.rs`
  - `masp_primitives/src/transaction/txid.rs`
  - `masp_proofs/src/circuit/sapling.rs`
  - `masp_proofs/src/sapling/prover.rs`
  - `masp_proofs/src/sapling/verifier.rs`
  - `masp_proofs/src/sapling/verifier/single.rs`
  - `masp_proofs/src/sapling/verifier/batch.rs`
  - `masp_primitives/src/test_vectors.rs`
  - `masp_primitives/src/zip32/sapling.rs`
  - `masp_primitives/src/test_vectors/sapling_zip32_ivk_vectors.json`
  - `masp_primitives/examples/dump_zip32_ivk_vectors.rs`

### OPT-005b Implementation (Output asset generator scalar migration): 2026-04-29
- **Status:** complete
- Actions taken:
  - Implemented scalar asset-id path and Poseidon asset-generator binding:
    - Added `Domain::AssetGen` (Poseidon domain scalar `6`).
    - Reworked `AssetType` generation to use BLAKE2b(512) and full-width reduction mod Fr for `asset_id`.
    - Replaced BLAKE2s hash-to-point with Poseidon(`AssetGen`, `[asset_id]`) -> v-coordinate plus Edwards equation reconstruction and sign convention.
  - Updated Output proof wiring:
    - Output circuit input changed from `asset_identifier` bits to scalar `asset_id` witness.
    - Replaced Output BLAKE2s integrity check with Poseidon v-binding (`generator.v == Poseidon(asset_id)`) and sign constraint (`u_lsb == v_lsb`).
    - Updated prover to pass `asset_id` scalar.
  - Updated and restored tests/vectors:
    - Re-pinned Output constraint count to `11401`.
    - Restored external commitment assertions in `test_input_circuit_with_bls12_381_external_test_vectors` with updated expected values.
    - Regenerated `poseidon_vectors.json` via `dump_poseidon_fixtures`.
    - Updated serialized amount fixtures in `amount_in_range` to current canonical asset-id bytes.
  - Validation:
    - `cargo test -p masp_primitives --lib` pass.
    - `cargo test -p masp_proofs --lib` pass.
    - `cargo test` pass.
- Files modified:
  - `masp_primitives/src/sapling/poseidon_hash.rs`
  - `masp_primitives/src/asset_type.rs`
  - `masp_primitives/src/constants.rs`
  - `masp_primitives/src/test_vectors/poseidon_vectors.json`
  - `masp_primitives/src/transaction/components/amount.rs`
  - `masp_proofs/src/circuit/sapling.rs`
  - `masp_proofs/src/circuit/convert.rs`
  - `masp_proofs/src/sapling/prover.rs`

---
*Update after completing each phase or encountering errors*

# Optimization Tracking (Poseidon2 Migration)

This document tracks constraint-efficiency opportunities discovered during the Pedersen -> Poseidon2 migration, with soundness notes and implementation status.

## Baseline and Current Counts

- Pre-migration baseline (Pedersen era):
  - Spend: `100637`
  - Output: `31205`
  - Convert: `47358`
- Current Poseidon2 counts (after OPT-001 + OPT-002 v0.2.0):
  - Spend: `83807` (-16.7% vs Pedersen)
  - Output: `31047` (-0.5% vs Pedersen)
  - Convert: `30898` (-34.7% vs Pedersen)
- Estimated after OPT-005a (scalar nullifier end-to-end):
  - Spend: `~56,800..61,800` (range from sizing uncertainty in replacement blocks)
  - Output: `31047` (unchanged)
  - Convert: `30898` (unchanged)
- Estimated after OPT-005b (scalar asset id + Poseidon asset-generator relation):
  - Output: `~20,500..26,200`
  - Spend: `~56,800..61,800` (unchanged after 005a)
  - Convert: `30898` (unchanged)

## Optimization Candidates

### OPT-001: Output asset-generator integrity checks

- **Area:** `masp_proofs/src/circuit/sapling.rs` (Output circuit)
- **Current behavior:** Enforces equality for all 256 bits between witnessed asset generator bits and BLAKE2s image bits.
- **Cost concern:** ~256 constraints just for bit equality in this block.
- **Candidate optimization:** Replace per-bit equality checks with packed chunk equality checks (e.g. 2x128-bit chunks or similar bounded chunking below field capacity).
- **Soundness requirements:**
  - Keep booleanity constraints for all involved bits.
  - Ensure packing bounds do not permit field wraparound aliasing.
  - Preserve exact relation to BLAKE2s output bits.
- **Protocol impact:** None (same transcript).
- **Status:** `implemented`
- **Implementation notes:**
  - Replaced per-bit equality checks with 2 packed-equality constraints over 128-bit chunks.
  - New integrity formulation enforces `sum_i 2^i*(a_i - b_i) = 0` per chunk, with `a_i` and `b_i` still boolean-constrained by existing paths.
- **Measured impact:**
  - Output constraints reduced from `32027` to `31773` (`-254`).

### OPT-002: Poseidon2 gadget linear-layer overhead

- **Area:** Poseidon2 gadget dependency (`poseidon2-r1cs-bls12-381`), consumed by:
  - `masp_proofs/src/circuit/poseidon_hash.rs`
  - Spend / Output / Convert hashing paths.
- **Current behavior:** Uses many allocated intermediates and explicit constraints for affine operations (additions/constants/matrix steps), not just nonlinear S-box work.
- **Cost concern:** High per-`compress` cost dominates circuits that invoke Poseidon repeatedly (especially Spend/Convert Merkle paths).
- **Candidate optimization:** Rework gadget internals to use linear combinations for affine portions and constrain primarily nonlinear transitions, while preserving exact round function semantics.
- **Soundness requirements:**
  - Preserve exact Poseidon2 function (same constants, rounds, feed-forward, output).
  - Keep native vs gadget parity tests.
  - Add targeted gadget tests proving equality with native `compress` for deterministic vectors.
- **Protocol impact:** None if transcript/function stays exactly unchanged.
- **Status:** `implemented`
- **Implementation notes:**
  - Released as `poseidon2-r1cs-bls12-381` v0.2.0.
  - Added `alloc_linear_combination` helper; collapsed `matmul_external` from 3→2 constraints, `matmul_internal` from 4→2, feed-forward stays at 1.
  - Per-`compress`: `540` → `419` (`-121`, -22.4%).
- **Measured impact on circuits:**
  - Spend: `92519` → `83807` (`-8712`)
  - Output: `31773` → `31047` (`-726`)
  - Convert: `39005` → `30898` (`-8107`)

### OPT-003: Constraint attribution and regression guardrails

- **Area:** `masp_proofs` tests for Spend/Output/Convert and hash helpers.
- **Current behavior:** Only end-to-end circuit constraint totals are pinned.
- **Cost concern:** Hard to localize regressions quickly.
- **Candidate optimization:** Add component-level counts for:
  - one Poseidon `compress`
  - Merkle parent hash
  - note hash path
  - nullifier rho hash
  - Output asset-generator integrity block
- **Soundness requirements:**
  - Component tests must assert functional equivalence, not only counts.
- **Protocol impact:** None.
- **Status:** `identified`

### OPT-004 (optional): Domain/length framing reductions

- **Area:** `hash_bits_with_suffix_scalars` framing in primitives + gadget.
- **Current behavior:** domain and bit length are absorbed before chunks.
- **Cost concern:** extra compress calls and constants in some paths.
- **Candidate optimization:** remove or simplify framing for fixed-length domains.
- **Soundness requirements:**
  - Re-specify collision/domain-separation rationale.
  - Recompute all fixtures and public commitment/nullifier vectors.
- **Protocol impact:** Yes (changes transcript/commitments/nullifiers).
- **Status:** `deferred (requires explicit protocol decision)`

### OPT-005a: Replace BLAKE2s with Poseidon for ivk, nf (Spend circuit)

- **Area:** Two BLAKE2s call sites in the Spend circuit + their primitive counterparts.
- **Current behavior:**
  - Spend: `ivk = BLAKE2s(ak_repr || nk_repr)` (~13k constraints)
  - Spend: `nf = BLAKE2s(nk_repr || rho_repr)` (~13k constraints), exposed as 2 packed public inputs
- **Cost concern:** ~26k constraints in Spend from BLAKE2s alone.
- **Candidate optimization:**
  - Replace `ivk` BLAKE2s with `poseidon_hash::hash_allocated_scalars(Domain::CRHIvk, [ak_u, nk_u])` (~2.5k constraints)
  - Replace `nf` BLAKE2s with `poseidon_hash::hash_bits_with_suffix_scalars(Domain::PRFNf, nk_repr_bits, [rho])` (~2.5k constraints), expose as 1 scalar public input instead of 2 packed
- **Soundness analysis:**

  **ivk — bls12_381::Scalar → jubjub::Fr conversion (CRITICAL)**

  Poseidon outputs a `bls12_381::Scalar` (255 bits). The ivk is used as `pk_d = g_d * ivk` where `g_d` is a jubjub subgroup point. Current BLAKE2s path: 256 bits → truncate(251) → guaranteed < 2^251 < jubjub_order → valid jubjub::Fr.

  With Poseidon, bit truncation is **unsound**: dropping the top 4 bits of a 255-bit scalar does not yield `s mod r_jubjub` when those bits are nonzero. The circuit would prove a false equivalence.

  **Resolution:** Feed all 255 bits of the Poseidon output (via `to_bits_le_strict`) into `g_d.mul()`. Since `g_d` is on the jubjub curve of order `r_jubjub`, we have `g_d * s = g_d * (s mod r_jubjub)` for any scalar `s`. This is sound without truncation. The primitives side reduces mod `r_jubjub` to obtain `jubjub::Fr`, then computes `pk_d = g_d * ivk` — same result.

  Key invariant: primitives must use explicit reduction semantics when converting to jubjub scalar (do not treat `from_repr` as modular reduction), while circuit does `g_d * poseidon_output_bits[0..255]`. Results agree because of group structure when conversions are defined correctly.

  **ivk — hash_bits vs hash_scalars (MEDIUM)**

  Using `hash_bits(CRHIvk, ak_repr || nk_repr)` requires 512 bits → 3 chunks → 5 compress calls.
  Using `hash_allocated_scalars(CRHIvk, [ak_u, nk_u])` requires 2 scalars → 3 compress calls (init + 2 data). Fewer constraints, same soundness (u-coordinate is injective for valid points).
  Primitives must use matching scalar inputs: `ViewingKey::ivk()` calls `hash_scalars(CRHIvk, [ak.to_u(), nk.0.to_u()])`.

  **nf — Nullifier scalar migration (MEDIUM/HIGH)**

  Current: `Nullifier(pub [u8; 32])` derived from BLAKE2s bytes, verified via multipack into 2 inputs.
  New: nullifier is scalar-native end-to-end (primitive type, prover, verifier, serialization); Spend exposes one direct scalar public input.
  Requirement: serialization must remain canonical and unique to prevent aliasing/malleability.

  **nf — Use suffix scalar for rho (optimization)**

  Instead of decomposing `rho` into 256 bits and feeding as part of the bit preimage, use `hash_bits_with_suffix_scalars(PRFNf, nk_repr_bits, &[rho])`. This avoids ~256 boolean allocations + packing constraints for rho.

- **Protocol impact:** Yes (changes ivk derivation, nullifier format, Spend public input count). Already protocol-breaking for new pool.
- **Status:** `implemented`
- **Estimated impact:**
  - Spend: `83807` → `~56,800..61,800` (`-22k..-27k`)
  - Output: unchanged (`31047`)
  - Convert: unchanged (`30898`)

- **Measured impact:**
  - Spend: `83807` → `44009` (`-39798`)
  - Output: unchanged (`31047`)
  - Convert: unchanged (`30898`)

#### Public input changes

Spend (8 → 7 inputs):
| Index | Current | New |
|-------|---------|-----|
| 0 | ONE | ONE |
| 1 | rk/u | rk/u |
| 2 | rk/v | rk/v |
| 3 | cv/u | cv/u |
| 4 | cv/v | cv/v |
| 5 | anchor | anchor |
| 6 | nullifier/packed 0 (multipack) | **nf_scalar** (direct) |
| 7 | nullifier/packed 1 (multipack) | *(removed)* |

Output (6 inputs, unchanged)

Convert (4 inputs, unchanged)

#### Implementation steps

1. Add `Domain::CRHIvk` (scalar `4`) and `Domain::PRFNf` (scalar `5`) to `masp_primitives/src/sapling/poseidon_hash.rs`
2. Rewrite `ViewingKey::ivk()` in `masp_primitives/src/sapling.rs`: `BLAKE2s(ak||nk) → poseidon_hash::hash_scalars(CRHIvk, [ak_u, nk_u])`, then convert to `jubjub::Fr` with explicit reduction semantics (do not rely on `from_repr` decode for reduction)
3. Rewrite `Note::nf()` in `masp_primitives/src/sapling.rs`: `BLAKE2s(nk||rho) → poseidon_hash::hash_bits_with_suffix_scalars(PRFNf, nk_repr, [rho])`, keeping nullifier scalar-native end-to-end
4. Replace Spend circuit ivk BLAKE2s with Poseidon `hash_allocated_scalars(Domain::CRHIvk, [ak_u, nk_u])` in `masp_proofs/src/circuit/sapling.rs`; then `to_bits_le_strict` on the result (255 bits) and feed all 255 bits to `g_d.mul()` — NO truncation
5. Replace Spend circuit nf BLAKE2s with Poseidon `hash_bits_with_suffix_scalars(Domain::PRFNf, nk_repr_bits, &[rho])` in `masp_proofs/src/circuit/sapling.rs`; change nullifier from `multipack::pack_into_inputs` → `nf_scalar.inputize()` (2 pub inputs → 1)
6. Update Spend prover (`masp_proofs/src/sapling/prover.rs`): remove multipack; pass direct scalar nullifier public input
7. Update Spend verifier (`masp_proofs/src/sapling/verifier.rs`): remove multipack path; accept direct scalar nullifier input
8. Update verifier single/batch (`masp_proofs/src/sapling/verifier/single.rs`, `masp_proofs/src/sapling/verifier/batch.rs`): propagate signature changes
9. Clean up: remove `blake2s` import from `masp_proofs/src/circuit/sapling.rs`, remove `multipack` imports where no longer used, deprecate/remove `CRH_IVK_PERSONALIZATION` / `PRF_NF_PERSONALIZATION` from `masp_primitives/src/constants.rs`
10. Update test assertions in `masp_proofs/src/circuit/sapling.rs`: Spend `num_inputs` 8→7, nf checks; re-pin constraint counts
11. Full `cargo test` validation

#### Soundness checklist (OPT-005a)

- [x] ivk: Poseidon output NOT bit-truncated; all 255 bits fed to `g_d.mul()`; group structure ensures `g_d * s = g_d * (s mod r_jubjub)`
- [x] ivk: Primitive conversion uses explicit reduction semantics (no `from_repr`-as-reduction assumption)
- [x] ivk: `hash_scalars` preimage uses point u-coordinates (injective for valid points); same scalars in primitives and circuit
- [x] nf: Nullifier is scalar-native through primitive, circuit, prover, verifier, and serialization
- [x] nf: `rho` used as suffix scalar (not bit-decomposed), matching `hash_bits_with_suffix_scalars` native API
- [x] No BLAKE2s calls remain in Spend circuit after refactor
- [x] No multipack usage remains after nullifier change
- [x] Native/circuit parity: ZIP32 `ivk` and `internal_ivk` assertions restored via JSON fixtures

#### Files affected

| File | Change |
|------|--------|
| `masp_primitives/src/sapling/poseidon_hash.rs` | Add `Domain::CRHIvk`, `Domain::PRFNf` |
| `masp_primitives/src/sapling.rs` | Rewrite `ViewingKey::ivk()` with `hash_scalars` and explicit reduction; rewrite `Note::nf()` with `hash_bits_with_suffix_scalars`; migrate nullifier type to scalar |
| `masp_primitives/src/constants.rs` | Deprecate/remove `CRH_IVK_PERSONALIZATION`, `PRF_NF_PERSONALIZATION` |
| `masp_proofs/src/circuit/sapling.rs` | Replace 2 BLAKE2s calls with Poseidon; ivk via `hash_allocated_scalars` + `to_bits_le_strict` (no truncation); nf via `hash_bits_with_suffix_scalars`; change nf from multipack to direct scalar; re-pin counts |
| `masp_proofs/src/circuit/poseidon_hash.rs` | No changes needed (existing API sufficient) |
| `masp_proofs/src/sapling/prover.rs` | Remove nullifier multipack path; use scalar nullifier input |
| `masp_proofs/src/sapling/verifier.rs` | Remove nullifier multipack path; use scalar nullifier input |
| `masp_proofs/src/sapling/verifier/single.rs` | Propagate signature change |
| `masp_proofs/src/sapling/verifier/batch.rs` | Propagate signature change |
| `masp_primitives/examples/dump_poseidon_fixtures.rs` | Add ivk/nf vectors if desired |

### OPT-005b: Replace BLAKE2s hash-to-curve for asset_generator

- **Area:** Output circuit BLAKE2s for asset_generator + primitive `AssetType::hash_to_point` / `group_hash`.
- **Current behavior (two BLAKE2s calls):**
  1. Identifier derivation (outside circuit): `identifier = BLAKE2s(MASP__t_, GH_FIRST_BLOCK || name || nonce)` → 32 bytes
  2. Hash-to-point (outside + inside circuit): `generator = from_bytes(BLAKE2s(MASP__v_, identifier))` — interpret as point encoding, reject if invalid/small-order
  - Output circuit: receives `identifier_bits` (256 bits), computes BLAKE2s on them, checks packed equality against witnessed generator's `repr()` (~6k constraints from BLAKE2s + 256 bit witnesses + packed equality)
- **Cost concern:** ~6.3k constraints in Output from BLAKE2s alone, plus 256 bit allocations + packed equality check.
- **Proposed design: BLAKE2b hash-to-field + Poseidon hash-to-curve**

  **Primitives (outside circuit):**
  1. `asset_id = reduce_to_scalar(BLAKE2b(name || nonce))` using full 512-bit digest reduced mod Fr (for example, `from_bytes_wide` semantics). This avoids truncation/decode ambiguity.
  2. `v = Poseidon(DomainAssetGen, [asset_id])` — compute v-coordinate from scalar identifier.
  3. Compute `u² = (v² - 1) / (dv² + 1)`. If not QR, increment `nonce` and go to step 1 (single try-and-increment loop).
  4. `u = sqrt(u²)`, sign determined by convention (e.g., bit 0 of v). Check that `(u, v)` is not small-order.
  5. Return `AssetType { asset_id, nonce }`.

  **Circuit (hash-to-curve verification, not computation):**
  1. Witness `asset_id` as `AllocatedNum<Scalar>` (1 allocation, not 256 bits).
  2. Compute `v = poseidon_hash::hash_allocated_scalars(DomainAssetGen, [asset_id])` (~3 compress ≈ ~1.3k constraints).
  3. Witness asset generator as `EdwardsPoint` (already done in `expose_value_commitment`).
  4. Constrain `generator.v == v` (1 equality constraint).
  5. Sign convention: constrain a bit of `generator.u` to prevent u/(-u) malleability.
  6. Curve equation already checked by `EdwardsPoint::interpret` / `witness`.
  7. Cofactor clearing + `assert_nonzero` in `expose_value_commitment` catches small-order generators (already exists).

- **Soundness analysis:**

  **Subgroup safety:** The circuit's `expose_value_commitment` already cofactor-clears the asset generator (3 doublings = ×8) and asserts the result is not the identity. A small-order generator would produce a zero value commitment after cofactor clearing, causing the proof to fail. The note commitment includes the pre-cofactor-cleared (extended) point bits — this is intentional, as cofactor clearing would destroy injectivity of `AssetType → generator` (multiple extended points cofactor-clear to the same subgroup point). The v-equality constraint + primitive-side small-order rejection ensures no valid AssetType produces a small-order generator.

  **Identifier binding:** The v-equality constraint proves `v = Poseidon(asset_id)`, binding the generator's v-coordinate to the witnessed `asset_id`. The sign convention prevents u/(-u) malleability. This gives the same security property as the current BLAKE2s check: the circuit proves "I know an identifier that hashes to this generator."

  **Name binding (out of circuit):** The current circuit does NOT prove that the identifier was derived from a specific name — it only proves identifier → generator binding. The new design preserves this: name → `asset_id` (via BLAKE2b) is outside the circuit, same as name → `identifier` (via BLAKE2s) is outside the circuit today.

  **Non-uniformity:** The sign convention (choosing u vs -u based on a convention) makes the hash-to-curve distribution non-uniform over the curve (exactly half the valid points are excluded). This is acceptable for this use case — we only need collision resistance and binding, not indifferentiability from a random oracle. Must be documented as a conscious trade-off.

  **BLAKE2b reduction semantics:** Use full-width reduction mod Fr. Do not rely on 255-bit truncation + canonical decode as an "always succeeds" mechanism.

- **`AssetType` struct changes:**
  - `identifier: [u8; 32]` → `asset_id: bls12_381::Scalar` (or its canonical byte representation)
  - `nonce: Option<u8>` is now the try-and-increment nonce for the QR check; must be serialized (remove `borsh(skip)`) so verifiers can reconstruct the hash
  - `AssetType::new_with_nonce` simplified: single loop on `nonce` until QR + not small-order

- **`group_hash` changes:**
  - `group_hash(tag, personalization)` currently uses BLAKE2s to hash to a point encoding
  - With the new design, this would also need a Poseidon-based hash-to-curve or be replaced entirely
  - Used for: `KEY_DIVERSIFICATION_PERSONALIZATION` (diversifier → g_d), `VALUE_COMMITMENT_RANDOMNESS_GENERATOR`, `SPENDING_KEY_GENERATOR`, `PROOF_GENERATION_KEY_GENERATOR`
  - These are fixed generators, not dynamic — they could be replaced with hardcoded constants or a Poseidon-based construction evaluated once

- **Protocol impact:** Yes (changes asset type representation, asset generator derivation, and group hash). Already protocol-breaking for new pool.
- **Status:** `planned`
- **Estimated impact:**
  - Output: `31047` → `~20,500..26,200` (`-4.8k..-10.5k`) depending on final constraint mix after scalar-witness migration and sign/binding checks
  - Spend: unchanged (asset_generator BLAKE2s is Output-only)
  - Convert: unchanged

#### Implementation steps

1. Add `Domain::AssetGen` (scalar `6`) to `masp_primitives/src/sapling/poseidon_hash.rs`
2. Add BLAKE2b dependency to `masp_primitives/Cargo.toml`
3. Rewrite `AssetType::new_with_nonce` in `masp_primitives/src/asset_type.rs`:
   - `asset_id = reduce_to_scalar(BLAKE2b(name || nonce))` (full 512-bit reduction mod Fr)
   - `v = poseidon_hash::hash_scalars(DomainAssetGen, [asset_id])`
   - Compute u from curve equation; if not QR, try next nonce
   - If small-order, try next nonce
   - `AssetType { asset_id, nonce }`
4. Rewrite `AssetType::from_identifier` to accept `bls12_381::Scalar` instead of `[u8; 32]`
5. Rewrite `AssetType::asset_generator()` and `value_commitment_generator()` using new hash-to-curve
6. Update `Output` circuit struct: `asset_identifier: Vec<Option<bool>>` → `asset_id: Option<bls12_381::Scalar>`
7. Replace Output circuit BLAKE2s with Poseidon `hash_allocated_scalars(DomainAssetGen, [asset_id])`; constrain `generator.v == v`; sign convention on u
8. Update Output prover: pass `asset_id` scalar instead of `identifier_bits`
9. Clean up: remove BLAKE2s from Output circuit, remove `VALUE_COMMITMENT_GENERATOR_PERSONALIZATION`, `ASSET_IDENTIFIER_PERSONALIZATION`, `GH_FIRST_BLOCK` from constants
10. `group_hash` handling is tracked separately from OPT-005b in this pass; do not include in this implementation phase unless explicitly approved
11. Update note commitment construction in `Note::cmu_inner()` — `asset_generator_bits` changes from 256-bit extended point repr to however the new generator is encoded
12. Update note encryption / decryption to handle new asset type representation
13. Re-pin Output constraint counts
14. Full `cargo test` validation

#### Soundness checklist (OPT-005b)

- [ ] v-equality constraint proves generator's v-coordinate equals Poseidon output
- [ ] Sign convention on u prevents u/(-u) malleability
- [ ] Cofactor clearing + assert_nonzero in `expose_value_commitment` catches small-order generators
- [ ] Note commitment uses pre-cofactor-cleared (extended) point for injectivity
- [ ] Primitive-side rejection sampling rejects small-order points
- [ ] BLAKE2b(512) reduction mod Fr semantics are fixed and deterministic (including byte order)
- [ ] Non-uniformity from sign convention is documented and acceptable for this use case
- [ ] Try-and-increment nonce is serialized in AssetType for deterministic reconstruction
- [ ] No BLAKE2s calls remain in Output circuit after refactor
- [ ] Native/circuit parity: verify asset generator matches for all test asset types

#### Files affected

| File | Change |
|------|--------|
| `masp_primitives/src/sapling/poseidon_hash.rs` | Add `Domain::AssetGen` |
| `masp_primitives/Cargo.toml` | Add BLAKE2b dependency |
| `masp_primitives/src/asset_type.rs` | Rewrite with BLAKE2b hash-to-field + Poseidon hash-to-curve |
| `masp_primitives/src/constants.rs` | Remove `GH_FIRST_BLOCK`, `ASSET_IDENTIFIER_*`, `VALUE_COMMITMENT_GENERATOR_PERSONALIZATION` |
| `masp_primitives/src/sapling/group_hash.rs` | Separate follow-up track (out-of-scope for OPT-005b implementation phase in this pass) |
| `masp_primitives/src/sapling.rs` | Update note commitment for new asset type representation |
| `masp_primitives/src/sapling/note_encryption.rs` | Update for new asset type representation |
| `masp_proofs/src/circuit/sapling.rs` | Replace BLAKE2s with Poseidon v-equality; `asset_identifier` → `asset_id` scalar; re-pin counts |
| `masp_proofs/src/sapling/prover.rs` | Pass `asset_id` scalar instead of `identifier_bits` |

#### Canonical Encoding Rules (must be fixed in spec/tests)

- Nullifier serialization uses a unique canonical scalar byte encoding at all transaction boundaries.
- Asset-id serialization uses a unique canonical scalar byte encoding at all transaction boundaries.
- BLAKE2b(512) → Fr reduction uses fixed byte-order semantics and deterministic test vectors.

## Prioritized Execution Order

1. ~~OPT-001~~ (done)
2. ~~OPT-002~~ (done, released v0.2.0)
3. **OPT-005a** (highest impact, Spend-only BLAKE2s removal with scalar nullifier migration)
4. **OPT-005b** (Output BLAKE2s removal via BLAKE2b(512)-to-Fr reduction + Poseidon hash-to-curve)
5. OPT-003 (measurement scaffolding — more useful after OPT-005a/005b)
6. Re-pin final counts and rerun full validation
7. OPT-004 only with explicit protocol-change approval

## Validation Checklist (for each implemented optimization)

- `cargo test -p masp_proofs --lib`
- `cargo test -p masp_primitives --lib`
- `cargo test`
- Verify no native/gadget hash mismatches.
- Update pinned `num_constraints()` only after implementation is stable.

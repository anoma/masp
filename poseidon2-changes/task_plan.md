# Task Plan: Poseidon2 Scalar-Only Migration

## Goal
Complete a soundness-preserving migration from remaining BLAKE2s random-oracle style paths to Poseidon2 scalar-native constructions, with scalar nullifiers and scalar asset identifiers end-to-end.

## Current Phase
Phase B (OPT-005b - Output asset generator scalar migration) - in progress

## Phases

### Completed Foundation (already done)
- [x] Pedersen -> Poseidon2 migration for Merkle and note hashing
- [x] Poseidon gadget linear-layer optimization (v0.2.0)
- [x] Native/circuit parity fixes for nullifier rho framing
- [x] Baseline count repin after OPT-001/OPT-002
- **Status:** complete

### Phase A: OPT-005a - Spend ivk/nf scalar migration
- [x] Add `Domain::CRHIvk` and `Domain::PRFNf` to `masp_primitives/src/sapling/poseidon_hash.rs`
- [x] Replace primitive `ViewingKey::ivk()` BLAKE2s with Poseidon scalar hash (`hash_scalars`)
- [x] Use explicit scalar reduction semantics for `bls12_381::Scalar -> jubjub::Fr` (no `from_repr`-as-reduction assumption)
- [x] Replace primitive `Note::nf()` BLAKE2s with Poseidon (`hash_bits_with_suffix_scalars` with `rho` suffix scalar)
- [x] Replace Spend circuit ivk BLAKE2s with Poseidon scalar hash; use full 255 bits in `g_d.mul()` (no truncation)
- [x] Replace Spend circuit nf BLAKE2s + multipack with direct scalar `inputize()`
- [x] Migrate nullifier type and all Spend callsites/APIs to scalar-backed nullifier
- [x] Update prover/verifier spend public inputs (`8 -> 7`) and remove multipack path
- [x] Re-pin Spend counts and run full tests
- [x] Restore ZIP32 `ivk`/`internal_ivk` assertions via JSON fixtures
- **Status:** complete
- **Measured impact:** Spend `83807 -> 44009` (`-39798`)

### Phase B: OPT-005b - Output asset generator scalar migration
- [x] Add `Domain::AssetGen` to `masp_primitives/src/sapling/poseidon_hash.rs`
- [x] Add BLAKE2b dependency and derive `asset_id` by reducing full 512-bit digest mod Fr
- [x] Migrate `AssetType` from byte identifier semantics to scalar `asset_id` semantics; serialize nonce
- [x] Replace Output circuit `asset_identifier` bits witness with scalar `asset_id` witness
- [x] Replace Output BLAKE2s integrity path with Poseidon v-binding + sign convention constraints
- [x] Update note commitment and note encryption/decryption asset-type handling
- [x] Update output prover paths and fixtures for scalar `asset_id`
- [x] Re-pin Output counts and run full tests
- **Status:** complete
- **Estimated impact:** Output `31047 -> ~20500..26200` (-4.8k to -10.5k)

### Phase C: Cleanup and final validation
- [ ] Remove dead BLAKE2s/multipack imports and stale constants where no longer used
- [ ] Keep `group_hash` redesign separate unless explicitly approved in this pass
- [ ] Run `cargo test -p masp_primitives --lib`, `cargo test -p masp_proofs --lib`, `cargo test`
- [ ] Re-pin final counts across Spend/Output/Convert
- **Status:** planned

## Hard Constraints
1. Do not weaken circuit soundness while optimizing.
2. Keep primitives and circuit transcripts aligned (native/gadget parity vectors required).
3. Scalar serialization must be canonical at all nullifier and asset-id boundaries.
4. Count pinning must occur only after functional stability.

## Decisions Made
| Decision | Rationale |
|----------|-----------|
| Migrate nullifier end-to-end to scalar | Removes multipack overhead and simplifies public-input model |
| Reduce full BLAKE2b(512) output mod Fr for `asset_id` | Cleaner and avoids truncation/decode ambiguity |
| Treat `from_repr` as canonical decode only | Avoids unsound assumptions about modular reduction |
| Keep full 255 Poseidon bits for circuit ivk scalar mul | Prevents incorrect truncation semantics |
| Track `group_hash` separately | High blast radius beyond Output optimization |

## Risks and Mitigations
| Risk | Mitigation |
|------|------------|
| Scalar encoding malleability | Enforce canonical read/write for nullifier and asset-id scalars |
| Native/circuit mismatch in scalar conversions | Add deterministic vectors and parity tests for ivk/nf/asset generator |
| Overreaching protocol changes in one patch | Stage Phase A and B independently; keep `group_hash` out unless approved |

## Notes
- This plan supersedes prior OPT-005 draft assumptions and reflects scalar-only migration requirements.

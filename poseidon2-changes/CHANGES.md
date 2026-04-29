# Protocol Hashing Changes

This document specifies the protocol-level hashing changes introduced during the Pedersen/Blake2s -> Poseidon2 migration.

## Breaking Changes Summary

- Merkle parent hashing changed to depth-framed Poseidon2 scalar compression.
- Sapling `ivk` derivation changed from Blake2s bytes to Poseidon scalar transcript (`CRHIvk`).
- Sapling nullifier derivation changed from Blake2s bytes to Poseidon scalar transcript (`PRFNf`) with Poseidon `rho`.
- Spend public inputs changed from 8 -> 7 (nullifier is now one direct scalar input, no multipack limbs).
- Note and allowed-conversion commitments now use Poseidon transcript helpers over scalar/bit transcripts.
- Asset type mapping changed to scalar `asset_id` semantics:
  - `asset_id` derived from BLAKE2b-512 reduced mod `Fr`.
  - Asset generator bound to `Poseidon(AssetGen, asset_id)` with in-circuit v-binding + sign convention constraints.
- Canonical scalar serialization is required at nullifier and asset-id boundaries.

## Notation

- Let `poseidon2 : Fr x Fr -> Fr` denote the 2-input Poseidon2 compression function used everywhere below.
- Scalars are in `Fr = bls12_381::Scalar` unless otherwise stated.
- Jubjub scalar field is denoted `Fr_j`.
- `LE(bits)` means little-endian bit packing into `Fr`.
- `repr(x)` means canonical 32-byte field encoding (`to_repr`).

## Domain Separation

Poseidon domain tags are encoded as scalars and absorbed as the first input in transcript initializers:

- `NoteCommitment = 1`
- `AllowedConversion = 2`
- `NullifierRho = 3`
- `CRHIvk = 4`
- `PRFNf = 5`
- `AssetGen = 6`

## Generic Poseidon transcript helpers

### Bit transcript

`hash_bits_with_suffix_scalars(domain, bits, suffix_scalars)` is defined as:

1. `acc = poseidon2(domain_scalar, len(bits))`
2. Split `bits` into 248-bit chunks.
3. For each chunk `c`: `acc = poseidon2(acc, LE(c))`
4. For each scalar `s` in `suffix_scalars`: `acc = poseidon2(acc, s)`
5. Output `acc`.

`hash_bits(domain, bits)` is the same with empty suffix list.

### Scalar transcript

`hash_scalars(domain, [s0, s1, ...])` is defined as:

1. `acc = poseidon2(domain_scalar, n_scalars)`
2. For each scalar `si`: `acc = poseidon2(acc, si)`
3. Output `acc`.

## Merkle hashing

### Old

- Pedersen-based Merkle parent hash over bit preimages.

### New

- Parent hash at depth `d`:
  - `inner = poseidon2(lhs, rhs)`
  - `parent = poseidon2(d, inner)`

This applies to Sapling note commitment tree nodes and all places that call Sapling merkle hashing.

## Viewing key ivk derivation (`CRH^ivk`)

### Old

- `ivk_bytes = BLAKE2s(ak_repr || nk_repr, personalization=MASP_ivk)`
- Then truncated/converted for Jubjub scalar use.

### New

- Compute affine u-coordinates:
  - `ak_u = u(ak)`
  - `nk_u = u(nk)`
- `ivk_fr = hash_scalars(CRHIvk, [ak_u, nk_u])`
- Primitive `SaplingIvk` conversion uses wide reduction semantics to Jubjub scalar (`Fr_j`) by interpreting `repr(ivk_fr)` in a 64-byte wide input (upper half zeroed) and calling `Fr_j::from_bytes_wide`.

Security/consistency note:

- In-circuit scalar multiplication uses all 255 bits of Poseidon output for `g_d * ivk`; no top-bit truncation is applied.

## Nullifier rho

### Old

- Pedersen-style position binding path.

### New

- `rho = poseidon2(NullifierRho, poseidon2(cmu, position))`

where `position` is the note position scalar.

## Nullifier (`PRF^nf`)

### Old

- `nf_bytes = BLAKE2s(nk_repr || rho_repr, personalization=MASP__nf)`
- Exposed as 2 packed public inputs in Spend proofs.

### New

- `nf = hash_bits_with_suffix_scalars(PRFNf, bits(nk_repr), [rho])`
- `nf` is scalar-native end-to-end.
- Spend public input model changes from 2 packed nullifier field elements to 1 direct scalar nullifier input.

## Note commitment (`cmu`)

### Old

- Pedersen-based note commitment over note contents.

### New

- Note preimage bytes are:
  - `asset_generator_bytes` (32, extended point encoding)
  - `value_le_u64` (8)
  - `g_d_bytes` (32)
  - `pk_d_bytes` (32)
- Let `note_bits` be those bytes expanded little-endian bitwise.
- Let `rcm_fr = Fr(repr(rcm_jubjub))`.
- `cmu = hash_bits_with_suffix_scalars(NoteCommitment, note_bits, [rcm_fr])`.

## Allowed conversion commitment

### Old

- Pedersen-based commitment hashing.

### New

- Let `gen_bytes = generator.to_bytes()` (32 bytes, not cofactor-cleared for commitment encoding).
- `cmu_convert = hash_bits(AllowedConversion, bits(gen_bytes))`.

## Asset identifier / asset generator mapping

### Old

- Asset identifier and generator integrity depended on Blake2s-based hashing to bytes/curve encoding.

### New

#### Asset id derivation

- For asset name `name` and trial nonce `nonce`:
  - `h = BLAKE2b-512( ASSET_IDENTIFIER_PERSONALIZATION || GH_FIRST_BLOCK || name || nonce )`
  - `asset_id = reduce_mod_Fr_le(h)`

`reduce_mod_Fr_le` is full-width modular reduction of the 64-byte digest interpreted in little-endian byte order.

#### Hash-to-curve relation for asset generator

- `v = hash_scalars(AssetGen, [asset_id])`
- Compute
  - `u2 = (v^2 - 1) / (d * v^2 + 1)` over Jubjub base field
- Reject if denominator has no inverse.
- Reject if `u2` is non-square.
- Let `u = sqrt(u2)` and enforce sign convention:
  - if `odd(u) != odd(v)`, set `u = -u`
- Construct point `(u, v)`.
- Reject if cofactor-cleared point is identity (small-order rejection).

`AssetType::new(name)` performs try-and-increment over nonce until a valid point is obtained.

#### Output circuit binding (protocol-critical)

For Output proofs, the circuit now proves:

1. Witness scalar `asset_id`.
2. Compute `expected_v = hash_scalars(AssetGen, [asset_id])` in-circuit.
3. Enforce witnessed asset generator `v` coordinate equals `expected_v`.
4. Enforce sign convention `lsb(u) == lsb(expected_v)`.
5. On-curve and small-order protections remain enforced by existing point gadgets/cofactor checks.

This replaces the previous bitwise Blake2s integrity block in Output.

## Public input changes

### Spend

- Old: 8 public inputs (including 2 multipacked nullifier limbs).
- New: 7 public inputs (single scalar nullifier).

### Output / Convert

- Output and Convert input arity remain unchanged by index count; Output hashing relation changed internally as specified above.

## Canonical encoding rules (current behavior)

- Nullifier is serialized as canonical scalar bytes (`repr`), and decoded canonically.
- Asset id is represented as canonical 32-byte scalar encoding at transaction boundaries.
- Any decode failure from canonical representation is invalid data.

## Scope note

- `group_hash`-based fixed generator derivations (diversifier map and fixed bases) remain Blake2s-based in this phase.
- This document covers the protocol-level changes that were migrated in the current Poseidon2 pass.

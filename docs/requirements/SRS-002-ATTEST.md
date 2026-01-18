# SRS-002-ATTEST: Cryptographic Attestation

**Project:** certifiable-deploy  
**Document ID:** SRS-002-ATTEST  
**Version:** 1.0 (Final)  
**Status:** ✅ Final  
**Date:** January 2026  
**Author:** William Murray  
**Classification:** Software Requirements Specification

---

## Traceability

| Type | Reference |
|------|-----------|
| Parent | CD-MATH-001 §5 (Attestation), §1.2 (Domain-Separated Hashing) |
| Structures | CD-STRUCT-001 §9 (Merkle Tree), §10 (Attestation) |
| Siblings | SRS-001-BUNDLE, SRS-004-MANIFEST, SRS-005-VERIFY |

---

## §1 Purpose

The Attestation Module ("The Notary") constructs the cryptographic proof binding all bundle components into a single verifiable root. It is responsible for:

- **Merkle tree construction** from component hashes
- **Bundle root computation** (flat hash alternative)
- **Optional Ed25519 signature** over the attestation root

**Core Responsibility:** Produce a tamper-evident commitment (R) that cryptographically binds manifest, weights, certificates, and inference artifacts.

---

## §2 Scope

### §2.1 In Scope

- Merkle leaf computation with domain separation
- Merkle node and root computation
- Bundle root hash (H_B) computation
- Ed25519 signature generation (optional)
- Attestation structure population

### §2.2 Out of Scope

- Component hash computation (H_M, H_W, H_C, H_I) — handled by respective modules
- Signature verification — handled by `verify/`
- Bundle serialization — handled by `bundle/`

---

## §3 Functional Requirements

### FR-ATT-01: Merkle Tree Construction

| Field | Value |
|-------|-------|
| Requirement ID | FR-ATT-01 |
| Title | Fixed-Topology Merkle Tree |
| Priority | Critical |

**SHALL:** The system shall construct a 4-leaf Merkle tree with fixed topology as defined in CD-MATH-001 §5.2.

**Input:** Four component hashes:
- H_M (manifest hash)
- H_W (weights hash)
- H_C (certificate chain hash)
- H_I (inference set hash)

**Leaf Computation:**

```
L_M = DH("CD:LEAF:MANIFEST:v1", H_M)
L_W = DH("CD:LEAF:WEIGHTS:v1", H_W)
L_C = DH("CD:LEAF:CERTS:v1", H_C)
L_I = DH("CD:LEAF:INFER:v1", H_I)
```

**Node Computation:**

```
R_1 = DH("CD:MERKLENODE:v1", L_M || L_W)
R_2 = DH("CD:MERKLENODE:v1", L_C || L_I)
```

**Root Computation:**

```
R = DH("CD:MERKLENODE:v1", R_1 || R_2)
```

**Constraints:**

- Domain separation tags MUST be applied at every level
- Tree topology is fixed (no dynamic balancing)
- All intermediate nodes MUST be stored in `cd_merkle_tree_t`

**Output:** Populated `cd_merkle_tree_t` structure.

---

### FR-ATT-02: Bundle Root Hash Computation

| Field | Value |
|-------|-------|
| Requirement ID | FR-ATT-02 |
| Title | Flat Bundle Hash |
| Priority | Critical |

**SHALL:** The system shall compute the bundle root hash as defined in CD-MATH-001 §5.1.

**Computation:**

```
H_B = H("CD:BUNDLE:v1" || H_M || H_W || H_C || H_I)
```

**Constraints:**

- Concatenation order is fixed: manifest, weights, certificates, inference
- Domain tag "CD:BUNDLE:v1" MUST prefix the hash input

**Output:** Populated `cd_attestation_t.bundle_root`.

**Rationale:** H_B provides a simpler commitment for systems that don't require Merkle proof capabilities.

---

### FR-ATT-03: Signature Envelope

| Field | Value |
|-------|-------|
| Requirement ID | FR-ATT-03 |
| Title | Ed25519 Signature Generation |
| Priority | High |

**SHALL:** The system shall optionally sign the Merkle root using Ed25519.

**Input:**
- Merkle root R (from FR-ATT-01)
- Ed25519 private key (64 bytes, caller-provided)

**Computation:**

```
σ = Ed25519.Sign(sk, R)
```

**Output:**
- `cd_attestation_t.signature` (64 bytes)
- `cd_attestation_t.signer_pubkey` (32 bytes, derived from sk)
- `cd_attestation_t.is_signed = 1`

**Constraints:**

- Signature is over R (Merkle root), NOT H_B (bundle root)
- If signing is disabled, `is_signed = 0` and signature fields are zeroed
- Private key MUST NOT be stored in the attestation structure

---

### FR-ATT-04: Timestamp Binding

| Field | Value |
|-------|-------|
| Requirement ID | FR-ATT-04 |
| Title | Attestation Timestamp |
| Priority | Medium |

**SHALL:** The system shall record the attestation timestamp.

**Policy:**

- If `mode == "deterministic"`: timestamp = 0 or externally provided fixed value
- If `mode == "audit"`: timestamp = current Unix time (seconds)

**Output:** `cd_attestation_t.timestamp`

**Constraints:**

- Timestamp MUST satisfy: `0 ≤ timestamp ≤ 4102444800` (year 2100)
- Timestamp is NOT included in the signed payload (R is computed before timestamp is set)

---

### FR-ATT-05: Domain-Separated Hashing Primitive

| Field | Value |
|-------|-------|
| Requirement ID | FR-ATT-05 |
| Title | DH() Implementation |
| Priority | Critical |

**SHALL:** The system shall implement the domain-separated hash function as defined in CD-MATH-001 §1.2.

**Definition:**

```
DH(tag, payload) = H(tag || LE64(|payload|) || payload)
```

Where:
- `tag` is ASCII string (e.g., "CD:LEAF:MANIFEST:v1")
- `LE64(n)` is 8-byte little-endian encoding of payload length
- `H` is SHA-256

**Constraints:**

- Tag MUST be null-terminated ASCII
- Tag length MUST NOT exceed CD_TAG_MAX_LEN (32 bytes)
- Payload length is encoded BEFORE payload bytes

---

## §4 Non-Functional Requirements

### NFR-ATT-01: Determinism

**SHALL:** Given identical inputs (H_M, H_W, H_C, H_I, private_key), the attestation module MUST produce bit-identical output across all platforms.

### NFR-ATT-02: No Dynamic Allocation

**SHALL:** All operations MUST use caller-provided buffers. No malloc/free permitted.

### NFR-ATT-03: Constant-Time Signature

**SHOULD:** Ed25519 signing SHOULD be constant-time to prevent timing side-channels.

---

## §5 Interface Specification

### §5.1 Attestation Builder API

```c
/**
 * @brief Initialize attestation context
 * @traceability SRS-002-ATTEST
 */
int cda_init(cd_attestation_t *att);

/**
 * @brief Compute Merkle tree from component hashes
 * @param h_m Manifest hash
 * @param h_w Weights hash
 * @param h_c Certificate chain hash
 * @param h_i Inference set hash
 * @traceability FR-ATT-01
 */
int cda_compute_merkle(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_fault_flags_t *faults
);

/**
 * @brief Compute bundle root hash
 * @traceability FR-ATT-02
 */
int cda_compute_bundle_root(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_fault_flags_t *faults
);

/**
 * @brief Sign the Merkle root
 * @param private_key Ed25519 private key (64 bytes)
 * @traceability FR-ATT-03
 */
int cda_sign(
    cd_attestation_t *att,
    const uint8_t *private_key,
    cd_fault_flags_t *faults
);

/**
 * @brief Set attestation timestamp
 * @param timestamp Unix timestamp (0 for deterministic mode)
 * @traceability FR-ATT-04
 */
int cda_set_timestamp(cd_attestation_t *att, uint64_t timestamp);
```

### §5.2 Domain Hash API

```c
/**
 * @brief Initialize domain-separated hash context
 * @param tag Domain separation tag (e.g., "CD:LEAF:MANIFEST:v1")
 * @traceability FR-ATT-05
 */
int cd_domain_hash_init(cd_domain_hash_ctx_t *ctx, const char *tag);

/**
 * @brief Update hash with payload bytes
 */
int cd_domain_hash_update(cd_domain_hash_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize and produce digest
 */
int cd_domain_hash_final(cd_domain_hash_ctx_t *ctx, cd_hash_t *out);

/**
 * @brief One-shot domain hash
 * @traceability FR-ATT-05
 */
int cd_domain_hash(
    const char *tag,
    const uint8_t *payload,
    size_t payload_len,
    cd_hash_t *out,
    cd_fault_flags_t *faults
);
```

---

## §6 Data Flow

```
                    ┌─────────────┐
                    │   Inputs    │
                    │ H_M,H_W,H_C,H_I │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    ┌─────────────────┐      ┌─────────────────┐
    │  Merkle Leaves  │      │  Bundle Root    │
    │  L_M,L_W,L_C,L_I │      │      H_B        │
    └────────┬────────┘      └─────────────────┘
             │
    ┌────────┴────────┐
    ▼                 ▼
┌───────┐        ┌───────┐
│  R_1  │        │  R_2  │
└───┬───┘        └───┬───┘
    │                │
    └───────┬────────┘
            ▼
      ┌───────────┐
      │  Root R   │
      └─────┬─────┘
            │
            ▼ (optional)
      ┌───────────┐
      │ Sign(R)   │
      │    σ      │
      └───────────┘
```

---

## §7 Traceability Matrix

| Requirement | CD-MATH-001 Link | CD-STRUCT-001 Link | Implementation Hook |
|-------------|------------------|-------------------|---------------------|
| FR-ATT-01 (Merkle) | §5.2 | §9 `cd_merkle_tree_t` | `cda_compute_merkle` |
| FR-ATT-02 (Bundle Root) | §5.1 | §10 `bundle_root` | `cda_compute_bundle_root` |
| FR-ATT-03 (Signature) | §5.3 | §10 `signature` | `cda_sign` |
| FR-ATT-04 (Timestamp) | §10 | §10 `timestamp` | `cda_set_timestamp` |
| FR-ATT-05 (DH) | §1.2 | §3 `cd_domain_hash_ctx_t` | `cd_domain_hash` |

---

## §8 Test Requirements

| Test ID | Requirement | Description |
|---------|-------------|-------------|
| T-ATT-01 | FR-ATT-01 | Merkle leaves match expected for known H_M,H_W,H_C,H_I |
| T-ATT-02 | FR-ATT-01 | Merkle root matches expected for test vectors |
| T-ATT-03 | FR-ATT-01 | Domain tags correctly applied at each level |
| T-ATT-04 | FR-ATT-02 | Bundle root H_B matches expected |
| T-ATT-05 | FR-ATT-02 | H_B differs from R (they are distinct) |
| T-ATT-06 | FR-ATT-03 | Signature verifies with corresponding public key |
| T-ATT-07 | FR-ATT-03 | Unsigned attestation has zeroed signature fields |
| T-ATT-08 | FR-ATT-04 | Timestamp bounds enforced |
| T-ATT-09 | FR-ATT-05 | DH() matches reference implementation |
| T-ATT-10 | FR-ATT-05 | Length encoding is little-endian |
| T-ATT-11 | NFR-ATT-01 | Bit-identical output on x86 and ARM |

---

## §9 Test Vectors

### §9.1 Domain Hash Test Vector

```
Tag:     "CD:TEST:v1"
Payload: 0x48454C4C4F (ASCII "HELLO", 5 bytes)

DH input: "CD:TEST:v1" || 0x0500000000000000 || 0x48454C4C4F
         (tag)            (LE64 length=5)      (payload)

Expected: (compute SHA-256 of above concatenation)
```

### §9.2 Merkle Tree Test Vector

```
H_M = 0x01 repeated 32 times
H_W = 0x02 repeated 32 times
H_C = 0x03 repeated 32 times
H_I = 0x04 repeated 32 times

Compute:
  L_M = DH("CD:LEAF:MANIFEST:v1", H_M)
  L_W = DH("CD:LEAF:WEIGHTS:v1", H_W)
  L_C = DH("CD:LEAF:CERTS:v1", H_C)
  L_I = DH("CD:LEAF:INFER:v1", H_I)
  
  R_1 = DH("CD:MERKLENODE:v1", L_M || L_W)
  R_2 = DH("CD:MERKLENODE:v1", L_C || L_I)
  
  R = DH("CD:MERKLENODE:v1", R_1 || R_2)

Expected R: (to be computed during implementation)
```

---

## §10 Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-18 | William Murray | Initial release |

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

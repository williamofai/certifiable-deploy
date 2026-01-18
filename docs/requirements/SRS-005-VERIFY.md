# SRS-005-VERIFY: Offline Verification

**Project:** certifiable-deploy  
**Document ID:** SRS-005-VERIFY  
**Version:** 1.0 (Final)  
**Status:** ✅ Final  
**Date:** January 2026  
**Author:** William Murray  
**Classification:** Software Requirements Specification

---

## Traceability

| Type | Reference |
|------|-----------|
| Parent | CD-MATH-001 §7 (Offline Verification), §6 (Chain Consistency) |
| Structures | CD-STRUCT-001 §13 (Verification Result) |
| Siblings | SRS-002-ATTEST, SRS-004-MANIFEST, SRS-006-LOADER |

---

## §1 Purpose

The Verification Module ("The Judge") implements offline bundle verification. It is distinct from the Runtime Loader (CD-LOAD) and is used for:

- **Pre-deployment validation** of bundles
- **Audit tooling** for compliance verification
- **CI/CD integration** for build pipelines

**Core Responsibility:** Determine if a bundle is valid and trustworthy WITHOUT executing any code from it.

---

## §2 Scope

### §2.1 In Scope

- Parse and verify CBF v1 structure
- Recompute all component hashes (H_M, H_W, H_C, H_I)
- Verify Merkle root against footer
- Verify chain consistency (weights ↔ quant cert)
- Verify optional Ed25519 signature
- Generate detailed reason codes on failure

### §2.2 Out of Scope

- Runtime loading and execution — handled by `loader/`
- Bundle creation — handled by `bundle/`
- Hash computation primitives — handled by `audit/`

---

## §3 Functional Requirements

### FR-VER-01: Verification State Machine

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-01 |
| Title | Verification Procedure |
| Priority | Critical |

**SHALL:** The system shall implement the verification procedure defined in CD-MATH-001 §7.1.

**State Machine:**

```
INIT → PARSE_HEADER → PARSE_TOC → EXTRACT_COMPONENTS →
HASH_MANIFEST → HASH_WEIGHTS → HASH_CERTS → HASH_INFERENCE →
COMPUTE_MERKLE → COMPARE_ROOT → CHECK_CHAIN → CHECK_TARGET →
[CHECK_SIGNATURE] → RESULT
```

**States:**

| State | Action | Next State (Success) | Next State (Failure) |
|-------|--------|---------------------|---------------------|
| INIT | Initialize context | PARSE_HEADER | — |
| PARSE_HEADER | Verify CBF magic, version | PARSE_TOC | FAILED |
| PARSE_TOC | Read and validate TOC | EXTRACT_COMPONENTS | FAILED |
| EXTRACT_COMPONENTS | Locate manifest, weights, certs, inference | HASH_MANIFEST | FAILED |
| HASH_MANIFEST | Compute H_M from manifest.json | HASH_WEIGHTS | FAILED |
| HASH_WEIGHTS | Compute H_W from weights.bin | HASH_CERTS | FAILED |
| HASH_CERTS | Compute H_C from certificates/ | HASH_INFERENCE | FAILED |
| HASH_INFERENCE | Compute H_I from inference/ | COMPUTE_MERKLE | FAILED |
| COMPUTE_MERKLE | Build Merkle tree, compute R' | COMPARE_ROOT | FAILED |
| COMPARE_ROOT | Assert R' == R_footer | CHECK_CHAIN | FAILED |
| CHECK_CHAIN | Verify certificate chain links | CHECK_TARGET | FAILED |
| CHECK_TARGET | Verify manifest target == inference target | CHECK_SIGNATURE | FAILED |
| CHECK_SIGNATURE | If signed, verify Ed25519 | RESULT | FAILED |
| RESULT | Populate cd_verify_result_t | — | — |

**Fail-Fast:** On any failure, immediately populate reason code and return.

---

### FR-VER-02: Chain Consistency Verification

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-02 |
| Title | Certificate Chain Validation |
| Priority | Critical |

**SHALL:** The system shall verify the chain of custody from weights to certificates.

**Verification Steps:**

1. Parse `quant.cert` from bundle
2. Extract claimed weights hash: `H_W^cert = QuantCertClaim(Q)`
3. Compute actual weights hash: `H_W' = DH("CD:WEIGHTS:v1", weights.bin)`
4. Assert: `H_W' == H_W^cert`

**Optional Chain Links:**

If `training.cert` present:
- Extract claimed quant hash from training cert
- Assert it matches `h_Q`

If `data.cert` present:
- Extract claimed training hash from data cert
- Assert it matches `h_T`

**Fail-Closed:** Any mismatch ⇒ CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH or CD_VERIFY_ERR_CHAIN_LINK_BROKEN

---

### FR-VER-03: Reason Code Generation

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-03 |
| Title | Detailed Failure Reporting |
| Priority | High |

**SHALL:** The system shall map all failures to specific reason codes.

**Reason Code Mapping:**

| Failure Condition | Reason Code |
|-------------------|-------------|
| Invalid CBF magic | CD_VERIFY_ERR_MAGIC |
| Unsupported CBF version | CD_VERIFY_ERR_VERSION |
| Truncated bundle | CD_VERIFY_ERR_TRUNCATED |
| Manifest hash mismatch | CD_VERIFY_ERR_MANIFEST_HASH |
| Weights hash mismatch | CD_VERIFY_ERR_WEIGHTS_HASH |
| Certificate chain hash mismatch | CD_VERIFY_ERR_CERTCHAIN_HASH |
| Inference hash mismatch | CD_VERIFY_ERR_INFERENCE_HASH |
| Merkle root mismatch | CD_VERIFY_ERR_MERKLE_ROOT |
| Weights ↔ quant cert mismatch | CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH |
| Certificate chain link broken | CD_VERIFY_ERR_CHAIN_LINK_BROKEN |
| Target tuple mismatch | CD_VERIFY_ERR_TARGET_MISMATCH |
| Signature invalid | CD_VERIFY_ERR_SIGNATURE_INVALID |
| Unknown public key | CD_VERIFY_ERR_PUBKEY_UNKNOWN |
| Invalid path in TOC | CD_VERIFY_ERR_PATH_INVALID |
| TOC not sorted | CD_VERIFY_ERR_TOC_UNSORTED |
| Duplicate path in TOC | CD_VERIFY_ERR_DUPLICATE_PATH |
| Manifest schema error | CD_VERIFY_ERR_MANIFEST_SCHEMA |
| Manifest non-canonical | CD_VERIFY_ERR_MANIFEST_NON_CANONICAL |
| Manifest target invalid | CD_VERIFY_ERR_MANIFEST_TARGET_INVALID |
| Manifest timestamp invalid | CD_VERIFY_ERR_MANIFEST_TIMESTAMP_INVALID |

**Constraints:**

- First failure encountered is the reported reason
- All individual check results are recorded in `cd_verify_result_t`
- Reason codes are stable identifiers for logging/auditing

---

### FR-VER-04: Signature Verification

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-04 |
| Title | Ed25519 Signature Check |
| Priority | High |

**SHALL:** If the bundle is signed, the system shall verify the Ed25519 signature.

**Verification Steps:**

1. Check `footer.is_signed`
2. If signed:
   a. Extract `signer_pubkey` from footer
   b. Extract `signature` from footer
   c. Extract `merkle_root` (R) from footer
   d. Verify: `Ed25519.Verify(signer_pubkey, R, signature)`

**Public Key Trust:**

- If `trusted_pubkeys` list provided, assert `signer_pubkey ∈ trusted_pubkeys`
- If no trust list provided, skip trust check (signature validity only)

**Fail-Closed:**

- Invalid signature ⇒ CD_VERIFY_ERR_SIGNATURE_INVALID
- Untrusted public key ⇒ CD_VERIFY_ERR_PUBKEY_UNKNOWN

---

### FR-VER-05: Manifest Canonicalization Check

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-05 |
| Title | JCS Canonicalization Verification |
| Priority | Critical |

**SHALL:** The system shall verify that `manifest.json` is JCS-canonical.

**Verification:**

```
canonical_bytes = JCS(manifest_bytes)
assert manifest_bytes == canonical_bytes  (byte-for-byte)
```

**Fail-Closed:** Non-canonical manifest ⇒ CD_VERIFY_ERR_MANIFEST_NON_CANONICAL

**Rationale:** Prevents "equivalent JSON" attacks where different byte representations hash differently.

---

### FR-VER-06: TOC Ordering Verification

| Field | Value |
|-------|-------|
| Requirement ID | FR-VER-06 |
| Title | TOC Sort Order Check |
| Priority | High |

**SHALL:** The system shall verify that the TOC is sorted lexicographically by normalized path.

**Verification:**

```
for i in 1..n:
  assert strcmp(toc[i-1].path, toc[i].path) < 0
```

**Fail-Closed:**

- Unsorted TOC ⇒ CD_VERIFY_ERR_TOC_UNSORTED
- Duplicate paths ⇒ CD_VERIFY_ERR_DUPLICATE_PATH

---

## §4 Non-Functional Requirements

### NFR-VER-01: Determinism

**SHALL:** Verification MUST produce identical results for identical bundles across all platforms.

### NFR-VER-02: No Code Execution

**SHALL:** Verification MUST NOT execute any code from the bundle. It is a pure data inspection.

### NFR-VER-03: Streaming Support

**SHOULD:** Verification SHOULD support streaming mode for large bundles (compute hashes while reading).

### NFR-VER-04: No Dynamic Allocation

**SHALL:** All operations use caller-provided buffers.

---

## §5 Interface Specification

### §5.1 Verification API

```c
/**
 * @brief Initialize verification context
 * @traceability SRS-005-VERIFY
 */
int cdv_init(cd_verify_ctx_t *ctx);

/**
 * @brief Verify bundle from file path
 * @param path Path to .cdb bundle file
 * @param result Verification result output
 * @traceability FR-VER-01
 */
int cdv_verify_file(
    const char *path,
    cd_verify_result_t *result,
    cd_fault_flags_t *faults
);

/**
 * @brief Verify bundle from memory buffer
 * @param data Bundle bytes
 * @param len Bundle length
 * @param result Verification result output
 * @traceability FR-VER-01
 */
int cdv_verify_buffer(
    const uint8_t *data,
    size_t len,
    cd_verify_result_t *result,
    cd_fault_flags_t *faults
);

/**
 * @brief Set trusted public keys for signature verification
 * @param pubkeys Array of trusted public keys
 * @param count Number of keys
 * @traceability FR-VER-04
 */
int cdv_set_trusted_pubkeys(
    cd_verify_ctx_t *ctx,
    const cd_pubkey_t *pubkeys,
    size_t count
);
```

### §5.2 Streaming Verification API

```c
/**
 * @brief Begin streaming verification
 * @traceability NFR-VER-03
 */
int cdv_stream_begin(cd_verify_stream_t *stream);

/**
 * @brief Feed bytes to streaming verifier
 */
int cdv_stream_update(cd_verify_stream_t *stream, const uint8_t *data, size_t len);

/**
 * @brief Finalize streaming verification
 */
int cdv_stream_finish(cd_verify_stream_t *stream, cd_verify_result_t *result);
```

### §5.3 Chain Verification API

```c
/**
 * @brief Verify certificate chain consistency
 * @param bundle Parsed bundle
 * @traceability FR-VER-02
 */
int cdv_verify_chain(
    const cd_bundle_t *bundle,
    cd_verify_result_t *result,
    cd_fault_flags_t *faults
);

/**
 * @brief Extract claimed weights hash from quant certificate
 * @param quant_cert_data Certificate bytes
 * @param quant_cert_len Certificate length
 * @param claimed_hash Output: claimed H_W
 */
int cdv_extract_quant_claim(
    const uint8_t *quant_cert_data,
    size_t quant_cert_len,
    cd_hash_t *claimed_hash
);
```

---

## §6 Verification Result Structure

```c
/**
 * @brief Detailed verification result
 * @traceability CD-STRUCT-001 §13
 */
typedef struct {
    /* Overall result */
    uint8_t passed;               /**< 1 if all checks pass */
    cd_verify_reason_t reason;    /**< First failure reason */
    
    /* Individual check results */
    uint8_t header_ok;            /**< CBF header valid */
    uint8_t toc_ok;               /**< TOC valid and sorted */
    uint8_t manifest_ok;          /**< Manifest hash matches */
    uint8_t weights_ok;           /**< Weights hash matches */
    uint8_t certchain_ok;         /**< Certificate chain hash matches */
    uint8_t inference_ok;         /**< Inference hash matches */
    uint8_t merkle_ok;            /**< Merkle root matches footer */
    uint8_t chain_consistency_ok; /**< Weights ↔ cert chain valid */
    uint8_t target_ok;            /**< Target tuples match */
    uint8_t signature_ok;         /**< Signature valid (if signed) */
    uint8_t canonical_ok;         /**< Manifest is JCS-canonical */
    
    /* Computed values (for debugging/auditing) */
    cd_hash_t computed_merkle_root;
    cd_hash_t expected_merkle_root;
    cd_hash_t computed_weights_hash;
    cd_hash_t claimed_weights_hash;
} cd_verify_result_t;
```

---

## §7 Traceability Matrix

| Requirement | CD-MATH-001 Link | CD-STRUCT-001 Link | Implementation Hook |
|-------------|------------------|-------------------|---------------------|
| FR-VER-01 (State Machine) | §7.1 | §13 | `cdv_verify_file`, `cdv_verify_buffer` |
| FR-VER-02 (Chain) | §6.1 | §6 `cd_cert_chain_t` | `cdv_verify_chain` |
| FR-VER-03 (Reason Codes) | §7, §12 | §13.1 | `cd_verify_reason_t` |
| FR-VER-04 (Signature) | §5.3 | §10 | `cdv_verify_signature` |
| FR-VER-05 (Canonical) | §3.1 | — | `cdv_check_canonical` |
| FR-VER-06 (TOC Order) | §2.2 | §11 | `cdv_check_toc_order` |

---

## §8 Test Requirements

| Test ID | Requirement | Description |
|---------|-------------|-------------|
| T-VER-01 | FR-VER-01 | Valid bundle passes verification |
| T-VER-02 | FR-VER-01 | Corrupted header detected |
| T-VER-03 | FR-VER-01 | Truncated bundle detected |
| T-VER-04 | FR-VER-01 | Modified manifest detected |
| T-VER-05 | FR-VER-01 | Modified weights detected |
| T-VER-06 | FR-VER-02 | Chain consistency verified |
| T-VER-07 | FR-VER-02 | Chain mismatch detected |
| T-VER-08 | FR-VER-03 | Correct reason code for each failure type |
| T-VER-09 | FR-VER-04 | Valid signature passes |
| T-VER-10 | FR-VER-04 | Invalid signature rejected |
| T-VER-11 | FR-VER-04 | Untrusted pubkey rejected |
| T-VER-12 | FR-VER-05 | Canonical manifest passes |
| T-VER-13 | FR-VER-05 | Non-canonical manifest rejected |
| T-VER-14 | FR-VER-06 | Sorted TOC passes |
| T-VER-15 | FR-VER-06 | Unsorted TOC rejected |
| T-VER-16 | FR-VER-06 | Duplicate path rejected |
| T-VER-17 | NFR-VER-01 | Deterministic results on x86/ARM |

---

## §9 Verification Flowchart

```
                    ┌─────────────┐
                    │   Bundle    │
                    │   Input     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Parse Header│───────────────┐
                    │ (magic/ver) │               │
                    └──────┬──────┘          FAIL │
                           │                      ▼
                    ┌──────▼──────┐         ┌─────────┐
                    │  Parse TOC  │────────▶│ REASON  │
                    │ (sorted?)   │         │  CODE   │
                    └──────┬──────┘         └─────────┘
                           │                      ▲
           ┌───────────────┼───────────────┐      │
           ▼               ▼               ▼      │
     ┌──────────┐   ┌──────────┐   ┌──────────┐   │
     │ Hash H_M │   │ Hash H_W │   │ Hash H_I │   │
     └────┬─────┘   └────┬─────┘   └────┬─────┘   │
          │              │              │         │
          └──────────────┼──────────────┘         │
                         ▼                        │
                  ┌──────────────┐                │
                  │ Compute R'   │                │
                  │ (Merkle Root)│                │
                  └──────┬───────┘                │
                         │                        │
                  ┌──────▼───────┐                │
                  │  R' == R ?   │────────────────┤
                  └──────┬───────┘     NO         │
                         │ YES                    │
                  ┌──────▼───────┐                │
                  │ Chain Check  │────────────────┤
                  │ H_W == H_W^c │     NO         │
                  └──────┬───────┘                │
                         │ YES                    │
                  ┌──────▼───────┐                │
                  │ Target Match │────────────────┤
                  └──────┬───────┘     NO         │
                         │ YES                    │
                  ┌──────▼───────┐                │
                  │  Signature?  │                │
                  └──────┬───────┘                │
                    YES  │  NO                    │
                  ┌──────▼───────┐                │
                  │ Verify Sig   │────────────────┘
                  └──────┬───────┘     FAIL
                         │ PASS
                  ┌──────▼───────┐
                  │    VALID     │
                  └──────────────┘
```

---

## §10 Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-18 | William Murray | Initial release |

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

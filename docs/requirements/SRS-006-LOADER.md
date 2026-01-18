# SRS-006-LOADER: Runtime Secure Loader

**Project:** Certifiable-Deploy  
**Document ID:** SRS-006-LOADER  
**Version:** 1.0  
**Status:** Final  
**Date:** January 2026  
**Author:** William Murray  
**Classification:** Software Requirements Specification

---

## Document Control

| Rev | Date | Author | Description |
|-----|------|--------|-------------|
| 1.0 | Jan 2026 | W. Murray | Initial release defining CD-LOAD |

---

## Traceability

| Type | Reference |
|------|-----------|
| Parent | CD-MATH-001 §4.3 (Runtime Consumption Contract) |
| Data Structures | CD-STRUCT-001 §14 (Loader Context) |
| Siblings | SRS-003-TARGET, SRS-005-VERIFY |

---

## §1 Purpose

The Loader Module ("The Gateway") implements the secure consumption of a deployment bundle on the target device. It is responsible for the JIT (Just-In-Time) Verification of artifacts as they are loaded from disk to memory, ensuring that no code or data is executed unless it mathematically matches the bundle's attestation.

**Core Responsibility:** Enforce the "Execution ⇒ Verification" invariant by refusing to return a valid model handle unless the hash chain is unbroken at load time.

---

## §2 Scope

### §2.1 In Scope

- Implementation of the CD-LOAD State Machine
- Streaming verification of inference/ artifacts (kernels)
- Streaming verification of weights.bin (parameters)
- Target Tuple matching against the physical device
- Memory mapping and permission lockdown (W^X)

### §2.2 Out of Scope

- Offline verification (delegated to verify/ via SRS-005)
- Neural network execution (delegated to the Inference Engine)
- File system parsing (delegated to bundle/ read API)

---

## §3 Functional Requirements

### FR-LDR-01: CD-LOAD State Machine

| Field | Value |
|-------|-------|
| Requirement ID | FR-LDR-01 |
| Title | Deterministic Load Sequence |
| Priority | Critical |

**SHALL:** The loader shall implement the strict state machine defined in CD-MATH-001 §4.3.2.

**States:**

| State | Description |
|-------|-------------|
| INIT | Context zeroed |
| HEADER_READ | CBF Magic/Version verified |
| TOC_READ | TOC sorted and loaded |
| MANIFEST_VERIFIED | H_M matches Merkle Leaf L_M |
| WEIGHTS_STREAMING | Reading weights, updating H_W' |
| WEIGHTS_VERIFIED | H_W' == H_W (from manifest) |
| INFERENCE_STREAMING | Reading kernels, updating H_I' |
| INFERENCE_VERIFIED | H_I' == H_I (from manifest) |
| CHAIN_VERIFIED | Certificate chain validated |
| ENABLED | API Ready |
| FAILED | Terminal error state |

**Fail-Closed:** Any error transitions immediately to FAILED state, which cannot be exited.

**State Diagram:**

```
INIT → HEADER_READ → TOC_READ → MANIFEST_VERIFIED →
WEIGHTS_STREAMING → WEIGHTS_VERIFIED →
INFERENCE_STREAMING → INFERENCE_VERIFIED →
CHAIN_VERIFIED → ENABLED

Any State --[error]--> FAILED (terminal)
```

---

### FR-LDR-02: Target Binding Enforcement

| Field | Value |
|-------|-------|
| Requirement ID | FR-LDR-02 |
| Title | Device Compatibility Check |
| Priority | Critical |

**SHALL:** Before loading any bulk data, the loader shall compare the Bundle Target T_B (from Manifest) against the Device Target T_D (hardcoded or queried from hardware).

**Logic:**

```c
if (!cdt_match(T_B, T_D)) {
    return CDL_ERR_TARGET_MISMATCH;
}
```

**Constraint:** The loader MUST NOT attempt to execute kernels if the architecture or ABI does not match.

---

### FR-LDR-03: JIT Weight Hashing

| Field | Value |
|-------|-------|
| Requirement ID | FR-LDR-03 |
| Title | Verify-While-Loading (Data) |
| Priority | Critical |

**SHALL:** The loader shall compute the SHA-256 hash of the weight payload as it is read from the bundle.

**SHALL:** The loader shall NOT rely on the hash stored in the TOC (which is untrusted). It MUST verify against the H_W registered in the verified Manifest.

**Logic:**

```c
// Pseudo-code
while (bytes_left > 0) {
    read(chunk);
    sha256_update(ctx, chunk);
    memcpy(device_memory, chunk);
}
sha256_final(ctx, hash_measured);
assert(hash_measured == manifest.components.weights.digest);
```

---

### FR-LDR-04: JIT Kernel Hashing

| Field | Value |
|-------|-------|
| Requirement ID | FR-LDR-04 |
| Title | Verify-While-Loading (Code) |
| Priority | Critical |

**SHALL:** The loader shall compute the hash of all files in inference/ as they are loaded into executable memory.

**SHALL:** The loader MUST reject any execution request if the measured Inference Set Hash H_I' does not match the Manifest's H_I.

---

### FR-LDR-05: Certificate Chain Interlock

| Field | Value |
|-------|-------|
| Requirement ID | FR-LDR-05 |
| Title | Quantization Custody Check |
| Priority | High |

**SHALL:** The loader shall parse certificates/quant.cert and extract the claimed weight hash H_W^cert.

**SHALL:** Assert H_W^measured == H_W^cert.

**Rationale:** This proves the weights loaded are the exact same bits that were mathematically certified, not just a random file that matches the manifest.

---

## §4 Non-Functional Requirements

### NFR-LDR-01: Zero-Copy Optimization

**SHOULD:** Where supported by the OS, the loader should use mmap to map the weights directly from the .cdb file, calculating the hash over the mapped region.

### NFR-LDR-02: Atomic Enablement

**SHALL:** The cd_load_ctx_t handle shall only be marked valid for execution after all hashes (Manifest, Weights, Inference, Certs) have passed verification.

### NFR-LDR-03: No Dynamic Allocation

**SHALL:** All operations MUST use caller-provided buffers. No malloc/free permitted.

### NFR-LDR-04: Determinism

**SHALL:** Given identical inputs (bundle bytes, device target), the loader MUST produce bit-identical results across all platforms.

---

## §5 Interface Specification

```c
/**
 * @brief Initialize loader context
 * @param ctx Caller-allocated context
 * @param device_target The hardware definition of the current device
 * @return 0 on success
 */
cdl_result_t cdl_init(cd_load_ctx_t *ctx, const cd_target_t *device_target);

/**
 * @brief Open bundle and verify header/target
 * @details Transitions INIT -> MANIFEST_VERIFIED
 */
cdl_result_t cdl_open_bundle(cd_load_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Get weights size from manifest
 */
cdl_result_t cdl_get_weights_size(const cd_load_ctx_t *ctx, uint64_t *size);

/**
 * @brief Load weights into memory with JIT verification
 * @details Transitions MANIFEST_VERIFIED -> WEIGHTS_VERIFIED
 * @param buffer Output buffer for weights (must be aligned)
 * @param size Buffer size (must match weight size)
 */
cdl_result_t cdl_load_weights(cd_load_ctx_t *ctx, void *buffer, size_t size);

/**
 * @brief Get inference set size from bundle
 */
cdl_result_t cdl_get_inference_size(const cd_load_ctx_t *ctx, uint64_t *size);

/**
 * @brief Load inference kernels with JIT verification
 * @details Transitions WEIGHTS_VERIFIED -> INFERENCE_VERIFIED
 */
cdl_result_t cdl_load_kernels(cd_load_ctx_t *ctx, void *kernel_buffer, size_t size);

/**
 * @brief Finalize and enable execution
 * @details Verifies Cert Chain. Transitions -> ENABLED
 */
cdl_result_t cdl_finalize(cd_load_ctx_t *ctx);

/**
 * @brief Check if loader is in ENABLED state
 */
bool cdl_is_enabled(const cd_load_ctx_t *ctx);

/**
 * @brief Get error description
 */
const char *cdl_error_string(cdl_result_t err);
```

---

## §6 Data Structures

### cd_load_ctx_t

```c
typedef struct {
    /* State machine */
    cdl_state_t state;
    cdl_result_t last_error;

    /* Device binding */
    cd_target_t device_target;
    bool device_target_set;

    /* Bundle reader */
    cd_reader_ctx_t reader;

    /* Parsed manifest */
    cd_manifest_t manifest;
    bool manifest_valid;

    /* Expected hashes (from manifest) */
    cd_hash_t expected_weights_hash;
    cd_hash_t expected_inference_hash;
    cd_hash_t expected_certs_hash;

    /* Measured hashes (JIT computed) */
    cd_hash_t measured_manifest_hash;
    cd_hash_t measured_weights_hash;
    cd_hash_t measured_inference_hash;

    /* Certificate chain */
    cd_cert_chain_t cert_chain;
    bool cert_chain_valid;

    /* Attestation */
    cd_attestation_t attestation;

    /* Fault flags */
    cd_fault_flags_t faults;
} cd_load_ctx_t;
```

---

## §7 Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | CDL_OK | Success |
| -1 | CDL_ERR_NULL | Null pointer argument |
| -2 | CDL_ERR_STATE | Invalid state for operation |
| -3 | CDL_ERR_IO | I/O operation failed |
| -4 | CDL_ERR_MAGIC | Invalid CBF magic number |
| -5 | CDL_ERR_VERSION | Unsupported CBF version |
| -6 | CDL_ERR_TOC_INVALID | TOC parse failed |
| -7 | CDL_ERR_MANIFEST_NOT_FOUND | manifest.json missing |
| -8 | CDL_ERR_MANIFEST_PARSE | Manifest parse failed |
| -9 | CDL_ERR_MANIFEST_HASH | H_M mismatch |
| -10 | CDL_ERR_TARGET_MISMATCH | Bundle/device target incompatible |
| -11 | CDL_ERR_WEIGHTS_NOT_FOUND | weights.bin missing |
| -12 | CDL_ERR_WEIGHTS_SIZE | Buffer size mismatch |
| -13 | CDL_ERR_WEIGHTS_HASH | H_W verification failed |
| -14 | CDL_ERR_INFERENCE_NOT_FOUND | Inference files missing |
| -15 | CDL_ERR_INFERENCE_SIZE | Buffer size mismatch |
| -16 | CDL_ERR_INFERENCE_HASH | H_I verification failed |
| -17 | CDL_ERR_CHAIN_NOT_FOUND | Certificate files missing |
| -18 | CDL_ERR_CHAIN_PARSE | Certificate parse failed |
| -19 | CDL_ERR_CHAIN_MISMATCH | H_W^measured != H_W^cert |
| -20 | CDL_ERR_MERKLE_ROOT | Merkle root mismatch |
| -21 | CDL_ERR_BUFFER_TOO_SMALL | Buffer insufficient |

---

## §8 Traceability Matrix

| Requirement | CD-MATH-001 | CD-STRUCT-001 | Implementation Hook |
|-------------|-------------|---------------|---------------------|
| FR-LDR-01 | §4.3.2 (State Machine) | §14 cdl_state_t | cdl_open_bundle, etc. |
| FR-LDR-02 | §4.2 (Target Binding) | §4 cd_target_t | cdt_match |
| FR-LDR-03 | §4.3.4 (Prop: H_W) | §14 measured_weights_hash | cdl_load_weights |
| FR-LDR-04 | §4.1 (Prop: H_I) | §14 measured_inference_hash | cdl_load_kernels |
| FR-LDR-05 | §3.2 (Chain Consistency) | §14 expected_weights_hash | cdl_finalize |

---

## §9 Test Requirements

| Test ID | Requirement | Description |
|---------|-------------|-------------|
| T-LDR-01 | FR-LDR-01 | State machine transitions correctly |
| T-LDR-02 | FR-LDR-01 | Error transitions to FAILED state |
| T-LDR-03 | FR-LDR-01 | FAILED state is terminal |
| T-LDR-04 | FR-LDR-02 | Target match succeeds for compatible |
| T-LDR-05 | FR-LDR-02 | Target mismatch rejects load |
| T-LDR-06 | FR-LDR-03 | Weights hash computed correctly |
| T-LDR-07 | FR-LDR-03 | Tampered weights detected |
| T-LDR-08 | FR-LDR-04 | Inference hash computed correctly |
| T-LDR-09 | FR-LDR-04 | Tampered kernels detected |
| T-LDR-10 | FR-LDR-05 | Certificate chain validates |
| T-LDR-11 | FR-LDR-05 | Chain mismatch detected |
| T-LDR-12 | NFR-LDR-02 | ENABLED only after all checks |
| T-LDR-13 | NFR-LDR-04 | Deterministic results |

---

## §10 Security Considerations

### §10.1 Threat Model

The loader assumes:
- Bundle may have been tampered with during storage or transmission
- Attacker may attempt to substitute weights or kernels
- Device target information is trusted (hardcoded or from secure source)

### §10.2 Mitigations

| Threat | Mitigation |
|--------|------------|
| Weight substitution | JIT hash verification (FR-LDR-03) |
| Kernel substitution | JIT hash verification (FR-LDR-04) |
| Manifest tampering | Hash included in Merkle root |
| Cross-architecture attack | Target binding (FR-LDR-02) |
| Provenance forgery | Certificate chain interlock (FR-LDR-05) |

### §10.3 TOC Hash Warning

The hash stored in the TOC for each file is NOT trusted for verification. It exists only for integrity checking during development. The loader MUST verify against hashes from the signed manifest, not the TOC.

---

## §11 Known Limitations (v1.0.0)

1. **Certificate Parsing (FR-LDR-05):** Stub implementation. Certificate format specification and parser not yet implemented. `cdl_finalize()` skips chain verification.

2. **Streaming Hash for Inference:** Current implementation uses post-hoc domain separation. Production may require protocol adjustment for true streaming with domain prefix.

3. **Memory Protection (W^X):** Not implemented. Production deployment should apply memory protection after loading.

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

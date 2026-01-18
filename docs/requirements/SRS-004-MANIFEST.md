# SRS-004-MANIFEST: Manifest Schema & Canonicalization

**Project:** certifiable-deploy  
**Document ID:** SRS-004-MANIFEST  
**Version:** 1.0 (Final)  
**Status:** ✅ Final  
**Date:** January 2026  
**Author:** William Murray  
**Classification:** Software Requirements Specification

---

## Traceability

| Type | Reference |
|------|-----------|
| Parent | CD-ARCH-MATH-001 §5 (Manifest), CD-MATH-001 §3.1 (H_M), §8 (CD-LOAD), §10 (Determinism) |
| Siblings | SRS-001-BUNDLE, SRS-002-ATTEST, SRS-005-VERIFY |

---

## §1 Purpose

The Manifest Module ("The Scribe") constructs, parses, and validates the deployment manifest (`manifest.json`). It is the logical root of the deployment artifact, binding:

- **Execution context** (Target Tuple T)
- **Bundle contents** (hash registry for weights/certs/inference)
- **Attestation semantics** (mode + time policy)

**Core Responsibility:** Produce a deterministic, unambiguous description of the deployment payload whose canonical byte representation is the input to H_M.

---

## §2 Scope

### §2.1 In Scope

- Manifest schema definition (Manifest v1)
- JSON Canonicalization Scheme (JCS – RFC 8785) for hashing
- Target Tuple validation
- Timestamp policy enforcement (Deterministic vs Audit)
- Component hash registry validation

### §2.2 Out of Scope

- File I/O (`bundle/`)
- Hash computation (`audit/`)
- Signature verification (`attest/` or `verify/`)
- Runtime loading logic (`loader/`)

---

## §3 Functional Requirements

### FR-MAN-01: Canonical JSON Encoding (JCS)

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-01 |
| Title | Deterministic Text Representation |
| Priority | Critical |

**SHALL:** The system shall serialize the manifest using RFC 8785 (JCS) rules before hashing or bundling as `manifest.json`.

**Key rules (normative):**

- **Object key ordering:** Lexicographic order by UTF-16 code units per RFC 8785
- **Whitespace:** None outside of string values (no pretty printing)
- **Numbers:** Must be valid JSON numbers; no NaN/Infinity; use RFC 8785 canonical number formatting
- **Strings:** UTF-8; escaping per JSON; canonicalization per RFC 8785
- **No duplicate object keys** (reject fail-closed)

**Verification:**

- Must pass RFC 8785 canonicalization test vectors
- H_M must be computed from the canonical output bytes exactly

---

### FR-MAN-02: Target Tuple Definition (T)

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-02 |
| Title | Execution Context Binding |
| Priority | Critical |

**SHALL:** Manifest shall include mandatory `target` object:

```json
"target": {
  "arch":   "riscv64 | x86_64 | aarch64 | ...",
  "vendor": "tenstorrent | nvidia | ...",
  "device": "p150 | a100 | ...",
  "abi":    "linux-gnu | metal | ..."
}
```

**Constraints (normative):**

- Each field MUST match: `^[a-z0-9\-_]+$`
- Fields MUST be lower-case
- Length limits (to prevent abuse):
  - arch ≤ 16 bytes
  - vendor ≤ 32 bytes
  - device ≤ 32 bytes
  - abi ≤ 16 bytes

**Fail-Closed:** Any violation ⇒ reject manifest.

---

### FR-MAN-03: Component Hash Registry

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-03 |
| Title | Internal Integrity Links |
| Priority | Critical |

**SHALL:** Manifest shall include a `components` registry:

```json
"components": {
  "weights":       { "digest": "<64 hex>" },
  "certificates":  { "digest": "<64 hex>" },
  "inference":     { "digest": "<64 hex>" }
}
```

**Constraints:**

- Digests MUST be lowercase hex: `^[a-f0-9]{64}$`
- These values correspond to H_W, H_C, H_I as defined in CD-MATH-001
- The verifier MUST compare these against recomputed values from bundle contents

**Fail-Closed:** Missing/invalid digest ⇒ reject.

---

### FR-MAN-04: Deterministic Timestamp Policy

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-04 |
| Title | Time Abstraction |
| Priority | High |

**SHALL:** Manifest shall include:

- `mode`: `"deterministic"` or `"audit"`
- `created_at`: integer Unix timestamp (seconds)

**Policy (normative):**

If `mode == "deterministic"` then:
- `created_at` SHALL be 0 or a fixed externally provided value (e.g., commit time)
- `created_at` SHALL NOT be the current wall-clock time

If `mode == "audit"` then:
- `created_at` MAY be wall-clock time

**Additional constraints:**

- `created_at` MUST satisfy: `0 ≤ created_at ≤ 4102444800` (≤ year 2100) to avoid integer abuse

**Rationale:** Prevent bit-identity drift caused by clocks.

---

### FR-MAN-05: Schema Versioning

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-05 |
| Title | Evolution Safety |
| Priority | Medium |

**SHALL:** Root must include:

```json
"manifest_version": 1
```

**SHALL:** Parser must reject unsupported versions (fail-closed).

---

### FR-MAN-06: Canonicalization Self-Consistency Check

| Field | Value |
|-------|-------|
| Requirement ID | FR-MAN-06 |
| Title | Reject Non-Canonical Input |
| Priority | Critical |

**SHALL:** The parser shall enforce one of the following policies (implementation choice must be fixed and documented):

**Strict policy (recommended):**
- Input `manifest.json` MUST already be JCS-canonical
- Verification: `json_in_bytes == JCS(json_in_bytes)` byte-for-byte

**Lenient policy (allowed for tooling, not for bundles):**
- Parser may accept non-canonical JSON but MUST re-emit canonical bytes for hashing and bundling
- However, the bundle's stored `manifest.json` must always be canonical

**Fail-Closed:** If strict mode is enabled (recommended), any mismatch ⇒ reject.

**Rationale:** This prevents an attacker from exploiting "equivalent JSON" parsing differences across implementations.

---

## §4 Non-Functional Requirements

### NFR-MAN-01: Strict JSON Only

**SHALL:** Manifest must comply with RFC 8259 JSON:

- No comments
- No trailing commas
- No extensions

### NFR-MAN-02: Human Readability (Dual Output)

**SHOULD:** Builder outputs:

- `manifest.json` (canonical, compact, bundled, hashed)
- `manifest.pretty.json` (pretty printed, NOT bundled, NOT hashed)

---

## §5 Interface Specification

### §5.1 Builder API

```c
/**
 * @brief Initialize manifest builder
 * @traceability SRS-004-MANIFEST
 */
int cdm_builder_init(cdm_builder_t *ctx);

/**
 * @brief Set deployment mode
 * @param mode "deterministic" or "audit"
 * @traceability FR-MAN-04
 */
int cdm_set_mode(cdm_builder_t *ctx, const char *mode);

/**
 * @brief Set creation timestamp
 * @param ts Unix timestamp (seconds), 0 for deterministic mode
 * @traceability FR-MAN-04
 */
int cdm_set_created_at(cdm_builder_t *ctx, uint64_t ts);

/**
 * @brief Set target tuple
 * @traceability FR-MAN-02
 */
int cdm_set_target(cdm_builder_t *ctx, const cd_target_t *target);

/**
 * @brief Set component hash
 * @param component "weights", "certificates", or "inference"
 * @param digest 32-byte SHA-256 hash
 * @traceability FR-MAN-03
 */
int cdm_set_component_hash(cdm_builder_t *ctx, const char *component, const cd_hash_t *digest);

/**
 * @brief Finalize and emit JCS-canonical JSON
 * @traceability FR-MAN-01
 */
int cdm_finalize_jcs(cdm_builder_t *ctx, uint8_t *out, size_t *out_len);
```

### §5.2 Parser API

```c
/**
 * @brief Parse manifest from JSON bytes
 * @traceability FR-MAN-06
 * 
 * Performs:
 * - Schema validation
 * - Regex validation
 * - Numeric bounds validation
 * - Canonicalization policy check (strict or documented alternative)
 */
int cdm_parse(const uint8_t *json, size_t len, cd_manifest_t *out, cd_fault_flags_t *faults);

/**
 * @brief Validate target tuple constraints
 * @traceability FR-MAN-02
 */
int cdm_check_target(const cd_target_t *target);
```

---

## §6 Data Structures (Schema Definition)

### §6.1 JSON Schema (Normative)

```json
{
  "type": "object",
  "required": ["manifest_version", "target", "components", "created_at", "mode"],
  "additionalProperties": false,
  "properties": {
    "manifest_version": { "type": "integer", "const": 1 },
    "created_at": { "type": "integer", "minimum": 0, "maximum": 4102444800 },
    "mode": { "type": "string", "enum": ["deterministic", "audit"] },

    "target": {
      "type": "object",
      "required": ["arch", "vendor", "device", "abi"],
      "additionalProperties": false,
      "properties": {
        "arch":   { "type": "string", "pattern": "^[a-z0-9\\-_]+$", "maxLength": 16 },
        "vendor": { "type": "string", "pattern": "^[a-z0-9\\-_]+$", "maxLength": 32 },
        "device": { "type": "string", "pattern": "^[a-z0-9\\-_]+$", "maxLength": 32 },
        "abi":    { "type": "string", "pattern": "^[a-z0-9\\-_]+$", "maxLength": 16 }
      }
    },

    "components": {
      "type": "object",
      "required": ["weights", "certificates", "inference"],
      "additionalProperties": false,
      "properties": {
        "weights": { "$ref": "#/definitions/hash_entry" },
        "certificates": { "$ref": "#/definitions/hash_entry" },
        "inference": { "$ref": "#/definitions/hash_entry" }
      }
    }
  },
  "definitions": {
    "hash_entry": {
      "type": "object",
      "required": ["digest"],
      "additionalProperties": false,
      "properties": {
        "digest": { "type": "string", "pattern": "^[a-f0-9]{64}$" }
      }
    }
  }
}
```

### §6.2 Example Manifest

```json
{"components":{"certificates":{"digest":"0300000000000000000000000000000000000000000000000000000000000003"},"inference":{"digest":"0400000000000000000000000000000000000000000000000000000000000004"},"weights":{"digest":"0200000000000000000000000000000000000000000000000000000000000002"}},"created_at":0,"manifest_version":1,"mode":"deterministic","target":{"abi":"linux-gnu","arch":"riscv64","device":"p150","vendor":"tenstorrent"}}
```

(Note: JCS-canonical — keys sorted, no whitespace)

---

## §7 Traceability Matrix

| Requirement | CD-MATH-001 Link | Implementation Hook |
|-------------|------------------|---------------------|
| FR-MAN-01 (JCS) | §3.1 H_M | `cdm_finalize_jcs` |
| FR-MAN-02 (Target) | §4, §8.2.1 | `cdm_set_target`, `cdm_check_target` |
| FR-MAN-03 (Hashes) | §3.2–§4 H_W, H_C, H_I | `cdm_set_component_hash` |
| FR-MAN-04 (Time) | §10 (Determinism) | `cdm_set_mode`, `cdm_set_created_at` |
| FR-MAN-05 (Version) | §5.2 | `cdm_parse` |
| FR-MAN-06 (Canonical input) | §3.1 (canonical bytes) | `cdm_parse` strict check |

---

## §8 Test Requirements

| Test ID | Requirement | Description |
|---------|-------------|-------------|
| T-MAN-01 | FR-MAN-01 | RFC 8785 test vectors pass |
| T-MAN-02 | FR-MAN-01 | H_M matches expected for known input |
| T-MAN-03 | FR-MAN-02 | Valid target tuples accepted |
| T-MAN-04 | FR-MAN-02 | Invalid characters rejected |
| T-MAN-05 | FR-MAN-02 | Oversized fields rejected |
| T-MAN-06 | FR-MAN-03 | Valid hex digests accepted |
| T-MAN-07 | FR-MAN-03 | Invalid hex rejected |
| T-MAN-08 | FR-MAN-04 | Mode "deterministic" enforces created_at rules |
| T-MAN-09 | FR-MAN-04 | Timestamp bounds enforced |
| T-MAN-10 | FR-MAN-05 | Unsupported version rejected |
| T-MAN-11 | FR-MAN-06 | Non-canonical JSON rejected (strict mode) |
| T-MAN-12 | NFR-MAN-01 | JSON with comments rejected |

---

## §9 Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-18 | William Murray | Initial release |

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

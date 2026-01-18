# SRS-003-TARGET: Target Tuple & Context Binding

**Project:** certifiable-deploy  
**Document ID:** SRS-003-TARGET  
**Version:** 1.0 (Final)  
**Status:** ✅ Final  
**Date:** January 2026  
**Author:** William Murray  
**Classification:** Software Requirements Specification

---

## Traceability

| Type | Reference |
|------|-----------|
| Parent | CD-MATH-001 §4 (Target Binding), §8.2.1 (Runtime Target Match) |
| Structures | CD-STRUCT-001 §4 (Target Tuple) |
| Siblings | SRS-001-BUNDLE, SRS-004-MANIFEST, SRS-006-LOADER |

---

## §1 Purpose

The Target Module ("The Gatekeeper") defines and enforces the execution context binding. It ensures that:

- **Single target tuple** per bundle (no multi-arch bundles)
- **Inference artifacts match** the declared target
- **ABI compatibility** is enforced at build time

**Core Responsibility:** Guarantee that a bundle's inference artifacts will only execute on the declared target platform.

---

## §2 Scope

### §2.1 In Scope

- Target tuple parsing and validation
- Canonical target encoding for hashing
- Inference artifact target verification
- ABI compatibility checking
- Target matching (bundle vs device)

### §2.2 Out of Scope

- Inference code generation — handled externally
- Runtime loading — handled by `loader/`
- Hash computation — handled by `audit/`

---

## §3 Functional Requirements

### FR-TGT-01: Target Tuple Parsing & Validation

| Field | Value |
|-------|-------|
| Requirement ID | FR-TGT-01 |
| Title | Tuple Parsing and Validation |
| Priority | Critical |

**SHALL:** The system shall parse and validate target tuples in the format:

```
arch-vendor-device-abi
```

**Examples:**
- `riscv64-tenstorrent-p150-lp64d`
- `x86_64-generic-cpu-sysv`
- `aarch64-nvidia-orin-lp64`

**Validation Rules:**

| Field | Constraint | Max Length |
|-------|------------|------------|
| arch | Must match `cd_arch_t` enum | 16 bytes |
| vendor | `^[a-z0-9\-_]+$` | 32 bytes |
| device | `^[a-z0-9\-_]+$` | 32 bytes |
| abi | Must match `cd_abi_t` enum or known ABI string | 16 bytes |

**Architecture Enum Mapping:**

| String | Enum Value |
|--------|------------|
| `x86_64` | CD_ARCH_X86_64 |
| `aarch64` | CD_ARCH_AARCH64 |
| `riscv64` | CD_ARCH_RISCV64 |

**ABI Enum Mapping:**

| String | Enum Value |
|--------|------------|
| `sysv`, `linux-gnu` | CD_ABI_SYSV |
| `eabi`, `lp64`, `lp64d` | CD_ABI_EABI |
| `metal`, `baremetal` | CD_ABI_BAREMETAL |

**Fail-Closed:** Invalid arch, unknown ABI, or regex violation ⇒ reject.

---

### FR-TGT-02: Inference Artifact Selection & Validation

| Field | Value |
|-------|-------|
| Requirement ID | FR-TGT-02 |
| Title | Single-Target Enforcement |
| Priority | Critical |

**SHALL:** The system shall enforce that all inference artifacts match the declared target tuple.

**Directory Structure:**

```
inference/
└── <arch>-<vendor>-<device>-<abi>/
    ├── kernel.bin
    ├── weights_layout.bin
    └── ...
```

**Validation Steps:**

1. Scan `inference/` directory
2. Assert exactly ONE subdirectory exists
3. Parse subdirectory name as target tuple
4. Assert parsed tuple matches manifest target T

**Constraints:**

- MUST NOT contain artifacts for multiple architectures
- MUST NOT contain stray files outside the target directory
- Directory name MUST exactly match canonical target string

**Fail-Closed:** Any of the following ⇒ reject build:
- Multiple target directories
- Target directory mismatch with manifest
- Files outside target directory
- Unparseable directory name

---

### FR-TGT-03: ABI Compatibility Check

| Field | Value |
|-------|-------|
| Requirement ID | FR-TGT-03 |
| Title | ABI Enforcement |
| Priority | High |

**SHALL:** The system shall enforce ABI compatibility rules.

**ABI Compatibility Matrix:**

| ABI | Floating-Point | Calling Convention | Notes |
|-----|----------------|-------------------|-------|
| `lp64` | Soft-float | LP64 | No FP registers |
| `lp64d` | Hard-float (double) | LP64 | D extension required |
| `lp64f` | Hard-float (single) | LP64 | F extension required |
| `sysv` | Platform default | System V | Linux/BSD standard |
| `eabi` | Configurable | Embedded | Bare-metal friendly |
| `baremetal` | None assumed | Custom | No OS |

**Constraints:**

- `lp64d` requires RISC-V D extension
- `lp64f` requires RISC-V F extension
- Mixed ABIs within a bundle are FORBIDDEN

**Fail-Closed:** ABI mismatch or unknown ABI ⇒ reject.

---

### FR-TGT-04: Canonical Target Encoding

| Field | Value |
|-------|-------|
| Requirement ID | FR-TGT-04 |
| Title | Deterministic Target Serialization |
| Priority | Critical |

**SHALL:** The system shall serialize target tuples canonically for inclusion in H_I.

**Encoding Format:**

```
T_bytes = arch_u32_le || vendor_len_u16_le || vendor_bytes || 
          device_len_u16_le || device_bytes || abi_u32_le
```

Where:
- `arch_u32_le`: Architecture enum as 4-byte little-endian
- `vendor_len_u16_le`: Vendor string length as 2-byte little-endian
- `vendor_bytes`: Vendor string (no null terminator)
- `device_len_u16_le`: Device string length as 2-byte little-endian
- `device_bytes`: Device string (no null terminator)
- `abi_u32_le`: ABI enum as 4-byte little-endian

**Constraints:**

- Encoding MUST be deterministic
- Strings are NOT null-terminated in encoding
- Length-prefixed to avoid ambiguity

---

### FR-TGT-05: Target Match (Bundle vs Device)

| Field | Value |
|-------|-------|
| Requirement ID | FR-TGT-05 |
| Title | Runtime Target Verification |
| Priority | Critical |

**SHALL:** The system shall provide a function to compare bundle target against device target.

**Match Rules:**

| Field | Match Rule |
|-------|------------|
| arch | MUST be identical |
| vendor | MUST be identical OR device accepts wildcard "generic" |
| device | MUST be identical OR bundle specifies "generic" |
| abi | MUST be compatible (see FR-TGT-03) |

**Wildcard Policy:**

- Bundle with `vendor=generic` matches any vendor
- Bundle with `device=generic` matches any device
- Wildcard in device target is NOT permitted (device must be specific)

**Fail-Closed:** Mismatch ⇒ CD_VERIFY_ERR_TARGET_MISMATCH

---

## §4 Non-Functional Requirements

### NFR-TGT-01: Determinism

**SHALL:** Target parsing and encoding MUST produce identical results across all platforms.

### NFR-TGT-02: Case Sensitivity

**SHALL:** All target fields are case-sensitive and MUST be lowercase.

### NFR-TGT-03: No Dynamic Allocation

**SHALL:** All operations use fixed-size buffers from `cd_target_t`.

---

## §5 Interface Specification

### §5.1 Target Parsing API

```c
/**
 * @brief Parse target tuple from string
 * @param str Target string (e.g., "riscv64-tenstorrent-p150-lp64d")
 * @param out Parsed target structure
 * @traceability FR-TGT-01
 */
int cdt_parse(const char *str, cd_target_t *out, cd_fault_flags_t *faults);

/**
 * @brief Validate target tuple fields
 * @traceability FR-TGT-01, FR-TGT-03
 */
int cdt_validate(const cd_target_t *target, cd_fault_flags_t *faults);

/**
 * @brief Format target tuple to canonical string
 * @param target Target structure
 * @param buf Output buffer (must be >= CD_TARGET_STRING_MAX_LEN)
 * @param len Buffer length
 */
int cdt_format(const cd_target_t *target, char *buf, size_t len);
```

### §5.2 Target Encoding API

```c
/**
 * @brief Encode target tuple to canonical bytes for hashing
 * @param target Target structure
 * @param out Output buffer (must be >= CD_TARGET_ENCODED_MAX_SIZE)
 * @param out_len Actual encoded length
 * @traceability FR-TGT-04
 */
int cdt_encode(const cd_target_t *target, uint8_t *out, size_t *out_len);

/**
 * @brief Decode target tuple from canonical bytes
 * @param data Encoded bytes
 * @param len Encoded length
 * @param out Decoded target structure
 */
int cdt_decode(const uint8_t *data, size_t len, cd_target_t *out);
```

### §5.3 Target Matching API

```c
/**
 * @brief Check if bundle target matches device target
 * @param bundle_target Target from bundle manifest
 * @param device_target Target of execution device
 * @traceability FR-TGT-05
 */
int cdt_match(const cd_target_t *bundle_target, const cd_target_t *device_target);

/**
 * @brief Check ABI compatibility
 * @param bundle_abi ABI from bundle
 * @param device_abi ABI of device
 * @traceability FR-TGT-03
 */
int cdt_abi_compatible(cd_abi_t bundle_abi, cd_abi_t device_abi);
```

### §5.4 Inference Directory Validation API

```c
/**
 * @brief Validate inference directory structure
 * @param inference_path Path to inference/ directory
 * @param expected_target Expected target from manifest
 * @traceability FR-TGT-02
 */
int cdt_validate_inference_dir(
    const char *inference_path,
    const cd_target_t *expected_target,
    cd_fault_flags_t *faults
);
```

---

## §6 Data Structures

### §6.1 Target String Constants

```c
#define CD_TARGET_STRING_MAX_LEN 96  /* arch(16) + vendor(32) + device(32) + abi(16) + separators */

/* Known architectures */
#define CD_ARCH_STR_X86_64   "x86_64"
#define CD_ARCH_STR_AARCH64  "aarch64"
#define CD_ARCH_STR_RISCV64  "riscv64"

/* Known ABIs */
#define CD_ABI_STR_SYSV      "sysv"
#define CD_ABI_STR_LINUX_GNU "linux-gnu"
#define CD_ABI_STR_LP64      "lp64"
#define CD_ABI_STR_LP64D     "lp64d"
#define CD_ABI_STR_LP64F     "lp64f"
#define CD_ABI_STR_EABI      "eabi"
#define CD_ABI_STR_METAL     "metal"
#define CD_ABI_STR_BAREMETAL "baremetal"

/* Wildcard */
#define CD_TARGET_WILDCARD   "generic"
```

---

## §7 Traceability Matrix

| Requirement | CD-MATH-001 Link | CD-STRUCT-001 Link | Implementation Hook |
|-------------|------------------|-------------------|---------------------|
| FR-TGT-01 (Parse) | §4.3 | §4 `cd_target_t` | `cdt_parse`, `cdt_validate` |
| FR-TGT-02 (Inference) | §4 | §7 `cd_inference_set_t` | `cdt_validate_inference_dir` |
| FR-TGT-03 (ABI) | §4.3 | §4.2 `cd_abi_t` | `cdt_abi_compatible` |
| FR-TGT-04 (Encode) | §4.3 | §4.3 | `cdt_encode`, `cdt_decode` |
| FR-TGT-05 (Match) | §8.2.1 | §4 | `cdt_match` |

---

## §8 Test Requirements

| Test ID | Requirement | Description |
|---------|-------------|-------------|
| T-TGT-01 | FR-TGT-01 | Valid target strings parse correctly |
| T-TGT-02 | FR-TGT-01 | Invalid arch rejected |
| T-TGT-03 | FR-TGT-01 | Invalid characters rejected |
| T-TGT-04 | FR-TGT-01 | Oversized fields rejected |
| T-TGT-05 | FR-TGT-02 | Single target directory accepted |
| T-TGT-06 | FR-TGT-02 | Multiple target directories rejected |
| T-TGT-07 | FR-TGT-02 | Mismatched directory name rejected |
| T-TGT-08 | FR-TGT-03 | Compatible ABIs pass |
| T-TGT-09 | FR-TGT-03 | Incompatible ABIs rejected |
| T-TGT-10 | FR-TGT-04 | Encoding is deterministic |
| T-TGT-11 | FR-TGT-04 | Encode/decode roundtrip |
| T-TGT-12 | FR-TGT-05 | Exact match succeeds |
| T-TGT-13 | FR-TGT-05 | Wildcard vendor matches |
| T-TGT-14 | FR-TGT-05 | Arch mismatch fails |

---

## §9 Test Vectors

### §9.1 Target Parsing

```
Input:  "riscv64-tenstorrent-p150-lp64d"
Output:
  arch   = CD_ARCH_RISCV64
  vendor = "tenstorrent"
  device = "p150"
  abi    = CD_ABI_EABI  (lp64d maps to EABI)
```

### §9.2 Canonical Encoding

```
Target: { arch=RISCV64, vendor="tenstorrent", device="p150", abi=EABI }

Encoded bytes:
  03 00 00 00           (arch = 3 = RISCV64, LE32)
  0B 00                 (vendor_len = 11, LE16)
  74 65 6E 73 74 6F 72 72 65 6E 74  ("tenstorrent")
  04 00                 (device_len = 4, LE16)
  70 31 35 30           ("p150")
  02 00 00 00           (abi = 2 = EABI, LE32)

Total: 4 + 2 + 11 + 2 + 4 + 4 = 27 bytes
```

---

## §10 Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-18 | William Murray | Initial release |

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

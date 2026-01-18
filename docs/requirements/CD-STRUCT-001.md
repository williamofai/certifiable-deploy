# CD-STRUCT-001: Data Structure Specification

**Project:** certifiable-deploy  
**Version:** 1.0.1  
**Status:** ✅ Final  
**Traces to:** CD-MATH-001 Rev A1

---

## 1. Overview

This document defines all data structures for certifiable-deploy, derived directly from CD-MATH-001. Every structure traces to its mathematical definition.

**Naming Convention:** All types use `cd_` prefix (certifiable-deploy).

**Alignment Policy:** All structures use explicit padding to ensure deterministic layout across compilers and architectures. No implicit padding is permitted.

---

## 2. Primitive Types

### 2.1 Fixed-Width Integers

| Type | Width | Use |
|------|-------|-----|
| `uint8_t` | 8 bits | Byte arrays, flags |
| `uint16_t` | 16 bits | Length prefixes |
| `uint32_t` | 32 bits | Sizes, enums |
| `uint64_t` | 64 bits | Lengths, timestamps |
| `int32_t` | 32 bits | Signed offsets |

**Traceability:** CD-MATH-001 §2.1 (LE64 encoding)

### 2.2 Hash Type

```c
/**
 * @brief 32-byte SHA-256 digest
 * @traceability CD-MATH-001 §1.1
 */
#define CD_HASH_SIZE 32

typedef struct {
    uint8_t bytes[CD_HASH_SIZE];
} cd_hash_t;
```

### 2.3 Signature Type

```c
/**
 * @brief 64-byte Ed25519 signature
 * @traceability CD-MATH-001 §5.3
 */
#define CD_SIGNATURE_SIZE 64

typedef struct {
    uint8_t bytes[CD_SIGNATURE_SIZE];
} cd_signature_t;
```

### 2.4 Public Key Type

```c
/**
 * @brief 32-byte Ed25519 public key
 * @traceability CD-MATH-001 §5.3
 */
#define CD_PUBKEY_SIZE 32

typedef struct {
    uint8_t bytes[CD_PUBKEY_SIZE];
} cd_pubkey_t;
```

---

## 3. Domain-Separated Hash Context

**Traceability:** CD-MATH-001 §1.2

```c
/**
 * @brief Domain tags for hash separation
 * @traceability CD-MATH-001 §1.2, §3, §4, §5
 */
#define CD_TAG_MANIFEST      "CD:MANIFEST:v1"
#define CD_TAG_WEIGHTS       "CD:WEIGHTS:v1"
#define CD_TAG_CERT_QUANT    "CD:CERT:QUANT:v1"
#define CD_TAG_CERT_TRAIN    "CD:CERT:TRAIN:v1"
#define CD_TAG_CERT_DATA     "CD:CERT:DATA:v1"
#define CD_TAG_CERTSET       "CD:CERTSET:v1"
#define CD_TAG_FILE          "CD:FILE:v1"
#define CD_TAG_INFERSET      "CD:INFERSET:v1"
#define CD_TAG_BUNDLE        "CD:BUNDLE:v1"
#define CD_TAG_LEAF_MANIFEST "CD:LEAF:MANIFEST:v1"
#define CD_TAG_LEAF_WEIGHTS  "CD:LEAF:WEIGHTS:v1"
#define CD_TAG_LEAF_CERTS    "CD:LEAF:CERTS:v1"
#define CD_TAG_LEAF_INFER    "CD:LEAF:INFER:v1"
#define CD_TAG_MERKLENODE    "CD:MERKLENODE:v1"

#define CD_TAG_MAX_LEN 32

/**
 * @brief Domain-separated hash context
 * @traceability CD-MATH-001 §1.2
 * 
 * Implements: DH(tag, payload) = H(tag || LE64(|payload|) || payload)
 */
typedef struct {
    cd_sha256_ctx_t sha_ctx;           /**< Underlying SHA-256 context */
    char tag[CD_TAG_MAX_LEN];          /**< Domain separation tag */
    uint64_t payload_len;              /**< Accumulated payload length */
    uint8_t finalized;                 /**< 1 if digest computed */
    uint8_t _pad0[7];                  /**< Explicit padding */
} cd_domain_hash_ctx_t;
```

---

## 4. Target Tuple

**Traceability:** CD-MATH-001 §4.3

### 4.1 Architecture Enum

```c
/**
 * @brief Supported CPU architectures
 * @traceability CD-MATH-001 §4.3
 */
typedef enum {
    CD_ARCH_UNKNOWN = 0,
    CD_ARCH_X86_64  = 1,
    CD_ARCH_AARCH64 = 2,
    CD_ARCH_RISCV64 = 3
} cd_arch_t;
```

### 4.2 ABI Enum

```c
/**
 * @brief Application Binary Interface
 * @traceability CD-MATH-001 §4.3
 */
typedef enum {
    CD_ABI_UNKNOWN  = 0,
    CD_ABI_SYSV     = 1,    /**< System V (Linux, BSD) */
    CD_ABI_EABI     = 2,    /**< Embedded ABI */
    CD_ABI_BAREMETAL = 3    /**< No OS */
} cd_abi_t;
```

### 4.3 Target Tuple Structure

```c
/**
 * @brief Target platform specification
 * @traceability CD-MATH-001 §4.3
 * 
 * Implements: T = enc(arch, vendor, device, abi)
 */
#define CD_VENDOR_MAX_LEN 32
#define CD_DEVICE_MAX_LEN 32

typedef struct {
    cd_arch_t architecture;            /**< CPU architecture (4 bytes) */
    cd_abi_t abi;                      /**< ABI specification (4 bytes) */
    char vendor[CD_VENDOR_MAX_LEN];    /**< Vendor name (e.g., "tenstorrent") */
    char device[CD_DEVICE_MAX_LEN];    /**< Device name (e.g., "p150") */
} cd_target_t;

/**
 * @brief Canonical target encoding size
 * 
 * Layout: arch(4) + vendor_len(2) + vendor + device_len(2) + device + abi(4)
 */
#define CD_TARGET_ENCODED_MAX_SIZE (4 + 2 + CD_VENDOR_MAX_LEN + 2 + CD_DEVICE_MAX_LEN + 4)
```

---

## 5. Manifest

**Traceability:** CD-MATH-001 §3.1

### 5.1 Format Specification

```c
/**
 * @brief Weight/activation format
 * @traceability CD-MATH-001 §3 (implicit)
 */
typedef enum {
    CD_FORMAT_UNKNOWN = 0,
    CD_FORMAT_Q16_16  = 1,    /**< Q16.16 fixed-point */
    CD_FORMAT_Q8_24   = 2,    /**< Q8.24 fixed-point */
    CD_FORMAT_Q32_32  = 3     /**< Q32.32 fixed-point */
} cd_format_t;
```

### 5.2 Mode Specification

```c
/**
 * @brief Deployment mode
 * @traceability CD-MATH-001 §10, SRS-004-MANIFEST FR-MAN-04
 */
typedef enum {
    CD_MODE_UNKNOWN       = 0,
    CD_MODE_DETERMINISTIC = 1,    /**< created_at must be 0 or fixed */
    CD_MODE_AUDIT         = 2     /**< created_at may be wall-clock */
} cd_mode_t;
```

### 5.3 Manifest Structure

```c
/**
 * @brief Bundle manifest
 * @traceability CD-MATH-001 §3.1, SRS-004-MANIFEST
 * 
 * H_M = DH("CD:MANIFEST:v1", M)
 * 
 * Layout verified for 64-bit alignment:
 *   Offset 0:   model_id[64]
 *   Offset 64:  version_major (4)
 *   Offset 68:  version_minor (4)
 *   Offset 72:  version_patch (4)
 *   Offset 76:  _pad0 (4) -- explicit padding
 *   Offset 80:  created_timestamp (8) -- 8-byte aligned
 *   Offset 88:  target (72)
 *   Offset 160: weights_format (4)
 *   Offset 164: activations_format (4)
 *   Offset 168: mode (4)
 *   Offset 172: has_quant_cert (1)
 *   Offset 173: has_training_cert (1)
 *   Offset 174: has_data_cert (1)
 *   Offset 175: _pad1 (1) -- explicit padding
 *   Total: 176 bytes
 */
#define CD_MODEL_ID_MAX_LEN 64

typedef struct {
    /* Identification */
    char model_id[CD_MODEL_ID_MAX_LEN];  /**< Model identifier */
    uint32_t version_major;               /**< Semantic version major */
    uint32_t version_minor;               /**< Semantic version minor */
    uint32_t version_patch;               /**< Semantic version patch */
    uint32_t _pad0;                       /**< Explicit padding for 64-bit alignment */
    
    /* Timestamp (explicit input, not ambient) */
    uint64_t created_timestamp;           /**< Unix timestamp (seconds) */
    
    /* Target platform */
    cd_target_t target;
    
    /* Data formats */
    cd_format_t weights_format;           /**< Weight encoding */
    cd_format_t activations_format;       /**< Activation encoding */
    
    /* Mode */
    cd_mode_t mode;                       /**< Deterministic or audit */
    
    /* Certificate presence flags */
    uint8_t has_quant_cert;
    uint8_t has_training_cert;
    uint8_t has_data_cert;
    uint8_t _pad1;                        /**< Explicit padding */
} cd_manifest_t;
```

---

## 6. Certificate Chain

**Traceability:** CD-MATH-001 §3.3, §3.4

### 6.1 Individual Certificate Digests

```c
/**
 * @brief Certificate presence and digest
 * @traceability CD-MATH-001 §3.3
 */
typedef struct {
    uint8_t present;          /**< 1 if certificate exists */
    uint8_t _pad0[3];         /**< Explicit padding */
    uint32_t _pad1;           /**< Explicit padding for 8-byte alignment of digest */
    cd_hash_t digest;         /**< h_Q, h_T, or h_D (0^32 if absent) */
} cd_cert_entry_t;
```

### 6.2 Certificate Chain Structure

```c
/**
 * @brief Complete certificate chain
 * @traceability CD-MATH-001 §3.4
 * 
 * H_C = H("CD:CERTSET:v1" || h_D || h_T || h_Q)
 * Order: [data, training, quant]
 */
typedef struct {
    cd_cert_entry_t data;       /**< Data pipeline certificate */
    cd_cert_entry_t training;   /**< Training certificate */
    cd_cert_entry_t quant;      /**< Quantization certificate */
    cd_hash_t chain_hash;       /**< H_C: computed chain hash */
} cd_cert_chain_t;
```

---

## 7. Inference Artifact Set

**Traceability:** CD-MATH-001 §4

### 7.1 File Entry

```c
/**
 * @brief Single file in inference set
 * @traceability CD-MATH-001 §4.2
 * 
 * h_i = DH("CD:FILE:v1", p_i || b_i)
 */
#define CD_PATH_MAX_LEN 256

typedef struct {
    char path[CD_PATH_MAX_LEN];   /**< Normalized relative path */
    uint64_t size;                /**< File size in bytes */
    cd_hash_t hash;               /**< Per-file hash h_i */
} cd_file_entry_t;
```

### 7.2 Inference Set Structure

```c
/**
 * @brief Complete inference artifact set
 * @traceability CD-MATH-001 §4.4
 * 
 * H_I = H("CD:INFERSET:v1" || T || (p_1, h_1) || ... || (p_n, h_n))
 */
#define CD_MAX_INFERENCE_FILES 256

typedef struct {
    cd_target_t target;                            /**< Bound target tuple */
    uint32_t file_count;                           /**< Number of files */
    uint32_t _pad0;                                /**< Explicit padding */
    cd_file_entry_t files[CD_MAX_INFERENCE_FILES]; /**< Sorted file list */
    cd_hash_t set_hash;                            /**< H_I: computed set hash */
} cd_inference_set_t;
```

---

## 8. Weights

**Traceability:** CD-MATH-001 §3.2

```c
/**
 * @brief Weights metadata and hash
 * @traceability CD-MATH-001 §3.2
 * 
 * H_W = DH("CD:WEIGHTS:v1", W)
 */
typedef struct {
    uint64_t size;              /**< Size in bytes */
    cd_format_t format;         /**< Encoding format */
    uint32_t _pad0;             /**< Explicit padding */
    cd_hash_t hash;             /**< H_W: computed weights hash */
} cd_weights_t;
```

---

## 9. Merkle Tree

**Traceability:** CD-MATH-001 §5.2

### 9.1 Merkle Leaves

```c
/**
 * @brief Merkle tree leaves
 * @traceability CD-MATH-001 §5.2
 * 
 * L_M = DH("CD:LEAF:MANIFEST:v1", H_M)
 * L_W = DH("CD:LEAF:WEIGHTS:v1", H_W)
 * L_C = DH("CD:LEAF:CERTS:v1", H_C)
 * L_I = DH("CD:LEAF:INFER:v1", H_I)
 */
typedef struct {
    cd_hash_t leaf_manifest;    /**< L_M */
    cd_hash_t leaf_weights;     /**< L_W */
    cd_hash_t leaf_certs;       /**< L_C */
    cd_hash_t leaf_infer;       /**< L_I */
} cd_merkle_leaves_t;
```

### 9.2 Merkle Tree Structure

```c
/**
 * @brief Complete Merkle tree
 * @traceability CD-MATH-001 §5.2
 * 
 * R_1 = Node(L_M, L_W)
 * R_2 = Node(L_C, L_I)
 * R = Node(R_1, R_2)
 */
typedef struct {
    cd_merkle_leaves_t leaves;
    cd_hash_t node_r1;          /**< R_1 = Node(L_M, L_W) */
    cd_hash_t node_r2;          /**< R_2 = Node(L_C, L_I) */
    cd_hash_t root;             /**< R = Node(R_1, R_2) */
} cd_merkle_tree_t;
```

---

## 10. Attestation

**Traceability:** CD-MATH-001 §5.1, §5.2, §5.3

```c
/**
 * @brief Bundle attestation
 * @traceability CD-MATH-001 §5
 */
typedef struct {
    /* Component hashes */
    cd_hash_t manifest_hash;      /**< H_M */
    cd_hash_t weights_hash;       /**< H_W */
    cd_hash_t cert_chain_hash;    /**< H_C */
    cd_hash_t inference_hash;     /**< H_I */
    
    /* Bundle root (flat hash) */
    cd_hash_t bundle_root;        /**< H_B = H("CD:BUNDLE:v1" || H_M || H_W || H_C || H_I) */
    
    /* Merkle tree */
    cd_merkle_tree_t merkle;      /**< Full Merkle tree */
    
    /* Timestamp */
    uint64_t timestamp;           /**< Signing timestamp */
    
    /* Optional signature */
    uint8_t is_signed;            /**< 1 if signature present */
    uint8_t _pad0[7];             /**< Explicit padding */
    cd_pubkey_t signer_pubkey;    /**< Ed25519 public key */
    cd_signature_t signature;     /**< σ = Ed25519.Sign(sk, R) */
} cd_attestation_t;
```

---

## 11. CBF v1 Container Structures

**Traceability:** CD-MATH-001 §2

### 11.1 Header

```c
/**
 * @brief CBF v1 header
 * @traceability CD-MATH-001 §2.1
 */
#define CD_CBF_MAGIC 0x43424631  /* "CBF1" little-endian */
#define CD_CBF_VERSION 1

typedef struct {
    uint32_t magic;               /**< CD_CBF_MAGIC */
    uint32_t version;             /**< CD_CBF_VERSION */
    uint64_t toc_offset;          /**< Byte offset to TOC */
    uint64_t toc_size;            /**< TOC size in bytes */
    uint64_t footer_offset;       /**< Byte offset to footer */
} cd_cbf_header_t;
```

### 11.2 TOC Entry

```c
/**
 * @brief CBF v1 table-of-contents entry
 * @traceability CD-MATH-001 §2.1, §2.2
 */
typedef struct {
    char path[CD_PATH_MAX_LEN];   /**< Normalized path */
    uint64_t offset;              /**< Byte offset in bundle */
    uint64_t size;                /**< Payload size */
    cd_hash_t hash;               /**< File hash (for verification) */
} cd_cbf_toc_entry_t;
```

### 11.3 TOC Structure

```c
/**
 * @brief CBF v1 table-of-contents
 * @traceability CD-MATH-001 §2.1
 */
#define CD_CBF_MAX_ENTRIES 512

typedef struct {
    uint32_t entry_count;
    uint32_t _pad0;                                  /**< Explicit padding */
    cd_cbf_toc_entry_t entries[CD_CBF_MAX_ENTRIES];  /**< Sorted by path */
} cd_cbf_toc_t;
```

### 11.4 Footer

```c
/**
 * @brief CBF v1 footer
 * @traceability CD-MATH-001 §5.2
 */
typedef struct {
    cd_hash_t merkle_root;        /**< R: attestation root */
    uint8_t is_signed;
    uint8_t _pad0[3];             /**< Explicit padding */
    uint32_t footer_magic;        /**< 0x46545231 "FTR1" */
    cd_pubkey_t signer_pubkey;
    cd_signature_t signature;
} cd_cbf_footer_t;
```

---

## 12. Bundle (Top-Level)

**Traceability:** CD-MATH-001 §2.1, §5

```c
/**
 * @brief Complete deployment bundle
 * @traceability CD-MATH-001 §2, §5
 */
typedef struct {
    /* Parsed components */
    cd_manifest_t manifest;
    cd_weights_t weights;
    cd_cert_chain_t certificates;
    cd_inference_set_t inference;
    cd_attestation_t attestation;
    
    /* CBF container */
    cd_cbf_header_t header;
    cd_cbf_toc_t toc;
    cd_cbf_footer_t footer;
    
    /* Validation state */
    uint8_t is_valid;             /**< 1 if verification passed */
    uint8_t _pad0[7];             /**< Explicit padding */
} cd_bundle_t;
```

---

## 13. Verification Result

**Traceability:** CD-MATH-001 §7

### 13.1 Verification Reason Codes

```c
/**
 * @brief Verification failure reasons
 * @traceability CD-MATH-001 §7, §12
 */
typedef enum {
    CD_VERIFY_OK = 0,
    
    /* Header/format errors (1-9) */
    CD_VERIFY_ERR_MAGIC = 1,
    CD_VERIFY_ERR_VERSION = 2,
    CD_VERIFY_ERR_TRUNCATED = 3,
    
    /* Hash mismatches (10-19) */
    CD_VERIFY_ERR_MANIFEST_HASH = 10,
    CD_VERIFY_ERR_WEIGHTS_HASH = 11,
    CD_VERIFY_ERR_CERTCHAIN_HASH = 12,
    CD_VERIFY_ERR_INFERENCE_HASH = 13,
    CD_VERIFY_ERR_MERKLE_ROOT = 14,
    
    /* Chain consistency (20-29) */
    CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH = 20,
    CD_VERIFY_ERR_CHAIN_LINK_BROKEN = 21,
    
    /* Target mismatch (30-39) */
    CD_VERIFY_ERR_TARGET_MISMATCH = 30,
    
    /* Signature errors (40-49) */
    CD_VERIFY_ERR_SIGNATURE_INVALID = 40,
    CD_VERIFY_ERR_PUBKEY_UNKNOWN = 41,
    
    /* Path/TOC errors (50-59) */
    CD_VERIFY_ERR_PATH_INVALID = 50,
    CD_VERIFY_ERR_TOC_UNSORTED = 51,
    CD_VERIFY_ERR_DUPLICATE_PATH = 52,
    
    /* Manifest errors (60-69) */
    CD_VERIFY_ERR_MANIFEST_SCHEMA = 60,
    CD_VERIFY_ERR_MANIFEST_NON_CANONICAL = 61,
    CD_VERIFY_ERR_MANIFEST_TARGET_INVALID = 62,
    CD_VERIFY_ERR_MANIFEST_TIMESTAMP_INVALID = 63
} cd_verify_reason_t;
```

### 13.2 Verification Result Structure

```c
/**
 * @brief Verification result
 * @traceability CD-MATH-001 §7.1
 */
typedef struct {
    uint8_t passed;               /**< 1 if all checks pass */
    uint8_t manifest_ok;
    uint8_t weights_ok;
    uint8_t certchain_ok;
    uint8_t inference_ok;
    uint8_t merkle_ok;
    uint8_t chain_consistency_ok;
    uint8_t target_ok;
    uint8_t signature_ok;         /**< Only checked if is_signed */
    uint8_t _pad0[3];             /**< Explicit padding */
    cd_verify_reason_t reason;    /**< First failure reason (if any) */
} cd_verify_result_t;
```

---

## 14. Runtime Loader Context (CD-LOAD)

**Traceability:** CD-MATH-001 §8

### 14.1 Loader State

```c
/**
 * @brief CD-LOAD state machine states
 * @traceability CD-MATH-001 §8.3
 */
typedef enum {
    CD_LOAD_STATE_INIT = 0,
    CD_LOAD_STATE_HEADER_READ = 1,
    CD_LOAD_STATE_TOC_READ = 2,
    CD_LOAD_STATE_MANIFEST_VERIFIED = 3,
    CD_LOAD_STATE_WEIGHTS_STREAMING = 4,
    CD_LOAD_STATE_WEIGHTS_VERIFIED = 5,
    CD_LOAD_STATE_INFERENCE_STREAMING = 6,
    CD_LOAD_STATE_INFERENCE_VERIFIED = 7,
    CD_LOAD_STATE_ENABLED = 8,
    CD_LOAD_STATE_FAILED = 99
} cd_load_state_t;
```

### 14.2 Loader Context

```c
/**
 * @brief Runtime loader context
 * @traceability CD-MATH-001 §8
 * 
 * Implements JIT hashing: H_I^measured, H_W^measured
 */
typedef struct {
    cd_load_state_t state;
    cd_verify_reason_t failure_reason;
    
    /* Expected values (from bundle) */
    cd_hash_t expected_weights_hash;
    cd_hash_t expected_inference_hash;
    cd_target_t expected_target;
    
    /* Measured values (computed during load) */
    cd_hash_t measured_weights_hash;
    cd_hash_t measured_inference_hash;
    cd_target_t device_target;
    
    /* Streaming hash contexts */
    cd_domain_hash_ctx_t weights_hash_ctx;
    cd_domain_hash_ctx_t inference_hash_ctx;
} cd_load_ctx_t;
```

---

## 15. Fault Flags

**Traceability:** Shared with certifiable-* family

```c
/**
 * @brief Fault flags (shared DVM pattern)
 * @traceability CT-MATH-001 §3.6 (inherited)
 */
typedef struct {
    uint32_t overflow    : 1;
    uint32_t underflow   : 1;
    uint32_t div_zero    : 1;
    uint32_t domain      : 1;
    uint32_t io_error    : 1;   /**< File/stream error */
    uint32_t hash_error  : 1;   /**< Hash computation failed */
    uint32_t parse_error : 1;   /**< JSON/manifest parse error */
    uint32_t _reserved   : 25;
} cd_fault_flags_t;

static inline uint8_t cd_has_fault(const cd_fault_flags_t *f) {
    return f->overflow || f->underflow || f->div_zero || 
           f->domain || f->io_error || f->hash_error || f->parse_error;
}
```

---

## 16. Path Normalization

**Traceability:** CD-MATH-001 §2.2

```c
/**
 * @brief Path normalization result
 * @traceability CD-MATH-001 §2.2
 */
typedef enum {
    CD_PATH_OK = 0,
    CD_PATH_ERR_EMPTY = 1,
    CD_PATH_ERR_DOTDOT = 2,       /**< Contains ".." */
    CD_PATH_ERR_TOO_LONG = 3,
    CD_PATH_ERR_INVALID_CHAR = 4
} cd_path_result_t;
```

---

## 17. Builder Context

**Traceability:** CD-MATH-001 §10.1 (deterministic build)

```c
/**
 * @brief Bundle builder context
 * @traceability CD-MATH-001 §10.1
 */
typedef struct {
    cd_manifest_t manifest;
    cd_target_t target;
    
    /* Component buffers (caller-provided) */
    const uint8_t *weights_data;
    uint64_t weights_size;
    
    const uint8_t *quant_cert_data;
    uint64_t quant_cert_size;
    
    const uint8_t *training_cert_data;
    uint64_t training_cert_size;
    
    const uint8_t *data_cert_data;
    uint64_t data_cert_size;
    
    /* Inference files (caller-provided) */
    uint32_t inference_file_count;
    uint32_t _pad0;               /**< Explicit padding */
    const char **inference_paths;
    const uint8_t **inference_data;
    const uint64_t *inference_sizes;
    
    /* Signing (optional) */
    uint8_t sign_bundle;
    uint8_t _pad1[7];             /**< Explicit padding */
    const uint8_t *private_key;   /**< Ed25519 private key (64 bytes) */
    
    /* Computed state */
    cd_attestation_t attestation;
    uint8_t attestation_computed;
    uint8_t _pad2[7];             /**< Explicit padding */
} cd_builder_ctx_t;
```

---

## 18. Constants Summary

```c
/* Sizes */
#define CD_HASH_SIZE           32
#define CD_SIGNATURE_SIZE      64
#define CD_PUBKEY_SIZE         32
#define CD_TAG_MAX_LEN         32
#define CD_VENDOR_MAX_LEN      32
#define CD_DEVICE_MAX_LEN      32
#define CD_MODEL_ID_MAX_LEN    64
#define CD_PATH_MAX_LEN        256

/* Limits */
#define CD_MAX_INFERENCE_FILES 256
#define CD_CBF_MAX_ENTRIES     512

/* Magic numbers */
#define CD_CBF_MAGIC           0x43424631  /* "CBF1" */
#define CD_CBF_FOOTER_MAGIC    0x46545231  /* "FTR1" */
#define CD_CBF_VERSION         1

/* Timestamp bounds (SRS-004-MANIFEST FR-MAN-04) */
#define CD_TIMESTAMP_MIN       0
#define CD_TIMESTAMP_MAX       4102444800  /* Year 2100 */
```

---

## 19. Traceability Matrix

| Structure | CD-MATH-001 Section | Alignment Verified |
|-----------|---------------------|-------------------|
| `cd_hash_t` | §1.1 | ✅ |
| `cd_domain_hash_ctx_t` | §1.2 | ✅ |
| `cd_target_t` | §4.3 | ✅ |
| `cd_manifest_t` | §3.1 | ✅ (v1.0.1 fix) |
| `cd_weights_t` | §3.2 | ✅ |
| `cd_cert_entry_t` | §3.3 | ✅ |
| `cd_cert_chain_t` | §3.3, §3.4 | ✅ |
| `cd_file_entry_t` | §4.2 | ✅ |
| `cd_inference_set_t` | §4.4 | ✅ |
| `cd_merkle_leaves_t` | §5.2 | ✅ |
| `cd_merkle_tree_t` | §5.2 | ✅ |
| `cd_attestation_t` | §5.1, §5.2, §5.3 | ✅ |
| `cd_cbf_header_t` | §2.1 | ✅ |
| `cd_cbf_toc_entry_t` | §2.1, §2.2 | ✅ |
| `cd_cbf_toc_t` | §2.1 | ✅ |
| `cd_cbf_footer_t` | §5.2 | ✅ |
| `cd_bundle_t` | §2, §5 | ✅ |
| `cd_verify_result_t` | §7.1 | ✅ |
| `cd_load_ctx_t` | §8 | ✅ |
| `cd_builder_ctx_t` | §10.1 | ✅ |

---

## 20. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-18 | William Murray | Initial release |
| 1.0.1 | 2026-01-18 | William Murray | Added explicit padding for 64-bit alignment (audit fix) |

---

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

/**
 * @file cd_types.h
 * @brief Core type definitions for certifiable-deploy
 * @traceability CD-STRUCT-001
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_TYPES_H
#define CD_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

/*============================================================================
 * Constants
 *============================================================================*/

#define CD_HASH_SIZE        32      /* SHA-256 output size */
#define CD_MAX_PATH         256     /* Maximum normalized path length */
#define CD_MAX_TAG          32      /* Maximum domain tag length */
#define CD_MAX_VENDOR       32      /* Maximum vendor name */
#define CD_MAX_DEVICE       32      /* Maximum device name */
#define CD_MAX_TOC_ENTRIES  256     /* Maximum files in bundle */
#define CD_MERKLE_LEAVES    4       /* Fixed 4-leaf tree */

/* CBF v1 Magic Numbers */
#define CD_CBF_MAGIC_HEADER 0x43424631  /* "CBF1" */
#define CD_CBF_MAGIC_FOOTER 0x31464243  /* "1FBC" (reversed) */
#define CD_CBF_VERSION      1

/*============================================================================
 * Fault Flags (CD-STRUCT-001 §11)
 *============================================================================*/

typedef struct {
    uint32_t overflow      : 1;  /* Arithmetic overflow */
    uint32_t underflow     : 1;  /* Arithmetic underflow */
    uint32_t div_zero      : 1;  /* Division by zero */
    uint32_t domain        : 1;  /* Domain error (e.g., bad input) */
    uint32_t io_error      : 1;  /* I/O operation failed */
    uint32_t hash_mismatch : 1;  /* Hash verification failed */
    uint32_t parse_error   : 1;  /* Parsing failed */
    uint32_t chain_invalid : 1;  /* Certificate chain invalid */
    uint32_t _reserved     : 24;
} cd_fault_flags_t;

static inline bool cd_has_fault(const cd_fault_flags_t *f) {
    return f->overflow || f->underflow || f->div_zero ||
           f->domain || f->io_error || f->hash_mismatch ||
           f->parse_error || f->chain_invalid;
}

static inline void cd_clear_faults(cd_fault_flags_t *f) {
    memset(f, 0, sizeof(*f));
}

/*============================================================================
 * Hash Types (CD-STRUCT-001 §2)
 *============================================================================*/

typedef struct {
    uint8_t bytes[CD_HASH_SIZE];
} cd_hash_t;

/* Domain-separated hash context */
typedef struct {
    char tag[CD_MAX_TAG];
    uint64_t payload_len;
    uint8_t state[128];  /* SHA-256 internal state */
    bool finalized;
} cd_domain_hash_ctx_t;

/*============================================================================
 * Target Tuple (CD-STRUCT-001 §6)
 *============================================================================*/

typedef enum {
    CD_ARCH_UNKNOWN = 0,
    CD_ARCH_X86_64,
    CD_ARCH_AARCH64,
    CD_ARCH_RISCV64,
    CD_ARCH_RISCV32
} cd_architecture_t;

typedef enum {
    CD_ABI_UNKNOWN = 0,
    CD_ABI_SYSV,
    CD_ABI_LP64D,
    CD_ABI_LP64,
    CD_ABI_ILP32,
    CD_ABI_LINUX_GNU
} cd_abi_t;

typedef struct {
    cd_architecture_t architecture;
    char vendor[CD_MAX_VENDOR];
    char device[CD_MAX_DEVICE];
    cd_abi_t abi;
} cd_target_t;

/* Match result */
typedef enum {
    CD_MATCH_EXACT = 0,
    CD_MATCH_WILDCARD_VENDOR,
    CD_MATCH_WILDCARD_DEVICE,
    CD_MATCH_WILDCARD_BOTH,
    CD_MATCH_FAIL_ARCH,
    CD_MATCH_FAIL_VENDOR,
    CD_MATCH_FAIL_DEVICE,
    CD_MATCH_FAIL_ABI
} cd_match_result_t;

/*============================================================================
 * Merkle Tree (CD-STRUCT-001 §4)
 *============================================================================*/

typedef struct {
    cd_hash_t leaves[CD_MERKLE_LEAVES];  /* L_M, L_W, L_C, L_I */
    cd_hash_t internal[2];               /* R_1, R_2 */
    cd_hash_t root;                      /* R */
    bool valid;
} cd_merkle_tree_t;

/*============================================================================
 * Attestation (CD-STRUCT-001 §5)
 *============================================================================*/

typedef struct {
    cd_hash_t h_manifest;    /* H_M: manifest hash */
    cd_hash_t h_weights;     /* H_W: weights hash */
    cd_hash_t h_certs;       /* H_C: certificate chain hash */
    cd_hash_t h_inference;   /* H_I: inference set hash */
    cd_merkle_tree_t tree;   /* Complete Merkle tree */
    uint8_t signature[64];   /* Optional Ed25519 signature */
    bool has_signature;
} cd_attestation_t;

/*============================================================================
 * CBF v1 Container (CD-STRUCT-001 §7)
 *============================================================================*/

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t payload_offset;
    uint64_t payload_size;
    uint64_t toc_offset;
    uint32_t toc_count;
    uint32_t _reserved;
} cd_cbf_header_t;

typedef struct {
    char path[CD_MAX_PATH];
    uint64_t offset;
    uint64_t size;
    cd_hash_t hash;
} cd_toc_entry_t;

typedef struct {
    cd_hash_t merkle_root;
    uint8_t signature[64];
    bool has_signature;
    uint32_t magic;
} cd_cbf_footer_t;

/*============================================================================
 * Manifest (CD-STRUCT-001 §8)
 *============================================================================*/

typedef struct {
    uint32_t manifest_version;
    char mode[32];            /* "deterministic" */
    uint64_t created_at;      /* Unix timestamp (0 for determinism) */
    cd_target_t target;
    cd_hash_t weights_digest;
    cd_hash_t certs_digest;
    cd_hash_t inference_digest;
} cd_manifest_t;

/*============================================================================
 * Certificate Chain (CD-STRUCT-001 §9)
 *============================================================================*/

typedef struct {
    cd_hash_t h_data;       /* From certifiable-data */
    cd_hash_t h_training;   /* From certifiable-training */
    cd_hash_t h_quant;      /* From certifiable-quant (includes H_W^cert) */
    cd_hash_t h_weights;    /* H_W^cert: claimed weights hash */
} cd_cert_chain_t;

/*============================================================================
 * Verification (CD-STRUCT-001 §10)
 *============================================================================*/

typedef enum {
    CD_VERIFY_OK = 0,
    CD_VERIFY_ERR_MAGIC,
    CD_VERIFY_ERR_VERSION,
    CD_VERIFY_ERR_HEADER_PARSE,
    CD_VERIFY_ERR_TOC_PARSE,
    CD_VERIFY_ERR_MANIFEST_HASH,
    CD_VERIFY_ERR_WEIGHTS_HASH,
    CD_VERIFY_ERR_CERTS_HASH,
    CD_VERIFY_ERR_INFERENCE_HASH,
    CD_VERIFY_ERR_MERKLE_ROOT,
    CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH,
    CD_VERIFY_ERR_CHAIN_INVALID,
    CD_VERIFY_ERR_TARGET_MISMATCH,
    CD_VERIFY_ERR_SIGNATURE_INVALID,
    CD_VERIFY_ERR_IO
} cd_verify_reason_t;

typedef struct {
    bool passed;
    cd_verify_reason_t reason;
    cd_hash_t computed_root;
    cd_hash_t expected_root;
    cd_match_result_t target_match;
} cd_verify_result_t;

/* Verification state machine states */
typedef enum {
    CD_VSTATE_INIT = 0,
    CD_VSTATE_PARSE_HEADER,
    CD_VSTATE_PARSE_TOC,
    CD_VSTATE_EXTRACT_COMPONENTS,
    CD_VSTATE_HASH_MANIFEST,
    CD_VSTATE_HASH_WEIGHTS,
    CD_VSTATE_HASH_CERTS,
    CD_VSTATE_HASH_INFERENCE,
    CD_VSTATE_COMPUTE_MERKLE,
    CD_VSTATE_COMPARE_ROOT,
    CD_VSTATE_CHECK_CHAIN,
    CD_VSTATE_CHECK_TARGET,
    CD_VSTATE_CHECK_SIGNATURE,
    CD_VSTATE_COMPLETE,
    CD_VSTATE_FAILED
} cd_verify_state_t;

typedef struct {
    cd_verify_state_t state;
    cd_verify_result_t result;
    cd_attestation_t attestation;
    cd_manifest_t manifest;
    cd_cert_chain_t chain;
    cd_target_t device_target;
    cd_fault_flags_t faults;
} cd_verify_ctx_t;

#endif /* CD_TYPES_H */

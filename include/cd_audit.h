/**
 * @file cd_audit.h
 * @brief Cryptographic audit primitives for certifiable-deploy
 * @traceability SRS-002-ATTEST, CD-MATH-001 §1
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_AUDIT_H
#define CD_AUDIT_H

#include "cd_types.h"

/*============================================================================
 * Domain Tags (CD-MATH-001 §1.2)
 *============================================================================*/

extern const char *CD_TAG_MANIFEST;
extern const char *CD_TAG_WEIGHTS;
extern const char *CD_TAG_CERTSET;
extern const char *CD_TAG_INFERSET;
extern const char *CD_TAG_LEAF_M;
extern const char *CD_TAG_LEAF_W;
extern const char *CD_TAG_LEAF_C;
extern const char *CD_TAG_LEAF_I;
extern const char *CD_TAG_MERKLE_NODE;

/*============================================================================
 * SHA-256 Context
 *============================================================================*/

typedef struct {
    uint8_t state[128];
    bool finalized;
} cd_sha256_ctx_t;

/*============================================================================
 * SHA-256 API
 *============================================================================*/

/**
 * Initialize SHA-256 context
 */
void cd_sha256_init(cd_sha256_ctx_t *ctx);

/**
 * Update with data
 */
void cd_sha256_update(cd_sha256_ctx_t *ctx, const void *data, size_t len);

/**
 * Finalize and output hash
 */
void cd_sha256_final(cd_sha256_ctx_t *ctx, cd_hash_t *out);

/**
 * One-shot hash
 */
void cd_sha256(const void *data, size_t len, cd_hash_t *out);

/*============================================================================
 * Domain-Separated Hashing API (FR-ATT-05)
 *============================================================================*/

/**
 * Initialize domain hash: DH(tag, payload) = H(tag || LE64(len) || payload)
 */
void cd_domain_hash_init(cd_domain_hash_ctx_t *ctx, const char *tag,
                         uint64_t payload_len, cd_fault_flags_t *faults);

/**
 * Update with payload data
 */
void cd_domain_hash_update(cd_domain_hash_ctx_t *ctx, const void *data,
                           size_t len, cd_fault_flags_t *faults);

/**
 * Finalize domain hash
 */
void cd_domain_hash_final(cd_domain_hash_ctx_t *ctx, cd_hash_t *out,
                          cd_fault_flags_t *faults);

/**
 * One-shot domain hash
 */
void cd_domain_hash(const char *tag, const void *payload, size_t payload_len,
                    cd_hash_t *out, cd_fault_flags_t *faults);

/*============================================================================
 * Hash Utilities
 *============================================================================*/

/**
 * Compare two hashes for equality
 */
bool cd_hash_equal(const cd_hash_t *a, const cd_hash_t *b);

/**
 * Copy hash from src to dst
 */
void cd_hash_copy(cd_hash_t *dst, const cd_hash_t *src);

/**
 * Zero a hash
 */
void cd_hash_zero(cd_hash_t *h);

/**
 * Check if hash is all zeros
 */
bool cd_hash_is_zero(const cd_hash_t *h);

#endif /* CD_AUDIT_H */

/**
 * @file domain_hash.c
 * @brief Domain-separated hashing per CD-MATH-001 §1.2
 * @traceability FR-ATT-05, CD-MATH-001 §1.2
 *
 * DH(tag, payload) = H(tag || LE64(|payload|) || payload)
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_audit.h"
#include <string.h>

/*============================================================================
 * Domain Tags (CD-MATH-001 §1.2)
 *============================================================================*/

const char *CD_TAG_MANIFEST    = "CD:MANIFEST:v1";
const char *CD_TAG_WEIGHTS     = "CD:WEIGHTS:v1";
const char *CD_TAG_CERTSET     = "CD:CERTSET:v1";
const char *CD_TAG_INFERSET    = "CD:INFERSET:v1";
const char *CD_TAG_LEAF_M      = "CD:LEAF:MANIFEST:v1";
const char *CD_TAG_LEAF_W      = "CD:LEAF:WEIGHTS:v1";
const char *CD_TAG_LEAF_C      = "CD:LEAF:CERTS:v1";
const char *CD_TAG_LEAF_I      = "CD:LEAF:INFER:v1";
const char *CD_TAG_MERKLE_NODE = "CD:MERKLENODE:v1";

/*============================================================================
 * Little-Endian Encoding
 *============================================================================*/

static void encode_le64(uint64_t value, uint8_t out[8]) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
    out[4] = (uint8_t)(value >> 32);
    out[5] = (uint8_t)(value >> 40);
    out[6] = (uint8_t)(value >> 48);
    out[7] = (uint8_t)(value >> 56);
}

/*============================================================================
 * Domain Hash API
 *============================================================================*/

void cd_domain_hash_init(cd_domain_hash_ctx_t *ctx, const char *tag,
                         uint64_t payload_len, cd_fault_flags_t *faults) {
    cd_sha256_ctx_t *sha_ctx;
    size_t tag_len;
    uint8_t len_bytes[8];

    if (!ctx || !tag) {
        if (faults) faults->domain = 1;
        return;
    }

    memset(ctx, 0, sizeof(*ctx));

    tag_len = strlen(tag);
    if (tag_len >= CD_MAX_TAG) {
        if (faults) faults->domain = 1;
        return;
    }

    memcpy(ctx->tag, tag, tag_len + 1);
    ctx->payload_len = payload_len;
    ctx->finalized = false;

    /* Initialize SHA-256 and feed tag + length prefix */
    sha_ctx = (cd_sha256_ctx_t *)ctx->state;
    cd_sha256_init(sha_ctx);

    /* Feed tag (no null terminator) */
    cd_sha256_update(sha_ctx, tag, tag_len);

    /* Feed LE64(payload_len) */
    encode_le64(payload_len, len_bytes);
    cd_sha256_update(sha_ctx, len_bytes, 8);
}

void cd_domain_hash_update(cd_domain_hash_ctx_t *ctx, const void *data,
                           size_t len, cd_fault_flags_t *faults) {
    cd_sha256_ctx_t *sha_ctx;

    if (!ctx || ctx->finalized) {
        if (faults) faults->domain = 1;
        return;
    }

    sha_ctx = (cd_sha256_ctx_t *)ctx->state;
    cd_sha256_update(sha_ctx, data, len);
}

void cd_domain_hash_final(cd_domain_hash_ctx_t *ctx, cd_hash_t *out,
                          cd_fault_flags_t *faults) {
    cd_sha256_ctx_t *sha_ctx;

    if (!ctx || !out || ctx->finalized) {
        if (faults) faults->domain = 1;
        if (out) memset(out->bytes, 0, CD_HASH_SIZE);
        return;
    }

    sha_ctx = (cd_sha256_ctx_t *)ctx->state;
    cd_sha256_final(sha_ctx, out);
    ctx->finalized = true;
}

void cd_domain_hash(const char *tag, const void *payload, size_t payload_len,
                    cd_hash_t *out, cd_fault_flags_t *faults) {
    cd_domain_hash_ctx_t ctx;

    if (!out) {
        if (faults) faults->domain = 1;
        return;
    }

    cd_domain_hash_init(&ctx, tag, (uint64_t)payload_len, faults);
    if (payload && payload_len > 0) {
        cd_domain_hash_update(&ctx, payload, payload_len, faults);
    }
    cd_domain_hash_final(&ctx, out, faults);
}

/*============================================================================
 * Hash Utilities
 *============================================================================*/

bool cd_hash_equal(const cd_hash_t *a, const cd_hash_t *b) {
    if (!a || !b) return false;
    return memcmp(a->bytes, b->bytes, CD_HASH_SIZE) == 0;
}

void cd_hash_copy(cd_hash_t *dst, const cd_hash_t *src) {
    if (dst && src) {
        memcpy(dst->bytes, src->bytes, CD_HASH_SIZE);
    }
}

void cd_hash_zero(cd_hash_t *h) {
    if (h) {
        memset(h->bytes, 0, CD_HASH_SIZE);
    }
}

bool cd_hash_is_zero(const cd_hash_t *h) {
    int i;
    if (!h) return true;
    for (i = 0; i < CD_HASH_SIZE; i++) {
        if (h->bytes[i] != 0) return false;
    }
    return true;
}

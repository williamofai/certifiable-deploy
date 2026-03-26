/**
 * @file builder.c
 * @brief CBF v1 bundle builder implementation
 * @traceability SRS-001-BUNDLE FR-BUN-01, FR-BUN-03, FR-BUN-05
 *
 * All multi-byte integers stored little-endian per FR-BUN-04.
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_bundle.h"
#include <string.h>
#include <stdint.h>

/*============================================================================
 * CBF v1 Layout Constants
 *============================================================================*/

#define CBF_HEADER_SIZE   32   /* magic(4) + version(4) + offsets(24) */
#define CBF_TOC_HDR_SIZE  8    /* count(4) + reserved(4) */
#define CBF_TOC_ENTRY_SIZE (CD_MAX_PATH + 8 + 8 + CD_HASH_SIZE)  /* 304 */
#define CBF_FOOTER_SIZE   (CD_HASH_SIZE + 64 + 4 + 4)  /* 104 */

/*============================================================================
 * Platform Safety
 *============================================================================*/

/*
 * CBF v1 supports files up to 2^64 bytes. On 32-bit platforms where
 * size_t is 32-bit, we cannot write files larger than SIZE_MAX in a
 * single fwrite call. This limit is checked at runtime in cd_builder_add_file.
 */
#define CD_MAX_SINGLE_WRITE SIZE_MAX

/*============================================================================
 * Internal Helpers
 *============================================================================*/

static cd_bundle_result_t write_header_placeholder(cd_builder_ctx_t *ctx)
{
    uint8_t buf[CBF_HEADER_SIZE];
    size_t written;

    memset(buf, 0, sizeof(buf));
    cd_write_u32_le(&buf[0], CD_CBF_MAGIC_HEADER);
    cd_write_u32_le(&buf[4], CD_CBF_VERSION);

    written = fwrite(buf, 1, CBF_HEADER_SIZE, ctx->out_stream);
    if (written != CBF_HEADER_SIZE) {
        ctx->faults.io_error = 1;
        return CD_BUNDLE_ERR_IO;
    }

    ctx->current_offset = CBF_HEADER_SIZE;
    return CD_BUNDLE_OK;
}

static cd_bundle_result_t write_toc(cd_builder_ctx_t *ctx)
{
    uint8_t hdr[CBF_TOC_HDR_SIZE];
    uint8_t entry_buf[CBF_TOC_ENTRY_SIZE];
    size_t written;
    uint32_t i;

    ctx->header.toc_offset = ctx->current_offset;
    ctx->header.toc_count = ctx->toc_count;

    memset(hdr, 0, sizeof(hdr));
    cd_write_u32_le(&hdr[0], ctx->toc_count);

    written = fwrite(hdr, 1, CBF_TOC_HDR_SIZE, ctx->out_stream);
    if (written != CBF_TOC_HDR_SIZE) {
        ctx->faults.io_error = 1;
        return CD_BUNDLE_ERR_IO;
    }
    ctx->current_offset += CBF_TOC_HDR_SIZE;

    for (i = 0; i < ctx->toc_count; i++) {
        const cd_toc_entry_t *e = &ctx->toc[i];

        memset(entry_buf, 0, sizeof(entry_buf));
        memcpy(&entry_buf[0], e->path, CD_MAX_PATH);
        /* Defensive null termination for malformed paths */
        entry_buf[CD_MAX_PATH - 1] = '\0';
        cd_write_u64_le(&entry_buf[CD_MAX_PATH], e->offset);
        cd_write_u64_le(&entry_buf[CD_MAX_PATH + 8], e->size);
        memcpy(&entry_buf[CD_MAX_PATH + 16], e->hash.bytes, CD_HASH_SIZE);

        written = fwrite(entry_buf, 1, CBF_TOC_ENTRY_SIZE, ctx->out_stream);
        if (written != CBF_TOC_ENTRY_SIZE) {
            ctx->faults.io_error = 1;
            return CD_BUNDLE_ERR_IO;
        }
        ctx->current_offset += CBF_TOC_ENTRY_SIZE;
    }

    return CD_BUNDLE_OK;
}

static cd_bundle_result_t write_footer(cd_builder_ctx_t *ctx,
                                       const cd_hash_t *merkle_root,
                                       bool has_signature,
                                       const uint8_t *signature)
{
    uint8_t buf[CBF_FOOTER_SIZE];
    size_t written;

    memset(buf, 0, sizeof(buf));
    memcpy(&buf[0], merkle_root->bytes, CD_HASH_SIZE);

    if (has_signature && signature != NULL) {
        memcpy(&buf[CD_HASH_SIZE], signature, 64);
        cd_write_u32_le(&buf[CD_HASH_SIZE + 64], 1);  /* has_signature flag */
    } else {
        cd_write_u32_le(&buf[CD_HASH_SIZE + 64], 0);
    }

    cd_write_u32_le(&buf[CD_HASH_SIZE + 68], CD_CBF_MAGIC_FOOTER);

    written = fwrite(buf, 1, CBF_FOOTER_SIZE, ctx->out_stream);
    if (written != CBF_FOOTER_SIZE) {
        ctx->faults.io_error = 1;
        return CD_BUNDLE_ERR_IO;
    }
    ctx->current_offset += CBF_FOOTER_SIZE;

    return CD_BUNDLE_OK;
}

static cd_bundle_result_t patch_header(cd_builder_ctx_t *ctx)
{
    uint8_t buf[CBF_HEADER_SIZE];
    size_t written;

    if (fseek(ctx->out_stream, 0, SEEK_SET) != 0) {
        ctx->faults.io_error = 1;
        return CD_BUNDLE_ERR_IO;
    }

    memset(buf, 0, sizeof(buf));
    cd_write_u32_le(&buf[0], CD_CBF_MAGIC_HEADER);
    cd_write_u32_le(&buf[4], CD_CBF_VERSION);
    cd_write_u64_le(&buf[8], ctx->header.payload_offset);
    cd_write_u64_le(&buf[16], ctx->header.payload_size);
    cd_write_u64_le(&buf[24], ctx->header.toc_offset);

    written = fwrite(buf, 1, CBF_HEADER_SIZE, ctx->out_stream);
    if (written != CBF_HEADER_SIZE) {
        ctx->faults.io_error = 1;
        return CD_BUNDLE_ERR_IO;
    }

    return CD_BUNDLE_OK;
}

/*============================================================================
 * Builder API
 *============================================================================*/

/**
 * Initialize bundle builder.
 *
 * Writes placeholder header and transitions to WRITING state.
 *
 * @param ctx       Builder context (caller-provided, zeroed on init)
 * @param out_stream Open file stream for writing (must be seekable)
 * @return CD_BUNDLE_OK on success, error code otherwise
 *
 * @traceability FR-BUN-01
 */
cd_bundle_result_t cd_builder_init(cd_builder_ctx_t *ctx, FILE *out_stream)
{
    cd_bundle_result_t result;

    if (ctx == NULL || out_stream == NULL) {
        return CD_BUNDLE_ERR_NULL;
    }

    memset(ctx, 0, sizeof(cd_builder_ctx_t));
    ctx->out_stream = out_stream;
    ctx->state = CD_BUILD_STATE_INIT;
    ctx->header.magic = CD_CBF_MAGIC_HEADER;
    ctx->header.version = CD_CBF_VERSION;

    result = write_header_placeholder(ctx);
    if (result != CD_BUNDLE_OK) {
        ctx->state = CD_BUILD_STATE_ERROR;
        return result;
    }

    ctx->header.payload_offset = ctx->current_offset;
    ctx->state = CD_BUILD_STATE_WRITING;

    return CD_BUNDLE_OK;
}

/**
 * Add a file payload to the bundle.
 *
 * Files MUST be added in sorted order by normalized path.
 * Duplicate paths are rejected.
 *
 * @param ctx       Builder context in WRITING state
 * @param path      File path (will be normalized)
 * @param data      File payload (may be NULL if len == 0)
 * @param len       Payload length in bytes
 * @param file_hash Pre-computed hash of payload
 * @return CD_BUNDLE_OK on success, error code otherwise
 *
 * @traceability FR-BUN-02, FR-BUN-03
 */
cd_bundle_result_t cd_builder_add_file(cd_builder_ctx_t *ctx, const char *path,
                                       const void *data, uint64_t len,
                                       const cd_hash_t *file_hash)
{
    cd_toc_entry_t *entry;
    size_t written;
    cd_path_result_t path_result;
    char normalized[CD_MAX_PATH];
    size_t path_len;
    int cmp;

    if (ctx == NULL || path == NULL || file_hash == NULL) {
        return CD_BUNDLE_ERR_NULL;
    }
    if (data == NULL && len > 0) {
        return CD_BUNDLE_ERR_NULL;
    }
    if (ctx->state != CD_BUILD_STATE_WRITING) {
        ctx->faults.domain = 1;
        return CD_BUNDLE_ERR_STATE;
    }
    if (ctx->toc_count >= CD_MAX_TOC_ENTRIES) {
        ctx->faults.overflow = 1;
        return CD_BUNDLE_ERR_TOC_FULL;
    }

    /*
     * 64-bit safety: On 32-bit platforms, size_t is 32-bit.
     * Reject files larger than SIZE_MAX to prevent truncation.
     */
    if (len > CD_MAX_SINGLE_WRITE) {
        ctx->faults.overflow = 1;
        return CD_BUNDLE_ERR_IO;
    }

    path_result = cd_path_normalize(path, normalized, sizeof(normalized), &ctx->faults);
    if (path_result != CD_PATH_OK) {
        return CD_BUNDLE_ERR_PATH_INVALID;
    }

    /* Verify sorted order (files must be added in lexicographic order) */
    if (ctx->toc_count > 0) {
        cmp = cd_path_compare(ctx->last_path, normalized);
        if (cmp >= 0) {
            ctx->faults.domain = 1;
            return (cmp == 0) ? CD_BUNDLE_ERR_DUPLICATE : CD_BUNDLE_ERR_NOT_SORTED;
        }
    }

    /* Write payload */
    if (len > 0) {
        written = fwrite(data, 1, (size_t)len, ctx->out_stream);
        if (written != (size_t)len) {
            ctx->faults.io_error = 1;
            ctx->state = CD_BUILD_STATE_ERROR;
            return CD_BUNDLE_ERR_IO;
        }
    }

    /* Create TOC entry */
    entry = &ctx->toc[ctx->toc_count];
    memset(entry, 0, sizeof(cd_toc_entry_t));

    /* Calculate path length once and reuse */
    path_len = strlen(normalized);
    if (path_len >= CD_MAX_PATH) {
        path_len = CD_MAX_PATH - 1;
    }

    /* Copy to TOC entry */
    memcpy(entry->path, normalized, path_len);
    entry->path[path_len] = '\0';  /* Explicit null termination */

    entry->offset = ctx->current_offset;
    entry->size = len;
    memcpy(&entry->hash, file_hash, sizeof(cd_hash_t));

    /* Update last_path for sorted order verification */
    memset(ctx->last_path, 0, CD_MAX_PATH);
    memcpy(ctx->last_path, normalized, path_len);
    ctx->last_path[path_len] = '\0';

    ctx->toc_count++;
    ctx->current_offset += len;

    return CD_BUNDLE_OK;
}

/**
 * Finalize the bundle with attestation.
 *
 * Writes TOC, footer, and patches header with final offsets.
 * Transitions to FINALIZED state on success.
 *
 * @param ctx         Builder context in WRITING state
 * @param merkle_root Merkle root hash for attestation
 * @param has_signature True if signature is provided
 * @param signature   64-byte Ed25519 signature (required if has_signature)
 * @return CD_BUNDLE_OK on success, error code otherwise
 *
 * @traceability FR-BUN-05
 */
cd_bundle_result_t cd_builder_finalize(cd_builder_ctx_t *ctx,
                                       const cd_hash_t *merkle_root,
                                       bool has_signature,
                                       const uint8_t *signature)
{
    cd_bundle_result_t result;

    if (ctx == NULL || merkle_root == NULL) {
        return CD_BUNDLE_ERR_NULL;
    }
    if (has_signature && signature == NULL) {
        return CD_BUNDLE_ERR_ATTESTATION;
    }
    if (ctx->state != CD_BUILD_STATE_WRITING) {
        ctx->faults.domain = 1;
        return CD_BUNDLE_ERR_STATE;
    }

    ctx->header.payload_size = ctx->current_offset - ctx->header.payload_offset;

    result = write_toc(ctx);
    if (result != CD_BUNDLE_OK) {
        ctx->state = CD_BUILD_STATE_ERROR;
        return result;
    }

    result = write_footer(ctx, merkle_root, has_signature, signature);
    if (result != CD_BUNDLE_OK) {
        ctx->state = CD_BUILD_STATE_ERROR;
        return result;
    }

    result = patch_header(ctx);
    if (result != CD_BUNDLE_OK) {
        ctx->state = CD_BUILD_STATE_ERROR;
        return result;
    }

    /* Seek to end for any subsequent operations */
    if (fseek(ctx->out_stream, 0, SEEK_END) != 0) {
        ctx->faults.io_error = 1;
        ctx->state = CD_BUILD_STATE_ERROR;
        return CD_BUNDLE_ERR_IO;
    }

    /* Flush to ensure all data is written */
    if (fflush(ctx->out_stream) != 0) {
        ctx->faults.io_error = 1;
        ctx->state = CD_BUILD_STATE_ERROR;
        return CD_BUNDLE_ERR_IO;
    }

    ctx->state = CD_BUILD_STATE_FINALIZED;
    return CD_BUNDLE_OK;
}

/**
 * Get fault flags from builder.
 *
 * @param ctx Builder context
 * @return Pointer to fault flags, or NULL if ctx is NULL
 */
const cd_fault_flags_t *cd_builder_get_faults(const cd_builder_ctx_t *ctx)
{
    return (ctx != NULL) ? &ctx->faults : NULL;
}

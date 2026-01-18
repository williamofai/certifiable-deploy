/**
 * @file reader.c
 * @brief CBF v1 bundle reader implementation
 * @traceability SRS-001-BUNDLE NFR-BUN-01
 * 
 * All multi-byte integers stored little-endian per FR-BUN-04.
 * Zero-copy design for mmap compatibility.
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_bundle.h"
#include <string.h>

/*============================================================================
 * CBF v1 Layout Constants
 *============================================================================*/

#define CBF_HEADER_SIZE   32
#define CBF_TOC_HDR_SIZE  8
#define CBF_TOC_ENTRY_SIZE (CD_MAX_PATH + 8 + 8 + CD_HASH_SIZE)
#define CBF_FOOTER_SIZE   (CD_HASH_SIZE + 64 + 4 + 4)

/*============================================================================
 * Internal Helpers
 *============================================================================*/

/**
 * Validate that [offset, offset+len) is within buffer bounds.
 * 
 * Safety: The second check is safe from overflow because the first
 * check guarantees offset <= data_len, so (data_len - offset) cannot
 * underflow.
 */
static int range_valid(const cd_reader_ctx_t *ctx, uint64_t offset, uint64_t len)
{
    /* Check 1: offset must be within buffer */
    if (offset > ctx->data_len) return 0;
    
    /* Check 2: len must fit in remaining space (safe: offset <= data_len) */
    if (len > ctx->data_len - offset) return 0;
    
    return 1;
}

/*============================================================================
 * Reader API
 *============================================================================*/

/**
 * Initialize reader from memory buffer.
 * 
 * The buffer must remain valid for the lifetime of the reader context.
 * Zero-copy: all data access is via pointer arithmetic into the buffer.
 * 
 * @param ctx  Reader context (caller-provided, zeroed on init)
 * @param data Pointer to CBF bundle data
 * @param len  Length of buffer in bytes
 * @return CD_READ_OK on success, error code otherwise
 * 
 * @traceability NFR-BUN-01
 */
cd_read_result_t cd_reader_init(cd_reader_ctx_t *ctx, const uint8_t *data,
                                size_t len)
{
    if (ctx == NULL) return CD_READ_ERR_NULL;
    if (data == NULL && len > 0) return CD_READ_ERR_NULL;
    
    memset(ctx, 0, sizeof(cd_reader_ctx_t));
    ctx->data = data;
    ctx->data_len = len;
    
    return CD_READ_OK;
}

/**
 * Parse CBF header.
 * 
 * Validates magic number, version, and that TOC offset is within bounds.
 * Sets header_valid flag on success.
 * 
 * @param ctx Reader context
 * @return CD_READ_OK on success, error code otherwise
 * 
 * @traceability SRS-001-BUNDLE Section 6.1
 */
cd_read_result_t cd_reader_parse_header(cd_reader_ctx_t *ctx)
{
    const uint8_t *hdr;
    
    if (ctx == NULL) return CD_READ_ERR_NULL;
    
    /* Validate minimum size for header */
    if (ctx->data_len < CBF_HEADER_SIZE) {
        ctx->faults.io_error = 1;
        return CD_READ_ERR_TRUNCATED;
    }
    
    hdr = ctx->data;
    
    ctx->header.magic = cd_read_u32_le(&hdr[0]);
    ctx->header.version = cd_read_u32_le(&hdr[4]);
    ctx->header.payload_offset = cd_read_u64_le(&hdr[8]);
    ctx->header.payload_size = cd_read_u64_le(&hdr[16]);
    ctx->header.toc_offset = cd_read_u64_le(&hdr[24]);
    
    if (ctx->header.magic != CD_CBF_MAGIC_HEADER) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_MAGIC;
    }
    if (ctx->header.version != CD_CBF_VERSION) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_VERSION;
    }
    
    /* Validate TOC offset allows reading at least the TOC header */
    if (!range_valid(ctx, ctx->header.toc_offset, CBF_TOC_HDR_SIZE)) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_TRUNCATED;
    }
    
    ctx->header_valid = true;
    return CD_READ_OK;
}

/**
 * Parse table of contents.
 * 
 * Reads TOC header to get entry count, then parses all entries.
 * Validates that all file offsets/sizes are within payload bounds.
 * Sets toc_valid flag on success.
 * 
 * Requires: header_valid == true
 * 
 * @param ctx Reader context with valid header
 * @return CD_READ_OK on success, error code otherwise
 * 
 * @traceability SRS-001-BUNDLE Section 6.2
 */
cd_read_result_t cd_reader_parse_toc(cd_reader_ctx_t *ctx)
{
    const uint8_t *toc_data;
    uint32_t count;
    uint64_t toc_size;
    uint32_t i;
    
    if (ctx == NULL) return CD_READ_ERR_NULL;
    if (!ctx->header_valid) {
        ctx->faults.domain = 1;
        return CD_READ_ERR_NULL;
    }
    
    /*
     * TOC header read is safe: range_valid(toc_offset, CBF_TOC_HDR_SIZE)
     * was verified in cd_reader_parse_header().
     */
    toc_data = ctx->data + ctx->header.toc_offset;
    count = cd_read_u32_le(&toc_data[0]);
    
    if (count > CD_MAX_TOC_ENTRIES) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_TOC_INVALID;
    }
    
    /* Validate full TOC size before parsing entries */
    toc_size = CBF_TOC_HDR_SIZE + ((uint64_t)count * CBF_TOC_ENTRY_SIZE);
    if (!range_valid(ctx, ctx->header.toc_offset, toc_size)) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_TRUNCATED;
    }
    
    ctx->toc_count = count;
    
    for (i = 0; i < count; i++) {
        /*
         * Widening cast: i is in [0, CD_MAX_TOC_ENTRIES), and
         * CBF_TOC_ENTRY_SIZE is 304. Product is bounded by
         * CD_MAX_TOC_ENTRIES * 304, well within size_t range.
         */
        const uint8_t *e = toc_data + CBF_TOC_HDR_SIZE + ((size_t)i * CBF_TOC_ENTRY_SIZE);
        cd_toc_entry_t *entry = &ctx->toc[i];
        
        memcpy(entry->path, e, CD_MAX_PATH);
        /* Defensive null termination for malformed bundles */
        entry->path[CD_MAX_PATH - 1] = '\0';
        entry->offset = cd_read_u64_le(&e[CD_MAX_PATH]);
        entry->size = cd_read_u64_le(&e[CD_MAX_PATH + 8]);
        memcpy(entry->hash.bytes, &e[CD_MAX_PATH + 16], CD_HASH_SIZE);
        
        /* Validate file data is within buffer bounds */
        if (!range_valid(ctx, entry->offset, entry->size)) {
            ctx->faults.parse_error = 1;
            return CD_READ_ERR_OFFSET_INVALID;
        }
    }
    
    ctx->toc_valid = true;
    return CD_READ_OK;
}

/**
 * Parse footer.
 * 
 * Reads Merkle root, optional signature, and footer magic.
 * Footer is located immediately after TOC entries.
 * Sets footer_valid flag on success.
 * 
 * Requires: header_valid == true, toc_valid == true
 * 
 * @param ctx Reader context with valid header and TOC
 * @return CD_READ_OK on success, error code otherwise
 * 
 * @traceability SRS-001-BUNDLE Section 6.3
 */
cd_read_result_t cd_reader_parse_footer(cd_reader_ctx_t *ctx)
{
    const uint8_t *ftr;
    uint64_t footer_offset;
    
    if (ctx == NULL) return CD_READ_ERR_NULL;
    if (!ctx->header_valid) {
        ctx->faults.domain = 1;
        return CD_READ_ERR_NULL;
    }
    if (!ctx->toc_valid) {
        ctx->faults.domain = 1;
        return CD_READ_ERR_NULL;
    }
    
    /* Footer is immediately after TOC entries */
    footer_offset = ctx->header.toc_offset + CBF_TOC_HDR_SIZE +
                    ((uint64_t)ctx->toc_count * CBF_TOC_ENTRY_SIZE);
    
    if (!range_valid(ctx, footer_offset, CBF_FOOTER_SIZE)) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_TRUNCATED;
    }
    
    ftr = ctx->data + footer_offset;
    
    memcpy(ctx->footer.merkle_root.bytes, &ftr[0], CD_HASH_SIZE);
    memcpy(ctx->footer.signature, &ftr[CD_HASH_SIZE], 64);
    ctx->footer.has_signature = (cd_read_u32_le(&ftr[CD_HASH_SIZE + 64]) != 0);
    ctx->footer.magic = cd_read_u32_le(&ftr[CD_HASH_SIZE + 68]);
    
    if (ctx->footer.magic != CD_CBF_MAGIC_FOOTER) {
        ctx->faults.parse_error = 1;
        return CD_READ_ERR_FOOTER_MAGIC;
    }
    
    ctx->footer_valid = true;
    return CD_READ_OK;
}

/**
 * Find entry by path using binary search.
 * 
 * TOC entries are stored in sorted order by normalized path,
 * enabling O(log n) lookup.
 * 
 * Requires: toc_valid == true
 * 
 * @param ctx   Reader context with valid TOC
 * @param path  Normalized path to search for
 * @param entry Output: pointer to found entry (not a copy)
 * @return CD_READ_OK if found, CD_READ_ERR_PATH_NOT_FOUND otherwise
 * 
 * @traceability FR-BUN-02
 */
cd_read_result_t cd_reader_find_entry(const cd_reader_ctx_t *ctx,
                                      const char *path,
                                      const cd_toc_entry_t **entry)
{
    uint32_t left, right, mid;
    int cmp;
    
    if (ctx == NULL || path == NULL || entry == NULL) return CD_READ_ERR_NULL;
    if (!ctx->toc_valid) return CD_READ_ERR_NULL;
    if (ctx->toc_count == 0) return CD_READ_ERR_PATH_NOT_FOUND;
    
    left = 0;
    right = ctx->toc_count;
    
    while (left < right) {
        mid = left + (right - left) / 2;
        cmp = cd_path_compare(ctx->toc[mid].path, path);
        
        if (cmp == 0) {
            *entry = &ctx->toc[mid];
            return CD_READ_OK;
        } else if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    
    return CD_READ_ERR_PATH_NOT_FOUND;
}

/**
 * Get pointer to file data (zero-copy).
 * 
 * Returns a pointer directly into the buffer. The data remains valid
 * as long as the underlying buffer is valid.
 * 
 * @param ctx   Reader context
 * @param entry TOC entry for the file
 * @param data  Output: pointer to file data
 * @param len   Output: file length in bytes
 * @return CD_READ_OK on success, error code otherwise
 * 
 * @traceability NFR-BUN-01
 */
cd_read_result_t cd_reader_get_data(const cd_reader_ctx_t *ctx,
                                    const cd_toc_entry_t *entry,
                                    const uint8_t **data, uint64_t *len)
{
    if (ctx == NULL || entry == NULL || data == NULL || len == NULL) {
        return CD_READ_ERR_NULL;
    }
    
    /* Re-validate bounds (defensive, entry was validated during TOC parse) */
    if (!range_valid(ctx, entry->offset, entry->size)) {
        return CD_READ_ERR_OFFSET_INVALID;
    }
    
    *data = ctx->data + entry->offset;
    *len = entry->size;
    return CD_READ_OK;
}

/**
 * Verify TOC is sorted by path.
 * 
 * CBF v1 requires TOC entries in strict ascending lexicographic order.
 * This enables binary search and ensures deterministic iteration.
 * 
 * Requires: toc_valid == true
 * 
 * @param ctx Reader context with valid TOC
 * @return CD_READ_OK if sorted, CD_READ_ERR_TOC_UNSORTED otherwise
 * 
 * @traceability FR-BUN-02
 */
cd_read_result_t cd_reader_verify_toc_order(const cd_reader_ctx_t *ctx)
{
    uint32_t i;
    
    if (ctx == NULL) return CD_READ_ERR_NULL;
    if (!ctx->toc_valid) return CD_READ_ERR_NULL;
    
    /* 0 or 1 entries are trivially sorted */
    if (ctx->toc_count <= 1) return CD_READ_OK;
    
    for (i = 1; i < ctx->toc_count; i++) {
        if (cd_path_compare(ctx->toc[i - 1].path, ctx->toc[i].path) >= 0) {
            return CD_READ_ERR_TOC_UNSORTED;
        }
    }
    
    return CD_READ_OK;
}

/**
 * Get fault flags from reader.
 * 
 * @param ctx Reader context
 * @return Pointer to fault flags, or NULL if ctx is NULL
 */
const cd_fault_flags_t *cd_reader_get_faults(const cd_reader_ctx_t *ctx)
{
    return (ctx != NULL) ? &ctx->faults : NULL;
}

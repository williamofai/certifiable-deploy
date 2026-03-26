/**
 * @file cd_bundle.h
 * @brief CBF v1 bundle builder and reader API
 * @traceability SRS-001-BUNDLE, CD-MATH-001 Section 2, CD-STRUCT-001 Section 7
 *
 * CBF v1 (Certifiable Bundle Format) is a deterministic container format
 * for safety-critical ML deployment. All multi-byte integers are stored
 * little-endian for cross-platform determinism (FR-BUN-04).
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_BUNDLE_H
#define CD_BUNDLE_H

#include "cd_types.h"
#include <stdio.h>

/*============================================================================
 * Path Normalization Result Codes (CD-STRUCT-001 Section 16)
 *============================================================================*/

typedef enum {
    CD_PATH_OK              = 0,
    CD_PATH_ERR_NULL        = 1,
    CD_PATH_ERR_EMPTY       = 2,
    CD_PATH_ERR_DOTDOT      = 3,
    CD_PATH_ERR_TOO_LONG    = 4,
    CD_PATH_ERR_INVALID_CHAR = 5,
    CD_PATH_ERR_ABSOLUTE    = 6
} cd_path_result_t;

/*============================================================================
 * Bundle Builder Result Codes
 *============================================================================*/

typedef enum {
    CD_BUNDLE_OK                = 0,
    CD_BUNDLE_ERR_NULL          = 1,
    CD_BUNDLE_ERR_IO            = 2,
    CD_BUNDLE_ERR_TOC_FULL      = 3,
    CD_BUNDLE_ERR_PATH_INVALID  = 4,
    CD_BUNDLE_ERR_DUPLICATE     = 5,
    CD_BUNDLE_ERR_NOT_SORTED    = 6,
    CD_BUNDLE_ERR_STATE         = 7,
    CD_BUNDLE_ERR_HASH          = 8,
    CD_BUNDLE_ERR_ATTESTATION   = 9
} cd_bundle_result_t;

/*============================================================================
 * Bundle Reader Result Codes
 *============================================================================*/

typedef enum {
    CD_READ_OK                  = 0,
    CD_READ_ERR_NULL            = 1,
    CD_READ_ERR_IO              = 2,
    CD_READ_ERR_MAGIC           = 3,
    CD_READ_ERR_VERSION         = 4,
    CD_READ_ERR_TRUNCATED       = 5,
    CD_READ_ERR_TOC_INVALID     = 6,
    CD_READ_ERR_TOC_UNSORTED    = 7,
    CD_READ_ERR_FOOTER_MAGIC    = 8,
    CD_READ_ERR_PATH_NOT_FOUND  = 9,
    CD_READ_ERR_OFFSET_INVALID  = 10
} cd_read_result_t;

/*============================================================================
 * Builder State Machine
 *============================================================================*/

typedef enum {
    CD_BUILD_STATE_INIT      = 0,
    CD_BUILD_STATE_WRITING   = 1,
    CD_BUILD_STATE_FINALIZED = 2,
    CD_BUILD_STATE_ERROR     = 99
} cd_build_state_t;

/*============================================================================
 * Builder Context
 *============================================================================*/

typedef struct {
    FILE *out_stream;
    cd_build_state_t state;
    cd_cbf_header_t header;
    cd_toc_entry_t toc[CD_MAX_TOC_ENTRIES];
    uint32_t toc_count;
    uint64_t current_offset;
    char last_path[CD_MAX_PATH];
    cd_fault_flags_t faults;
} cd_builder_ctx_t;

/*============================================================================
 * Reader Context
 *============================================================================*/

typedef struct {
    const uint8_t *data;
    size_t data_len;
    cd_cbf_header_t header;
    cd_toc_entry_t toc[CD_MAX_TOC_ENTRIES];
    uint32_t toc_count;
    cd_cbf_footer_t footer;
    bool header_valid;
    bool toc_valid;
    bool footer_valid;
    cd_fault_flags_t faults;
} cd_reader_ctx_t;

/*============================================================================
 * Path Normalization API (FR-BUN-02)
 *============================================================================*/

/**
 * Normalize a file path for canonical storage.
 * - Converts backslashes to forward slashes
 * - Removes leading "./" and "/"
 * - Collapses consecutive slashes
 * - Removes trailing slash
 * - Rejects paths containing ".."
 *
 * @param input   Input path string
 * @param output  Output buffer (must be at least CD_MAX_PATH bytes)
 * @param out_len Size of output buffer
 * @param faults  Fault flags (domain set on error)
 * @return CD_PATH_OK on success, error code otherwise
 *
 * @traceability FR-BUN-02, CD-MATH-001 Section 2.2
 */
cd_path_result_t cd_path_normalize(const char *input, char *output,
                                   size_t out_len, cd_fault_flags_t *faults);

/**
 * Compare two normalized paths lexicographically.
 *
 * @param a First path (may be NULL)
 * @param b Second path (may be NULL)
 * @return <0 if a<b, 0 if a==b, >0 if a>b
 *
 * @traceability FR-BUN-02
 */
int cd_path_compare(const char *a, const char *b);

/**
 * Validate a normalized path.
 *
 * @param path Path to validate
 * @return CD_PATH_OK if valid, error code otherwise
 *
 * @traceability FR-BUN-02
 */
cd_path_result_t cd_path_validate(const char *path);

/*============================================================================
 * Builder API (SRS-001-BUNDLE Section 5)
 *============================================================================*/

/**
 * Initialize bundle builder.
 *
 * @param ctx        Builder context (caller-provided)
 * @param out_stream Open file stream for writing (must be seekable)
 * @return CD_BUNDLE_OK on success, error code otherwise
 *
 * @traceability FR-BUN-01
 */
cd_bundle_result_t cd_builder_init(cd_builder_ctx_t *ctx, FILE *out_stream);

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
                                       const cd_hash_t *file_hash);

/**
 * Finalize the bundle with attestation.
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
                                       const uint8_t *signature);

/**
 * Get fault flags from builder.
 *
 * @param ctx Builder context
 * @return Pointer to fault flags, or NULL if ctx is NULL
 */
const cd_fault_flags_t *cd_builder_get_faults(const cd_builder_ctx_t *ctx);

/*============================================================================
 * Reader API (NFR-BUN-01)
 *============================================================================*/

/**
 * Initialize reader from memory buffer.
 *
 * Zero-copy design: all data access is via pointer arithmetic.
 * Buffer must remain valid for lifetime of reader context.
 *
 * @param ctx  Reader context (caller-provided)
 * @param data Pointer to CBF bundle data
 * @param len  Length of buffer in bytes
 * @return CD_READ_OK on success, error code otherwise
 *
 * @traceability NFR-BUN-01
 */
cd_read_result_t cd_reader_init(cd_reader_ctx_t *ctx, const uint8_t *data,
                                size_t len);

/**
 * Parse CBF header.
 *
 * @param ctx Reader context
 * @return CD_READ_OK on success, error code otherwise
 *
 * @traceability SRS-001-BUNDLE Section 6.1
 */
cd_read_result_t cd_reader_parse_header(cd_reader_ctx_t *ctx);

/**
 * Parse table of contents.
 *
 * Requires: header_valid == true
 *
 * @param ctx Reader context with valid header
 * @return CD_READ_OK on success, error code otherwise
 *
 * @traceability SRS-001-BUNDLE Section 6.2
 */
cd_read_result_t cd_reader_parse_toc(cd_reader_ctx_t *ctx);

/**
 * Parse footer.
 *
 * Requires: header_valid == true, toc_valid == true
 *
 * @param ctx Reader context with valid header and TOC
 * @return CD_READ_OK on success, error code otherwise
 *
 * @traceability SRS-001-BUNDLE Section 6.3
 */
cd_read_result_t cd_reader_parse_footer(cd_reader_ctx_t *ctx);

/**
 * Find entry by path (binary search).
 *
 * Requires: toc_valid == true
 *
 * @param ctx   Reader context with valid TOC
 * @param path  Normalized path to search for
 * @param entry Output: pointer to found entry
 * @return CD_READ_OK if found, CD_READ_ERR_PATH_NOT_FOUND otherwise
 *
 * @traceability FR-BUN-02
 */
cd_read_result_t cd_reader_find_entry(const cd_reader_ctx_t *ctx,
                                      const char *path,
                                      const cd_toc_entry_t **entry);

/**
 * Get pointer to file data (zero-copy).
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
                                    const uint8_t **data, uint64_t *len);

/**
 * Verify TOC is sorted.
 *
 * Requires: toc_valid == true
 *
 * @param ctx Reader context with valid TOC
 * @return CD_READ_OK if sorted, CD_READ_ERR_TOC_UNSORTED otherwise
 *
 * @traceability FR-BUN-02
 */
cd_read_result_t cd_reader_verify_toc_order(const cd_reader_ctx_t *ctx);

/**
 * Get fault flags from reader.
 *
 * @param ctx Reader context
 * @return Pointer to fault flags, or NULL if ctx is NULL
 */
const cd_fault_flags_t *cd_reader_get_faults(const cd_reader_ctx_t *ctx);

/*============================================================================
 * Little-Endian Utilities (FR-BUN-04)
 *
 * All multi-byte integers in CBF v1 format are stored little-endian
 * for cross-platform determinism.
 *============================================================================*/

void cd_write_u32_le(uint8_t *buf, uint32_t val);
void cd_write_u64_le(uint8_t *buf, uint64_t val);
uint32_t cd_read_u32_le(const uint8_t *buf);
uint64_t cd_read_u64_le(const uint8_t *buf);

#endif /* CD_BUNDLE_H */

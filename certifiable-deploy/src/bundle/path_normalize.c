/**
 * @file path_normalize.c
 * @brief Path normalization for canonical bundle storage
 * @traceability SRS-001-BUNDLE FR-BUN-02, CD-MATH-001 Section 2.2
 *
 * All multi-byte integers stored little-endian per FR-BUN-04.
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_bundle.h"
#include <string.h>

/*============================================================================
 * Internal Helpers
 *============================================================================*/

static int is_valid_path_char(char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9')) {
        return 1;
    }
    if (c == '_' || c == '-' || c == '.' || c == '/') {
        return 1;
    }
    return 0;
}

static int contains_dotdot(const char *path)
{
    size_t len;
    size_t i;

    if (path == NULL) return 0;
    len = strlen(path);

    /* Exact match: ".." */
    if (len == 2 && path[0] == '.' && path[1] == '.') return 1;

    /* Starts with "../" */
    if (len >= 3 && path[0] == '.' && path[1] == '.' && path[2] == '/') return 1;

    /* Contains "/.." followed by "/" or end */
    for (i = 0; i + 2 < len; i++) {
        if (path[i] == '/' && path[i + 1] == '.' && path[i + 2] == '.') {
            if (i + 3 >= len || path[i + 3] == '/') return 1;
        }
    }

    /* Ends with "/.." */
    if (len >= 3 && path[len - 3] == '/' && path[len - 2] == '.' && path[len - 1] == '.') {
        return 1;
    }

    return 0;
}

/*============================================================================
 * Path Normalization API
 *============================================================================*/

/**
 * Normalize a file path for canonical storage.
 * - Converts backslashes to forward slashes
 * - Removes leading "./" and "/"
 * - Collapses consecutive slashes
 * - Removes trailing slash
 * - Rejects paths containing ".."
 *
 * Complexity: O(CD_MAX_PATH) for initialization, O(n) for processing
 * where n = strlen(input).
 *
 * @traceability FR-BUN-02, CD-MATH-001 Section 2.2
 */
cd_path_result_t cd_path_normalize(const char *input, char *output,
                                   size_t out_len, cd_fault_flags_t *faults)
{
    size_t in_len, read_pos, write_pos;
    char c;

    if (input == NULL || output == NULL) {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_NULL;
    }

    if (out_len < CD_MAX_PATH) {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_TOO_LONG;
    }

    in_len = strlen(input);
    if (in_len == 0) {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_EMPTY;
    }

    /* Fixed upper bound initialization for predictable timing */
    memset(output, 0, CD_MAX_PATH);
    read_pos = 0;
    write_pos = 0;

    /* Skip leading "./" sequences */
    while (read_pos + 1 < in_len &&
           input[read_pos] == '.' &&
           (input[read_pos + 1] == '/' || input[read_pos + 1] == '\\')) {
        read_pos += 2;
    }

    /* Skip leading "/" or "\" */
    while (read_pos < in_len &&
           (input[read_pos] == '/' || input[read_pos] == '\\')) {
        read_pos++;
    }

    /* Process remaining characters */
    while (read_pos < in_len) {
        c = input[read_pos];

        /* Normalize backslash to forward slash */
        if (c == '\\') c = '/';

        if (!is_valid_path_char(c)) {
            if (faults != NULL) faults->domain = 1;
            return CD_PATH_ERR_INVALID_CHAR;
        }

        /* Collapse consecutive slashes */
        if (c == '/' && write_pos > 0 && output[write_pos - 1] == '/') {
            read_pos++;
            continue;
        }

        if (write_pos >= CD_MAX_PATH - 1) {
            if (faults != NULL) faults->domain = 1;
            return CD_PATH_ERR_TOO_LONG;
        }

        output[write_pos++] = c;
        read_pos++;
    }

    /* Remove trailing slash (but keep single-char paths) */
    if (write_pos > 1 && output[write_pos - 1] == '/') {
        output[--write_pos] = '\0';
    }

    /* Ensure null termination */
    output[write_pos] = '\0';

    if (write_pos == 0) {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_EMPTY;
    }

    if (contains_dotdot(output)) {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_DOTDOT;
    }

    if (output[0] == '/') {
        if (faults != NULL) faults->domain = 1;
        return CD_PATH_ERR_ABSOLUTE;
    }

    return CD_PATH_OK;
}

/**
 * Compare two normalized paths lexicographically.
 *
 * @traceability FR-BUN-02
 */
int cd_path_compare(const char *a, const char *b)
{
    if (a == NULL && b == NULL) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    return strcmp(a, b);
}

/**
 * Validate a normalized path.
 *
 * @traceability FR-BUN-02
 */
cd_path_result_t cd_path_validate(const char *path)
{
    size_t len, i;

    if (path == NULL) return CD_PATH_ERR_NULL;

    len = strlen(path);
    if (len == 0) return CD_PATH_ERR_EMPTY;
    if (len >= CD_MAX_PATH) return CD_PATH_ERR_TOO_LONG;
    if (path[0] == '/') return CD_PATH_ERR_ABSOLUTE;
    if (contains_dotdot(path)) return CD_PATH_ERR_DOTDOT;

    for (i = 0; i < len; i++) {
        if (!is_valid_path_char(path[i])) return CD_PATH_ERR_INVALID_CHAR;
    }

    return CD_PATH_OK;
}

/*============================================================================
 * Little-Endian Utilities (FR-BUN-04)
 *
 * All multi-byte integers in CBF v1 format are stored little-endian
 * for cross-platform determinism.
 *============================================================================*/

void cd_write_u32_le(uint8_t *buf, uint32_t val)
{
    if (buf == NULL) return;
    buf[0] = (uint8_t)(val & 0xFFU);
    buf[1] = (uint8_t)((val >> 8) & 0xFFU);
    buf[2] = (uint8_t)((val >> 16) & 0xFFU);
    buf[3] = (uint8_t)((val >> 24) & 0xFFU);
}

void cd_write_u64_le(uint8_t *buf, uint64_t val)
{
    if (buf == NULL) return;
    buf[0] = (uint8_t)(val & 0xFFU);
    buf[1] = (uint8_t)((val >> 8) & 0xFFU);
    buf[2] = (uint8_t)((val >> 16) & 0xFFU);
    buf[3] = (uint8_t)((val >> 24) & 0xFFU);
    buf[4] = (uint8_t)((val >> 32) & 0xFFU);
    buf[5] = (uint8_t)((val >> 40) & 0xFFU);
    buf[6] = (uint8_t)((val >> 48) & 0xFFU);
    buf[7] = (uint8_t)((val >> 56) & 0xFFU);
}

uint32_t cd_read_u32_le(const uint8_t *buf)
{
    if (buf == NULL) return 0;
    return ((uint32_t)buf[0]) | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

uint64_t cd_read_u64_le(const uint8_t *buf)
{
    if (buf == NULL) return 0;
    return ((uint64_t)buf[0]) | ((uint64_t)buf[1] << 8) |
           ((uint64_t)buf[2] << 16) | ((uint64_t)buf[3] << 24) |
           ((uint64_t)buf[4] << 32) | ((uint64_t)buf[5] << 40) |
           ((uint64_t)buf[6] << 48) | ((uint64_t)buf[7] << 56);
}

/**
 * @file jcs.c
 * @brief RFC 8785 JSON Canonicalization Scheme (JCS) primitives
 * @project Certifiable Deploy
 *
 * @details
 * Implements the low-level primitives required for JCS-canonical JSON output:
 * - String encoding with proper escaping
 * - Integer formatting (no leading zeros, no sign for positive)
 * - Hash-to-hex conversion (lowercase)
 * - Field validation against pattern ^[a-z0-9\-_]+$
 *
 * RFC 8785 key rules:
 * - Object keys sorted lexicographically by UTF-16 code units
 * - No whitespace outside string values
 * - Canonical number formatting
 * - Specific escape sequences for strings
 *
 * @traceability FR-MAN-01 (JCS), FR-MAN-02 (field validation), FR-MAN-03 (hash)
 * @compliance MISRA-C:2012, ISO 26262, IEC 62304
 *
 * @author William Murray
 * @copyright Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * @license Licensed under GPL-3.0 or commercial license.
 */

#include "cd_manifest.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/*============================================================================
 * Field Validation
 * @traceability FR-MAN-02
 *============================================================================*/

/**
 * @brief Validate a field string against pattern ^[a-z0-9\-_]+$
 * @traceability FR-MAN-02
 *
 * Constraints (normative from SRS-004-MANIFEST):
 * - Non-empty
 * - Length <= max_len
 * - Only lowercase a-z, digits 0-9, hyphen '-', underscore '_'
 * - Must be lowercase (no uppercase allowed)
 */
cdm_result_t cdm_validate_field(const char *field, size_t max_len)
{
    size_t len;
    size_t i;
    char c;

    if (field == NULL) {
        return CDM_ERR_NULL;
    }

    len = strlen(field);

    /* Must be non-empty */
    if (len == 0) {
        return CDM_ERR_INVALID_CHAR;
    }

    /* Check length limit */
    if (len > max_len) {
        return CDM_ERR_FIELD_TOO_LONG;
    }

    /* Validate each character: ^[a-z0-9\-_]+$ */
    for (i = 0; i < len; i++) {
        c = field[i];

        /* Lowercase letters */
        if (c >= 'a' && c <= 'z') {
            continue;
        }

        /* Digits */
        if (c >= '0' && c <= '9') {
            continue;
        }

        /* Hyphen */
        if (c == '-') {
            continue;
        }

        /* Underscore */
        if (c == '_') {
            continue;
        }

        /* Any other character is invalid */
        return CDM_ERR_INVALID_CHAR;
    }

    return CDM_OK;
}

/*============================================================================
 * JCS String Writing
 * @traceability FR-MAN-01
 *============================================================================*/

/**
 * @brief Write a JSON string value in JCS canonical form
 * @traceability FR-MAN-01
 *
 * RFC 8785 / JSON escaping rules:
 * - Wrap in double quotes
 * - Escape: \" \\ \n \r \t
 * - Control characters (0x00-0x1F) as \u00XX
 * - UTF-8 passthrough (JCS allows UTF-8)
 *
 * For our use case (ASCII-only fields), we handle:
 * - ASCII printable directly
 * - Special escapes for control and backslash/quote
 */
cdm_result_t cdm_jcs_write_string(uint8_t *out, size_t *out_len, const char *str)
{
    size_t capacity;
    size_t pos = 0;
    size_t i;
    size_t len;
    unsigned char c;

    if (out == NULL || out_len == NULL || str == NULL) {
        return CDM_ERR_NULL;
    }

    capacity = *out_len;
    len = strlen(str);

    /* Opening quote */
    if (pos >= capacity) {
        return CDM_ERR_BUFFER_TOO_SMALL;
    }
    out[pos++] = '"';

    /* Process each character */
    for (i = 0; i < len; i++) {
        c = (unsigned char)str[i];

        /* Check for special escapes */
        switch (c) {
            case '"':
                if (pos + 2 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                out[pos++] = '\\';
                out[pos++] = '"';
                break;

            case '\\':
                if (pos + 2 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                out[pos++] = '\\';
                out[pos++] = '\\';
                break;

            case '\n':
                if (pos + 2 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                out[pos++] = '\\';
                out[pos++] = 'n';
                break;

            case '\r':
                if (pos + 2 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                out[pos++] = '\\';
                out[pos++] = 'r';
                break;

            case '\t':
                if (pos + 2 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                out[pos++] = '\\';
                out[pos++] = 't';
                break;

            default:
                /* Control characters (0x00-0x1F except those above) */
                if (c < 0x20) {
                    /* \u00XX format */
                    static const char hex[] = "0123456789abcdef";
                    if (pos + 6 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                    out[pos++] = '\\';
                    out[pos++] = 'u';
                    out[pos++] = '0';
                    out[pos++] = '0';
                    out[pos++] = (uint8_t)hex[(c >> 4) & 0x0F];
                    out[pos++] = (uint8_t)hex[c & 0x0F];
                }
                /* DEL character (0x7F) - technically valid JSON but escape for safety */
                else if (c == 0x7F) {
                    static const char hex[] = "0123456789abcdef";
                    if (pos + 6 > capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                    out[pos++] = '\\';
                    out[pos++] = 'u';
                    out[pos++] = '0';
                    out[pos++] = '0';
                    out[pos++] = (uint8_t)hex[(c >> 4) & 0x0F];
                    out[pos++] = (uint8_t)hex[c & 0x0F];
                }
                /* Regular printable ASCII or valid UTF-8 byte */
                else {
                    if (pos >= capacity) return CDM_ERR_BUFFER_TOO_SMALL;
                    out[pos++] = c;
                }
                break;
        }
    }

    /* Closing quote */
    if (pos >= capacity) {
        return CDM_ERR_BUFFER_TOO_SMALL;
    }
    out[pos++] = '"';

    *out_len = pos;
    return CDM_OK;
}

/*============================================================================
 * JCS Integer Writing
 * @traceability FR-MAN-01
 *============================================================================*/

/**
 * @brief Write an unsigned integer in JCS canonical form
 * @traceability FR-MAN-01
 *
 * RFC 8785 number rules:
 * - No leading zeros (except "0" itself)
 * - No positive sign
 * - No decimal point for integers
 * - No exponential notation for integers that fit
 *
 * We only need unsigned integers for manifest (version, timestamp).
 */
cdm_result_t cdm_jcs_write_uint(uint8_t *out, size_t *out_len, uint64_t value)
{
    size_t capacity;
    char buf[21];  /* Max uint64 is 20 digits + null */
    size_t i = 0;
    size_t len;
    uint64_t v;

    if (out == NULL || out_len == NULL) {
        return CDM_ERR_NULL;
    }

    capacity = *out_len;

    /* Special case: zero */
    if (value == 0) {
        if (capacity < 1) {
            return CDM_ERR_BUFFER_TOO_SMALL;
        }
        out[0] = '0';
        *out_len = 1;
        return CDM_OK;
    }

    /* Build digits in reverse */
    v = value;
    while (v > 0 && i < sizeof(buf) - 1) {
        buf[i++] = (char)('0' + (v % 10));
        v /= 10;
    }
    len = i;

    /* Check buffer capacity */
    if (len > capacity) {
        return CDM_ERR_BUFFER_TOO_SMALL;
    }

    /* Reverse into output buffer */
    for (i = 0; i < len; i++) {
        out[i] = (uint8_t)buf[len - 1 - i];
    }

    *out_len = len;
    return CDM_OK;
}

/*============================================================================
 * JCS Hash Writing
 * @traceability FR-MAN-03
 *============================================================================*/

/**
 * @brief Write a 32-byte hash as 64-character lowercase hex string (quoted)
 * @traceability FR-MAN-03
 *
 * Format: "abcdef0123456789..." (64 hex chars, lowercase, quoted)
 */
cdm_result_t cdm_jcs_write_hash(uint8_t *out, size_t *out_len, const cd_hash_t *hash)
{
    static const char hex[] = "0123456789abcdef";
    size_t capacity;
    size_t pos = 0;
    size_t i;

    if (out == NULL || out_len == NULL || hash == NULL) {
        return CDM_ERR_NULL;
    }

    capacity = *out_len;

    /* Need: 1 quote + 64 hex chars + 1 quote = 66 bytes */
    if (capacity < 66) {
        return CDM_ERR_BUFFER_TOO_SMALL;
    }

    /* Opening quote */
    out[pos++] = '"';

    /* Convert each byte to two hex characters */
    for (i = 0; i < CD_HASH_SIZE; i++) {
        out[pos++] = (uint8_t)hex[(hash->bytes[i] >> 4) & 0x0F];
        out[pos++] = (uint8_t)hex[hash->bytes[i] & 0x0F];
    }

    /* Closing quote */
    out[pos++] = '"';

    *out_len = pos;
    return CDM_OK;
}

/*============================================================================
 * Architecture String Conversion
 * @traceability FR-MAN-02
 *============================================================================*/

/**
 * Architecture string table (sorted for binary search, but linear is fine here)
 */
static const struct {
    cd_architecture_t arch;
    const char *str;
} arch_table[] = {
    { CD_ARCH_X86_64,  "x86_64"  },
    { CD_ARCH_AARCH64, "aarch64" },
    { CD_ARCH_RISCV64, "riscv64" },
    { CD_ARCH_RISCV32, "riscv32" }
};

#define ARCH_TABLE_SIZE (sizeof(arch_table) / sizeof(arch_table[0]))

const char *cdm_arch_to_string(cd_architecture_t arch)
{
    size_t i;

    for (i = 0; i < ARCH_TABLE_SIZE; i++) {
        if (arch_table[i].arch == arch) {
            return arch_table[i].str;
        }
    }

    return NULL;
}

cd_architecture_t cdm_string_to_arch(const char *str)
{
    size_t i;

    if (str == NULL) {
        return CD_ARCH_UNKNOWN;
    }

    for (i = 0; i < ARCH_TABLE_SIZE; i++) {
        if (strcmp(arch_table[i].str, str) == 0) {
            return arch_table[i].arch;
        }
    }

    return CD_ARCH_UNKNOWN;
}

/*============================================================================
 * ABI String Conversion
 * @traceability FR-MAN-02
 *============================================================================*/

/**
 * ABI string table
 */
static const struct {
    cd_abi_t abi;
    const char *str;
} abi_table[] = {
    { CD_ABI_SYSV,      "sysv"      },
    { CD_ABI_LP64D,     "lp64d"     },
    { CD_ABI_LP64,      "lp64"      },
    { CD_ABI_ILP32,     "ilp32"     },
    { CD_ABI_LINUX_GNU, "linux-gnu" }
};

#define ABI_TABLE_SIZE (sizeof(abi_table) / sizeof(abi_table[0]))

const char *cdm_abi_to_string(cd_abi_t abi)
{
    size_t i;

    for (i = 0; i < ABI_TABLE_SIZE; i++) {
        if (abi_table[i].abi == abi) {
            return abi_table[i].str;
        }
    }

    return NULL;
}

cd_abi_t cdm_string_to_abi(const char *str)
{
    size_t i;

    if (str == NULL) {
        return CD_ABI_UNKNOWN;
    }

    for (i = 0; i < ABI_TABLE_SIZE; i++) {
        if (strcmp(abi_table[i].str, str) == 0) {
            return abi_table[i].abi;
        }
    }

    return CD_ABI_UNKNOWN;
}

/*============================================================================
 * Result Code to String
 *============================================================================*/

const char *cdm_result_to_string(cdm_result_t result)
{
    switch (result) {
        case CDM_OK:                    return "OK";
        case CDM_ERR_NULL:              return "NULL pointer argument";
        case CDM_ERR_STATE:             return "Invalid builder state";
        case CDM_ERR_MISSING_FIELD:     return "Required field not set";
        case CDM_ERR_BUFFER_TOO_SMALL:  return "Output buffer too small";
        case CDM_ERR_INVALID_ARCH:      return "Invalid architecture";
        case CDM_ERR_INVALID_VENDOR:    return "Invalid vendor field";
        case CDM_ERR_INVALID_DEVICE:    return "Invalid device field";
        case CDM_ERR_INVALID_ABI:       return "Invalid ABI";
        case CDM_ERR_INVALID_TARGET:    return "Invalid target";
        case CDM_ERR_FIELD_TOO_LONG:    return "Field too long";
        case CDM_ERR_INVALID_CHAR:      return "Invalid character in field";
        case CDM_ERR_INVALID_MODE:      return "Invalid mode (must be deterministic or audit)";
        case CDM_ERR_INVALID_TIMESTAMP: return "Timestamp out of bounds";
        case CDM_ERR_INVALID_DIGEST:    return "Invalid digest (must be 64 hex chars)";
        case CDM_ERR_PARSE_FAILED:      return "JSON parse error";
        case CDM_ERR_INVALID_VERSION:   return "Unsupported manifest version";
        case CDM_ERR_NON_CANONICAL:     return "Input not JCS-canonical";
        case CDM_ERR_UNKNOWN_KEY:       return "Unknown key in JSON";
        case CDM_ERR_DUPLICATE_KEY:     return "Duplicate key in JSON";
        case CDM_ERR_INVALID_TYPE:      return "Wrong JSON value type";
        case CDM_ERR_ADDITIONAL_PROPS:  return "Additional properties not allowed";
        case CDM_ERR_JCS_OVERFLOW:      return "Number too large for canonical form";
        case CDM_ERR_JCS_INVALID_STRING: return "String cannot be canonicalized";
        default:                        return "Unknown error";
    }
}

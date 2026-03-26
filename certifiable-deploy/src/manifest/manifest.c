/**
 * @file manifest.c
 * @brief Manifest builder and parser implementation
 * @project Certifiable Deploy
 *
 * @details
 * Implements the manifest builder and parser with JCS canonicalization.
 * The canonical JSON output is the input to H_M for Merkle tree construction.
 *
 * JCS key ordering for manifest (RFC 8785 - lexicographic by UTF-16):
 *   Root level:  components, created_at, manifest_version, mode, target
 *   components:  certificates, inference, weights
 *   target:      abi, arch, device, vendor
 *
 * This ordering is derived by sorting keys as UTF-16 code units:
 *   "abi" < "arch" < "device" < "vendor" (ASCII = UTF-16 for BMP)
 *   "certificates" < "inference" < "weights"
 *   "components" < "created_at" < "manifest_version" < "mode" < "target"
 *
 * @traceability SRS-004-MANIFEST (all requirements)
 * @compliance MISRA-C:2012, ISO 26262, IEC 62304
 *
 * @author William Murray
 * @copyright Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * @license Licensed under GPL-3.0 or commercial license.
 */

#include "cd_manifest.h"
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Internal Buffer Writer
 *
 * A simple streaming buffer writer that tracks position and errors.
 * All errors are sticky - once an error occurs, subsequent writes are no-ops.
 *============================================================================*/

typedef struct {
    uint8_t *buf;
    size_t capacity;
    size_t pos;
    cdm_result_t error;
} jcs_writer_t;

static void writer_init(jcs_writer_t *w, uint8_t *buf, size_t capacity)
{
    w->buf = buf;
    w->capacity = capacity;
    w->pos = 0;
    w->error = CDM_OK;
}

static void writer_append(jcs_writer_t *w, const char *str)
{
    size_t len;

    if (w->error != CDM_OK) {
        return;
    }

    len = strlen(str);
    if (w->pos + len > w->capacity) {
        w->error = CDM_ERR_BUFFER_TOO_SMALL;
        return;
    }

    memcpy(&w->buf[w->pos], str, len);
    w->pos += len;
}

static void writer_append_char(jcs_writer_t *w, char c)
{
    if (w->error != CDM_OK) {
        return;
    }

    if (w->pos >= w->capacity) {
        w->error = CDM_ERR_BUFFER_TOO_SMALL;
        return;
    }

    w->buf[w->pos++] = (uint8_t)c;
}

static void writer_append_string(jcs_writer_t *w, const char *str)
{
    size_t available;
    cdm_result_t r;

    if (w->error != CDM_OK) {
        return;
    }

    available = w->capacity - w->pos;
    r = cdm_jcs_write_string(&w->buf[w->pos], &available, str);
    if (r != CDM_OK) {
        w->error = r;
        return;
    }

    w->pos += available;
}

static void writer_append_uint(jcs_writer_t *w, uint64_t value)
{
    size_t available;
    cdm_result_t r;

    if (w->error != CDM_OK) {
        return;
    }

    available = w->capacity - w->pos;
    r = cdm_jcs_write_uint(&w->buf[w->pos], &available, value);
    if (r != CDM_OK) {
        w->error = r;
        return;
    }

    w->pos += available;
}

static void writer_append_hash(jcs_writer_t *w, const cd_hash_t *hash)
{
    size_t available;
    cdm_result_t r;

    if (w->error != CDM_OK) {
        return;
    }

    available = w->capacity - w->pos;
    r = cdm_jcs_write_hash(&w->buf[w->pos], &available, hash);
    if (r != CDM_OK) {
        w->error = r;
        return;
    }

    w->pos += available;
}

/*============================================================================
 * Target Validation
 * @traceability FR-MAN-02
 *============================================================================*/

/**
 * @brief Check target tuple validity
 * @traceability FR-MAN-02
 *
 * Validates:
 * - Architecture is known (not CD_ARCH_UNKNOWN)
 * - Vendor matches ^[a-z0-9\-_]+$ and length <= 32
 * - Device matches ^[a-z0-9\-_]+$ and length <= 32
 * - ABI is known (not CD_ABI_UNKNOWN)
 */
cdm_result_t cdm_check_target(const cd_target_t *target)
{
    const char *arch_str;
    const char *abi_str;
    cdm_result_t r;

    if (target == NULL) {
        return CDM_ERR_NULL;
    }

    /* Check architecture is known */
    arch_str = cdm_arch_to_string(target->architecture);
    if (arch_str == NULL) {
        return CDM_ERR_INVALID_ARCH;
    }

    /* Validate vendor field: ^[a-z0-9\-_]+$ with max length 32 */
    r = cdm_validate_field(target->vendor, CDM_VENDOR_MAX_LEN);
    if (r != CDM_OK) {
        return CDM_ERR_INVALID_VENDOR;
    }

    /* Validate device field: ^[a-z0-9\-_]+$ with max length 32 */
    r = cdm_validate_field(target->device, CDM_DEVICE_MAX_LEN);
    if (r != CDM_OK) {
        return CDM_ERR_INVALID_DEVICE;
    }

    /* Check ABI is known */
    abi_str = cdm_abi_to_string(target->abi);
    if (abi_str == NULL) {
        return CDM_ERR_INVALID_ABI;
    }

    return CDM_OK;
}

/*============================================================================
 * Builder API
 * @traceability SRS-004-MANIFEST §5.1
 *============================================================================*/

/**
 * @brief Initialize manifest builder
 * @traceability SRS-004-MANIFEST
 */
cdm_result_t cdm_builder_init(cdm_builder_t *ctx)
{
    if (ctx == NULL) {
        return CDM_ERR_NULL;
    }

    memset(ctx, 0, sizeof(cdm_builder_t));
    ctx->state = CDM_STATE_CONFIGURING;
    ctx->manifest.manifest_version = CDM_VERSION;

    return CDM_OK;
}

/**
 * @brief Set deployment mode
 * @traceability FR-MAN-04
 */
cdm_result_t cdm_set_mode(cdm_builder_t *ctx, const char *mode)
{
    if (ctx == NULL || mode == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    /* Validate mode is exactly "deterministic" or "audit" */
    if (strcmp(mode, "deterministic") != 0 && strcmp(mode, "audit") != 0) {
        ctx->faults.domain = 1;
        return CDM_ERR_INVALID_MODE;
    }

    /* Safe copy with bounds check */
    if (strlen(mode) >= sizeof(ctx->manifest.mode)) {
        ctx->faults.domain = 1;
        return CDM_ERR_INVALID_MODE;
    }

    memset(ctx->manifest.mode, 0, sizeof(ctx->manifest.mode));
    strcpy(ctx->manifest.mode, mode);
    ctx->mode_set = true;

    return CDM_OK;
}

/**
 * @brief Set creation timestamp
 * @traceability FR-MAN-04
 */
cdm_result_t cdm_set_created_at(cdm_builder_t *ctx, uint64_t ts)
{
    if (ctx == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    /* Bounds check: 0 <= ts <= year 2100 (FR-MAN-04) */
    if (ts > CDM_MAX_TIMESTAMP) {
        ctx->faults.domain = 1;
        return CDM_ERR_INVALID_TIMESTAMP;
    }

    ctx->manifest.created_at = ts;
    ctx->timestamp_set = true;

    return CDM_OK;
}

/**
 * @brief Set target tuple
 * @traceability FR-MAN-02
 */
cdm_result_t cdm_set_target(cdm_builder_t *ctx, const cd_target_t *target)
{
    cdm_result_t r;

    if (ctx == NULL || target == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    /* Validate target tuple */
    r = cdm_check_target(target);
    if (r != CDM_OK) {
        ctx->faults.domain = 1;
        return r;
    }

    /* Copy target */
    memcpy(&ctx->manifest.target, target, sizeof(cd_target_t));
    ctx->target_set = true;

    return CDM_OK;
}

/**
 * @brief Set weights component hash (H_W)
 * @traceability FR-MAN-03
 */
cdm_result_t cdm_set_weights_hash(cdm_builder_t *ctx, const cd_hash_t *digest)
{
    if (ctx == NULL || digest == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    memcpy(&ctx->manifest.weights_digest, digest, sizeof(cd_hash_t));
    ctx->weights_set = true;

    return CDM_OK;
}

/**
 * @brief Set certificates component hash (H_C)
 * @traceability FR-MAN-03
 */
cdm_result_t cdm_set_certs_hash(cdm_builder_t *ctx, const cd_hash_t *digest)
{
    if (ctx == NULL || digest == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    memcpy(&ctx->manifest.certs_digest, digest, sizeof(cd_hash_t));
    ctx->certs_set = true;

    return CDM_OK;
}

/**
 * @brief Set inference component hash (H_I)
 * @traceability FR-MAN-03
 */
cdm_result_t cdm_set_inference_hash(cdm_builder_t *ctx, const cd_hash_t *digest)
{
    if (ctx == NULL || digest == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    memcpy(&ctx->manifest.inference_digest, digest, sizeof(cd_hash_t));
    ctx->inference_set = true;

    return CDM_OK;
}

/**
 * @brief Finalize and emit JCS-canonical JSON
 * @traceability FR-MAN-01
 *
 * JCS key ordering (lexicographic by UTF-16 code units):
 *   Root:       components, created_at, manifest_version, mode, target
 *   components: certificates, inference, weights
 *   target:     abi, arch, device, vendor
 */
cdm_result_t cdm_finalize_jcs(cdm_builder_t *ctx, uint8_t *out, size_t *out_len)
{
    jcs_writer_t w;
    const char *arch_str;
    const char *abi_str;

    if (ctx == NULL || out == NULL || out_len == NULL) {
        return CDM_ERR_NULL;
    }

    if (ctx->state != CDM_STATE_CONFIGURING) {
        ctx->faults.domain = 1;
        return CDM_ERR_STATE;
    }

    /* Check all required fields are set */
    if (!ctx->mode_set) {
        ctx->faults.domain = 1;
        return CDM_ERR_MISSING_FIELD;
    }
    if (!ctx->timestamp_set) {
        ctx->faults.domain = 1;
        return CDM_ERR_MISSING_FIELD;
    }
    if (!ctx->target_set) {
        ctx->faults.domain = 1;
        return CDM_ERR_MISSING_FIELD;
    }
    if (!ctx->weights_set || !ctx->certs_set || !ctx->inference_set) {
        ctx->faults.domain = 1;
        return CDM_ERR_MISSING_FIELD;
    }

    /* Get arch/abi strings (already validated in set_target) */
    arch_str = cdm_arch_to_string(ctx->manifest.target.architecture);
    abi_str = cdm_abi_to_string(ctx->manifest.target.abi);
    if (arch_str == NULL || abi_str == NULL) {
        ctx->faults.domain = 1;
        return CDM_ERR_INVALID_TARGET;
    }

    /* Initialize writer */
    writer_init(&w, out, *out_len);

    /*
     * Emit JCS-canonical JSON
     *
     * Key ordering for root object (sorted UTF-16):
     *   components < created_at < manifest_version < mode < target
     */

    /* Root object open */
    writer_append_char(&w, '{');

    /*
     * "components": {...}
     * Key ordering: certificates < inference < weights
     */
    writer_append(&w, "\"components\":{");

    /* certificates */
    writer_append(&w, "\"certificates\":{\"digest\":");
    writer_append_hash(&w, &ctx->manifest.certs_digest);
    writer_append_char(&w, '}');

    /* inference */
    writer_append(&w, ",\"inference\":{\"digest\":");
    writer_append_hash(&w, &ctx->manifest.inference_digest);
    writer_append_char(&w, '}');

    /* weights */
    writer_append(&w, ",\"weights\":{\"digest\":");
    writer_append_hash(&w, &ctx->manifest.weights_digest);
    writer_append(&w, "}}");

    /* "created_at": N */
    writer_append(&w, ",\"created_at\":");
    writer_append_uint(&w, ctx->manifest.created_at);

    /* "manifest_version": 1 */
    writer_append(&w, ",\"manifest_version\":");
    writer_append_uint(&w, ctx->manifest.manifest_version);

    /* "mode": "..." */
    writer_append(&w, ",\"mode\":");
    writer_append_string(&w, ctx->manifest.mode);

    /*
     * "target": {...}
     * Key ordering: abi < arch < device < vendor
     */
    writer_append(&w, ",\"target\":{");

    /* abi */
    writer_append(&w, "\"abi\":");
    writer_append_string(&w, abi_str);

    /* arch */
    writer_append(&w, ",\"arch\":");
    writer_append_string(&w, arch_str);

    /* device */
    writer_append(&w, ",\"device\":");
    writer_append_string(&w, ctx->manifest.target.device);

    /* vendor */
    writer_append(&w, ",\"vendor\":");
    writer_append_string(&w, ctx->manifest.target.vendor);

    /* Close target and root */
    writer_append(&w, "}}");

    /* Check for errors */
    if (w.error != CDM_OK) {
        ctx->faults.io_error = 1;
        ctx->state = CDM_STATE_ERROR;
        return w.error;
    }

    /* Null terminate (but don't include in length) */
    if (w.pos < w.capacity) {
        w.buf[w.pos] = '\0';
    }

    *out_len = w.pos;
    ctx->state = CDM_STATE_FINALIZED;

    return CDM_OK;
}

/**
 * @brief Get fault flags from builder
 */
const cd_fault_flags_t *cdm_builder_get_faults(const cdm_builder_t *ctx)
{
    return (ctx != NULL) ? &ctx->faults : NULL;
}

/*============================================================================
 * Parser - Strict JSON Implementation
 *
 * This parser is specifically designed for the manifest schema and provides:
 * - Strict schema validation
 * - Field constraint enforcement
 * - JCS canonicalization verification (strict mode)
 *
 * @traceability FR-MAN-06
 *============================================================================*/

/* Parser context */
typedef struct {
    const char *p;           /* Current position */
    const char *end;         /* End of input */
    cd_fault_flags_t *faults;
    bool strict_canonical;   /* Require JCS-canonical input */
} parser_ctx_t;

/*----------------------------------------------------------------------------
 * Parser Helpers
 *----------------------------------------------------------------------------*/

/**
 * Skip JSON whitespace (space, tab, newline, carriage return)
 */
static void parser_skip_ws(parser_ctx_t *ctx)
{
    while (ctx->p < ctx->end) {
        char c = *ctx->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ctx->p++;
        } else {
            break;
        }
    }
}

/**
 * Match a single expected character
 */
static bool parser_match_char(parser_ctx_t *ctx, char expected)
{
    if (ctx->p < ctx->end && *ctx->p == expected) {
        ctx->p++;
        return true;
    }
    return false;
}

/**
 * Parse a JSON string value into a buffer
 * Expects: "..." (already at opening quote)
 */
static cdm_result_t parser_read_string(parser_ctx_t *ctx, char *out, size_t out_size)
{
    size_t i = 0;

    /* Expect opening quote */
    if (ctx->p >= ctx->end || *ctx->p != '"') {
        return CDM_ERR_PARSE_FAILED;
    }
    ctx->p++;

    /* Read characters until closing quote */
    while (ctx->p < ctx->end && *ctx->p != '"') {
        if (*ctx->p == '\\') {
            /* Escape sequence */
            ctx->p++;
            if (ctx->p >= ctx->end) {
                return CDM_ERR_PARSE_FAILED;
            }

            char escaped;
            switch (*ctx->p) {
                case '"':  escaped = '"';  break;
                case '\\': escaped = '\\'; break;
                case '/':  escaped = '/';  break;
                case 'b':  escaped = '\b'; break;
                case 'f':  escaped = '\f'; break;
                case 'n':  escaped = '\n'; break;
                case 'r':  escaped = '\r'; break;
                case 't':  escaped = '\t'; break;
                case 'u':
                    /* Unicode escape \uXXXX - parse but reject for our fields */
                    /* Our manifest fields are ASCII-only */
                    return CDM_ERR_INVALID_CHAR;
                default:
                    return CDM_ERR_PARSE_FAILED;
            }

            if (i < out_size - 1) {
                out[i++] = escaped;
            } else {
                return CDM_ERR_FIELD_TOO_LONG;
            }
        } else {
            /* Regular character */
            if (i < out_size - 1) {
                out[i++] = *ctx->p;
            } else {
                return CDM_ERR_FIELD_TOO_LONG;
            }
        }
        ctx->p++;
    }

    /* Expect closing quote */
    if (ctx->p >= ctx->end || *ctx->p != '"') {
        return CDM_ERR_PARSE_FAILED;
    }
    ctx->p++;

    out[i] = '\0';
    return CDM_OK;
}

/**
 * Parse an unsigned 64-bit integer
 */
static cdm_result_t parser_read_uint64(parser_ctx_t *ctx, uint64_t *out)
{
    uint64_t value = 0;
    bool has_digit = false;

    /* Check for leading zero (not allowed except for "0") */
    if (ctx->p < ctx->end && *ctx->p == '0') {
        ctx->p++;
        has_digit = true;

        /* If next char is a digit, this is invalid "0X" */
        if (ctx->p < ctx->end && *ctx->p >= '0' && *ctx->p <= '9') {
            return CDM_ERR_PARSE_FAILED;  /* Leading zero not allowed */
        }

        *out = 0;
        return CDM_OK;
    }

    /* Parse digits */
    while (ctx->p < ctx->end && *ctx->p >= '0' && *ctx->p <= '9') {
        /* Check for overflow */
        uint64_t digit = (uint64_t)(*ctx->p - '0');
        if (value > (UINT64_MAX - digit) / 10) {
            return CDM_ERR_INVALID_TIMESTAMP;  /* Overflow */
        }
        value = value * 10 + digit;
        ctx->p++;
        has_digit = true;
    }

    if (!has_digit) {
        return CDM_ERR_PARSE_FAILED;
    }

    *out = value;
    return CDM_OK;
}

/**
 * Parse a 64-character hex string into a hash
 */
static cdm_result_t parser_read_hex_hash(const char *hex, size_t len, cd_hash_t *out)
{
    size_t i;

    if (len != 64) {
        return CDM_ERR_INVALID_DIGEST;
    }

    for (i = 0; i < 32; i++) {
        uint8_t val = 0;
        char c;

        /* High nibble */
        c = hex[i * 2];
        if (c >= '0' && c <= '9') {
            val = (uint8_t)(c - '0') << 4;
        } else if (c >= 'a' && c <= 'f') {
            val = (uint8_t)(c - 'a' + 10) << 4;
        } else {
            /* Uppercase or invalid - reject (FR-MAN-03: lowercase only) */
            return CDM_ERR_INVALID_DIGEST;
        }

        /* Low nibble */
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') {
            val |= (uint8_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            val |= (uint8_t)(c - 'a' + 10);
        } else {
            return CDM_ERR_INVALID_DIGEST;
        }

        out->bytes[i] = val;
    }

    return CDM_OK;
}

/*----------------------------------------------------------------------------
 * Nested Object Parsers
 *----------------------------------------------------------------------------*/

/**
 * Parse hash entry: {"digest":"<64 hex>"}
 */
static cdm_result_t parser_read_hash_entry(parser_ctx_t *ctx, cd_hash_t *out)
{
    char key[32];
    char hex[128];
    cdm_result_t r;

    parser_skip_ws(ctx);
    if (!parser_match_char(ctx, '{')) {
        return CDM_ERR_PARSE_FAILED;
    }

    parser_skip_ws(ctx);
    r = parser_read_string(ctx, key, sizeof(key));
    if (r != CDM_OK) return r;

    if (strcmp(key, "digest") != 0) {
        return CDM_ERR_UNKNOWN_KEY;  /* Only "digest" allowed */
    }

    parser_skip_ws(ctx);
    if (!parser_match_char(ctx, ':')) {
        return CDM_ERR_PARSE_FAILED;
    }

    parser_skip_ws(ctx);
    r = parser_read_string(ctx, hex, sizeof(hex));
    if (r != CDM_OK) return r;

    r = parser_read_hex_hash(hex, strlen(hex), out);
    if (r != CDM_OK) return r;

    parser_skip_ws(ctx);
    if (!parser_match_char(ctx, '}')) {
        return CDM_ERR_PARSE_FAILED;
    }

    return CDM_OK;
}

/**
 * Parse components object
 * @traceability FR-MAN-03
 */
static cdm_result_t parser_read_components(parser_ctx_t *ctx, cd_manifest_t *out,
                                           bool *found_weights, bool *found_certs,
                                           bool *found_inference)
{
    char key[32];
    cdm_result_t r;
    bool first = true;

    parser_skip_ws(ctx);
    if (!parser_match_char(ctx, '{')) {
        return CDM_ERR_PARSE_FAILED;
    }

    while (true) {
        parser_skip_ws(ctx);

        /* Check for end of object */
        if (ctx->p < ctx->end && *ctx->p == '}') {
            ctx->p++;
            break;
        }

        /* Comma between entries (except first) */
        if (!first) {
            if (!parser_match_char(ctx, ',')) {
                return CDM_ERR_PARSE_FAILED;
            }
            parser_skip_ws(ctx);
        }
        first = false;

        /* Read key */
        r = parser_read_string(ctx, key, sizeof(key));
        if (r != CDM_OK) return r;

        parser_skip_ws(ctx);
        if (!parser_match_char(ctx, ':')) {
            return CDM_ERR_PARSE_FAILED;
        }

        /* Read value based on key */
        if (strcmp(key, "weights") == 0) {
            if (*found_weights) return CDM_ERR_DUPLICATE_KEY;
            r = parser_read_hash_entry(ctx, &out->weights_digest);
            if (r != CDM_OK) return r;
            *found_weights = true;
        }
        else if (strcmp(key, "certificates") == 0) {
            if (*found_certs) return CDM_ERR_DUPLICATE_KEY;
            r = parser_read_hash_entry(ctx, &out->certs_digest);
            if (r != CDM_OK) return r;
            *found_certs = true;
        }
        else if (strcmp(key, "inference") == 0) {
            if (*found_inference) return CDM_ERR_DUPLICATE_KEY;
            r = parser_read_hash_entry(ctx, &out->inference_digest);
            if (r != CDM_OK) return r;
            *found_inference = true;
        }
        else {
            /* Unknown key - fail closed (additionalProperties: false) */
            return CDM_ERR_ADDITIONAL_PROPS;
        }
    }

    return CDM_OK;
}

/**
 * Parse target object
 * @traceability FR-MAN-02
 */
static cdm_result_t parser_read_target(parser_ctx_t *ctx, cd_target_t *out,
                                       bool *found_arch, bool *found_vendor,
                                       bool *found_device, bool *found_abi)
{
    char key[32];
    char value[64];
    cdm_result_t r;
    bool first = true;

    parser_skip_ws(ctx);
    if (!parser_match_char(ctx, '{')) {
        return CDM_ERR_PARSE_FAILED;
    }

    while (true) {
        parser_skip_ws(ctx);

        /* Check for end of object */
        if (ctx->p < ctx->end && *ctx->p == '}') {
            ctx->p++;
            break;
        }

        /* Comma between entries (except first) */
        if (!first) {
            if (!parser_match_char(ctx, ',')) {
                return CDM_ERR_PARSE_FAILED;
            }
            parser_skip_ws(ctx);
        }
        first = false;

        /* Read key */
        r = parser_read_string(ctx, key, sizeof(key));
        if (r != CDM_OK) return r;

        parser_skip_ws(ctx);
        if (!parser_match_char(ctx, ':')) {
            return CDM_ERR_PARSE_FAILED;
        }

        parser_skip_ws(ctx);
        r = parser_read_string(ctx, value, sizeof(value));
        if (r != CDM_OK) return r;

        /* Process based on key */
        if (strcmp(key, "arch") == 0) {
            if (*found_arch) return CDM_ERR_DUPLICATE_KEY;
            out->architecture = cdm_string_to_arch(value);
            if (out->architecture == CD_ARCH_UNKNOWN) {
                return CDM_ERR_INVALID_ARCH;
            }
            *found_arch = true;
        }
        else if (strcmp(key, "vendor") == 0) {
            if (*found_vendor) return CDM_ERR_DUPLICATE_KEY;
            r = cdm_validate_field(value, CDM_VENDOR_MAX_LEN);
            if (r != CDM_OK) return CDM_ERR_INVALID_VENDOR;
            strncpy(out->vendor, value, CD_MAX_VENDOR - 1);
            out->vendor[CD_MAX_VENDOR - 1] = '\0';
            *found_vendor = true;
        }
        else if (strcmp(key, "device") == 0) {
            if (*found_device) return CDM_ERR_DUPLICATE_KEY;
            r = cdm_validate_field(value, CDM_DEVICE_MAX_LEN);
            if (r != CDM_OK) return CDM_ERR_INVALID_DEVICE;
            strncpy(out->device, value, CD_MAX_DEVICE - 1);
            out->device[CD_MAX_DEVICE - 1] = '\0';
            *found_device = true;
        }
        else if (strcmp(key, "abi") == 0) {
            if (*found_abi) return CDM_ERR_DUPLICATE_KEY;
            out->abi = cdm_string_to_abi(value);
            if (out->abi == CD_ABI_UNKNOWN) {
                return CDM_ERR_INVALID_ABI;
            }
            *found_abi = true;
        }
        else {
            /* Unknown key - fail closed */
            return CDM_ERR_ADDITIONAL_PROPS;
        }
    }

    return CDM_OK;
}

/*----------------------------------------------------------------------------
 * Main Parser
 *----------------------------------------------------------------------------*/

/**
 * @brief Parse manifest from JSON bytes (internal)
 */
static cdm_result_t cdm_parse_internal(const uint8_t *json, size_t len,
                                       cd_manifest_t *out, cd_fault_flags_t *faults,
                                       bool strict_canonical)
{
    parser_ctx_t ctx;
    char key[64];
    char strval[64];
    uint64_t intval;
    cdm_result_t r;

    /* Required field tracking */
    bool found_version = false;
    bool found_mode = false;
    bool found_created_at = false;
    bool found_target = false;
    bool found_components = false;

    /* Target field tracking */
    bool found_arch = false;
    bool found_vendor = false;
    bool found_device = false;
    bool found_abi = false;

    /* Components field tracking */
    bool found_weights = false;
    bool found_certs = false;
    bool found_inference = false;

    bool first_field = true;

    if (json == NULL || out == NULL) {
        if (faults != NULL) faults->domain = 1;
        return CDM_ERR_NULL;
    }

    memset(out, 0, sizeof(cd_manifest_t));

    /* Initialize parser context */
    ctx.p = (const char *)json;
    ctx.end = ctx.p + len;
    ctx.faults = faults;
    ctx.strict_canonical = strict_canonical;

    /* For strict mode, verify no leading/trailing whitespace */
    if (strict_canonical) {
        if (len > 0 && (json[0] == ' ' || json[0] == '\t' ||
                        json[0] == '\n' || json[0] == '\r')) {
            if (faults != NULL) faults->parse_error = 1;
            return CDM_ERR_NON_CANONICAL;
        }
        if (len > 0 && (json[len-1] == ' ' || json[len-1] == '\t' ||
                        json[len-1] == '\n' || json[len-1] == '\r')) {
            if (faults != NULL) faults->parse_error = 1;
            return CDM_ERR_NON_CANONICAL;
        }
    }

    parser_skip_ws(&ctx);

    /* Expect opening brace */
    if (!parser_match_char(&ctx, '{')) {
        if (faults != NULL) faults->parse_error = 1;
        return CDM_ERR_PARSE_FAILED;
    }

    /* Parse key-value pairs */
    while (true) {
        parser_skip_ws(&ctx);

        /* Check for end of object */
        if (ctx.p < ctx.end && *ctx.p == '}') {
            ctx.p++;
            break;
        }

        /* Comma between entries (except first) */
        if (!first_field) {
            if (!parser_match_char(&ctx, ',')) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_PARSE_FAILED;
            }
            parser_skip_ws(&ctx);
        }
        first_field = false;

        /* Read key */
        r = parser_read_string(&ctx, key, sizeof(key));
        if (r != CDM_OK) {
            if (faults != NULL) faults->parse_error = 1;
            return r;
        }

        parser_skip_ws(&ctx);
        if (!parser_match_char(&ctx, ':')) {
            if (faults != NULL) faults->parse_error = 1;
            return CDM_ERR_PARSE_FAILED;
        }
        parser_skip_ws(&ctx);

        /* Parse value based on key */
        if (strcmp(key, "manifest_version") == 0) {
            if (found_version) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_DUPLICATE_KEY;
            }
            r = parser_read_uint64(&ctx, &intval);
            if (r != CDM_OK) {
                if (faults != NULL) faults->parse_error = 1;
                return r;
            }
            if (intval != CDM_VERSION) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_INVALID_VERSION;
            }
            out->manifest_version = (uint32_t)intval;
            found_version = true;
        }
        else if (strcmp(key, "mode") == 0) {
            if (found_mode) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_DUPLICATE_KEY;
            }
            r = parser_read_string(&ctx, strval, sizeof(strval));
            if (r != CDM_OK) {
                if (faults != NULL) faults->parse_error = 1;
                return r;
            }
            if (strcmp(strval, "deterministic") != 0 &&
                strcmp(strval, "audit") != 0) {
                if (faults != NULL) faults->domain = 1;
                return CDM_ERR_INVALID_MODE;
            }
            strcpy(out->mode, strval);
            found_mode = true;
        }
        else if (strcmp(key, "created_at") == 0) {
            if (found_created_at) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_DUPLICATE_KEY;
            }
            r = parser_read_uint64(&ctx, &intval);
            if (r != CDM_OK) {
                if (faults != NULL) faults->parse_error = 1;
                return r;
            }
            if (intval > CDM_MAX_TIMESTAMP) {
                if (faults != NULL) faults->domain = 1;
                return CDM_ERR_INVALID_TIMESTAMP;
            }
            out->created_at = intval;
            found_created_at = true;
        }
        else if (strcmp(key, "target") == 0) {
            if (found_target) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_DUPLICATE_KEY;
            }
            r = parser_read_target(&ctx, &out->target,
                                   &found_arch, &found_vendor,
                                   &found_device, &found_abi);
            if (r != CDM_OK) {
                if (faults != NULL) faults->parse_error = 1;
                return r;
            }
            /* Check all target fields present */
            if (!found_arch || !found_vendor || !found_device || !found_abi) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_MISSING_FIELD;
            }
            found_target = true;
        }
        else if (strcmp(key, "components") == 0) {
            if (found_components) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_DUPLICATE_KEY;
            }
            r = parser_read_components(&ctx, out,
                                       &found_weights, &found_certs,
                                       &found_inference);
            if (r != CDM_OK) {
                if (faults != NULL) faults->parse_error = 1;
                return r;
            }
            /* Check all component fields present */
            if (!found_weights || !found_certs || !found_inference) {
                if (faults != NULL) faults->parse_error = 1;
                return CDM_ERR_MISSING_FIELD;
            }
            found_components = true;
        }
        else {
            /* Unknown key - fail closed (additionalProperties: false) */
            if (faults != NULL) faults->parse_error = 1;
            return CDM_ERR_ADDITIONAL_PROPS;
        }
    }

    /* Check all required root fields present */
    if (!found_version || !found_mode || !found_created_at ||
        !found_target || !found_components) {
        if (faults != NULL) faults->parse_error = 1;
        return CDM_ERR_MISSING_FIELD;
    }

    /* Skip any trailing whitespace */
    parser_skip_ws(&ctx);

    /* Must be at end of input */
    if (ctx.p != ctx.end) {
        if (faults != NULL) faults->parse_error = 1;
        return CDM_ERR_PARSE_FAILED;
    }

    return CDM_OK;
}

/**
 * @brief Parse manifest from JSON bytes (strict mode)
 * @traceability FR-MAN-06 (strict policy)
 */
cdm_result_t cdm_parse(const uint8_t *json, size_t len,
                       cd_manifest_t *out, cd_fault_flags_t *faults)
{
    cdm_result_t r;

    /* First, parse the manifest */
    r = cdm_parse_internal(json, len, out, faults, true);
    if (r != CDM_OK) {
        return r;
    }

    /* Then verify canonicalization */
    r = cdm_verify_canonical(json, len);
    if (r != CDM_OK) {
        if (faults != NULL) faults->parse_error = 1;
        return r;
    }

    return CDM_OK;
}

/**
 * @brief Parse manifest with lenient canonicalization
 * @traceability FR-MAN-06 (lenient policy)
 */
cdm_result_t cdm_parse_lenient(const uint8_t *json, size_t len,
                               cd_manifest_t *out, cd_fault_flags_t *faults)
{
    return cdm_parse_internal(json, len, out, faults, false);
}

/**
 * @brief Verify that JSON bytes are JCS-canonical
 * @traceability FR-MAN-06
 */
cdm_result_t cdm_verify_canonical(const uint8_t *json, size_t len)
{
    cd_manifest_t manifest;
    cdm_builder_t builder;
    uint8_t canonical[CDM_MAX_JSON_SIZE];
    size_t canonical_len;
    cdm_result_t r;

    if (json == NULL) {
        return CDM_ERR_NULL;
    }

    /* Parse the input */
    r = cdm_parse_internal(json, len, &manifest, NULL, false);
    if (r != CDM_OK) {
        return r;
    }

    /* Re-emit in canonical form */
    r = cdm_builder_init(&builder);
    if (r != CDM_OK) return r;

    r = cdm_set_mode(&builder, manifest.mode);
    if (r != CDM_OK) return r;

    r = cdm_set_created_at(&builder, manifest.created_at);
    if (r != CDM_OK) return r;

    r = cdm_set_target(&builder, &manifest.target);
    if (r != CDM_OK) return r;

    r = cdm_set_weights_hash(&builder, &manifest.weights_digest);
    if (r != CDM_OK) return r;

    r = cdm_set_certs_hash(&builder, &manifest.certs_digest);
    if (r != CDM_OK) return r;

    r = cdm_set_inference_hash(&builder, &manifest.inference_digest);
    if (r != CDM_OK) return r;

    canonical_len = sizeof(canonical);
    r = cdm_finalize_jcs(&builder, canonical, &canonical_len);
    if (r != CDM_OK) return r;

    /* Compare byte-for-byte */
    if (canonical_len != len) {
        return CDM_ERR_NON_CANONICAL;
    }

    if (memcmp(json, canonical, len) != 0) {
        return CDM_ERR_NON_CANONICAL;
    }

    return CDM_OK;
}

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * @brief Compare two manifests for equality
 */
bool cdm_manifest_equal(const cd_manifest_t *a, const cd_manifest_t *b)
{
    if (a == NULL || b == NULL) {
        return (a == b);
    }

    if (a->manifest_version != b->manifest_version) return false;
    if (strcmp(a->mode, b->mode) != 0) return false;
    if (a->created_at != b->created_at) return false;

    if (a->target.architecture != b->target.architecture) return false;
    if (strcmp(a->target.vendor, b->target.vendor) != 0) return false;
    if (strcmp(a->target.device, b->target.device) != 0) return false;
    if (a->target.abi != b->target.abi) return false;

    if (memcmp(&a->weights_digest, &b->weights_digest, sizeof(cd_hash_t)) != 0) return false;
    if (memcmp(&a->certs_digest, &b->certs_digest, sizeof(cd_hash_t)) != 0) return false;
    if (memcmp(&a->inference_digest, &b->inference_digest, sizeof(cd_hash_t)) != 0) return false;

    return true;
}

/**
 * @brief Convert manifest to pretty-printed JSON
 * @traceability NFR-MAN-02
 *
 * WARNING: Pretty output is NOT for hashing or bundling.
 */
cdm_result_t cdm_to_pretty_json(const cd_manifest_t *manifest,
                                 uint8_t *out, size_t *out_len)
{
    const char *arch_str;
    const char *abi_str;
    int written;
    char weights_hex[65];
    char certs_hex[65];
    char inference_hex[65];
    size_t i;

    if (manifest == NULL || out == NULL || out_len == NULL) {
        return CDM_ERR_NULL;
    }

    arch_str = cdm_arch_to_string(manifest->target.architecture);
    abi_str = cdm_abi_to_string(manifest->target.abi);

    if (arch_str == NULL || abi_str == NULL) {
        return CDM_ERR_INVALID_TARGET;
    }

    /* Convert hashes to hex */
    for (i = 0; i < 32; i++) {
        snprintf(&weights_hex[i*2], 3, "%02x", manifest->weights_digest.bytes[i]);
        snprintf(&certs_hex[i*2], 3, "%02x", manifest->certs_digest.bytes[i]);
        snprintf(&inference_hex[i*2], 3, "%02x", manifest->inference_digest.bytes[i]);
    }

    written = snprintf((char *)out, *out_len,
        "{\n"
        "  \"manifest_version\": %u,\n"
        "  \"mode\": \"%s\",\n"
        "  \"created_at\": %llu,\n"
        "  \"target\": {\n"
        "    \"arch\": \"%s\",\n"
        "    \"vendor\": \"%s\",\n"
        "    \"device\": \"%s\",\n"
        "    \"abi\": \"%s\"\n"
        "  },\n"
        "  \"components\": {\n"
        "    \"weights\": { \"digest\": \"%s\" },\n"
        "    \"certificates\": { \"digest\": \"%s\" },\n"
        "    \"inference\": { \"digest\": \"%s\" }\n"
        "  }\n"
        "}\n",
        manifest->manifest_version,
        manifest->mode,
        (unsigned long long)manifest->created_at,
        arch_str,
        manifest->target.vendor,
        manifest->target.device,
        abi_str,
        weights_hex,
        certs_hex,
        inference_hex
    );

    if (written < 0 || (size_t)written >= *out_len) {
        return CDM_ERR_BUFFER_TOO_SMALL;
    }

    *out_len = (size_t)written;
    return CDM_OK;
}

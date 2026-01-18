/**
 * @file cd_manifest.h
 * @brief Manifest builder and parser API for certifiable-deploy
 * @project Certifiable Deploy
 *
 * @details
 * This module implements the manifest builder and parser with RFC 8785 (JCS)
 * canonicalization. The canonical JSON output is the input to H_M for Merkle
 * tree construction.
 *
 * Key responsibilities:
 * - Construct deployment manifests with validated fields
 * - Emit JCS-canonical JSON for deterministic hashing
 * - Parse and validate manifest JSON with strict schema enforcement
 * - Enforce timestamp policies (deterministic vs audit modes)
 *
 * @traceability SRS-004-MANIFEST (all requirements)
 * @compliance MISRA-C:2012, ISO 26262, IEC 62304
 *
 * @author William Murray
 * @copyright Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * @license Licensed under the GPL-3.0 (Open Source) or Commercial License.
 *          For commercial licensing: william@fstopify.com
 */

#ifndef CD_MANIFEST_H
#define CD_MANIFEST_H

#include "cd_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 * @traceability SRS-004-MANIFEST §6
 *============================================================================*/

/** Manifest schema version (FR-MAN-05) */
#define CDM_VERSION             1

/** Maximum timestamp value (year 2100) - FR-MAN-04 */
#define CDM_MAX_TIMESTAMP       4102444800ULL

/** Maximum field lengths - FR-MAN-02 */
#define CDM_ARCH_MAX_LEN        16
#define CDM_VENDOR_MAX_LEN      32
#define CDM_DEVICE_MAX_LEN      32
#define CDM_ABI_MAX_LEN         16
#define CDM_MODE_MAX_LEN        16

/** Maximum manifest JSON size (conservative bound) */
#define CDM_MAX_JSON_SIZE       2048

/** Maximum pretty-printed JSON size */
#define CDM_MAX_PRETTY_SIZE     4096

/*============================================================================
 * Result Codes
 * @traceability SRS-004-MANIFEST §5
 *============================================================================*/

/**
 * @brief Result codes for manifest operations
 * @traceability SRS-004-MANIFEST
 */
typedef enum {
    CDM_OK = 0,                     /**< Success */

    /* Input validation errors (1-19) */
    CDM_ERR_NULL = 1,               /**< NULL pointer argument */
    CDM_ERR_STATE = 2,              /**< Invalid builder state */
    CDM_ERR_MISSING_FIELD = 3,      /**< Required field not set */
    CDM_ERR_BUFFER_TOO_SMALL = 4,   /**< Output buffer insufficient */

    /* Target validation errors (20-29) - FR-MAN-02 */
    CDM_ERR_INVALID_ARCH = 20,      /**< Unknown architecture */
    CDM_ERR_INVALID_VENDOR = 21,    /**< Vendor field validation failed */
    CDM_ERR_INVALID_DEVICE = 22,    /**< Device field validation failed */
    CDM_ERR_INVALID_ABI = 23,       /**< Unknown ABI */
    CDM_ERR_INVALID_TARGET = 24,    /**< General target error */
    CDM_ERR_FIELD_TOO_LONG = 25,    /**< Field exceeds maximum length */
    CDM_ERR_INVALID_CHAR = 26,      /**< Invalid character in field */

    /* Mode/timestamp errors (30-39) - FR-MAN-04 */
    CDM_ERR_INVALID_MODE = 30,      /**< Mode not "deterministic" or "audit" */
    CDM_ERR_INVALID_TIMESTAMP = 31, /**< Timestamp out of bounds */

    /* Hash/digest errors (40-49) - FR-MAN-03 */
    CDM_ERR_INVALID_DIGEST = 40,    /**< Digest not valid hex */

    /* Parse errors (50-69) - FR-MAN-06 */
    CDM_ERR_PARSE_FAILED = 50,      /**< JSON parse error */
    CDM_ERR_INVALID_VERSION = 51,   /**< Unsupported manifest version */
    CDM_ERR_NON_CANONICAL = 52,     /**< Input not JCS-canonical (strict mode) */
    CDM_ERR_UNKNOWN_KEY = 53,       /**< Unknown key in JSON (fail-closed) */
    CDM_ERR_DUPLICATE_KEY = 54,     /**< Duplicate key in JSON */
    CDM_ERR_INVALID_TYPE = 55,      /**< Wrong JSON value type */
    CDM_ERR_ADDITIONAL_PROPS = 56,  /**< additionalProperties violation */

    /* JCS errors (70-79) - FR-MAN-01 */
    CDM_ERR_JCS_OVERFLOW = 70,      /**< Number too large for canonical form */
    CDM_ERR_JCS_INVALID_STRING = 71 /**< String cannot be canonicalized */
} cdm_result_t;

/*============================================================================
 * Builder State Machine
 * @traceability SRS-004-MANIFEST §5.1
 *============================================================================*/

/**
 * @brief Builder state machine states
 */
typedef enum {
    CDM_STATE_UNINITIALIZED = 0,    /**< Not initialized */
    CDM_STATE_CONFIGURING = 1,      /**< Accepting configuration */
    CDM_STATE_FINALIZED = 2,        /**< JSON emitted, no further changes */
    CDM_STATE_ERROR = 3             /**< Error occurred, must re-init */
} cdm_builder_state_t;

/*============================================================================
 * Builder Context
 * @traceability SRS-004-MANIFEST §5.1
 *============================================================================*/

/**
 * @brief Manifest builder context
 * @traceability SRS-004-MANIFEST §5.1
 *
 * Usage:
 *   1. cdm_builder_init()
 *   2. cdm_set_mode(), cdm_set_created_at(), cdm_set_target()
 *   3. cdm_set_weights_hash(), cdm_set_certs_hash(), cdm_set_inference_hash()
 *   4. cdm_finalize_jcs() to emit canonical JSON
 */
typedef struct {
    /* State machine */
    cdm_builder_state_t state;

    /* Manifest data */
    cd_manifest_t manifest;

    /* Field presence flags */
    bool mode_set;
    bool timestamp_set;
    bool target_set;
    bool weights_set;
    bool certs_set;
    bool inference_set;

    /* Fault tracking */
    cd_fault_flags_t faults;
} cdm_builder_t;

/*============================================================================
 * JCS Primitives (RFC 8785)
 * @traceability FR-MAN-01
 *============================================================================*/

/**
 * @brief Validate a field string against pattern ^[a-z0-9\-_]+$
 * @traceability FR-MAN-02
 *
 * @param field     The string to validate
 * @param max_len   Maximum allowed length (not including null terminator)
 * @return CDM_OK if valid, error code otherwise
 *
 * Validates:
 * - Non-empty
 * - Length <= max_len
 * - Only lowercase alphanumeric, hyphen, underscore
 */
cdm_result_t cdm_validate_field(const char *field, size_t max_len);

/**
 * @brief Write a JSON string value in JCS canonical form
 * @traceability FR-MAN-01
 *
 * @param out       Output buffer
 * @param out_len   [in/out] Buffer size, updated to bytes written
 * @param str       String to encode (null-terminated)
 * @return CDM_OK on success, error code otherwise
 *
 * Handles:
 * - Quote wrapping
 * - Escape sequences (\", \\, \n, \r, \t)
 * - Control character escaping (\u00XX)
 */
cdm_result_t cdm_jcs_write_string(uint8_t *out, size_t *out_len, const char *str);

/**
 * @brief Write an unsigned integer in JCS canonical form
 * @traceability FR-MAN-01
 *
 * @param out       Output buffer
 * @param out_len   [in/out] Buffer size, updated to bytes written
 * @param value     Integer value
 * @return CDM_OK on success, error code otherwise
 *
 * JCS rules:
 * - No leading zeros (except for 0 itself)
 * - No positive sign
 * - No decimal point for integers
 */
cdm_result_t cdm_jcs_write_uint(uint8_t *out, size_t *out_len, uint64_t value);

/**
 * @brief Write a 32-byte hash as 64-character lowercase hex string
 * @traceability FR-MAN-03
 *
 * @param out       Output buffer
 * @param out_len   [in/out] Buffer size, updated to bytes written
 * @param hash      Hash to encode
 * @return CDM_OK on success, error code otherwise
 */
cdm_result_t cdm_jcs_write_hash(uint8_t *out, size_t *out_len, const cd_hash_t *hash);

/*============================================================================
 * Architecture/ABI String Conversion
 * @traceability FR-MAN-02
 *============================================================================*/

/**
 * @brief Convert architecture enum to canonical string
 * @param arch Architecture enum value
 * @return String or NULL if unknown
 */
const char *cdm_arch_to_string(cd_architecture_t arch);

/**
 * @brief Convert string to architecture enum
 * @param str Architecture string (e.g., "x86_64")
 * @return Architecture enum or CD_ARCH_UNKNOWN
 */
cd_architecture_t cdm_string_to_arch(const char *str);

/**
 * @brief Convert ABI enum to canonical string
 * @param abi ABI enum value
 * @return String or NULL if unknown
 */
const char *cdm_abi_to_string(cd_abi_t abi);

/**
 * @brief Convert string to ABI enum
 * @param str ABI string (e.g., "linux-gnu")
 * @return ABI enum or CD_ABI_UNKNOWN
 */
cd_abi_t cdm_string_to_abi(const char *str);

/*============================================================================
 * Builder API
 * @traceability SRS-004-MANIFEST §5.1
 *============================================================================*/

/**
 * @brief Initialize manifest builder
 * @traceability SRS-004-MANIFEST
 *
 * @param ctx Builder context to initialize
 * @return CDM_OK on success
 */
cdm_result_t cdm_builder_init(cdm_builder_t *ctx);

/**
 * @brief Set deployment mode
 * @traceability FR-MAN-04
 *
 * @param ctx  Builder context
 * @param mode "deterministic" or "audit"
 * @return CDM_OK on success, CDM_ERR_INVALID_MODE if invalid
 */
cdm_result_t cdm_set_mode(cdm_builder_t *ctx, const char *mode);

/**
 * @brief Set creation timestamp
 * @traceability FR-MAN-04
 *
 * @param ctx Builder context
 * @param ts  Unix timestamp (seconds), 0 for deterministic mode
 * @return CDM_OK on success, CDM_ERR_INVALID_TIMESTAMP if out of bounds
 *
 * Note: In deterministic mode, ts should be 0 or a fixed value.
 */
cdm_result_t cdm_set_created_at(cdm_builder_t *ctx, uint64_t ts);

/**
 * @brief Set target tuple
 * @traceability FR-MAN-02
 *
 * @param ctx    Builder context
 * @param target Target specification (architecture, vendor, device, ABI)
 * @return CDM_OK on success, target validation error otherwise
 */
cdm_result_t cdm_set_target(cdm_builder_t *ctx, const cd_target_t *target);

/**
 * @brief Set weights component hash (H_W)
 * @traceability FR-MAN-03
 *
 * @param ctx    Builder context
 * @param digest 32-byte SHA-256 hash
 * @return CDM_OK on success
 */
cdm_result_t cdm_set_weights_hash(cdm_builder_t *ctx, const cd_hash_t *digest);

/**
 * @brief Set certificates component hash (H_C)
 * @traceability FR-MAN-03
 *
 * @param ctx    Builder context
 * @param digest 32-byte SHA-256 hash
 * @return CDM_OK on success
 */
cdm_result_t cdm_set_certs_hash(cdm_builder_t *ctx, const cd_hash_t *digest);

/**
 * @brief Set inference component hash (H_I)
 * @traceability FR-MAN-03
 *
 * @param ctx    Builder context
 * @param digest 32-byte SHA-256 hash
 * @return CDM_OK on success
 */
cdm_result_t cdm_set_inference_hash(cdm_builder_t *ctx, const cd_hash_t *digest);

/**
 * @brief Check target tuple validity
 * @traceability FR-MAN-02
 *
 * @param target Target to validate
 * @return CDM_OK if valid, error code otherwise
 */
cdm_result_t cdm_check_target(const cd_target_t *target);

/**
 * @brief Finalize and emit JCS-canonical JSON
 * @traceability FR-MAN-01
 *
 * @param ctx     Builder context
 * @param out     Output buffer for canonical JSON
 * @param out_len [in/out] Buffer size, updated to bytes written (excludes null)
 * @return CDM_OK on success, error code otherwise
 *
 * JCS key ordering (lexicographic by UTF-16 code units):
 *   Root level:  components, created_at, manifest_version, mode, target
 *   components:  certificates, inference, weights
 *   target:      abi, arch, device, vendor
 *
 * After successful call, builder transitions to FINALIZED state.
 */
cdm_result_t cdm_finalize_jcs(cdm_builder_t *ctx, uint8_t *out, size_t *out_len);

/**
 * @brief Get fault flags from builder
 * @param ctx Builder context
 * @return Pointer to fault flags or NULL if ctx is NULL
 */
const cd_fault_flags_t *cdm_builder_get_faults(const cdm_builder_t *ctx);

/*============================================================================
 * Parser API
 * @traceability SRS-004-MANIFEST §5.2
 *============================================================================*/

/**
 * @brief Parse manifest from JSON bytes
 * @traceability FR-MAN-06
 *
 * @param json   JSON bytes (need not be null-terminated)
 * @param len    Length of JSON data
 * @param out    Parsed manifest structure
 * @param faults Fault flags (may be NULL)
 * @return CDM_OK on success, error code otherwise
 *
 * Performs (strict mode):
 * - Schema validation against §6.1 JSON schema
 * - Regex validation for all string fields
 * - Numeric bounds validation
 * - Canonicalization check: input must already be JCS-canonical
 *
 * Fail-closed on any violation.
 */
cdm_result_t cdm_parse(const uint8_t *json, size_t len,
                       cd_manifest_t *out, cd_fault_flags_t *faults);

/**
 * @brief Parse manifest with lenient canonicalization
 * @traceability FR-MAN-06 (lenient policy)
 *
 * @param json   JSON bytes
 * @param len    Length of JSON data
 * @param out    Parsed manifest structure
 * @param faults Fault flags (may be NULL)
 * @return CDM_OK on success, error code otherwise
 *
 * Accepts non-canonical JSON but validates all fields.
 * Use cdm_parse() for strict mode in bundle verification.
 */
cdm_result_t cdm_parse_lenient(const uint8_t *json, size_t len,
                               cd_manifest_t *out, cd_fault_flags_t *faults);

/**
 * @brief Verify that JSON bytes are JCS-canonical
 * @traceability FR-MAN-06
 *
 * @param json JSON bytes
 * @param len  Length of JSON data
 * @return CDM_OK if canonical, CDM_ERR_NON_CANONICAL otherwise
 *
 * Parses the JSON, re-emits in canonical form, and compares byte-for-byte.
 */
cdm_result_t cdm_verify_canonical(const uint8_t *json, size_t len);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * @brief Convert result code to string description
 * @param result Result code
 * @return Static string description
 */
const char *cdm_result_to_string(cdm_result_t result);

/**
 * @brief Compare two manifests for equality
 * @param a First manifest
 * @param b Second manifest
 * @return true if all fields match, false otherwise
 */
bool cdm_manifest_equal(const cd_manifest_t *a, const cd_manifest_t *b);

/**
 * @brief Convert manifest to pretty-printed JSON (for debugging)
 * @traceability NFR-MAN-02
 *
 * @param manifest Source manifest
 * @param out      Output buffer
 * @param out_len  [in/out] Buffer size, updated to bytes written
 * @return CDM_OK on success
 *
 * WARNING: Pretty output is NOT for hashing or bundling.
 */
cdm_result_t cdm_to_pretty_json(const cd_manifest_t *manifest,
                                 uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CD_MANIFEST_H */

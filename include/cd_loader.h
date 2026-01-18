/**
 * @file cd_loader.h
 * @brief Runtime secure loader API for certifiable-deploy
 * @traceability SRS-006-LOADER, CD-MATH-001 §4.3
 *
 * The Loader Module ("The Gateway") implements secure consumption of
 * deployment bundles on target devices. It enforces the core invariant:
 *
 *   "Execution ⇒ Verification"
 *
 * No code or data is made available for execution unless it mathematically
 * matches the bundle's attestation through JIT (Just-In-Time) hashing.
 *
 * Key capabilities:
 * - CD-LOAD state machine with fail-closed semantics
 * - Target tuple matching against physical device
 * - JIT weight verification (FR-LDR-03)
 * - JIT kernel verification (FR-LDR-04)
 * - Certificate chain interlock (FR-LDR-05)
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_LOADER_H
#define CD_LOADER_H

#include "cd_types.h"
#include "cd_bundle.h"
#include "cd_audit.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * CD-LOAD State Machine (FR-LDR-01)
 *
 * State transitions are strictly linear with fail-closed semantics.
 * Any error transitions immediately to CDL_STATE_FAILED, which cannot
 * be exited.
 *
 * Normal flow:
 *   INIT -> HEADER_READ -> TOC_READ -> MANIFEST_VERIFIED ->
 *   WEIGHTS_STREAMING -> WEIGHTS_VERIFIED ->
 *   INFERENCE_STREAMING -> INFERENCE_VERIFIED ->
 *   CHAIN_VERIFIED -> ENABLED
 *
 * @traceability FR-LDR-01, CD-MATH-001 §4.3.2
 *============================================================================*/

typedef enum {
    CDL_STATE_INIT              = 0,   /**< Context zeroed, not started */
    CDL_STATE_HEADER_READ       = 1,   /**< CBF magic/version verified */
    CDL_STATE_TOC_READ          = 2,   /**< TOC parsed and validated */
    CDL_STATE_MANIFEST_VERIFIED = 3,   /**< H_M matches Merkle leaf L_M */
    CDL_STATE_WEIGHTS_STREAMING = 4,   /**< Reading weights, updating H_W' */
    CDL_STATE_WEIGHTS_VERIFIED  = 5,   /**< H_W' == H_W (from manifest) */
    CDL_STATE_INFERENCE_STREAMING = 6, /**< Reading kernels, updating H_I' */
    CDL_STATE_INFERENCE_VERIFIED = 7,  /**< H_I' == H_I (from manifest) */
    CDL_STATE_CHAIN_VERIFIED    = 8,   /**< Certificate chain validated */
    CDL_STATE_ENABLED           = 9,   /**< API ready for execution */
    CDL_STATE_FAILED            = 99   /**< Terminal error state */
} cdl_state_t;

/*============================================================================
 * Loader Error Codes
 *============================================================================*/

typedef enum {
    CDL_OK                      = 0,
    CDL_ERR_NULL                = -1,
    CDL_ERR_STATE               = -2,   /**< Invalid state for operation */
    CDL_ERR_IO                  = -3,   /**< I/O operation failed */
    CDL_ERR_MAGIC               = -4,   /**< Invalid CBF magic */
    CDL_ERR_VERSION             = -5,   /**< Unsupported CBF version */
    CDL_ERR_TOC_INVALID         = -6,   /**< TOC parse failed */
    CDL_ERR_MANIFEST_NOT_FOUND  = -7,   /**< manifest.json missing */
    CDL_ERR_MANIFEST_PARSE      = -8,   /**< Manifest parse failed */
    CDL_ERR_MANIFEST_HASH       = -9,   /**< H_M mismatch */
    CDL_ERR_TARGET_MISMATCH     = -10,  /**< Bundle/device target incompatible */
    CDL_ERR_WEIGHTS_NOT_FOUND   = -11,  /**< weights.bin missing */
    CDL_ERR_WEIGHTS_SIZE        = -12,  /**< Buffer size mismatch */
    CDL_ERR_WEIGHTS_HASH        = -13,  /**< H_W' != H_W */
    CDL_ERR_INFERENCE_NOT_FOUND = -14,  /**< Inference files missing */
    CDL_ERR_INFERENCE_SIZE      = -15,  /**< Buffer size mismatch */
    CDL_ERR_INFERENCE_HASH      = -16,  /**< H_I' != H_I */
    CDL_ERR_CHAIN_NOT_FOUND     = -17,  /**< Certificate files missing */
    CDL_ERR_CHAIN_PARSE         = -18,  /**< Certificate parse failed */
    CDL_ERR_CHAIN_MISMATCH      = -19,  /**< H_W^measured != H_W^cert */
    CDL_ERR_MERKLE_ROOT         = -20,  /**< Merkle root mismatch */
    CDL_ERR_BUFFER_TOO_SMALL    = -21   /**< Provided buffer insufficient */
} cdl_result_t;

/*============================================================================
 * Loader Context (CD-STRUCT-001 §14)
 *
 * All state for a single bundle load operation. Caller-allocated,
 * no dynamic memory. Context must remain valid until load completes
 * or fails.
 *============================================================================*/

typedef struct {
    /* State machine */
    cdl_state_t state;
    cdl_result_t last_error;
    
    /* Device binding */
    cd_target_t device_target;
    bool device_target_set;
    
    /* Bundle reader (zero-copy into mmap'd buffer) */
    cd_reader_ctx_t reader;
    
    /* Parsed manifest */
    cd_manifest_t manifest;
    bool manifest_valid;
    
    /* Expected hashes (from manifest) */
    cd_hash_t expected_weights_hash;    /**< H_W from manifest */
    cd_hash_t expected_inference_hash;  /**< H_I from manifest */
    cd_hash_t expected_certs_hash;      /**< H_C from manifest */
    
    /* Measured hashes (computed during JIT load) */
    cd_hash_t measured_manifest_hash;   /**< H_M computed */
    cd_hash_t measured_weights_hash;    /**< H_W' computed */
    cd_hash_t measured_inference_hash;  /**< H_I' computed */
    
    /* Streaming hash contexts */
    cd_sha256_ctx_t weights_hash_ctx;
    cd_sha256_ctx_t inference_hash_ctx;
    uint64_t weights_bytes_remaining;
    uint64_t inference_bytes_remaining;
    
    /* Certificate chain (parsed from bundle) */
    cd_cert_chain_t cert_chain;
    bool cert_chain_valid;
    
    /* Attestation (rebuilt for verification) */
    cd_attestation_t attestation;
    
    /* Fault flags */
    cd_fault_flags_t faults;
} cd_load_ctx_t;

/*============================================================================
 * Loader API (SRS-006-LOADER §5)
 *============================================================================*/

/**
 * @brief Initialize loader context
 *
 * Zeroes context and sets device target for compatibility checking.
 * Must be called before any other cdl_* function.
 *
 * @param[out] ctx           Caller-allocated loader context
 * @param[in]  device_target Hardware definition of current device
 * @return CDL_OK on success, error code otherwise
 *
 * @traceability SRS-006-LOADER §5
 *
 * @post ctx->state == CDL_STATE_INIT
 * @post ctx->device_target_set == true
 */
cdl_result_t cdl_init(cd_load_ctx_t *ctx, const cd_target_t *device_target);

/**
 * @brief Open bundle and verify header/target
 *
 * Performs initial bundle validation:
 * 1. Parse CBF header (magic, version)
 * 2. Parse TOC
 * 3. Locate and parse manifest.json
 * 4. Verify manifest hash against Merkle expectation
 * 5. Check target tuple compatibility
 *
 * @param[in,out] ctx   Loader context in INIT state
 * @param[in]     data  Memory-mapped bundle data
 * @param[in]     len   Bundle size in bytes
 * @return CDL_OK on success, error code otherwise
 *
 * @traceability FR-LDR-01, FR-LDR-02
 *
 * @pre ctx->state == CDL_STATE_INIT
 * @post ctx->state == CDL_STATE_MANIFEST_VERIFIED on success
 * @post ctx->state == CDL_STATE_FAILED on error
 */
cdl_result_t cdl_open_bundle(cd_load_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Get weights size from manifest
 *
 * Returns the expected weights size so caller can allocate buffer.
 *
 * @param[in]  ctx  Loader context with valid manifest
 * @param[out] size Output for weights size in bytes
 * @return CDL_OK on success, error code otherwise
 *
 * @pre ctx->state >= CDL_STATE_MANIFEST_VERIFIED
 */
cdl_result_t cdl_get_weights_size(const cd_load_ctx_t *ctx, uint64_t *size);

/**
 * @brief Load weights into memory with JIT verification
 *
 * Streams weights from bundle to caller's buffer while computing
 * SHA-256 hash. Verifies H_W' == H_W from manifest.
 *
 * @param[in,out] ctx    Loader context in MANIFEST_VERIFIED state
 * @param[out]    buffer Output buffer for weights (must be aligned)
 * @param[in]     size   Buffer size (must match weights size)
 * @return CDL_OK on success, error code otherwise
 *
 * @traceability FR-LDR-03
 *
 * @pre ctx->state == CDL_STATE_MANIFEST_VERIFIED
 * @post ctx->state == CDL_STATE_WEIGHTS_VERIFIED on success
 * @post ctx->state == CDL_STATE_FAILED on error
 *
 * @note Caller is responsible for memory alignment requirements.
 * @note Buffer must remain valid; loader does not retain copy.
 */
cdl_result_t cdl_load_weights(cd_load_ctx_t *ctx, void *buffer, size_t size);

/**
 * @brief Get inference set size from bundle
 *
 * Returns total size of all files in inference/ directory.
 *
 * @param[in]  ctx  Loader context with valid manifest
 * @param[out] size Output for total inference size in bytes
 * @return CDL_OK on success, error code otherwise
 *
 * @pre ctx->state >= CDL_STATE_WEIGHTS_VERIFIED
 */
cdl_result_t cdl_get_inference_size(const cd_load_ctx_t *ctx, uint64_t *size);

/**
 * @brief Load inference kernels with JIT verification
 *
 * Streams inference artifacts from bundle to caller's buffer while
 * computing hash. Verifies H_I' == H_I from manifest.
 *
 * @param[in,out] ctx           Loader context in WEIGHTS_VERIFIED state
 * @param[out]    kernel_buffer Output buffer for kernels
 * @param[in]     size          Buffer size
 * @return CDL_OK on success, error code otherwise
 *
 * @traceability FR-LDR-04
 *
 * @pre ctx->state == CDL_STATE_WEIGHTS_VERIFIED
 * @post ctx->state == CDL_STATE_INFERENCE_VERIFIED on success
 * @post ctx->state == CDL_STATE_FAILED on error
 */
cdl_result_t cdl_load_kernels(cd_load_ctx_t *ctx, void *kernel_buffer, size_t size);

/**
 * @brief Finalize and enable execution
 *
 * Performs final verification steps:
 * 1. Parse certificate chain
 * 2. Verify H_W^measured == H_W^cert (chain interlock)
 * 3. Verify Merkle root matches footer
 * 4. Transition to ENABLED state
 *
 * @param[in,out] ctx  Loader context in INFERENCE_VERIFIED state
 * @return CDL_OK on success, error code otherwise
 *
 * @traceability FR-LDR-05, NFR-LDR-02
 *
 * @pre ctx->state == CDL_STATE_INFERENCE_VERIFIED
 * @post ctx->state == CDL_STATE_ENABLED on success
 * @post ctx->state == CDL_STATE_FAILED on error
 */
cdl_result_t cdl_finalize(cd_load_ctx_t *ctx);

/*============================================================================
 * Query API
 *============================================================================*/

/**
 * @brief Get current loader state
 *
 * @param[in] ctx  Loader context
 * @return Current state, or CDL_STATE_FAILED if ctx is NULL
 */
cdl_state_t cdl_get_state(const cd_load_ctx_t *ctx);

/**
 * @brief Check if loader is in ENABLED state
 *
 * Only returns true if all verification steps passed and
 * execution is permitted.
 *
 * @param[in] ctx  Loader context
 * @return true if enabled, false otherwise
 */
bool cdl_is_enabled(const cd_load_ctx_t *ctx);

/**
 * @brief Check if loader is in FAILED state
 *
 * @param[in] ctx  Loader context
 * @return true if failed, false otherwise
 */
bool cdl_is_failed(const cd_load_ctx_t *ctx);

/**
 * @brief Get last error code
 *
 * @param[in] ctx  Loader context
 * @return Last error code, or CDL_ERR_NULL if ctx is NULL
 */
cdl_result_t cdl_get_error(const cd_load_ctx_t *ctx);

/**
 * @brief Get error description string
 *
 * @param[in] err  Error code
 * @return Human-readable error description
 */
const char *cdl_error_string(cdl_result_t err);

/**
 * @brief Get fault flags from loader
 *
 * @param[in] ctx  Loader context
 * @return Pointer to fault flags, or NULL if ctx is NULL
 */
const cd_fault_flags_t *cdl_get_faults(const cd_load_ctx_t *ctx);

/**
 * @brief Get loaded manifest
 *
 * Returns pointer to parsed manifest. Only valid after
 * cdl_open_bundle() succeeds.
 *
 * @param[in] ctx  Loader context
 * @return Pointer to manifest, or NULL if not available
 */
const cd_manifest_t *cdl_get_manifest(const cd_load_ctx_t *ctx);

/**
 * @brief Get measured hashes
 *
 * Returns the JIT-computed hashes for diagnostic purposes.
 *
 * @param[in]  ctx   Loader context
 * @param[out] h_m   Output for manifest hash (may be NULL)
 * @param[out] h_w   Output for weights hash (may be NULL)
 * @param[out] h_i   Output for inference hash (may be NULL)
 * @return CDL_OK on success, error code otherwise
 */
cdl_result_t cdl_get_measured_hashes(const cd_load_ctx_t *ctx,
                                     cd_hash_t *h_m,
                                     cd_hash_t *h_w,
                                     cd_hash_t *h_i);

#ifdef __cplusplus
}
#endif

#endif /* CD_LOADER_H */

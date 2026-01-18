/**
 * @file cd_verify.h
 * @brief Offline verification API for certifiable-deploy
 * @traceability SRS-005-VERIFY
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_VERIFY_H
#define CD_VERIFY_H

#include "cd_types.h"

/*============================================================================
 * Context Management
 *============================================================================*/

/**
 * Initialize verification context
 */
void cdv_init(cd_verify_ctx_t *ctx);

/**
 * Set device target for target matching
 */
void cdv_set_device_target(cd_verify_ctx_t *ctx, const cd_target_t *device);

/*============================================================================
 * State Machine
 *============================================================================*/

/**
 * Get current state
 */
cd_verify_state_t cdv_state(const cd_verify_ctx_t *ctx);

/**
 * Check if verification is complete (passed or failed)
 */
bool cdv_is_complete(const cd_verify_ctx_t *ctx);

/**
 * Check if verification passed
 */
bool cdv_passed(const cd_verify_ctx_t *ctx);

/**
 * Get failure reason
 */
cd_verify_reason_t cdv_reason(const cd_verify_ctx_t *ctx);

/**
 * Get full result
 */
void cdv_get_result(const cd_verify_ctx_t *ctx, cd_verify_result_t *result);

/**
 * Execute one verification step
 * @param data State-specific data (header, hash, target, etc.)
 * @return 0 on success, -1 on failure
 */
int cdv_step(cd_verify_ctx_t *ctx, const void *data);

/*============================================================================
 * Hash Setting
 *============================================================================*/

void cdv_set_manifest_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h);
void cdv_set_weights_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h);
void cdv_set_certs_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h);
void cdv_set_inference_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h);
void cdv_set_cert_chain(cd_verify_ctx_t *ctx, const cd_cert_chain_t *chain);

/*============================================================================
 * Simplified Full Verification
 *============================================================================*/

/**
 * Verify a bundle in one call
 * @return 0 if verification passed, -1 if failed
 */
int cdv_verify_bundle(cd_verify_ctx_t *ctx,
                      const cd_cbf_header_t *header,
                      const cd_hash_t *h_manifest,
                      const cd_hash_t *h_weights,
                      const cd_hash_t *h_certs,
                      const cd_hash_t *h_inference,
                      const cd_hash_t *expected_root,
                      const cd_cert_chain_t *chain,
                      const cd_target_t *bundle_target);

#endif /* CD_VERIFY_H */

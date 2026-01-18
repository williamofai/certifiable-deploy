/**
 * @file verify.c
 * @brief Offline verification state machine per SRS-005-VERIFY
 * @traceability SRS-005-VERIFY
 * 
 * Verification flow:
 * INIT → PARSE_HEADER → PARSE_TOC → EXTRACT_COMPONENTS →
 * HASH_MANIFEST → HASH_WEIGHTS → HASH_CERTS → HASH_INFERENCE →
 * COMPUTE_MERKLE → COMPARE_ROOT → CHECK_CHAIN → CHECK_TARGET →
 * [CHECK_SIGNATURE] → RESULT
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_verify.h"
#include "cd_audit.h"
#include "cd_attest.h"
#include "cd_target.h"
#include <string.h>

/*============================================================================
 * State Machine Transitions
 *============================================================================*/

static const cd_verify_state_t next_state[] = {
    [CD_VSTATE_INIT]               = CD_VSTATE_PARSE_HEADER,
    [CD_VSTATE_PARSE_HEADER]       = CD_VSTATE_PARSE_TOC,
    [CD_VSTATE_PARSE_TOC]          = CD_VSTATE_EXTRACT_COMPONENTS,
    [CD_VSTATE_EXTRACT_COMPONENTS] = CD_VSTATE_HASH_MANIFEST,
    [CD_VSTATE_HASH_MANIFEST]      = CD_VSTATE_HASH_WEIGHTS,
    [CD_VSTATE_HASH_WEIGHTS]       = CD_VSTATE_HASH_CERTS,
    [CD_VSTATE_HASH_CERTS]         = CD_VSTATE_HASH_INFERENCE,
    [CD_VSTATE_HASH_INFERENCE]     = CD_VSTATE_COMPUTE_MERKLE,
    [CD_VSTATE_COMPUTE_MERKLE]     = CD_VSTATE_COMPARE_ROOT,
    [CD_VSTATE_COMPARE_ROOT]       = CD_VSTATE_CHECK_CHAIN,
    [CD_VSTATE_CHECK_CHAIN]        = CD_VSTATE_CHECK_TARGET,
    [CD_VSTATE_CHECK_TARGET]       = CD_VSTATE_CHECK_SIGNATURE,
    [CD_VSTATE_CHECK_SIGNATURE]    = CD_VSTATE_COMPLETE,
    [CD_VSTATE_COMPLETE]           = CD_VSTATE_COMPLETE,
    [CD_VSTATE_FAILED]             = CD_VSTATE_FAILED
};

/*============================================================================
 * Context Initialization
 *============================================================================*/

void cdv_init(cd_verify_ctx_t *ctx) {
    if (!ctx) return;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = CD_VSTATE_INIT;
    ctx->result.passed = false;
    ctx->result.reason = CD_VERIFY_OK;
    cd_attestation_init(&ctx->attestation);
}

void cdv_set_device_target(cd_verify_ctx_t *ctx, const cd_target_t *device) {
    if (!ctx || !device) return;
    memcpy(&ctx->device_target, device, sizeof(cd_target_t));
}

/*============================================================================
 * State Helpers
 *============================================================================*/

static void fail(cd_verify_ctx_t *ctx, cd_verify_reason_t reason) {
    ctx->state = CD_VSTATE_FAILED;
    ctx->result.passed = false;
    ctx->result.reason = reason;
}

static void advance(cd_verify_ctx_t *ctx) {
    if (ctx->state < CD_VSTATE_COMPLETE) {
        ctx->state = next_state[ctx->state];
    }
}

/*============================================================================
 * Verification Steps
 *============================================================================*/

static int step_parse_header(cd_verify_ctx_t *ctx, const cd_cbf_header_t *header) {
    if (!header) {
        fail(ctx, CD_VERIFY_ERR_HEADER_PARSE);
        return -1;
    }

    if (header->magic != CD_CBF_MAGIC_HEADER) {
        fail(ctx, CD_VERIFY_ERR_MAGIC);
        return -1;
    }

    if (header->version != CD_CBF_VERSION) {
        fail(ctx, CD_VERIFY_ERR_VERSION);
        return -1;
    }

    advance(ctx);
    return 0;
}

static int step_compute_merkle(cd_verify_ctx_t *ctx) {
    cd_attestation_compute(&ctx->attestation, &ctx->faults);
    
    if (cd_has_fault(&ctx->faults)) {
        fail(ctx, CD_VERIFY_ERR_IO);
        return -1;
    }

    advance(ctx);
    return 0;
}

static int step_compare_root(cd_verify_ctx_t *ctx, const cd_hash_t *expected) {
    cd_hash_t computed;

    if (!cd_attestation_get_root(&ctx->attestation, &computed)) {
        fail(ctx, CD_VERIFY_ERR_MERKLE_ROOT);
        return -1;
    }

    cd_hash_copy(&ctx->result.computed_root, &computed);
    cd_hash_copy(&ctx->result.expected_root, expected);

    if (!cd_hash_equal(&computed, expected)) {
        fail(ctx, CD_VERIFY_ERR_MERKLE_ROOT);
        return -1;
    }

    advance(ctx);
    return 0;
}

static int step_check_chain(cd_verify_ctx_t *ctx) {
    /* Verify H_W (computed from weights.bin) matches H_W^cert (in cert chain) */
    if (!cd_hash_equal(&ctx->attestation.h_weights, &ctx->chain.h_weights)) {
        fail(ctx, CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH);
        return -1;
    }

    advance(ctx);
    return 0;
}

static int step_check_target(cd_verify_ctx_t *ctx, const cd_target_t *bundle_target) {
    cd_match_result_t match;

    if (!bundle_target) {
        /* No target check required */
        ctx->result.target_match = CD_MATCH_EXACT;
        advance(ctx);
        return 0;
    }

    match = cdt_match(bundle_target, &ctx->device_target, &ctx->faults);
    ctx->result.target_match = match;

    if (!cdt_match_ok(match)) {
        fail(ctx, CD_VERIFY_ERR_TARGET_MISMATCH);
        return -1;
    }

    advance(ctx);
    return 0;
}

/*============================================================================
 * Public API
 *============================================================================*/

cd_verify_state_t cdv_state(const cd_verify_ctx_t *ctx) {
    if (!ctx) return CD_VSTATE_FAILED;
    return ctx->state;
}

bool cdv_is_complete(const cd_verify_ctx_t *ctx) {
    if (!ctx) return false;
    return ctx->state == CD_VSTATE_COMPLETE || ctx->state == CD_VSTATE_FAILED;
}

bool cdv_passed(const cd_verify_ctx_t *ctx) {
    if (!ctx) return false;
    return ctx->state == CD_VSTATE_COMPLETE && ctx->result.passed;
}

cd_verify_reason_t cdv_reason(const cd_verify_ctx_t *ctx) {
    if (!ctx) return CD_VERIFY_ERR_IO;
    return ctx->result.reason;
}

void cdv_get_result(const cd_verify_ctx_t *ctx, cd_verify_result_t *result) {
    if (!ctx || !result) return;
    memcpy(result, &ctx->result, sizeof(cd_verify_result_t));
}

/*============================================================================
 * Step Execution
 *============================================================================*/

int cdv_step(cd_verify_ctx_t *ctx, const void *data) {
    if (!ctx) return -1;

    switch (ctx->state) {
        case CD_VSTATE_INIT:
            advance(ctx);
            return 0;

        case CD_VSTATE_PARSE_HEADER:
            return step_parse_header(ctx, (const cd_cbf_header_t *)data);

        case CD_VSTATE_PARSE_TOC:
            /* TOC parsing - advance for now */
            advance(ctx);
            return 0;

        case CD_VSTATE_EXTRACT_COMPONENTS:
            /* Component extraction - advance for now */
            advance(ctx);
            return 0;

        case CD_VSTATE_HASH_MANIFEST:
        case CD_VSTATE_HASH_WEIGHTS:
        case CD_VSTATE_HASH_CERTS:
        case CD_VSTATE_HASH_INFERENCE:
            /* Hash steps handled by set_hashes */
            advance(ctx);
            return 0;

        case CD_VSTATE_COMPUTE_MERKLE:
            return step_compute_merkle(ctx);

        case CD_VSTATE_COMPARE_ROOT:
            return step_compare_root(ctx, (const cd_hash_t *)data);

        case CD_VSTATE_CHECK_CHAIN:
            return step_check_chain(ctx);

        case CD_VSTATE_CHECK_TARGET:
            return step_check_target(ctx, (const cd_target_t *)data);

        case CD_VSTATE_CHECK_SIGNATURE:
            /* Signature check optional - advance */
            advance(ctx);
            ctx->result.passed = true;
            return 0;

        case CD_VSTATE_COMPLETE:
        case CD_VSTATE_FAILED:
            return 0;

        default:
            fail(ctx, CD_VERIFY_ERR_IO);
            return -1;
    }
}

/*============================================================================
 * Hash Setting
 *============================================================================*/

void cdv_set_manifest_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h) {
    if (!ctx || !h) return;
    cd_hash_copy(&ctx->attestation.h_manifest, h);
}

void cdv_set_weights_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h) {
    if (!ctx || !h) return;
    cd_hash_copy(&ctx->attestation.h_weights, h);
}

void cdv_set_certs_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h) {
    if (!ctx || !h) return;
    cd_hash_copy(&ctx->attestation.h_certs, h);
}

void cdv_set_inference_hash(cd_verify_ctx_t *ctx, const cd_hash_t *h) {
    if (!ctx || !h) return;
    cd_hash_copy(&ctx->attestation.h_inference, h);
}

void cdv_set_cert_chain(cd_verify_ctx_t *ctx, const cd_cert_chain_t *chain) {
    if (!ctx || !chain) return;
    memcpy(&ctx->chain, chain, sizeof(cd_cert_chain_t));
}

/*============================================================================
 * Simplified Full Verification
 *============================================================================*/

int cdv_verify_bundle(cd_verify_ctx_t *ctx,
                      const cd_cbf_header_t *header,
                      const cd_hash_t *h_manifest,
                      const cd_hash_t *h_weights,
                      const cd_hash_t *h_certs,
                      const cd_hash_t *h_inference,
                      const cd_hash_t *expected_root,
                      const cd_cert_chain_t *chain,
                      const cd_target_t *bundle_target) {
    
    cdv_init(ctx);

    /* Step 1: Parse header */
    cdv_step(ctx, NULL);  /* INIT -> PARSE_HEADER */
    if (cdv_step(ctx, header) != 0) return -1;

    /* Skip TOC and extract for simplified API */
    cdv_step(ctx, NULL);  /* PARSE_TOC */
    cdv_step(ctx, NULL);  /* EXTRACT_COMPONENTS */

    /* Set hashes */
    cdv_set_manifest_hash(ctx, h_manifest);
    cdv_step(ctx, NULL);  /* HASH_MANIFEST */

    cdv_set_weights_hash(ctx, h_weights);
    cdv_step(ctx, NULL);  /* HASH_WEIGHTS */

    cdv_set_certs_hash(ctx, h_certs);
    cdv_step(ctx, NULL);  /* HASH_CERTS */

    cdv_set_inference_hash(ctx, h_inference);
    cdv_step(ctx, NULL);  /* HASH_INFERENCE */

    /* Set cert chain */
    if (chain) {
        cdv_set_cert_chain(ctx, chain);
    }

    /* Compute Merkle */
    if (cdv_step(ctx, NULL) != 0) return -1;

    /* Compare root */
    if (cdv_step(ctx, expected_root) != 0) return -1;

    /* Check chain */
    if (cdv_step(ctx, NULL) != 0) return -1;

    /* Check target */
    if (cdv_step(ctx, bundle_target) != 0) return -1;

    /* Check signature (skip) */
    if (cdv_step(ctx, NULL) != 0) return -1;

    return ctx->result.passed ? 0 : -1;
}

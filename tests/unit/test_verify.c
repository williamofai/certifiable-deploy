/**
 * @file test_verify.c
 * @brief Unit tests for offline verification state machine
 * @traceability SRS-005-VERIFY
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 */

#include "../../include/cd_types.h"
#include "../../include/cd_audit.h"
#include "../../include/cd_attest.h"
#include "../../include/cd_target.h"
#include "../../include/cd_verify.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static void test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    fflush(stdout); \
    test_##name(); \
    tests_run++; \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    Assertion failed: %s (line %d)\n", #cond, __LINE__); \
        exit(1); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    Expected %d, got %d (line %d)\n", (int)(b), (int)(a), __LINE__); \
        exit(1); \
    } \
} while(0)

static void make_test_hash(cd_hash_t *h, uint8_t seed) {
    int i;
    for (i = 0; i < CD_HASH_SIZE; i++) {
        h->bytes[i] = (uint8_t)(seed + i);
    }
}

static void make_valid_header(cd_cbf_header_t *h) {
    memset(h, 0, sizeof(*h));
    h->magic = CD_CBF_MAGIC_HEADER;
    h->version = CD_CBF_VERSION;
}

/* Context Tests */
TEST(init_state) {
    cd_verify_ctx_t ctx;
    cdv_init(&ctx);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_INIT);
    ASSERT_TRUE(!cdv_is_complete(&ctx));
    ASSERT_TRUE(!cdv_passed(&ctx));
}

TEST(set_device_target) {
    cd_verify_ctx_t ctx;
    cd_target_t device;
    cd_fault_flags_t faults = {0};
    cdv_init(&ctx);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    cdv_set_device_target(&ctx, &device);
    ASSERT_EQ(ctx.device_target.architecture, CD_ARCH_X86_64);
}

/* State Machine Tests */
TEST(step_init_to_parse_header) {
    cd_verify_ctx_t ctx;
    cdv_init(&ctx);
    cdv_step(&ctx, NULL);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_PARSE_HEADER);
}

TEST(step_parse_header_valid) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cdv_init(&ctx);
    make_valid_header(&header);
    cdv_step(&ctx, NULL);
    ASSERT_EQ(cdv_step(&ctx, &header), 0);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_PARSE_TOC);
}

TEST(step_parse_header_bad_magic) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cdv_init(&ctx);
    make_valid_header(&header);
    header.magic = 0xDEADBEEF;
    cdv_step(&ctx, NULL);
    ASSERT_EQ(cdv_step(&ctx, &header), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_MAGIC);
}

TEST(step_parse_header_bad_version) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cdv_init(&ctx);
    make_valid_header(&header);
    header.version = 99;
    cdv_step(&ctx, NULL);
    ASSERT_EQ(cdv_step(&ctx, &header), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_VERSION);
}

TEST(step_parse_header_null) {
    cd_verify_ctx_t ctx;
    cdv_init(&ctx);
    cdv_step(&ctx, NULL);
    ASSERT_EQ(cdv_step(&ctx, NULL), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_HEADER_PARSE);
}

/* Hash Setting Tests */
TEST(set_hashes) {
    cd_verify_ctx_t ctx;
    cd_hash_t h_m, h_w, h_c, h_i;
    cdv_init(&ctx);
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cdv_set_manifest_hash(&ctx, &h_m);
    cdv_set_weights_hash(&ctx, &h_w);
    cdv_set_certs_hash(&ctx, &h_c);
    cdv_set_inference_hash(&ctx, &h_i);
    ASSERT_TRUE(cd_hash_equal(&ctx.attestation.h_manifest, &h_m));
    ASSERT_TRUE(cd_hash_equal(&ctx.attestation.h_weights, &h_w));
    ASSERT_TRUE(cd_hash_equal(&ctx.attestation.h_certs, &h_c));
    ASSERT_TRUE(cd_hash_equal(&ctx.attestation.h_inference, &h_i));
}

TEST(set_cert_chain) {
    cd_verify_ctx_t ctx;
    cd_cert_chain_t chain;
    cdv_init(&ctx);
    make_test_hash(&chain.h_data, 0x10);
    make_test_hash(&chain.h_training, 0x20);
    make_test_hash(&chain.h_quant, 0x30);
    make_test_hash(&chain.h_weights, 0x40);
    cdv_set_cert_chain(&ctx, &chain);
    ASSERT_TRUE(cd_hash_equal(&ctx.chain.h_weights, &chain.h_weights));
}

/* Root Comparison Tests */
TEST(compare_root_match) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cd_hash_t h_m, h_w, h_c, h_i, expected;
    cd_attestation_t attest;
    cd_fault_flags_t faults = {0};
    
    cdv_init(&ctx);
    make_valid_header(&header);
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_get_root(&attest, &expected);
    
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, &header);
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, NULL);
    cdv_set_manifest_hash(&ctx, &h_m);
    cdv_step(&ctx, NULL);
    cdv_set_weights_hash(&ctx, &h_w);
    cdv_step(&ctx, NULL);
    cdv_set_certs_hash(&ctx, &h_c);
    cdv_step(&ctx, NULL);
    cdv_set_inference_hash(&ctx, &h_i);
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, NULL);
    
    ASSERT_EQ(cdv_step(&ctx, &expected), 0);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_CHECK_CHAIN);
}

TEST(compare_root_mismatch) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cd_hash_t h_m, h_w, h_c, h_i, wrong;
    
    cdv_init(&ctx);
    make_valid_header(&header);
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    make_test_hash(&wrong, 0xFF);
    
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, &header);
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, NULL);
    cdv_set_manifest_hash(&ctx, &h_m);
    cdv_step(&ctx, NULL);
    cdv_set_weights_hash(&ctx, &h_w);
    cdv_step(&ctx, NULL);
    cdv_set_certs_hash(&ctx, &h_c);
    cdv_step(&ctx, NULL);
    cdv_set_inference_hash(&ctx, &h_i);
    cdv_step(&ctx, NULL);
    cdv_step(&ctx, NULL);
    
    ASSERT_EQ(cdv_step(&ctx, &wrong), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_MERKLE_ROOT);
}

/* Chain Validation Tests */
TEST(check_chain_match) {
    cd_verify_ctx_t ctx;
    cd_hash_t h_w;
    cd_cert_chain_t chain;
    
    cdv_init(&ctx);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&chain.h_weights, 0x20);
    
    cdv_set_weights_hash(&ctx, &h_w);
    cdv_set_cert_chain(&ctx, &chain);
    ctx.state = CD_VSTATE_CHECK_CHAIN;
    
    ASSERT_EQ(cdv_step(&ctx, NULL), 0);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_CHECK_TARGET);
}

TEST(check_chain_mismatch) {
    cd_verify_ctx_t ctx;
    cd_hash_t h_w;
    cd_cert_chain_t chain;
    
    cdv_init(&ctx);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&chain.h_weights, 0xFF);
    
    cdv_set_weights_hash(&ctx, &h_w);
    cdv_set_cert_chain(&ctx, &chain);
    ctx.state = CD_VSTATE_CHECK_CHAIN;
    
    ASSERT_EQ(cdv_step(&ctx, NULL), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_WEIGHTS_CERT_MISMATCH);
}

/* Target Matching Tests */
TEST(check_target_exact_match) {
    cd_verify_ctx_t ctx;
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    
    cdv_init(&ctx);
    cdt_parse("x86_64-intel-xeon-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    cdv_set_device_target(&ctx, &device);
    ctx.state = CD_VSTATE_CHECK_TARGET;
    
    ASSERT_EQ(cdv_step(&ctx, &bundle), 0);
    ASSERT_EQ(ctx.result.target_match, CD_MATCH_EXACT);
}

TEST(check_target_wildcard_match) {
    cd_verify_ctx_t ctx;
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    
    cdv_init(&ctx);
    cdt_parse("x86_64-generic-generic-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    cdv_set_device_target(&ctx, &device);
    ctx.state = CD_VSTATE_CHECK_TARGET;
    
    ASSERT_EQ(cdv_step(&ctx, &bundle), 0);
    ASSERT_EQ(ctx.result.target_match, CD_MATCH_WILDCARD_BOTH);
}

TEST(check_target_mismatch) {
    cd_verify_ctx_t ctx;
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    
    cdv_init(&ctx);
    cdt_parse("x86_64-intel-xeon-sysv", &bundle, &faults);
    cdt_parse("aarch64-nvidia-orin-lp64", &device, &faults);
    cdv_set_device_target(&ctx, &device);
    ctx.state = CD_VSTATE_CHECK_TARGET;
    
    ASSERT_EQ(cdv_step(&ctx, &bundle), -1);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_FAILED);
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_TARGET_MISMATCH);
}

TEST(check_target_null_skips) {
    cd_verify_ctx_t ctx;
    cdv_init(&ctx);
    ctx.state = CD_VSTATE_CHECK_TARGET;
    ASSERT_EQ(cdv_step(&ctx, NULL), 0);
    ASSERT_EQ(cdv_state(&ctx), CD_VSTATE_CHECK_SIGNATURE);
}

/* Full Verification Tests */
TEST(verify_bundle_success) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cd_hash_t h_m, h_w, h_c, h_i, expected;
    cd_cert_chain_t chain;
    cd_attestation_t attest;
    cd_fault_flags_t faults = {0};
    
    make_valid_header(&header);
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_get_root(&attest, &expected);
    
    memset(&chain, 0, sizeof(chain));
    cd_hash_copy(&chain.h_weights, &h_w);
    
    /* Use NULL bundle_target to skip target check */
    ASSERT_EQ(cdv_verify_bundle(&ctx, &header, &h_m, &h_w, &h_c, &h_i,
                                 &expected, &chain, NULL), 0);
    ASSERT_TRUE(cdv_passed(&ctx));
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_OK);
}

TEST(verify_bundle_bad_header) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cd_hash_t h_m, h_w, h_c, h_i, expected;
    
    make_valid_header(&header);
    header.magic = 0xBAD;
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    make_test_hash(&expected, 0xFF);
    
    cdv_init(&ctx);
    ASSERT_EQ(cdv_verify_bundle(&ctx, &header, &h_m, &h_w, &h_c, &h_i,
                                 &expected, NULL, NULL), -1);
    ASSERT_TRUE(!cdv_passed(&ctx));
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_MAGIC);
}

TEST(verify_bundle_bad_root) {
    cd_verify_ctx_t ctx;
    cd_cbf_header_t header;
    cd_hash_t h_m, h_w, h_c, h_i, wrong;
    cd_cert_chain_t chain;
    
    make_valid_header(&header);
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    make_test_hash(&wrong, 0xFF);
    
    memset(&chain, 0, sizeof(chain));
    cd_hash_copy(&chain.h_weights, &h_w);
    
    cdv_init(&ctx);
    ASSERT_EQ(cdv_verify_bundle(&ctx, &header, &h_m, &h_w, &h_c, &h_i,
                                 &wrong, &chain, NULL), -1);
    ASSERT_TRUE(!cdv_passed(&ctx));
    ASSERT_EQ(cdv_reason(&ctx), CD_VERIFY_ERR_MERKLE_ROOT);
}

/* Result Retrieval Tests */
TEST(get_result) {
    cd_verify_ctx_t ctx;
    cd_verify_result_t result;
    
    cdv_init(&ctx);
    ctx.result.passed = true;
    ctx.result.reason = CD_VERIFY_OK;
    ctx.result.target_match = CD_MATCH_EXACT;
    
    cdv_get_result(&ctx, &result);
    ASSERT_TRUE(result.passed);
    ASSERT_EQ(result.reason, CD_VERIFY_OK);
    ASSERT_EQ(result.target_match, CD_MATCH_EXACT);
}

TEST(is_complete_states) {
    cd_verify_ctx_t ctx;
    
    cdv_init(&ctx);
    ASSERT_TRUE(!cdv_is_complete(&ctx));
    
    ctx.state = CD_VSTATE_COMPLETE;
    ASSERT_TRUE(cdv_is_complete(&ctx));
    
    ctx.state = CD_VSTATE_FAILED;
    ASSERT_TRUE(cdv_is_complete(&ctx));
    
    ctx.state = CD_VSTATE_HASH_WEIGHTS;
    ASSERT_TRUE(!cdv_is_complete(&ctx));
}

TEST(null_context_handling) {
    ASSERT_EQ(cdv_state(NULL), CD_VSTATE_FAILED);
    ASSERT_TRUE(!cdv_is_complete(NULL));
    ASSERT_TRUE(!cdv_passed(NULL));
    ASSERT_EQ(cdv_reason(NULL), CD_VERIFY_ERR_IO);
}

int main(void) {
    printf("\n=== test_verify ===\n\n");
    RUN_TEST(init_state);
    RUN_TEST(set_device_target);
    RUN_TEST(step_init_to_parse_header);
    RUN_TEST(step_parse_header_valid);
    RUN_TEST(step_parse_header_bad_magic);
    RUN_TEST(step_parse_header_bad_version);
    RUN_TEST(step_parse_header_null);
    RUN_TEST(set_hashes);
    RUN_TEST(set_cert_chain);
    RUN_TEST(compare_root_match);
    RUN_TEST(compare_root_mismatch);
    RUN_TEST(check_chain_match);
    RUN_TEST(check_chain_mismatch);
    RUN_TEST(check_target_exact_match);
    RUN_TEST(check_target_wildcard_match);
    RUN_TEST(check_target_mismatch);
    RUN_TEST(check_target_null_skips);
    RUN_TEST(verify_bundle_success);
    RUN_TEST(verify_bundle_bad_header);
    RUN_TEST(verify_bundle_bad_root);
    RUN_TEST(get_result);
    RUN_TEST(is_complete_states);
    RUN_TEST(null_context_handling);
    printf("\n  Results: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

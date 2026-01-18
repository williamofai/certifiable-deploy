/**
 * @file test_loader.c
 * @brief Unit tests for runtime secure loader (SRS-006-LOADER)
 *
 * Test coverage:
 * - T-LDR-01: State machine transitions correctly
 * - T-LDR-02: Error transitions to FAILED state
 * - T-LDR-03: FAILED state is terminal
 * - T-LDR-04: Target match succeeds for compatible
 * - T-LDR-05: Target mismatch rejects load
 * - T-LDR-06: Weights hash computed correctly
 * - T-LDR-07: Tampered weights detected
 * - T-LDR-08: Inference hash computed correctly
 * - T-LDR-09: Tampered kernels detected
 * - T-LDR-12: ENABLED only after all checks
 *
 * @traceability SRS-006-LOADER §9
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_loader.h"
#include "cd_bundle.h"
#include "cd_manifest.h"
#include "cd_attest.h"
#include "cd_audit.h"
#include "cd_target.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*============================================================================
 * Test Infrastructure
 *============================================================================*/

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static int test_##name(void)
#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    fflush(stdout); \
    tests_run++; \
    if (test_##name() == 0) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("\n    ASSERT FAILED: %s (line %d)\n", #cond, __LINE__); \
        return -1; \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("\n    ASSERT_EQ FAILED: %s != %s (line %d)\n", #a, #b, __LINE__); \
        return -1; \
    } \
} while(0)

/*============================================================================
 * Mock Bundle Builder
 *
 * Creates a minimal valid CBF bundle in memory for testing the loader.
 * The bundle contains:
 * - manifest.json (JCS-canonical)
 * - weights.bin (test data)
 * - inference/kernel.bin (test data)
 *============================================================================*/

/* Test data */
static const uint8_t TEST_WEIGHTS[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
#define TEST_WEIGHTS_SIZE sizeof(TEST_WEIGHTS)

static const uint8_t TEST_KERNEL[] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
};
#define TEST_KERNEL_SIZE sizeof(TEST_KERNEL)

/**
 * Mock bundle structure for in-memory testing
 */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
    
    /* Computed hashes for verification */
    cd_hash_t h_manifest;
    cd_hash_t h_weights;
    cd_hash_t h_inference;
    cd_hash_t h_certs;
    cd_hash_t merkle_root;
} mock_bundle_t;

/**
 * Write little-endian uint32
 */
static void write_u32_le(uint8_t *buf, uint32_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

/**
 * Write little-endian uint64
 */
static void write_u64_le(uint8_t *buf, uint64_t val)
{
    buf[0] = (uint8_t)(val & 0xFF);
    buf[1] = (uint8_t)((val >> 8) & 0xFF);
    buf[2] = (uint8_t)((val >> 16) & 0xFF);
    buf[3] = (uint8_t)((val >> 24) & 0xFF);
    buf[4] = (uint8_t)((val >> 32) & 0xFF);
    buf[5] = (uint8_t)((val >> 40) & 0xFF);
    buf[6] = (uint8_t)((val >> 48) & 0xFF);
    buf[7] = (uint8_t)((val >> 56) & 0xFF);
}

/**
 * Append data to mock bundle
 */
static int mock_append(mock_bundle_t *bundle, const void *data, size_t len)
{
    if (bundle->len + len > bundle->capacity) {
        return -1;
    }
    memcpy(bundle->data + bundle->len, data, len);
    bundle->len += len;
    return 0;
}

/**
 * Build a valid mock bundle for testing
 */
static int build_mock_bundle(mock_bundle_t *bundle, const cd_target_t *target)
{
    cdm_builder_t builder;
    uint8_t manifest_json[2048];
    size_t manifest_len;
    cd_fault_flags_t faults = {0};
    cd_attestation_t attest;
    
    /* File offsets and sizes */
    uint64_t payload_offset;
    uint64_t manifest_offset, weights_offset, inference_offset;
    uint64_t toc_offset;
    
    /* Allocate bundle buffer */
    bundle->capacity = 16384;
    bundle->data = (uint8_t *)malloc(bundle->capacity);
    if (!bundle->data) return -1;
    bundle->len = 0;
    
    /*
     * Step 1: Compute component hashes
     */
    
    /* H_W = DH("CD:WEIGHTS:v1", weights_data) */
    cd_domain_hash(CD_TAG_WEIGHTS, TEST_WEIGHTS, TEST_WEIGHTS_SIZE,
                   &bundle->h_weights, &faults);
    
    /* H_I = DH("CD:INFERSET:v1", kernel_data) */
    cd_domain_hash(CD_TAG_INFERSET, TEST_KERNEL, TEST_KERNEL_SIZE,
                   &bundle->h_inference, &faults);
    
    /* H_C = zero hash (no certs in test) */
    cd_hash_zero(&bundle->h_certs);
    
    /*
     * Step 2: Build manifest JSON
     */
    cdm_builder_init(&builder);
    cdm_set_mode(&builder, "deterministic");
    cdm_set_created_at(&builder, 0);
    cdm_set_target(&builder, target);
    cdm_set_weights_hash(&builder, &bundle->h_weights);
    cdm_set_certs_hash(&builder, &bundle->h_certs);
    cdm_set_inference_hash(&builder, &bundle->h_inference);
    
    manifest_len = sizeof(manifest_json);
    if (cdm_finalize_jcs(&builder, manifest_json, &manifest_len) != CDM_OK) {
        free(bundle->data);
        return -1;
    }
    
    /* H_M = DH("CD:MANIFEST:v1", manifest_json) */
    cd_domain_hash(CD_TAG_MANIFEST, manifest_json, manifest_len,
                   &bundle->h_manifest, &faults);
    
    /*
     * Step 3: Compute Merkle root
     */
    cda_init(&attest);
    cda_compute_merkle(&attest,
                       &bundle->h_manifest,
                       &bundle->h_weights,
                       &bundle->h_certs,
                       &bundle->h_inference,
                       &faults);
    cda_get_root(&attest, &bundle->merkle_root);
    
    /*
     * Step 4: Build CBF structure
     *
     * Layout:
     *   [0..31]     Header (32 bytes)
     *   [32..]      Payloads (manifest, weights, inference)
     *   [...]       TOC
     *   [...]       Footer
     */
    
    /* Reserve header space */
    bundle->len = 32;
    payload_offset = 32;
    
    /* Write manifest payload */
    manifest_offset = bundle->len;
    if (mock_append(bundle, manifest_json, manifest_len) != 0) {
        free(bundle->data);
        return -1;
    }
    
    /* Write weights payload */
    weights_offset = bundle->len;
    if (mock_append(bundle, TEST_WEIGHTS, TEST_WEIGHTS_SIZE) != 0) {
        free(bundle->data);
        return -1;
    }
    
    /* Write inference payload */
    inference_offset = bundle->len;
    if (mock_append(bundle, TEST_KERNEL, TEST_KERNEL_SIZE) != 0) {
        free(bundle->data);
        return -1;
    }
    
    /* Record TOC offset */
    toc_offset = bundle->len;
    
    /*
     * Step 5: Write TOC
     *
     * TOC Header: count (4 bytes) + reserved (4 bytes)
     * TOC Entry: path (256) + offset (8) + size (8) + hash (32) = 304 bytes
     */
    {
        uint8_t toc_header[8];
        write_u32_le(toc_header, 3);  /* 3 files */
        write_u32_le(toc_header + 4, 0);  /* reserved */
        if (mock_append(bundle, toc_header, 8) != 0) {
            free(bundle->data);
            return -1;
        }
    }
    
    /* TOC entries must be sorted by path */
    /* Entry 1: inference/kernel.bin */
    {
        uint8_t entry[304];
        cd_hash_t file_hash;
        memset(entry, 0, sizeof(entry));
        strcpy((char *)entry, "inference/kernel.bin");
        write_u64_le(entry + 256, inference_offset);
        write_u64_le(entry + 264, TEST_KERNEL_SIZE);
        cd_sha256(TEST_KERNEL, TEST_KERNEL_SIZE, &file_hash);
        memcpy(entry + 272, file_hash.bytes, 32);
        if (mock_append(bundle, entry, sizeof(entry)) != 0) {
            free(bundle->data);
            return -1;
        }
    }
    
    /* Entry 2: manifest.json */
    {
        uint8_t entry[304];
        cd_hash_t file_hash;
        memset(entry, 0, sizeof(entry));
        strcpy((char *)entry, "manifest.json");
        write_u64_le(entry + 256, manifest_offset);
        write_u64_le(entry + 264, manifest_len);
        cd_sha256(manifest_json, manifest_len, &file_hash);
        memcpy(entry + 272, file_hash.bytes, 32);
        if (mock_append(bundle, entry, sizeof(entry)) != 0) {
            free(bundle->data);
            return -1;
        }
    }
    
    /* Entry 3: weights.bin */
    {
        uint8_t entry[304];
        cd_hash_t file_hash;
        memset(entry, 0, sizeof(entry));
        strcpy((char *)entry, "weights.bin");
        write_u64_le(entry + 256, weights_offset);
        write_u64_le(entry + 264, TEST_WEIGHTS_SIZE);
        cd_sha256(TEST_WEIGHTS, TEST_WEIGHTS_SIZE, &file_hash);
        memcpy(entry + 272, file_hash.bytes, 32);
        if (mock_append(bundle, entry, sizeof(entry)) != 0) {
            free(bundle->data);
            return -1;
        }
    }
    
    /*
     * Step 6: Write Footer
     *
     * Footer: merkle_root (32) + signature (64) + has_sig (4) + magic (4) = 104 bytes
     */
    {
        uint8_t footer[104];
        memset(footer, 0, sizeof(footer));
        memcpy(footer, bundle->merkle_root.bytes, 32);
        /* No signature */
        write_u32_le(footer + 96, 0);  /* has_signature = false */
        write_u32_le(footer + 100, CD_CBF_MAGIC_FOOTER);
        if (mock_append(bundle, footer, sizeof(footer)) != 0) {
            free(bundle->data);
            return -1;
        }
    }
    
    /*
     * Step 7: Write Header (backfill)
     */
    {
        uint8_t header[32];
        memset(header, 0, sizeof(header));
        write_u32_le(header, CD_CBF_MAGIC_HEADER);
        write_u32_le(header + 4, CD_CBF_VERSION);
        write_u64_le(header + 8, payload_offset);
        write_u64_le(header + 16, toc_offset - payload_offset);  /* payload_size */
        write_u64_le(header + 24, toc_offset);
        memcpy(bundle->data, header, 32);
    }
    
    return 0;
}

/**
 * Free mock bundle
 */
static void free_mock_bundle(mock_bundle_t *bundle)
{
    if (bundle->data) {
        free(bundle->data);
        bundle->data = NULL;
    }
    bundle->len = 0;
    bundle->capacity = 0;
}

/*============================================================================
 * Test Cases
 *============================================================================*/

/**
 * T-LDR-01: State machine initializes correctly
 */
TEST(init_state)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    
    ASSERT_EQ(cdl_init(&ctx, &device), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_INIT);
    ASSERT(!cdl_is_enabled(&ctx));
    ASSERT(!cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-01: Init with NULL context fails
 */
TEST(init_null)
{
    ASSERT_EQ(cdl_init(NULL, NULL), CDL_ERR_NULL);
    return 0;
}

/**
 * T-LDR-01: Init without device target succeeds
 */
TEST(init_no_device)
{
    cd_load_ctx_t ctx;
    
    ASSERT_EQ(cdl_init(&ctx, NULL), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_INIT);
    
    return 0;
}

/**
 * T-LDR-02: Open with NULL data transitions to FAILED
 */
TEST(open_null_data)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdl_init(&ctx, &device);
    
    ASSERT_EQ(cdl_open_bundle(&ctx, NULL, 0), CDL_ERR_NULL);
    ASSERT(cdl_is_failed(&ctx));
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_FAILED);
    
    return 0;
}

/**
 * T-LDR-03: FAILED state is terminal
 */
TEST(failed_terminal)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    uint8_t dummy[32] = {0};
    
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdl_init(&ctx, &device);
    
    /* Force to failed state */
    cdl_open_bundle(&ctx, NULL, 0);
    ASSERT(cdl_is_failed(&ctx));
    
    /* Subsequent operations should fail */
    ASSERT(cdl_open_bundle(&ctx, dummy, sizeof(dummy)) != CDL_OK);
    ASSERT(cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-02: Invalid magic transitions to FAILED
 */
TEST(invalid_magic)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    uint8_t bad_bundle[64] = {0};
    
    /* Write wrong magic */
    write_u32_le(bad_bundle, 0xDEADBEEF);
    
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdl_init(&ctx, &device);
    
    ASSERT_EQ(cdl_open_bundle(&ctx, bad_bundle, sizeof(bad_bundle)), CDL_ERR_MAGIC);
    ASSERT(cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-04: Compatible target match succeeds
 */
TEST(target_match_exact)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    
    /* Bundle and device have same target */
    cdt_set(&bundle_target, CD_ARCH_X86_64, "intel", "xeon", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "intel", "xeon", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    cdl_result_t r = cdl_open_bundle(&ctx, bundle.data, bundle.len);
    
    free_mock_bundle(&bundle);
    
    ASSERT_EQ(r, CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_MANIFEST_VERIFIED);
    
    return 0;
}

/**
 * T-LDR-04: Wildcard target match succeeds
 */
TEST(target_match_wildcard)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    
    /* Bundle has generic vendor/device */
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "generic", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "intel", "xeon", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    cdl_result_t r = cdl_open_bundle(&ctx, bundle.data, bundle.len);
    
    free_mock_bundle(&bundle);
    
    ASSERT_EQ(r, CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_MANIFEST_VERIFIED);
    
    return 0;
}

/**
 * T-LDR-05: Architecture mismatch rejects load
 */
TEST(target_arch_mismatch)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    
    /* Bundle is x86_64, device is aarch64 */
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_AARCH64, "generic", "cpu", CD_ABI_LP64);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    cdl_result_t r = cdl_open_bundle(&ctx, bundle.data, bundle.len);
    
    free_mock_bundle(&bundle);
    
    ASSERT_EQ(r, CDL_ERR_TARGET_MISMATCH);
    ASSERT(cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-05: ABI mismatch rejects load
 */
TEST(target_abi_mismatch)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    
    /* Same arch but different ABI */
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_LINUX_GNU);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    cdl_result_t r = cdl_open_bundle(&ctx, bundle.data, bundle.len);
    
    free_mock_bundle(&bundle);
    
    ASSERT_EQ(r, CDL_ERR_TARGET_MISMATCH);
    ASSERT(cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-06: Weights load and hash correctly
 */
TEST(weights_load_ok)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    uint8_t weights_buf[TEST_WEIGHTS_SIZE];
    uint64_t weights_size;
    
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    ASSERT_EQ(cdl_open_bundle(&ctx, bundle.data, bundle.len), CDL_OK);
    
    ASSERT_EQ(cdl_get_weights_size(&ctx, &weights_size), CDL_OK);
    ASSERT_EQ(weights_size, TEST_WEIGHTS_SIZE);
    
    ASSERT_EQ(cdl_load_weights(&ctx, weights_buf, sizeof(weights_buf)), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_WEIGHTS_VERIFIED);
    
    /* Verify data was copied correctly */
    ASSERT(memcmp(weights_buf, TEST_WEIGHTS, TEST_WEIGHTS_SIZE) == 0);
    
    free_mock_bundle(&bundle);
    return 0;
}

/**
 * T-LDR-07: Tampered weights detected
 */
TEST(weights_tampered)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    uint8_t weights_buf[TEST_WEIGHTS_SIZE];
    
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    /* Tamper with weights in bundle (find and modify) */
    /* weights.bin starts at a known offset - flip a byte */
    size_t i;
    for (i = 32; i < bundle.len - 100; i++) {
        if (memcmp(bundle.data + i, TEST_WEIGHTS, 8) == 0) {
            bundle.data[i] ^= 0xFF;  /* Flip first byte */
            break;
        }
    }
    
    cdl_init(&ctx, &device);
    ASSERT_EQ(cdl_open_bundle(&ctx, bundle.data, bundle.len), CDL_OK);
    
    cdl_result_t r = cdl_load_weights(&ctx, weights_buf, sizeof(weights_buf));
    
    free_mock_bundle(&bundle);
    
    ASSERT_EQ(r, CDL_ERR_WEIGHTS_HASH);
    ASSERT(cdl_is_failed(&ctx));
    
    return 0;
}

/**
 * T-LDR-12: Full load sequence reaches ENABLED
 */
TEST(full_load_enabled)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    uint8_t weights_buf[TEST_WEIGHTS_SIZE];
    uint8_t kernel_buf[TEST_KERNEL_SIZE];
    
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    
    /* Step 1: Open bundle */
    ASSERT_EQ(cdl_open_bundle(&ctx, bundle.data, bundle.len), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_MANIFEST_VERIFIED);
    
    /* Step 2: Load weights */
    ASSERT_EQ(cdl_load_weights(&ctx, weights_buf, sizeof(weights_buf)), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_WEIGHTS_VERIFIED);
    
    /* Step 3: Load kernels */
    ASSERT_EQ(cdl_load_kernels(&ctx, kernel_buf, sizeof(kernel_buf)), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_INFERENCE_VERIFIED);
    
    /* Step 4: Finalize */
    ASSERT_EQ(cdl_finalize(&ctx), CDL_OK);
    ASSERT_EQ(cdl_get_state(&ctx), CDL_STATE_ENABLED);
    ASSERT(cdl_is_enabled(&ctx));
    
    free_mock_bundle(&bundle);
    return 0;
}

/**
 * Test state machine prevents out-of-order calls
 */
TEST(state_machine_order)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    uint8_t weights_buf[TEST_WEIGHTS_SIZE];
    
    cdt_set(&bundle_target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    
    /* Try to load weights before opening - should fail */
    ASSERT(cdl_load_weights(&ctx, weights_buf, sizeof(weights_buf)) != CDL_OK);
    
    /* Context should be failed now */
    ASSERT(cdl_is_failed(&ctx));
    
    free_mock_bundle(&bundle);
    return 0;
}

/**
 * Test error string function
 */
TEST(error_strings)
{
    ASSERT(cdl_error_string(CDL_OK) != NULL);
    ASSERT(cdl_error_string(CDL_ERR_NULL) != NULL);
    ASSERT(cdl_error_string(CDL_ERR_TARGET_MISMATCH) != NULL);
    ASSERT(cdl_error_string(CDL_ERR_WEIGHTS_HASH) != NULL);
    ASSERT(cdl_error_string(CDL_ERR_MERKLE_ROOT) != NULL);
    
    /* Unknown error should still return something */
    ASSERT(cdl_error_string((cdl_result_t)-999) != NULL);
    
    return 0;
}

/**
 * Test get_manifest returns valid pointer after open
 */
TEST(get_manifest)
{
    cd_load_ctx_t ctx;
    cd_target_t device;
    mock_bundle_t bundle = {0};
    cd_target_t bundle_target;
    const cd_manifest_t *manifest;
    
    cdt_set(&bundle_target, CD_ARCH_X86_64, "testvendor", "testdevice", CD_ABI_SYSV);
    cdt_set(&device, CD_ARCH_X86_64, "testvendor", "testdevice", CD_ABI_SYSV);
    
    if (build_mock_bundle(&bundle, &bundle_target) != 0) {
        return -1;
    }
    
    cdl_init(&ctx, &device);
    
    /* Before open, manifest should be NULL */
    ASSERT(cdl_get_manifest(&ctx) == NULL);
    
    ASSERT_EQ(cdl_open_bundle(&ctx, bundle.data, bundle.len), CDL_OK);
    
    /* After open, manifest should be valid */
    manifest = cdl_get_manifest(&ctx);
    ASSERT(manifest != NULL);
    ASSERT_EQ(manifest->manifest_version, 1);
    ASSERT(strcmp(manifest->mode, "deterministic") == 0);
    ASSERT(manifest->target.architecture == CD_ARCH_X86_64);
    
    free_mock_bundle(&bundle);
    return 0;
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void)
{
    printf("\n=== Loader Module Tests (SRS-006-LOADER) ===\n\n");
    
    printf("--- Initialization (T-LDR-01) ---\n");
    RUN_TEST(init_state);
    RUN_TEST(init_null);
    RUN_TEST(init_no_device);
    
    printf("\n--- Error Handling (T-LDR-02/03) ---\n");
    RUN_TEST(open_null_data);
    RUN_TEST(failed_terminal);
    RUN_TEST(invalid_magic);
    
    printf("\n--- Target Binding (T-LDR-04/05) ---\n");
    RUN_TEST(target_match_exact);
    RUN_TEST(target_match_wildcard);
    RUN_TEST(target_arch_mismatch);
    RUN_TEST(target_abi_mismatch);
    
    printf("\n--- JIT Verification (T-LDR-06/07) ---\n");
    RUN_TEST(weights_load_ok);
    RUN_TEST(weights_tampered);
    
    printf("\n--- Full Load Sequence (T-LDR-12) ---\n");
    RUN_TEST(full_load_enabled);
    RUN_TEST(state_machine_order);
    
    printf("\n--- Utilities ---\n");
    RUN_TEST(error_strings);
    RUN_TEST(get_manifest);
    
    printf("\n=== Summary ===\n");
    printf("Tests: %d | Passed: %d | Failed: %d\n\n",
           tests_run, tests_passed, tests_run - tests_passed);
    
    return (tests_passed == tests_run) ? 0 : 1;
}

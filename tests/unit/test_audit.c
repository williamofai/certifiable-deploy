/**
 * @file test_audit.c
 * @brief Unit tests for SHA-256 and domain-separated hashing
 * @traceability SRS-002-ATTEST FR-ATT-05, CD-MATH-001 §1
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 */

#include "../../include/cd_types.h"
#include "../../include/cd_audit.h"
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

static void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + (i * 2), "%02x", &val);
        bytes[i] = (uint8_t)val;
    }
}

TEST(sha256_empty) {
    cd_hash_t hash;
    uint8_t expected[32];
    hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expected, 32);
    cd_sha256("", 0, &hash);
    ASSERT_TRUE(memcmp(hash.bytes, expected, 32) == 0);
}

TEST(sha256_abc) {
    cd_hash_t hash;
    uint8_t expected[32];
    hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expected, 32);
    cd_sha256("abc", 3, &hash);
    ASSERT_TRUE(memcmp(hash.bytes, expected, 32) == 0);
}

TEST(sha256_448_bits) {
    cd_hash_t hash;
    uint8_t expected[32];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", expected, 32);
    cd_sha256(msg, strlen(msg), &hash);
    ASSERT_TRUE(memcmp(hash.bytes, expected, 32) == 0);
}

TEST(sha256_streaming) {
    cd_sha256_ctx_t ctx;
    cd_hash_t hash1, hash2;
    cd_sha256("hello world", 11, &hash1);
    cd_sha256_init(&ctx);
    cd_sha256_update(&ctx, "hello", 5);
    cd_sha256_update(&ctx, " ", 1);
    cd_sha256_update(&ctx, "world", 5);
    cd_sha256_final(&ctx, &hash2);
    ASSERT_TRUE(memcmp(hash1.bytes, hash2.bytes, 32) == 0);
}

TEST(sha256_streaming_byte_by_byte) {
    cd_sha256_ctx_t ctx;
    cd_hash_t hash1, hash2;
    const char *msg = "test message";
    size_t i;
    cd_sha256(msg, strlen(msg), &hash1);
    cd_sha256_init(&ctx);
    for (i = 0; i < strlen(msg); i++) {
        cd_sha256_update(&ctx, &msg[i], 1);
    }
    cd_sha256_final(&ctx, &hash2);
    ASSERT_TRUE(memcmp(hash1.bytes, hash2.bytes, 32) == 0);
}

TEST(sha256_large_update) {
    cd_sha256_ctx_t ctx;
    cd_hash_t hash;
    uint8_t block[1024];
    int i;
    memset(block, 'A', sizeof(block));
    cd_sha256_init(&ctx);
    for (i = 0; i < 100; i++) {
        cd_sha256_update(&ctx, block, sizeof(block));
    }
    cd_sha256_final(&ctx, &hash);
    ASSERT_TRUE(!cd_hash_is_zero(&hash));
}

TEST(domain_hash_basic) {
    cd_hash_t hash;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:TEST:v1", "payload", 7, &hash, &faults);
    ASSERT_TRUE(!cd_has_fault(&faults));
    ASSERT_TRUE(!cd_hash_is_zero(&hash));
}

TEST(domain_hash_deterministic) {
    cd_hash_t hash1, hash2;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:MANIFEST:v1", "test data", 9, &hash1, &faults);
    cd_domain_hash("CD:MANIFEST:v1", "test data", 9, &hash2, &faults);
    ASSERT_TRUE(cd_hash_equal(&hash1, &hash2));
}

TEST(domain_hash_different_tags) {
    cd_hash_t hash1, hash2;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:MANIFEST:v1", "data", 4, &hash1, &faults);
    cd_domain_hash("CD:WEIGHTS:v1", "data", 4, &hash2, &faults);
    ASSERT_TRUE(!cd_hash_equal(&hash1, &hash2));
}

TEST(domain_hash_different_lengths) {
    cd_hash_t hash1, hash2;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:TEST:v1", "data", 4, &hash1, &faults);
    cd_domain_hash("CD:TEST:v1", "data", 3, &hash2, &faults);
    ASSERT_TRUE(!cd_hash_equal(&hash1, &hash2));
}

TEST(domain_hash_empty_payload) {
    cd_hash_t hash;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:EMPTY:v1", NULL, 0, &hash, &faults);
    ASSERT_TRUE(!cd_has_fault(&faults));
    ASSERT_TRUE(!cd_hash_is_zero(&hash));
}

TEST(domain_hash_streaming) {
    cd_domain_hash_ctx_t ctx;
    cd_hash_t hash1, hash2;
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:TEST:v1", "hello world", 11, &hash1, &faults);
    cd_domain_hash_init(&ctx, "CD:TEST:v1", 11, &faults);
    cd_domain_hash_update(&ctx, "hello", 5, &faults);
    cd_domain_hash_update(&ctx, " ", 1, &faults);
    cd_domain_hash_update(&ctx, "world", 5, &faults);
    cd_domain_hash_final(&ctx, &hash2, &faults);
    ASSERT_TRUE(cd_hash_equal(&hash1, &hash2));
}

TEST(domain_hash_null_tag) {
    cd_hash_t hash;
    cd_fault_flags_t faults = {0};
    cd_domain_hash(NULL, "data", 4, &hash, &faults);
    ASSERT_TRUE(faults.domain);
}

TEST(domain_hash_null_output) {
    cd_fault_flags_t faults = {0};
    cd_domain_hash("CD:TEST:v1", "data", 4, NULL, &faults);
    ASSERT_TRUE(faults.domain);
}

TEST(hash_equal) {
    cd_hash_t a, b;
    memset(a.bytes, 0xAA, CD_HASH_SIZE);
    memset(b.bytes, 0xAA, CD_HASH_SIZE);
    ASSERT_TRUE(cd_hash_equal(&a, &b));
    b.bytes[0] = 0xBB;
    ASSERT_TRUE(!cd_hash_equal(&a, &b));
}

TEST(hash_copy) {
    cd_hash_t src, dst;
    memset(src.bytes, 0x42, CD_HASH_SIZE);
    memset(dst.bytes, 0, CD_HASH_SIZE);
    cd_hash_copy(&dst, &src);
    ASSERT_TRUE(cd_hash_equal(&src, &dst));
}

TEST(hash_zero) {
    cd_hash_t h;
    memset(h.bytes, 0xFF, CD_HASH_SIZE);
    cd_hash_zero(&h);
    ASSERT_TRUE(cd_hash_is_zero(&h));
}

TEST(hash_is_zero) {
    cd_hash_t h;
    memset(h.bytes, 0, CD_HASH_SIZE);
    ASSERT_TRUE(cd_hash_is_zero(&h));
    h.bytes[15] = 1;
    ASSERT_TRUE(!cd_hash_is_zero(&h));
}

int main(void) {
    printf("\n=== test_audit ===\n\n");
    RUN_TEST(sha256_empty);
    RUN_TEST(sha256_abc);
    RUN_TEST(sha256_448_bits);
    RUN_TEST(sha256_streaming);
    RUN_TEST(sha256_streaming_byte_by_byte);
    RUN_TEST(sha256_large_update);
    RUN_TEST(domain_hash_basic);
    RUN_TEST(domain_hash_deterministic);
    RUN_TEST(domain_hash_different_tags);
    RUN_TEST(domain_hash_different_lengths);
    RUN_TEST(domain_hash_empty_payload);
    RUN_TEST(domain_hash_streaming);
    RUN_TEST(domain_hash_null_tag);
    RUN_TEST(domain_hash_null_output);
    RUN_TEST(hash_equal);
    RUN_TEST(hash_copy);
    RUN_TEST(hash_zero);
    RUN_TEST(hash_is_zero);
    printf("\n  Results: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

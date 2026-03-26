/**
 * @file test_manifest.c
 * @brief Comprehensive test suite for manifest module
 * @traceability SRS-004-MANIFEST §8
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 */

#include "cd_manifest.h"
#include "cd_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { printf("  FAIL: %s (line %d)\n", msg, __LINE__); tests_failed++; return 0; } \
    tests_passed++; \
} while(0)

#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define TEST_ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)
#define TEST_ASSERT_STR_EQ(a, b, msg) TEST_ASSERT(strcmp((a), (b)) == 0, msg)
#define RUN_TEST(fn) do { printf("Running %s...\n", #fn); if (fn()) printf("  PASS\n"); else printf("  FAILED\n"); } while(0)

static void make_test_hash(cd_hash_t *hash, uint8_t base) {
    for (int i = 0; i < CD_HASH_SIZE; i++) hash->bytes[i] = (uint8_t)(base + i);
}

static void make_test_target(cd_target_t *target) {
    target->architecture = CD_ARCH_RISCV64;
    strncpy(target->vendor, "tenstorrent", CD_MAX_VENDOR - 1);
    strncpy(target->device, "p150", CD_MAX_DEVICE - 1);
    target->abi = CD_ABI_LINUX_GNU;
}

static cdm_result_t make_test_builder(cdm_builder_t *builder) {
    cd_target_t target; cd_hash_t weights, certs, inference; cdm_result_t r;
    if ((r = cdm_builder_init(builder)) != CDM_OK) return r;
    if ((r = cdm_set_mode(builder, "deterministic")) != CDM_OK) return r;
    if ((r = cdm_set_created_at(builder, 0)) != CDM_OK) return r;
    make_test_target(&target);
    if ((r = cdm_set_target(builder, &target)) != CDM_OK) return r;
    make_test_hash(&weights, 0x02); if ((r = cdm_set_weights_hash(builder, &weights)) != CDM_OK) return r;
    make_test_hash(&certs, 0x03); if ((r = cdm_set_certs_hash(builder, &certs)) != CDM_OK) return r;
    make_test_hash(&inference, 0x04); if ((r = cdm_set_inference_hash(builder, &inference)) != CDM_OK) return r;
    return CDM_OK;
}

/* T-MAN-01: JCS string encoding */
static int test_jcs_string_basic(void) {
    uint8_t buf[256]; size_t len = sizeof(buf);
    TEST_ASSERT_EQ(cdm_jcs_write_string(buf, &len, "hello"), CDM_OK, "jcs_write_string");
    TEST_ASSERT_EQ(len, 7, "quoted string length");
    TEST_ASSERT(memcmp(buf, "\"hello\"", 7) == 0, "string content");
    return 1;
}

/* T-MAN-01: JCS string escaping */
static int test_jcs_string_escapes(void) {
    uint8_t buf[256]; size_t len;
    len = sizeof(buf); cdm_jcs_write_string(buf, &len, "a\"b");
    TEST_ASSERT(memcmp(buf, "\"a\\\"b\"", 6) == 0, "quote escape");
    len = sizeof(buf); cdm_jcs_write_string(buf, &len, "a\\b");
    TEST_ASSERT(memcmp(buf, "\"a\\\\b\"", 6) == 0, "backslash escape");
    len = sizeof(buf); cdm_jcs_write_string(buf, &len, "a\nb");
    TEST_ASSERT(memcmp(buf, "\"a\\nb\"", 6) == 0, "newline escape");
    return 1;
}

/* T-MAN-01: JCS integer formatting */
static int test_jcs_uint_basic(void) {
    uint8_t buf[64]; size_t len;
    len = sizeof(buf); cdm_jcs_write_uint(buf, &len, 0);
    TEST_ASSERT_EQ(len, 1, "uint 0 length"); TEST_ASSERT(buf[0] == '0', "uint 0");
    len = sizeof(buf); cdm_jcs_write_uint(buf, &len, 42);
    TEST_ASSERT(memcmp(buf, "42", 2) == 0, "uint 42");
    len = sizeof(buf); cdm_jcs_write_uint(buf, &len, CDM_MAX_TIMESTAMP);
    buf[len] = '\0'; TEST_ASSERT_STR_EQ((char*)buf, "4102444800", "max timestamp");
    return 1;
}

/* T-MAN-01: JCS hash formatting */
static int test_jcs_hash_basic(void) {
    uint8_t buf[128]; size_t len; cd_hash_t hash;
    memset(&hash, 0, sizeof(hash)); len = sizeof(buf);
    TEST_ASSERT_EQ(cdm_jcs_write_hash(buf, &len, &hash), CDM_OK, "hash zeros");
    TEST_ASSERT_EQ(len, 66, "hash length with quotes");
    len = 10; TEST_ASSERT_EQ(cdm_jcs_write_hash(buf, &len, &hash), CDM_ERR_BUFFER_TOO_SMALL, "buffer small");
    return 1;
}

/* T-MAN-03: Valid fields */
static int test_field_validation_valid(void) {
    TEST_ASSERT_EQ(cdm_validate_field("hello", 32), CDM_OK, "lowercase");
    TEST_ASSERT_EQ(cdm_validate_field("riscv64", 32), CDM_OK, "alphanumeric");
    TEST_ASSERT_EQ(cdm_validate_field("linux-gnu", 32), CDM_OK, "hyphen");
    TEST_ASSERT_EQ(cdm_validate_field("test_device", 32), CDM_OK, "underscore");
    return 1;
}

/* T-MAN-04: Invalid characters */
static int test_field_validation_invalid_chars(void) {
    TEST_ASSERT_EQ(cdm_validate_field("Hello", 32), CDM_ERR_INVALID_CHAR, "uppercase");
    TEST_ASSERT_EQ(cdm_validate_field("hello world", 32), CDM_ERR_INVALID_CHAR, "space");
    TEST_ASSERT_EQ(cdm_validate_field("", 32), CDM_ERR_INVALID_CHAR, "empty");
    return 1;
}

/* T-MAN-05: Oversized fields */
static int test_field_validation_oversized(void) {
    TEST_ASSERT_EQ(cdm_validate_field("abcdefghijklmnopq", 16), CDM_ERR_FIELD_TOO_LONG, "17 chars");
    return 1;
}

/* T-MAN-03: Valid targets */
static int test_target_valid(void) {
    cd_target_t target;
    make_test_target(&target);
    TEST_ASSERT_EQ(cdm_check_target(&target), CDM_OK, "valid target");
    return 1;
}

/* T-MAN-04: Invalid targets */
static int test_target_invalid(void) {
    cd_target_t target; make_test_target(&target);
    target.architecture = CD_ARCH_UNKNOWN;
    TEST_ASSERT_EQ(cdm_check_target(&target), CDM_ERR_INVALID_ARCH, "unknown arch");
    TEST_ASSERT_EQ(cdm_check_target(NULL), CDM_ERR_NULL, "NULL target");
    return 1;
}

/* Builder tests */
static int test_builder_init(void) {
    cdm_builder_t builder;
    TEST_ASSERT_EQ(cdm_builder_init(&builder), CDM_OK, "init");
    TEST_ASSERT_EQ(builder.state, CDM_STATE_CONFIGURING, "state");
    TEST_ASSERT_EQ(cdm_builder_init(NULL), CDM_ERR_NULL, "NULL");
    return 1;
}

/* T-MAN-08: Mode setting */
static int test_builder_mode(void) {
    cdm_builder_t builder; cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_mode(&builder, "deterministic"), CDM_OK, "deterministic");
    cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_mode(&builder, "audit"), CDM_OK, "audit");
    cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_mode(&builder, "invalid"), CDM_ERR_INVALID_MODE, "invalid");
    return 1;
}

/* T-MAN-09: Timestamp bounds */
static int test_builder_timestamp(void) {
    cdm_builder_t builder;
    cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_created_at(&builder, 0), CDM_OK, "ts 0");
    cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_created_at(&builder, CDM_MAX_TIMESTAMP), CDM_OK, "max ts");
    cdm_builder_init(&builder);
    TEST_ASSERT_EQ(cdm_set_created_at(&builder, CDM_MAX_TIMESTAMP + 1), CDM_ERR_INVALID_TIMESTAMP, "over max");
    return 1;
}

/* Full workflow */
static int test_builder_full_workflow(void) {
    cdm_builder_t builder; uint8_t json[2048]; size_t len;
    TEST_ASSERT_EQ(make_test_builder(&builder), CDM_OK, "setup");
    len = sizeof(json);
    TEST_ASSERT_EQ(cdm_finalize_jcs(&builder, json, &len), CDM_OK, "finalize");
    TEST_ASSERT(len > 0, "output length");
    TEST_ASSERT_EQ(json[0], '{', "starts with {");
    TEST_ASSERT_EQ(json[len-1], '}', "ends with }");
    TEST_ASSERT_EQ(builder.state, CDM_STATE_FINALIZED, "finalized state");
    return 1;
}

/* T-MAN-01: JCS key ordering */
static int test_jcs_key_ordering(void) {
    cdm_builder_t builder; uint8_t json[2048]; size_t len;
    make_test_builder(&builder); len = sizeof(json);
    cdm_finalize_jcs(&builder, json, &len);
    char *p_comp = strstr((char*)json, "\"components\"");
    char *p_created = strstr((char*)json, "\"created_at\"");
    char *p_ver = strstr((char*)json, "\"manifest_version\"");
    char *p_mode = strstr((char*)json, "\"mode\"");
    char *p_target = strstr((char*)json, "\"target\"");
    TEST_ASSERT(p_comp && p_created && p_ver && p_mode && p_target, "all keys");
    TEST_ASSERT(p_comp < p_created, "comp < created");
    TEST_ASSERT(p_created < p_ver, "created < version");
    TEST_ASSERT(p_ver < p_mode, "version < mode");
    TEST_ASSERT(p_mode < p_target, "mode < target");
    return 1;
}

/* T-MAN-06: Valid parsing */
static int test_parser_valid(void) {
    cdm_builder_t builder; uint8_t json[2048]; size_t len;
    cd_manifest_t parsed; cd_fault_flags_t faults = {0};
    make_test_builder(&builder); len = sizeof(json);
    cdm_finalize_jcs(&builder, json, &len);
    TEST_ASSERT_EQ(cdm_parse_lenient(json, len, &parsed, &faults), CDM_OK, "parse");
    TEST_ASSERT_EQ(parsed.manifest_version, CDM_VERSION, "version");
    TEST_ASSERT_STR_EQ(parsed.mode, "deterministic", "mode");
    return 1;
}

/* T-MAN-07: Invalid hex */
static int test_parser_invalid_hex(void) {
    cd_manifest_t parsed; cd_fault_flags_t faults = {0};
    const char *upper = "{\"components\":{\"certificates\":{\"digest\":\"0300000000000000000000000000000000000000000000000000000000000003\"},\"inference\":{\"digest\":\"0400000000000000000000000000000000000000000000000000000000000004\"},\"weights\":{\"digest\":\"02000000000000000000000000000000000000000000000000000000000000AB\"}},\"created_at\":0,\"manifest_version\":1,\"mode\":\"deterministic\",\"target\":{\"abi\":\"linux-gnu\",\"arch\":\"riscv64\",\"device\":\"p150\",\"vendor\":\"tenstorrent\"}}";
    TEST_ASSERT_EQ(cdm_parse_lenient((uint8_t*)upper, strlen(upper), &parsed, &faults), CDM_ERR_INVALID_DIGEST, "uppercase");
    return 1;
}

/* T-MAN-10: Invalid version */
static int test_parser_invalid_version(void) {
    cd_manifest_t parsed; cd_fault_flags_t faults = {0};
    const char *v2 = "{\"components\":{\"certificates\":{\"digest\":\"0300000000000000000000000000000000000000000000000000000000000003\"},\"inference\":{\"digest\":\"0400000000000000000000000000000000000000000000000000000000000004\"},\"weights\":{\"digest\":\"0200000000000000000000000000000000000000000000000000000000000002\"}},\"created_at\":0,\"manifest_version\":2,\"mode\":\"deterministic\",\"target\":{\"abi\":\"linux-gnu\",\"arch\":\"riscv64\",\"device\":\"p150\",\"vendor\":\"tenstorrent\"}}";
    TEST_ASSERT_EQ(cdm_parse_lenient((uint8_t*)v2, strlen(v2), &parsed, &faults), CDM_ERR_INVALID_VERSION, "v2");
    return 1;
}

/* T-MAN-11: Non-canonical */
static int test_parser_non_canonical(void) {
    cd_manifest_t parsed; cd_fault_flags_t faults = {0};
    const char *ws = "{ \"components\":{\"certificates\":{\"digest\":\"0300000000000000000000000000000000000000000000000000000000000003\"},\"inference\":{\"digest\":\"0400000000000000000000000000000000000000000000000000000000000004\"},\"weights\":{\"digest\":\"0200000000000000000000000000000000000000000000000000000000000002\"}},\"created_at\":0,\"manifest_version\":1,\"mode\":\"deterministic\",\"target\":{\"abi\":\"linux-gnu\",\"arch\":\"riscv64\",\"device\":\"p150\",\"vendor\":\"tenstorrent\"}}";
    TEST_ASSERT_EQ(cdm_parse((uint8_t*)ws, strlen(ws), &parsed, &faults), CDM_ERR_NON_CANONICAL, "whitespace");
    return 1;
}

/* Roundtrip test */
static int test_roundtrip(void) {
    cdm_builder_t builder; uint8_t json[2048]; size_t len;
    cd_manifest_t parsed; cd_fault_flags_t faults = {0};
    make_test_builder(&builder); len = sizeof(json);
    cdm_finalize_jcs(&builder, json, &len);
    TEST_ASSERT_EQ(cdm_parse(json, len, &parsed, &faults), CDM_OK, "parse");
    TEST_ASSERT(cdm_manifest_equal(&builder.manifest, &parsed), "equal");
    return 1;
}

/* Arch/ABI conversion */
static int test_conversions(void) {
    TEST_ASSERT_STR_EQ(cdm_arch_to_string(CD_ARCH_X86_64), "x86_64", "x86_64");
    TEST_ASSERT_STR_EQ(cdm_arch_to_string(CD_ARCH_RISCV64), "riscv64", "riscv64");
    TEST_ASSERT_EQ(cdm_string_to_arch("x86_64"), CD_ARCH_X86_64, "parse x86_64");
    TEST_ASSERT_STR_EQ(cdm_abi_to_string(CD_ABI_LINUX_GNU), "linux-gnu", "linux-gnu");
    TEST_ASSERT_EQ(cdm_string_to_abi("linux-gnu"), CD_ABI_LINUX_GNU, "parse linux-gnu");
    return 1;
}

int main(void) {
    printf("=== Manifest Module Tests (SRS-004-MANIFEST) ===\n\n");

    printf("--- JCS Primitives (T-MAN-01) ---\n");
    RUN_TEST(test_jcs_string_basic);
    RUN_TEST(test_jcs_string_escapes);
    RUN_TEST(test_jcs_uint_basic);
    RUN_TEST(test_jcs_hash_basic);

    printf("\n--- Field Validation (T-MAN-03/04/05) ---\n");
    RUN_TEST(test_field_validation_valid);
    RUN_TEST(test_field_validation_invalid_chars);
    RUN_TEST(test_field_validation_oversized);

    printf("\n--- Target Validation ---\n");
    RUN_TEST(test_target_valid);
    RUN_TEST(test_target_invalid);

    printf("\n--- Builder ---\n");
    RUN_TEST(test_builder_init);
    RUN_TEST(test_builder_mode);
    RUN_TEST(test_builder_timestamp);
    RUN_TEST(test_builder_full_workflow);

    printf("\n--- JCS Output (T-MAN-01/02) ---\n");
    RUN_TEST(test_jcs_key_ordering);

    printf("\n--- Parser (T-MAN-06/07/10/11) ---\n");
    RUN_TEST(test_parser_valid);
    RUN_TEST(test_parser_invalid_hex);
    RUN_TEST(test_parser_invalid_version);
    RUN_TEST(test_parser_non_canonical);
    RUN_TEST(test_roundtrip);

    printf("\n--- Conversions ---\n");
    RUN_TEST(test_conversions);

    printf("\n=== Summary ===\n");
    printf("Tests: %d | Passed: %d | Failed: %d\n", tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}

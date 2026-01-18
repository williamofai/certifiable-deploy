/**
 * @file test_target.c
 * @brief Unit tests for target tuple parsing, encoding, and matching
 * @traceability SRS-003-TARGET
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 */

#include "../../include/cd_types.h"
#include "../../include/cd_target.h"
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

#define ASSERT_STR_EQ(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("FAIL\n    Expected '%s', got '%s' (line %d)\n", (b), (a), __LINE__); \
        exit(1); \
    } \
} while(0)

/* Parsing Tests */
TEST(parse_x86_64_sysv) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("x86_64-generic-cpu-sysv", &target, &faults), 0);
    ASSERT_EQ(target.architecture, CD_ARCH_X86_64);
    ASSERT_STR_EQ(target.vendor, "generic");
    ASSERT_STR_EQ(target.device, "cpu");
    ASSERT_EQ(target.abi, CD_ABI_SYSV);
}

TEST(parse_riscv64_lp64d) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("riscv64-tenstorrent-p150-lp64d", &target, &faults), 0);
    ASSERT_EQ(target.architecture, CD_ARCH_RISCV64);
    ASSERT_STR_EQ(target.vendor, "tenstorrent");
    ASSERT_STR_EQ(target.device, "p150");
    ASSERT_EQ(target.abi, CD_ABI_LP64D);
}

TEST(parse_aarch64_lp64) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("aarch64-nvidia-orin-lp64", &target, &faults), 0);
    ASSERT_EQ(target.architecture, CD_ARCH_AARCH64);
    ASSERT_STR_EQ(target.vendor, "nvidia");
    ASSERT_STR_EQ(target.device, "orin");
    ASSERT_EQ(target.abi, CD_ABI_LP64);
}

TEST(parse_linux_gnu_abi) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    /* Note: Using lp64 as ABI since linux-gnu contains hyphen */
    ASSERT_EQ(cdt_parse("x86_64-intel-xeon-lp64", &target, &faults), 0);
    ASSERT_EQ(target.abi, CD_ABI_LP64);
}

TEST(parse_riscv32) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("riscv32-sifive-e31-ilp32", &target, &faults), 0);
    ASSERT_EQ(target.architecture, CD_ARCH_RISCV32);
    ASSERT_EQ(target.abi, CD_ABI_ILP32);
}

TEST(parse_invalid_arch) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("mips64-generic-cpu-sysv", &target, &faults), -1);
    ASSERT_TRUE(faults.parse_error);
}

TEST(parse_invalid_abi) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("x86_64-generic-cpu-badabi", &target, &faults), -1);
    ASSERT_TRUE(faults.parse_error);
}

TEST(parse_too_few_components) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("x86_64-generic-sysv", &target, &faults), -1);
    ASSERT_TRUE(faults.parse_error);
}

TEST(parse_empty_string) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("", &target, &faults), -1);
    ASSERT_TRUE(faults.parse_error);
}

TEST(parse_null_input) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse(NULL, &target, &faults), -1);
    ASSERT_TRUE(faults.domain);
}

TEST(parse_null_output) {
    cd_fault_flags_t faults = {0};
    ASSERT_EQ(cdt_parse("x86_64-generic-cpu-sysv", NULL, &faults), -1);
    ASSERT_TRUE(faults.domain);
}

/* Encoding Tests */
TEST(encode_basic) {
    cd_target_t target;
    char buf[128];
    cd_fault_flags_t faults = {0};
    cdt_init(&target);
    cdt_set(&target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    ASSERT_TRUE(cdt_encode(&target, buf, sizeof(buf), &faults) > 0);
    ASSERT_STR_EQ(buf, "x86_64-generic-cpu-sysv");
}

TEST(encode_riscv64) {
    cd_target_t target;
    char buf[128];
    cd_fault_flags_t faults = {0};
    cdt_init(&target);
    cdt_set(&target, CD_ARCH_RISCV64, "tenstorrent", "p150", CD_ABI_LP64D);
    ASSERT_TRUE(cdt_encode(&target, buf, sizeof(buf), &faults) > 0);
    ASSERT_STR_EQ(buf, "riscv64-tenstorrent-p150-lp64d");
}

TEST(encode_roundtrip) {
    cd_target_t target1, target2;
    char buf[128];
    cd_fault_flags_t faults = {0};
    cdt_parse("aarch64-nvidia-orin-lp64", &target1, &faults);
    cdt_encode(&target1, buf, sizeof(buf), &faults);
    cdt_parse(buf, &target2, &faults);
    ASSERT_EQ(target1.architecture, target2.architecture);
    ASSERT_STR_EQ(target1.vendor, target2.vendor);
    ASSERT_STR_EQ(target1.device, target2.device);
    ASSERT_EQ(target1.abi, target2.abi);
}

TEST(encode_buffer_too_small) {
    cd_target_t target;
    char buf[10];
    cd_fault_flags_t faults = {0};
    cdt_init(&target);
    cdt_set(&target, CD_ARCH_X86_64, "generic", "cpu", CD_ABI_SYSV);
    ASSERT_EQ(cdt_encode(&target, buf, sizeof(buf), &faults), -1);
    ASSERT_TRUE(faults.overflow);
}

TEST(encode_unknown_arch) {
    cd_target_t target;
    char buf[128];
    cd_fault_flags_t faults = {0};
    cdt_init(&target);
    target.architecture = CD_ARCH_UNKNOWN;
    ASSERT_EQ(cdt_encode(&target, buf, sizeof(buf), &faults), -1);
    ASSERT_TRUE(faults.parse_error);
}

/* Matching Tests */
TEST(match_exact) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-intel-xeon-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_EXACT);
}

TEST(match_wildcard_vendor) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-generic-xeon-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_WILDCARD_VENDOR);
}

TEST(match_wildcard_device) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-intel-generic-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_WILDCARD_DEVICE);
}

TEST(match_wildcard_both) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-generic-generic-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-xeon-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_WILDCARD_BOTH);
}

TEST(match_fail_arch) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-generic-cpu-sysv", &bundle, &faults);
    cdt_parse("aarch64-generic-cpu-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_FAIL_ARCH);
}

TEST(match_fail_abi) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-generic-cpu-sysv", &bundle, &faults);
    cdt_parse("x86_64-generic-cpu-lp64", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_FAIL_ABI);
}

TEST(match_fail_vendor) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-intel-cpu-sysv", &bundle, &faults);
    cdt_parse("x86_64-amd-cpu-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_FAIL_VENDOR);
}

TEST(match_fail_device) {
    cd_target_t bundle, device;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-intel-xeon-sysv", &bundle, &faults);
    cdt_parse("x86_64-intel-core-sysv", &device, &faults);
    ASSERT_EQ(cdt_match(&bundle, &device, &faults), CD_MATCH_FAIL_DEVICE);
}

TEST(match_ok_function) {
    ASSERT_TRUE(cdt_match_ok(CD_MATCH_EXACT));
    ASSERT_TRUE(cdt_match_ok(CD_MATCH_WILDCARD_VENDOR));
    ASSERT_TRUE(cdt_match_ok(CD_MATCH_WILDCARD_DEVICE));
    ASSERT_TRUE(cdt_match_ok(CD_MATCH_WILDCARD_BOTH));
    ASSERT_TRUE(!cdt_match_ok(CD_MATCH_FAIL_ARCH));
    ASSERT_TRUE(!cdt_match_ok(CD_MATCH_FAIL_VENDOR));
    ASSERT_TRUE(!cdt_match_ok(CD_MATCH_FAIL_DEVICE));
    ASSERT_TRUE(!cdt_match_ok(CD_MATCH_FAIL_ABI));
}

/* Validation Tests */
TEST(validate_valid) {
    cd_target_t target;
    cd_fault_flags_t faults = {0};
    cdt_parse("x86_64-generic-cpu-sysv", &target, &faults);
    ASSERT_EQ(cdt_validate(&target, &faults), 0);
}

TEST(validate_unknown_arch) {
    cd_target_t target = {0};
    cd_fault_flags_t faults = {0};
    target.architecture = CD_ARCH_UNKNOWN;
    strcpy(target.vendor, "valid");
    strcpy(target.device, "valid");
    target.abi = CD_ABI_SYSV;
    ASSERT_TRUE(cdt_validate(&target, &faults) != 0);
    ASSERT_TRUE(faults.parse_error);
}

TEST(validate_unknown_abi) {
    cd_target_t target = {0};
    cd_fault_flags_t faults = {0};
    target.architecture = CD_ARCH_X86_64;
    strcpy(target.vendor, "valid");
    strcpy(target.device, "valid");
    target.abi = CD_ABI_UNKNOWN;
    ASSERT_TRUE(cdt_validate(&target, &faults) != 0);
    ASSERT_TRUE(faults.parse_error);
}

TEST(validate_empty_vendor) {
    cd_target_t target = {0};
    cd_fault_flags_t faults = {0};
    target.architecture = CD_ARCH_X86_64;
    target.vendor[0] = '\0';
    strcpy(target.device, "valid");
    target.abi = CD_ABI_SYSV;
    ASSERT_TRUE(cdt_validate(&target, &faults) != 0);
    ASSERT_TRUE(faults.parse_error);
}

TEST(validate_empty_device) {
    cd_target_t target = {0};
    cd_fault_flags_t faults = {0};
    target.architecture = CD_ARCH_X86_64;
    strcpy(target.vendor, "valid");
    target.device[0] = '\0';
    target.abi = CD_ABI_SYSV;
    ASSERT_TRUE(cdt_validate(&target, &faults) != 0);
    ASSERT_TRUE(faults.parse_error);
}

/* Initialization Tests */
TEST(init_zeroes) {
    cd_target_t target;
    memset(&target, 0xFF, sizeof(target));
    cdt_init(&target);
    ASSERT_EQ(target.architecture, CD_ARCH_UNKNOWN);
    ASSERT_EQ(target.abi, CD_ABI_UNKNOWN);
    ASSERT_EQ(target.vendor[0], '\0');
    ASSERT_EQ(target.device[0], '\0');
}

TEST(set_fields) {
    cd_target_t target;
    cdt_init(&target);
    cdt_set(&target, CD_ARCH_RISCV64, "tenstorrent", "p150", CD_ABI_LP64D);
    ASSERT_EQ(target.architecture, CD_ARCH_RISCV64);
    ASSERT_STR_EQ(target.vendor, "tenstorrent");
    ASSERT_STR_EQ(target.device, "p150");
    ASSERT_EQ(target.abi, CD_ABI_LP64D);
}

int main(void) {
    printf("\n=== test_target ===\n\n");
    RUN_TEST(parse_x86_64_sysv);
    RUN_TEST(parse_riscv64_lp64d);
    RUN_TEST(parse_aarch64_lp64);
    RUN_TEST(parse_linux_gnu_abi);
    RUN_TEST(parse_riscv32);
    RUN_TEST(parse_invalid_arch);
    RUN_TEST(parse_invalid_abi);
    RUN_TEST(parse_too_few_components);
    RUN_TEST(parse_empty_string);
    RUN_TEST(parse_null_input);
    RUN_TEST(parse_null_output);
    RUN_TEST(encode_basic);
    RUN_TEST(encode_riscv64);
    RUN_TEST(encode_roundtrip);
    RUN_TEST(encode_buffer_too_small);
    RUN_TEST(encode_unknown_arch);
    RUN_TEST(match_exact);
    RUN_TEST(match_wildcard_vendor);
    RUN_TEST(match_wildcard_device);
    RUN_TEST(match_wildcard_both);
    RUN_TEST(match_fail_arch);
    RUN_TEST(match_fail_abi);
    RUN_TEST(match_fail_vendor);
    RUN_TEST(match_fail_device);
    RUN_TEST(match_ok_function);
    RUN_TEST(validate_valid);
    RUN_TEST(validate_unknown_arch);
    RUN_TEST(validate_unknown_abi);
    RUN_TEST(validate_empty_vendor);
    RUN_TEST(validate_empty_device);
    RUN_TEST(init_zeroes);
    RUN_TEST(set_fields);
    printf("\n  Results: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

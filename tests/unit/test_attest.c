/**
 * @file test_attest.c
 * @brief Unit tests for Merkle tree and attestation
 * @traceability SRS-002-ATTEST §8, FR-ATT-01 through FR-ATT-04
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 */

#include "../../include/cd_types.h"
#include "../../include/cd_audit.h"
#include "../../include/cd_attest.h"
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

static void make_test_hash(cd_hash_t *h, uint8_t seed) {
    int i;
    for (i = 0; i < CD_HASH_SIZE; i++) {
        h->bytes[i] = (uint8_t)(seed + i);
    }
}

TEST(merkle_init) {
    cd_merkle_tree_t tree;
    cd_merkle_init(&tree);
    ASSERT_TRUE(!tree.valid);
}

TEST(merkle_set_leaves_basic) {
    cd_merkle_tree_t tree;
    cd_hash_t h_m, h_w, h_c, h_i;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_merkle_init(&tree);
    cd_merkle_set_leaves(&tree, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(!cd_has_fault(&faults));
    ASSERT_TRUE(tree.valid);
    ASSERT_TRUE(!cd_hash_is_zero(&tree.root));
}

TEST(merkle_deterministic) {
    cd_merkle_tree_t tree1, tree2;
    cd_hash_t h_m, h_w, h_c, h_i;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_merkle_init(&tree1);
    cd_merkle_init(&tree2);
    cd_merkle_set_leaves(&tree1, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_merkle_set_leaves(&tree2, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(cd_hash_equal(&tree1.root, &tree2.root));
}

TEST(merkle_different_inputs) {
    cd_merkle_tree_t tree1, tree2;
    cd_hash_t h_m1, h_m2, h_w, h_c, h_i;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m1, 0x10);
    make_test_hash(&h_m2, 0x11);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_merkle_init(&tree1);
    cd_merkle_init(&tree2);
    cd_merkle_set_leaves(&tree1, &h_m1, &h_w, &h_c, &h_i, &faults);
    cd_merkle_set_leaves(&tree2, &h_m2, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(!cd_hash_equal(&tree1.root, &tree2.root));
}

TEST(merkle_verify_root_correct) {
    cd_merkle_tree_t tree;
    cd_hash_t h_m, h_w, h_c, h_i, expected;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_merkle_init(&tree);
    cd_merkle_set_leaves(&tree, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_hash_copy(&expected, &tree.root);
    ASSERT_TRUE(cd_merkle_verify_root(&tree, &expected));
}

TEST(merkle_verify_root_wrong) {
    cd_merkle_tree_t tree;
    cd_hash_t h_m, h_w, h_c, h_i, wrong;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    make_test_hash(&wrong, 0xFF);
    cd_merkle_init(&tree);
    cd_merkle_set_leaves(&tree, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(!cd_merkle_verify_root(&tree, &wrong));
}

TEST(merkle_get_root) {
    cd_merkle_tree_t tree;
    cd_hash_t h_m, h_w, h_c, h_i, root_out;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_merkle_init(&tree);
    cd_merkle_set_leaves(&tree, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(cd_merkle_get_root(&tree, &root_out));
    ASSERT_TRUE(cd_hash_equal(&root_out, &tree.root));
}

TEST(merkle_get_root_invalid) {
    cd_merkle_tree_t tree;
    cd_hash_t root_out;
    cd_merkle_init(&tree);
    ASSERT_TRUE(!cd_merkle_get_root(&tree, &root_out));
}

TEST(merkle_null_tree) {
    cd_hash_t h;
    make_test_hash(&h, 0x10);
    ASSERT_TRUE(!cd_merkle_verify_root(NULL, &h));
    ASSERT_TRUE(!cd_merkle_get_root(NULL, &h));
}

TEST(attestation_init) {
    cd_attestation_t attest;
    cd_attestation_init(&attest);
    ASSERT_TRUE(!attest.has_signature);
    ASSERT_TRUE(!attest.tree.valid);
}

TEST(attestation_set_hashes) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(!cd_has_fault(&faults));
    ASSERT_TRUE(attest.tree.valid);
}

TEST(attestation_get_root) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i, root;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(cd_attestation_get_root(&attest, &root));
    ASSERT_TRUE(!cd_hash_is_zero(&root));
}

TEST(attestation_verify_correct) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i, expected;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_get_root(&attest, &expected);
    ASSERT_TRUE(cd_attestation_verify(&attest, &expected));
}

TEST(attestation_verify_wrong) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i, wrong;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    make_test_hash(&wrong, 0xFF);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(!cd_attestation_verify(&attest, &wrong));
}

TEST(attestation_deterministic) {
    cd_attestation_t attest1, attest2;
    cd_hash_t h_m, h_w, h_c, h_i, root1, root2;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest1);
    cd_attestation_init(&attest2);
    cd_attestation_set_hashes(&attest1, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_set_hashes(&attest2, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_get_root(&attest1, &root1);
    cd_attestation_get_root(&attest2, &root2);
    ASSERT_TRUE(cd_hash_equal(&root1, &root2));
}

TEST(attestation_compute) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i, root1, root2;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    cd_attestation_get_root(&attest, &root1);
    cd_attestation_compute(&attest, &faults);
    cd_attestation_get_root(&attest, &root2);
    ASSERT_TRUE(cd_hash_equal(&root1, &root2));
}

TEST(attestation_null) {
    cd_hash_t h;
    make_test_hash(&h, 0x10);
    ASSERT_TRUE(!cd_attestation_get_root(NULL, &h));
    ASSERT_TRUE(!cd_attestation_verify(NULL, &h));
}

TEST(attestation_stores_hashes) {
    cd_attestation_t attest;
    cd_hash_t h_m, h_w, h_c, h_i;
    cd_fault_flags_t faults = {0};
    make_test_hash(&h_m, 0x10);
    make_test_hash(&h_w, 0x20);
    make_test_hash(&h_c, 0x30);
    make_test_hash(&h_i, 0x40);
    cd_attestation_init(&attest);
    cd_attestation_set_hashes(&attest, &h_m, &h_w, &h_c, &h_i, &faults);
    ASSERT_TRUE(cd_hash_equal(&attest.h_manifest, &h_m));
    ASSERT_TRUE(cd_hash_equal(&attest.h_weights, &h_w));
    ASSERT_TRUE(cd_hash_equal(&attest.h_certs, &h_c));
    ASSERT_TRUE(cd_hash_equal(&attest.h_inference, &h_i));
}

int main(void) {
    printf("\n=== test_attest ===\n\n");
    RUN_TEST(merkle_init);
    RUN_TEST(merkle_set_leaves_basic);
    RUN_TEST(merkle_deterministic);
    RUN_TEST(merkle_different_inputs);
    RUN_TEST(merkle_verify_root_correct);
    RUN_TEST(merkle_verify_root_wrong);
    RUN_TEST(merkle_get_root);
    RUN_TEST(merkle_get_root_invalid);
    RUN_TEST(merkle_null_tree);
    RUN_TEST(attestation_init);
    RUN_TEST(attestation_set_hashes);
    RUN_TEST(attestation_get_root);
    RUN_TEST(attestation_verify_correct);
    RUN_TEST(attestation_verify_wrong);
    RUN_TEST(attestation_deterministic);
    RUN_TEST(attestation_compute);
    RUN_TEST(attestation_null);
    RUN_TEST(attestation_stores_hashes);
    printf("\n  Results: %d/%d passed\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}

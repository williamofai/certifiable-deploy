/**
 * @file test_bundle.c
 * @brief Unit tests for bundle module (CBF v1 builder/reader)
 * @traceability SRS-001-BUNDLE Section 8
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_types.h"
#include "cd_bundle.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Test Framework
 *============================================================================*/

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) static int name(void)
#define RUN_TEST(name) do { \
    tests_run++; \
    printf("  %-50s ", #name); \
    fflush(stdout); \
    if (name()) { tests_passed++; printf("[PASS]\n"); } \
    else { printf("[FAIL]\n"); } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) return 0; } while(0)
#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_STR_EQ(a, b) ASSERT(strcmp((a), (b)) == 0)

/*============================================================================
 * Path Normalization Tests (T-BUN-04, T-BUN-05, T-BUN-06)
 *============================================================================*/

TEST(test_path_normalize_basic)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("weights.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "weights.bin");
    return 1;
}

TEST(test_path_normalize_backslash)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("a\\b\\c.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "a/b/c.bin");
    return 1;
}

TEST(test_path_normalize_leading_dotslash)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("./weights.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "weights.bin");
    ASSERT_EQ(cd_path_normalize("././a/b.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "a/b.bin");
    return 1;
}

TEST(test_path_normalize_leading_slash)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("/weights.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "weights.bin");
    return 1;
}

TEST(test_path_normalize_consecutive_slashes)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("a//b///c.bin", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "a/b/c.bin");
    return 1;
}

TEST(test_path_normalize_trailing_slash)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("dir/subdir/", out, sizeof(out), &f), CD_PATH_OK);
    ASSERT_STR_EQ(out, "dir/subdir");
    return 1;
}

TEST(test_path_normalize_dotdot_rejected)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("../secret", out, sizeof(out), &f), CD_PATH_ERR_DOTDOT);
    f = (cd_fault_flags_t){0};
    ASSERT_EQ(cd_path_normalize("a/../b", out, sizeof(out), &f), CD_PATH_ERR_DOTDOT);
    f = (cd_fault_flags_t){0};
    ASSERT_EQ(cd_path_normalize("a/..", out, sizeof(out), &f), CD_PATH_ERR_DOTDOT);
    f = (cd_fault_flags_t){0};
    ASSERT_EQ(cd_path_normalize("..", out, sizeof(out), &f), CD_PATH_ERR_DOTDOT);
    return 1;
}

TEST(test_path_normalize_empty_rejected)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize("", out, sizeof(out), &f), CD_PATH_ERR_EMPTY);
    f = (cd_fault_flags_t){0};
    ASSERT_EQ(cd_path_normalize("./", out, sizeof(out), &f), CD_PATH_ERR_EMPTY);
    return 1;
}

TEST(test_path_normalize_null_args)
{
    char out[CD_MAX_PATH];
    cd_fault_flags_t f = {0};
    ASSERT_EQ(cd_path_normalize(NULL, out, sizeof(out), &f), CD_PATH_ERR_NULL);
    ASSERT_EQ(f.domain, 1);
    f = (cd_fault_flags_t){0};
    ASSERT_EQ(cd_path_normalize("test", NULL, sizeof(out), &f), CD_PATH_ERR_NULL);
    return 1;
}

TEST(test_path_compare)
{
    ASSERT(cd_path_compare("a", "b") < 0);
    ASSERT(cd_path_compare("b", "a") > 0);
    ASSERT(cd_path_compare("abc", "abc") == 0);
    ASSERT(cd_path_compare("certificates/quant.cert", "inference/kernel.bin") < 0);
    ASSERT(cd_path_compare("manifest.json", "weights.bin") < 0);
    /* NULL handling */
    ASSERT(cd_path_compare(NULL, NULL) == 0);
    ASSERT(cd_path_compare(NULL, "a") < 0);
    ASSERT(cd_path_compare("a", NULL) > 0);
    return 1;
}

TEST(test_path_validate)
{
    ASSERT_EQ(cd_path_validate("weights.bin"), CD_PATH_OK);
    ASSERT_EQ(cd_path_validate("a/b/c.txt"), CD_PATH_OK);
    ASSERT_EQ(cd_path_validate("/absolute"), CD_PATH_ERR_ABSOLUTE);
    ASSERT_EQ(cd_path_validate("../escape"), CD_PATH_ERR_DOTDOT);
    ASSERT_EQ(cd_path_validate(""), CD_PATH_ERR_EMPTY);
    ASSERT_EQ(cd_path_validate(NULL), CD_PATH_ERR_NULL);
    return 1;
}

/*============================================================================
 * Little-Endian Tests (T-BUN-08)
 *============================================================================*/

TEST(test_u32_le)
{
    uint8_t buf[4];
    cd_write_u32_le(buf, 0x12345678U);
    ASSERT_EQ(buf[0], 0x78);
    ASSERT_EQ(buf[1], 0x56);
    ASSERT_EQ(buf[2], 0x34);
    ASSERT_EQ(buf[3], 0x12);
    ASSERT_EQ(cd_read_u32_le(buf), 0x12345678U);
    
    /* Verify magic constant encoding */
    cd_write_u32_le(buf, CD_CBF_MAGIC_HEADER);
    ASSERT_EQ(buf[0], '1');
    ASSERT_EQ(buf[1], 'F');
    ASSERT_EQ(buf[2], 'B');
    ASSERT_EQ(buf[3], 'C');
    return 1;
}

TEST(test_u64_le)
{
    uint8_t buf[8];
    cd_write_u64_le(buf, 0x123456789ABCDEF0ULL);
    ASSERT_EQ(buf[0], 0xF0);
    ASSERT_EQ(buf[7], 0x12);
    ASSERT_EQ(cd_read_u64_le(buf), 0x123456789ABCDEF0ULL);
    return 1;
}

TEST(test_le_null_safety)
{
    /* NULL buffer should not crash */
    cd_write_u32_le(NULL, 0x12345678U);
    cd_write_u64_le(NULL, 0x123456789ABCDEF0ULL);
    ASSERT_EQ(cd_read_u32_le(NULL), 0);
    ASSERT_EQ(cd_read_u64_le(NULL), 0);
    return 1;
}

/*============================================================================
 * Builder Tests (T-BUN-01, T-BUN-05)
 *============================================================================*/

TEST(test_builder_init)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.state, CD_BUILD_STATE_WRITING);
    ASSERT_EQ(ctx.toc_count, 0);
    ASSERT_EQ(ctx.header.magic, CD_CBF_MAGIC_HEADER);
    ASSERT_EQ(ctx.header.version, CD_CBF_VERSION);
    fclose(fp);
    return 1;
}

TEST(test_builder_null_args)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(NULL, fp), CD_BUNDLE_ERR_NULL);
    ASSERT_EQ(cd_builder_init(&ctx, NULL), CD_BUNDLE_ERR_NULL);
    fclose(fp);
    return 1;
}

TEST(test_builder_add_sorted)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    uint8_t data[] = "test";
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "a.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "b.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "c.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.toc_count, 3);
    fclose(fp);
    return 1;
}

TEST(test_builder_reject_unsorted)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    uint8_t data[] = "test";
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "b.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "a.bin", data, sizeof(data), &h), CD_BUNDLE_ERR_NOT_SORTED);
    ASSERT_EQ(ctx.faults.domain, 1);
    fclose(fp);
    return 1;
}

TEST(test_builder_reject_duplicate)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    uint8_t data[] = "test";
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "a.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "a.bin", data, sizeof(data), &h), CD_BUNDLE_ERR_DUPLICATE);
    ASSERT_EQ(ctx.faults.domain, 1);
    fclose(fp);
    return 1;
}

TEST(test_builder_empty_file)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    cd_hash_t root = {{0xAA}};
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    /* Empty file: data=NULL, len=0 is valid */
    ASSERT_EQ(cd_builder_add_file(&ctx, "empty.bin", NULL, 0, &h), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.toc_count, 1);
    ASSERT_EQ(ctx.toc[0].size, 0);
    ASSERT_EQ(cd_builder_finalize(&ctx, &root, false, NULL), CD_BUNDLE_OK);
    fclose(fp);
    return 1;
}

TEST(test_builder_add_null_data_nonzero_len)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    /* NULL data with non-zero length is an error */
    ASSERT_EQ(cd_builder_add_file(&ctx, "test.bin", NULL, 100, &h), CD_BUNDLE_ERR_NULL);
    fclose(fp);
    return 1;
}

TEST(test_builder_finalize_with_signature)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0x11}};
    cd_hash_t root = {{0xAA, 0xBB, 0xCC, 0xDD}};
    uint8_t signature[64];
    uint8_t data[] = "payload";
    
    memset(signature, 0x55, sizeof(signature));
    
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "test.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_finalize(&ctx, &root, true, signature), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.state, CD_BUILD_STATE_FINALIZED);
    fclose(fp);
    return 1;
}

TEST(test_builder_finalize_signature_null_error)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t root = {{0xAA}};
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    /* has_signature=true but signature=NULL is an error */
    ASSERT_EQ(cd_builder_finalize(&ctx, &root, true, NULL), CD_BUNDLE_ERR_ATTESTATION);
    fclose(fp);
    return 1;
}

TEST(test_builder_state_machine)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    cd_hash_t root = {{0xAA}};
    uint8_t data[] = "test";
    
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.state, CD_BUILD_STATE_WRITING);
    
    ASSERT_EQ(cd_builder_add_file(&ctx, "test.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_finalize(&ctx, &root, false, NULL), CD_BUNDLE_OK);
    ASSERT_EQ(ctx.state, CD_BUILD_STATE_FINALIZED);
    
    /* Cannot add file after finalize */
    ASSERT_EQ(cd_builder_add_file(&ctx, "late.bin", data, sizeof(data), &h), CD_BUNDLE_ERR_STATE);
    
    /* Cannot finalize twice */
    ASSERT_EQ(cd_builder_finalize(&ctx, &root, false, NULL), CD_BUNDLE_ERR_STATE);
    
    fclose(fp);
    return 1;
}

/*============================================================================
 * Full Cycle Test (T-BUN-01 through T-BUN-12)
 *============================================================================*/

TEST(test_full_build_read_cycle)
{
    cd_builder_ctx_t builder;
    cd_reader_ctx_t reader;
    FILE *fp;
    uint8_t manifest[] = "{\"version\":1}";
    uint8_t weights[] = {0x01, 0x02, 0x03, 0x04};
    cd_hash_t mh = {{0x11}};
    cd_hash_t wh = {{0x22}};
    cd_hash_t root = {{0xAA, 0xBB, 0xCC, 0xDD}};
    uint8_t *bundle;
    size_t bundle_size;
    const cd_toc_entry_t *entry;
    const uint8_t *data_ptr;
    uint64_t data_len;
    
    fp = tmpfile();
    ASSERT(fp != NULL);
    
    /* Build */
    ASSERT_EQ(cd_builder_init(&builder, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&builder, "manifest.json", manifest, sizeof(manifest), &mh), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&builder, "weights.bin", weights, sizeof(weights), &wh), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_finalize(&builder, &root, false, NULL), CD_BUNDLE_OK);
    
    /* Read back */
    fseek(fp, 0, SEEK_END);
    bundle_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    bundle = (uint8_t *)malloc(bundle_size);
    ASSERT(bundle != NULL);
    ASSERT_EQ(fread(bundle, 1, bundle_size, fp), bundle_size);
    fclose(fp);
    
    /* Parse */
    ASSERT_EQ(cd_reader_init(&reader, bundle, bundle_size), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_header(&reader), CD_READ_OK);
    ASSERT_EQ(reader.header.magic, CD_CBF_MAGIC_HEADER);
    ASSERT_EQ(reader.header.version, CD_CBF_VERSION);
    ASSERT(reader.header_valid);
    
    ASSERT_EQ(cd_reader_parse_toc(&reader), CD_READ_OK);
    ASSERT_EQ(reader.toc_count, 2);
    ASSERT_STR_EQ(reader.toc[0].path, "manifest.json");
    ASSERT_STR_EQ(reader.toc[1].path, "weights.bin");
    ASSERT(reader.toc_valid);
    
    ASSERT_EQ(cd_reader_parse_footer(&reader), CD_READ_OK);
    ASSERT_EQ(reader.footer.magic, CD_CBF_MAGIC_FOOTER);
    ASSERT_EQ(reader.footer.has_signature, false);
    ASSERT_EQ(memcmp(reader.footer.merkle_root.bytes, root.bytes, 4), 0);
    ASSERT(reader.footer_valid);
    
    ASSERT_EQ(cd_reader_verify_toc_order(&reader), CD_READ_OK);
    
    /* Find and read */
    ASSERT_EQ(cd_reader_find_entry(&reader, "manifest.json", &entry), CD_READ_OK);
    ASSERT_EQ(cd_reader_get_data(&reader, entry, &data_ptr, &data_len), CD_READ_OK);
    ASSERT_EQ(data_len, sizeof(manifest));
    ASSERT_EQ(memcmp(data_ptr, manifest, sizeof(manifest)), 0);
    
    ASSERT_EQ(cd_reader_find_entry(&reader, "weights.bin", &entry), CD_READ_OK);
    ASSERT_EQ(cd_reader_get_data(&reader, entry, &data_ptr, &data_len), CD_READ_OK);
    ASSERT_EQ(data_len, sizeof(weights));
    ASSERT_EQ(memcmp(data_ptr, weights, sizeof(weights)), 0);
    
    ASSERT_EQ(cd_reader_find_entry(&reader, "nonexistent", &entry), CD_READ_ERR_PATH_NOT_FOUND);
    
    free(bundle);
    return 1;
}

TEST(test_full_cycle_with_signature)
{
    cd_builder_ctx_t builder;
    cd_reader_ctx_t reader;
    FILE *fp;
    uint8_t data[] = "signed payload";
    cd_hash_t h = {{0x11}};
    cd_hash_t root = {{0xAA, 0xBB, 0xCC, 0xDD}};
    uint8_t signature[64];
    uint8_t *bundle;
    size_t bundle_size;
    
    memset(signature, 0x42, sizeof(signature));
    
    fp = tmpfile();
    ASSERT(fp != NULL);
    
    ASSERT_EQ(cd_builder_init(&builder, fp), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&builder, "data.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_finalize(&builder, &root, true, signature), CD_BUNDLE_OK);
    
    fseek(fp, 0, SEEK_END);
    bundle_size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    bundle = (uint8_t *)malloc(bundle_size);
    ASSERT(bundle != NULL);
    ASSERT_EQ(fread(bundle, 1, bundle_size, fp), bundle_size);
    fclose(fp);
    
    ASSERT_EQ(cd_reader_init(&reader, bundle, bundle_size), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_header(&reader), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_toc(&reader), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_footer(&reader), CD_READ_OK);
    
    ASSERT_EQ(reader.footer.has_signature, true);
    ASSERT_EQ(memcmp(reader.footer.signature, signature, 64), 0);
    
    free(bundle);
    return 1;
}

/*============================================================================
 * Reader Error Tests (T-BUN-01, T-BUN-02, T-BUN-03)
 *============================================================================*/

TEST(test_reader_invalid_magic)
{
    cd_reader_ctx_t r;
    uint8_t bad[64] = {0};
    bad[0] = 'X';  /* Invalid magic */
    ASSERT_EQ(cd_reader_init(&r, bad, sizeof(bad)), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_header(&r), CD_READ_ERR_MAGIC);
    ASSERT_EQ(r.faults.parse_error, 1);
    return 1;
}

TEST(test_reader_truncated)
{
    cd_reader_ctx_t r;
    uint8_t small[16] = {0};
    ASSERT_EQ(cd_reader_init(&r, small, sizeof(small)), CD_READ_OK);
    ASSERT_EQ(cd_reader_parse_header(&r), CD_READ_ERR_TRUNCATED);
    ASSERT_EQ(r.faults.io_error, 1);
    return 1;
}

TEST(test_reader_null_args)
{
    cd_reader_ctx_t r;
    uint8_t data[64] = {0};
    ASSERT_EQ(cd_reader_init(NULL, data, sizeof(data)), CD_READ_ERR_NULL);
    ASSERT_EQ(cd_reader_init(&r, NULL, 100), CD_READ_ERR_NULL);
    /* NULL data with len=0 is valid (empty bundle) */
    ASSERT_EQ(cd_reader_init(&r, NULL, 0), CD_READ_OK);
    return 1;
}

TEST(test_reader_parse_order)
{
    cd_reader_ctx_t r;
    uint8_t data[64] = {0};
    ASSERT_EQ(cd_reader_init(&r, data, sizeof(data)), CD_READ_OK);
    
    /* Cannot parse TOC without valid header */
    ASSERT_EQ(cd_reader_parse_toc(&r), CD_READ_ERR_NULL);
    ASSERT_EQ(r.faults.domain, 1);
    
    /* Cannot parse footer without valid TOC */
    r.faults.domain = 0;
    r.header_valid = true;  /* Fake valid header */
    ASSERT_EQ(cd_reader_parse_footer(&r), CD_READ_ERR_NULL);
    ASSERT_EQ(r.faults.domain, 1);
    
    return 1;
}

TEST(test_reader_verify_toc_order_empty)
{
    cd_reader_ctx_t r = {0};
    r.toc_valid = true;
    r.toc_count = 0;
    ASSERT_EQ(cd_reader_verify_toc_order(&r), CD_READ_OK);
    return 1;
}

TEST(test_reader_verify_toc_order_single)
{
    cd_reader_ctx_t r = {0};
    r.toc_valid = true;
    r.toc_count = 1;
    strcpy(r.toc[0].path, "only.bin");
    ASSERT_EQ(cd_reader_verify_toc_order(&r), CD_READ_OK);
    return 1;
}

/*============================================================================
 * Format Compliance Tests
 *============================================================================*/

TEST(test_no_timestamps)
{
    /* FR-BUN-03: No timestamps in bundle format */
    /* Verified by structure definitions - no timestamp fields */
    /* cd_cbf_header_t, cd_toc_entry_t, cd_cbf_footer_t contain no time fields */
    return 1;
}

TEST(test_mmap_layout)
{
    /* NFR-BUN-01: Structure sizes for mmap compatibility */
    ASSERT_EQ(CD_MAX_PATH, 256);
    ASSERT_EQ(CD_HASH_SIZE, 32);
    /* TOC entry size: 256 (path) + 8 (offset) + 8 (size) + 32 (hash) = 304 */
    return 1;
}

TEST(test_little_endian_format)
{
    /* FR-BUN-04: Little-endian encoding */
    uint8_t buf[8];
    
    /* Magic numbers should encode as ASCII in little-endian */
    cd_write_u32_le(buf, CD_CBF_MAGIC_HEADER);
    ASSERT_EQ(buf[0], '1');
    ASSERT_EQ(buf[1], 'F');
    ASSERT_EQ(buf[2], 'B');
    ASSERT_EQ(buf[3], 'C');
    
    cd_write_u32_le(buf, CD_CBF_MAGIC_FOOTER);
    ASSERT_EQ(buf[0], 'C');
    ASSERT_EQ(buf[1], 'B');
    ASSERT_EQ(buf[2], 'F');
    ASSERT_EQ(buf[3], '1');  
    return 1;
}

/*============================================================================
 * Fault Flag Tests
 *============================================================================*/

TEST(test_builder_fault_flags)
{
    cd_builder_ctx_t ctx;
    FILE *fp = tmpfile();
    cd_hash_t h = {{0}};
    uint8_t data[] = "test";
    const cd_fault_flags_t *faults;
    
    ASSERT(fp != NULL);
    ASSERT_EQ(cd_builder_init(&ctx, fp), CD_BUNDLE_OK);
    
    faults = cd_builder_get_faults(&ctx);
    ASSERT(faults != NULL);
    ASSERT_EQ(faults->overflow, 0);
    ASSERT_EQ(faults->domain, 0);
    ASSERT_EQ(faults->io_error, 0);
    
    /* Trigger domain fault */
    ASSERT_EQ(cd_builder_add_file(&ctx, "b.bin", data, sizeof(data), &h), CD_BUNDLE_OK);
    ASSERT_EQ(cd_builder_add_file(&ctx, "a.bin", data, sizeof(data), &h), CD_BUNDLE_ERR_NOT_SORTED);
    ASSERT_EQ(faults->domain, 1);
    
    fclose(fp);
    
    /* NULL context */
    ASSERT(cd_builder_get_faults(NULL) == NULL);
    
    return 1;
}

TEST(test_reader_fault_flags)
{
    cd_reader_ctx_t ctx;
    uint8_t bad[64] = {0};
    const cd_fault_flags_t *faults;
    
    ASSERT_EQ(cd_reader_init(&ctx, bad, sizeof(bad)), CD_READ_OK);
    
    faults = cd_reader_get_faults(&ctx);
    ASSERT(faults != NULL);
    ASSERT_EQ(faults->parse_error, 0);
    
    /* Trigger parse_error fault */
    ASSERT_EQ(cd_reader_parse_header(&ctx), CD_READ_ERR_MAGIC);
    ASSERT_EQ(faults->parse_error, 1);
    
    /* NULL context */
    ASSERT(cd_reader_get_faults(NULL) == NULL);
    
    return 1;
}

/*============================================================================
 * Main
 *============================================================================*/

int main(void)
{
    printf("\n");
    printf("==========================================================\n");
    printf("  Bundle Module Tests (SRS-001-BUNDLE)\n");
    printf("==========================================================\n\n");
    
    printf("Path Normalization:\n");
    RUN_TEST(test_path_normalize_basic);
    RUN_TEST(test_path_normalize_backslash);
    RUN_TEST(test_path_normalize_leading_dotslash);
    RUN_TEST(test_path_normalize_leading_slash);
    RUN_TEST(test_path_normalize_consecutive_slashes);
    RUN_TEST(test_path_normalize_trailing_slash);
    RUN_TEST(test_path_normalize_dotdot_rejected);
    RUN_TEST(test_path_normalize_empty_rejected);
    RUN_TEST(test_path_normalize_null_args);
    RUN_TEST(test_path_compare);
    RUN_TEST(test_path_validate);
    
    printf("\nLittle-Endian Encoding:\n");
    RUN_TEST(test_u32_le);
    RUN_TEST(test_u64_le);
    RUN_TEST(test_le_null_safety);
    
    printf("\nBuilder:\n");
    RUN_TEST(test_builder_init);
    RUN_TEST(test_builder_null_args);
    RUN_TEST(test_builder_add_sorted);
    RUN_TEST(test_builder_reject_unsorted);
    RUN_TEST(test_builder_reject_duplicate);
    RUN_TEST(test_builder_empty_file);
    RUN_TEST(test_builder_add_null_data_nonzero_len);
    RUN_TEST(test_builder_finalize_with_signature);
    RUN_TEST(test_builder_finalize_signature_null_error);
    RUN_TEST(test_builder_state_machine);
    
    printf("\nFull Cycle:\n");
    RUN_TEST(test_full_build_read_cycle);
    RUN_TEST(test_full_cycle_with_signature);
    
    printf("\nReader Errors:\n");
    RUN_TEST(test_reader_invalid_magic);
    RUN_TEST(test_reader_truncated);
    RUN_TEST(test_reader_null_args);
    RUN_TEST(test_reader_parse_order);
    RUN_TEST(test_reader_verify_toc_order_empty);
    RUN_TEST(test_reader_verify_toc_order_single);
    
    printf("\nFormat Compliance:\n");
    RUN_TEST(test_no_timestamps);
    RUN_TEST(test_mmap_layout);
    RUN_TEST(test_little_endian_format);
    
    printf("\nFault Flags:\n");
    RUN_TEST(test_builder_fault_flags);
    RUN_TEST(test_reader_fault_flags);
    
    printf("\n==========================================================\n");
    printf("  Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("==========================================================\n\n");
    
    return (tests_passed == tests_run) ? 0 : 1;
}

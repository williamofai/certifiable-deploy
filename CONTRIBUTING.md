# Contributing to Certifiable Deploy

Thank you for your interest! We are building deterministic model packaging for safety-critical ML deployment.

## 1. The Legal Bit (CLA)

All contributors must sign our **Contributor License Agreement (CLA)**.

**Why?** It allows SpeyTech to provide commercial licenses to companies that cannot use GPL code while keeping the project open source.

**How?** Our [CLA Assistant](https://cla-assistant.io/) will prompt you when you open your first Pull Request.

## 2. Coding Standards

All code must adhere to our **Safety-Critical Guidelines**:

- **No Dynamic Allocation:** Do not use `malloc`, `free`, or `realloc`
- **MISRA-C Compliance:** Follow MISRA-C:2012 guidelines
- **Explicit Types:** Use `int32_t`, `uint32_t`, `size_t`, not `int` or `long`
- **C99 Standard:** No compiler extensions
- **Bounded Loops:** All loops must have provable upper bounds
- **Deterministic Output:** Same inputs must produce bit-identical outputs across platforms

## 3. The Definition of Done

A PR is only merged when:

1. ✅ It is linked to a **Requirement ID** in the SRS documents (SRS-001 through SRS-006)
2. ✅ It has **100% Branch Coverage** in unit tests
3. ✅ It passes all existing tests (`make test-all`)
4. ✅ It is **MISRA-C compliant**
5. ✅ It traces to **CD-MATH-001** or **CD-STRUCT-001**
6. ✅ It compiles with `-Wall -Wextra -Wpedantic -Werror`
7. ✅ It has been reviewed by the Project Lead

## 4. Documentation

Every function must document:
- Purpose
- Preconditions
- Postconditions
- Traceability reference
- Thread safety (if applicable)

Example:
```c
/**
 * @brief Load weights with JIT hash verification
 *
 * @traceability SRS-006-LOADER FR-LDR-03
 *
 * @param[in,out] ctx    Loader context in MANIFEST_VERIFIED state
 * @param[out]    buffer Output buffer for weights (must be aligned)
 * @param[in]     size   Buffer size (must match weights size)
 * @return CDL_OK on success, error code otherwise
 *
 * @pre ctx->state == CDL_STATE_MANIFEST_VERIFIED
 * @post ctx->state == CDL_STATE_WEIGHTS_VERIFIED on success
 * @post ctx->state == CDL_STATE_FAILED on error
 */
cdl_result_t cdl_load_weights(cd_load_ctx_t *ctx, void *buffer, size_t size);
```

## 5. Module Guidelines

### Cryptographic Code (audit/, attest/)
- Use domain-separated hashing (CD-MATH-001 §1.2)
- All hash operations via `cd_domain_hash()` or `cd_sha256()`
- Constant-time comparisons where security-relevant

### Bundle Code (bundle/)
- Little-endian encoding for all multi-byte integers
- Paths normalized before storage
- TOC entries sorted lexicographically

### Manifest Code (manifest/)
- JCS canonicalization per RFC 8785
- Keys sorted by UTF-16 code units
- No whitespace outside strings

### Loader Code (loader/)
- Fail-closed state machine (any error → FAILED)
- JIT hash verification during load
- No execution without verification

## 6. Fault Handling

All operations that can fail must:
1. Accept a `cd_fault_flags_t *faults` parameter
2. Set appropriate flags on error
3. Return a deterministic error code
4. Never crash or invoke undefined behavior

## 7. Test Requirements

Every module needs:
- **Unit tests**: Comprehensive test suite in `tests/unit/`
- **Test vectors**: Exact values from specification where applicable
- **Edge cases**: NULL inputs, empty data, boundary conditions
- **Coverage**: Clear pass/fail output with test counts

## 8. Integration Points

Some functionality is designed for third-party integration:

- **Ed25519 Signing:** `cda_sign()` interface — integrators provide crypto library
- **Certificate Chain:** `cdl_finalize()` — integrators define certificate format

Do not implement these without discussion. They are integration boundaries, not missing features.

## 9. Getting Started

Look for issues labeled `good-first-issue` or `documentation`.

We recommend starting with:
- Additional test coverage for existing modules
- Documentation improvements
- Edge case handling

## Questions?

- **Technical questions:** Open an issue
- **General inquiries:** william@fstopify.com
- **Security issues:** Email william@fstopify.com (do not open public issues)

Thank you for helping make deterministic deployment a reality! 🎯

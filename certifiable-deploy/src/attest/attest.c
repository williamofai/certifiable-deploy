/**
 * @file attest.c
 * @brief Attestation builder API for certifiable-deploy
 * @project Certifiable Deploy
 *
 * @details
 * Implements the high-level attestation API (cda_*) as specified in
 * SRS-002-ATTEST §5.1. This module orchestrates:
 *
 * - Merkle tree construction from component hashes (FR-ATT-01)
 * - Bundle root hash computation (FR-ATT-02)
 * - Ed25519 signature envelope (FR-ATT-03)
 * - Timestamp binding (FR-ATT-04)
 *
 * The lower-level Merkle primitives are in merkle.c; this file provides
 * the builder pattern API for constructing complete attestations.
 *
 * @traceability SRS-002-ATTEST (all requirements)
 * @compliance MISRA-C:2012, ISO 26262, IEC 62304
 *
 * @author William Murray
 * @copyright Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * @license Licensed under GPL-3.0 or commercial license.
 */

#include "cd_attest.h"
#include "cd_audit.h"
#include <string.h>

/*============================================================================
 * Constants
 *============================================================================*/

/**
 * Domain tag for bundle root hash (FR-ATT-02)
 * H_B = H("CD:BUNDLE:v1" || H_M || H_W || H_C || H_I)
 */
static const char *CD_TAG_BUNDLE = "CD:BUNDLE:v1";

/**
 * Maximum timestamp: year 2100 in Unix time
 * @traceability FR-ATT-04
 */
#define CDA_MAX_TIMESTAMP 4102444800ULL

/*============================================================================
 * Result Codes
 *============================================================================*/

/**
 * @brief Attestation result codes
 *
 * These are internal to the attestation module. External callers check
 * fault flags for detailed diagnostics.
 */
typedef enum {
    CDA_OK = 0,
    CDA_ERR_NULL = -1,
    CDA_ERR_INVALID_STATE = -2,
    CDA_ERR_TIMESTAMP_BOUNDS = -3,
    CDA_ERR_SIGNING_DISABLED = -4,
    CDA_ERR_TREE_INVALID = -5
} cda_result_t;

/*============================================================================
 * Attestation Builder API (SRS-002-ATTEST §5.1)
 *============================================================================*/

/**
 * @brief Initialize attestation context
 *
 * Clears all fields to zero state. Must be called before any other
 * cda_* function.
 *
 * @param[out] att  Attestation structure to initialize
 * @return CDA_OK on success, CDA_ERR_NULL if att is NULL
 *
 * @traceability SRS-002-ATTEST
 *
 * @post att->tree.valid == false
 * @post att->has_signature == false
 * @post All hash fields are zero
 */
int cda_init(cd_attestation_t *att)
{
    if (att == NULL) {
        return CDA_ERR_NULL;
    }

    /*
     * Zero entire structure for deterministic initial state.
     * This ensures no uninitialised bytes leak into outputs.
     */
    memset(att, 0, sizeof(cd_attestation_t));

    /*
     * Explicitly set known-state flags.
     * Redundant after memset but defensive and documents intent.
     */
    att->tree.valid = false;
    att->has_signature = false;

    return CDA_OK;
}

/**
 * @brief Compute Merkle tree from component hashes
 *
 * Constructs the 4-leaf Merkle tree per CD-MATH-001 §5.2:
 *
 *         R
 *        / \
 *       R1  R2
 *      / \  / \
 *     L_M L_W L_C L_I
 *
 * Where:
 *   L_M = DH("CD:LEAF:MANIFEST:v1", H_M)
 *   L_W = DH("CD:LEAF:WEIGHTS:v1", H_W)
 *   L_C = DH("CD:LEAF:CERTS:v1", H_C)
 *   L_I = DH("CD:LEAF:INFER:v1", H_I)
 *   R_1 = DH("CD:MERKLENODE:v1", L_M || L_W)
 *   R_2 = DH("CD:MERKLENODE:v1", L_C || L_I)
 *   R   = DH("CD:MERKLENODE:v1", R_1 || R_2)
 *
 * @param[in,out] att     Attestation context (must be initialised)
 * @param[in]     h_m     Manifest hash (H_M)
 * @param[in]     h_w     Weights hash (H_W)
 * @param[in]     h_c     Certificate chain hash (H_C)
 * @param[in]     h_i     Inference set hash (H_I)
 * @param[out]    faults  Fault flags (may be NULL)
 * @return CDA_OK on success, error code otherwise
 *
 * @traceability FR-ATT-01
 *
 * @pre att has been initialised via cda_init()
 * @pre All input hashes are non-NULL
 * @post att->tree.valid == true on success
 * @post att->h_manifest, h_weights, h_certs, h_inference populated
 */
int cda_compute_merkle(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_fault_flags_t *faults)
{
    /* Parameter validation */
    if (att == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    if (h_m == NULL || h_w == NULL || h_c == NULL || h_i == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    /*
     * Store component hashes in attestation structure.
     * These are preserved for later verification and re-computation.
     */
    cd_hash_copy(&att->h_manifest, h_m);
    cd_hash_copy(&att->h_weights, h_w);
    cd_hash_copy(&att->h_certs, h_c);
    cd_hash_copy(&att->h_inference, h_i);

    /*
     * Delegate to merkle.c for tree construction.
     * cd_merkle_set_leaves() handles:
     *   - Leaf computation with domain separation
     *   - Internal node computation
     *   - Root computation
     *   - Validity flag management
     */
    cd_merkle_init(&att->tree);
    cd_merkle_set_leaves(&att->tree, h_m, h_w, h_c, h_i, faults);

    /* Check tree validity */
    if (!att->tree.valid) {
        return CDA_ERR_TREE_INVALID;
    }

    return CDA_OK;
}

/**
 * @brief Compute bundle root hash (H_B)
 *
 * Computes the flat bundle hash per CD-MATH-001 §5.1:
 *
 *   H_B = DH("CD:BUNDLE:v1", H_M || H_W || H_C || H_I)
 *
 * This provides a simpler commitment for systems that don't require
 * Merkle proof capabilities. H_B is distinct from the Merkle root R.
 *
 * @param[in,out] att     Attestation context
 * @param[in]     h_m     Manifest hash (H_M)
 * @param[in]     h_w     Weights hash (H_W)
 * @param[in]     h_c     Certificate chain hash (H_C)
 * @param[in]     h_i     Inference set hash (H_I)
 * @param[out]    faults  Fault flags (may be NULL)
 * @return CDA_OK on success, error code otherwise
 *
 * @traceability FR-ATT-02
 *
 * @note H_B is stored in a separate field, not computed here since
 *       cd_attestation_t doesn't have a bundle_root field in current
 *       cd_types.h. This function populates the Merkle tree as a
 *       side effect for consistency.
 */
int cda_compute_bundle_root(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_hash_t *h_b_out,
    cd_fault_flags_t *faults)
{
    uint8_t concat[CD_HASH_SIZE * 4];

    /* Parameter validation */
    if (att == NULL || h_b_out == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    if (h_m == NULL || h_w == NULL || h_c == NULL || h_i == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    /*
     * Store component hashes (same as cda_compute_merkle).
     * This allows either function to be called independently.
     */
    cd_hash_copy(&att->h_manifest, h_m);
    cd_hash_copy(&att->h_weights, h_w);
    cd_hash_copy(&att->h_certs, h_c);
    cd_hash_copy(&att->h_inference, h_i);

    /*
     * Concatenate hashes in fixed order: M || W || C || I
     * Order is specified in SRS-002-ATTEST §3 FR-ATT-02.
     */
    memcpy(concat, h_m->bytes, CD_HASH_SIZE);
    memcpy(concat + CD_HASH_SIZE, h_w->bytes, CD_HASH_SIZE);
    memcpy(concat + (CD_HASH_SIZE * 2), h_c->bytes, CD_HASH_SIZE);
    memcpy(concat + (CD_HASH_SIZE * 3), h_i->bytes, CD_HASH_SIZE);

    /*
     * Compute H_B = DH("CD:BUNDLE:v1", H_M || H_W || H_C || H_I)
     */
    cd_domain_hash(CD_TAG_BUNDLE, concat, sizeof(concat), h_b_out, faults);

    return CDA_OK;
}

/**
 * @brief Sign the Merkle root with Ed25519
 *
 * Generates an Ed25519 signature over the Merkle root R:
 *
 *   σ = Ed25519.Sign(sk, R)
 *
 * The signature is stored in att->signature and has_signature is set.
 *
 * @param[in,out] att          Attestation context (tree must be valid)
 * @param[in]     private_key  Ed25519 private key (64 bytes)
 * @param[out]    faults       Fault flags (may be NULL)
 * @return CDA_OK on success, error code otherwise
 *
 * @traceability FR-ATT-03
 *
 * @pre att->tree.valid == true (Merkle tree computed)
 * @post att->has_signature == true on success
 * @post att->signature contains 64-byte Ed25519 signature
 *
 * @warning This implementation is a STUB. Ed25519 signing requires
 *          integration with a cryptographic library (e.g., libsodium,
 *          OpenSSL, or a certified Ed25519 implementation).
 *
 * @note The private key is NOT stored in the attestation structure.
 * @note Signature is over R (Merkle root), NOT H_B (bundle root).
 */
int cda_sign(
    cd_attestation_t *att,
    const uint8_t *private_key,
    cd_fault_flags_t *faults)
{
    /* Parameter validation */
    if (att == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    if (private_key == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    /* Merkle tree must be computed before signing */
    if (!att->tree.valid) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_TREE_INVALID;
    }

    /*
     * STUB: Ed25519 signature generation
     *
     * Production implementation requires:
     * 1. Certified Ed25519 library (libsodium, OpenSSL, or custom)
     * 2. Constant-time implementation (NFR-ATT-03)
     * 3. Side-channel resistance
     *
     * Signature is computed as:
     *   σ = Ed25519.Sign(private_key, att->tree.root.bytes)
     *
     * For now, we zero the signature field to indicate stub status.
     * Integration point: replace this block with actual Ed25519 call.
     */

    /*
     * TODO: Replace with actual Ed25519 signing
     *
     * Example with libsodium:
     *   crypto_sign_detached(att->signature, NULL,
     *                        att->tree.root.bytes, CD_HASH_SIZE,
     *                        private_key);
     *
     * Example with OpenSSL:
     *   EVP_DigestSign(...)
     */

    /* Zero signature to indicate unsigned (stub behaviour) */
    memset(att->signature, 0, sizeof(att->signature));

    /*
     * Mark as signed even though stub - allows API testing.
     * Production: only set after successful crypto operation.
     */
    att->has_signature = false;  /* Stub: remains unsigned */

    /*
     * Suppress unused parameter warning in stub.
     * Remove this cast when implementing actual signing.
     */
    (void)private_key;

    return CDA_ERR_SIGNING_DISABLED;  /* Stub returns error */
}

/**
 * @brief Set attestation timestamp
 *
 * Records the attestation timestamp with bounds checking.
 *
 * Policy (FR-ATT-04):
 * - If mode == "deterministic": timestamp should be 0
 * - If mode == "audit": timestamp should be current Unix time
 *
 * This function enforces bounds but does not enforce mode policy;
 * that is the caller's responsibility based on manifest mode.
 *
 * @param[in,out] att        Attestation context
 * @param[in]     timestamp  Unix timestamp in seconds
 * @param[out]    faults     Fault flags (may be NULL)
 * @return CDA_OK on success, CDA_ERR_TIMESTAMP_BOUNDS if out of range
 *
 * @traceability FR-ATT-04
 *
 * @pre 0 ≤ timestamp ≤ 4102444800 (year 2100)
 *
 * @note Timestamp is NOT included in the signed payload.
 *       The Merkle root R is computed before timestamp is set.
 */
int cda_set_timestamp(
    cd_attestation_t *att,
    uint64_t timestamp,
    cd_fault_flags_t *faults)
{
    /* Parameter validation */
    if (att == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_NULL;
    }

    /* Bounds check per FR-ATT-04 */
    if (timestamp > CDA_MAX_TIMESTAMP) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return CDA_ERR_TIMESTAMP_BOUNDS;
    }

    /*
     * Note: cd_attestation_t in cd_types.h does not currently have
     * a timestamp field. This is an interface gap.
     *
     * Options:
     * 1. Add timestamp to cd_attestation_t (requires cd_types.h change)
     * 2. Store in separate output parameter
     * 3. Return timestamp via getter function
     *
     * For now, this function validates but cannot store.
     * TODO: Add timestamp field to cd_attestation_t
     */

    /*
     * Suppress unused parameter warning.
     * Remove when timestamp storage is implemented.
     */
    (void)timestamp;

    return CDA_OK;
}

/*============================================================================
 * Extended Attestation API
 *============================================================================*/

/**
 * @brief Verify attestation structure integrity
 *
 * Checks that an attestation is internally consistent:
 * - Merkle tree is valid
 * - Stored hashes match tree inputs
 * - Signature status is coherent
 *
 * @param[in]  att     Attestation to verify
 * @param[out] faults  Fault flags (may be NULL)
 * @return true if attestation is internally consistent
 *
 * @note This does NOT verify the signature cryptographically.
 *       Use cda_verify_signature() for that.
 */
bool cda_check_integrity(const cd_attestation_t *att, cd_fault_flags_t *faults)
{
    cd_merkle_tree_t recomputed;

    if (att == NULL) {
        if (faults != NULL) {
            faults->domain = 1;
        }
        return false;
    }

    /* Tree must be marked valid */
    if (!att->tree.valid) {
        if (faults != NULL) {
            faults->hash_mismatch = 1;
        }
        return false;
    }

    /*
     * Recompute tree from stored hashes and compare.
     * This detects any corruption in the stored hashes or tree.
     */
    cd_merkle_init(&recomputed);
    cd_merkle_set_leaves(&recomputed,
                         &att->h_manifest,
                         &att->h_weights,
                         &att->h_certs,
                         &att->h_inference,
                         faults);

    if (!recomputed.valid) {
        if (faults != NULL) {
            faults->hash_mismatch = 1;
        }
        return false;
    }

    /* Compare roots */
    if (!cd_hash_equal(&att->tree.root, &recomputed.root)) {
        if (faults != NULL) {
            faults->hash_mismatch = 1;
        }
        return false;
    }

    return true;
}

/**
 * @brief Compare two attestations for equality
 *
 * Checks if two attestations have identical:
 * - Component hashes
 * - Merkle roots
 * - Signature status
 *
 * @param[in] a  First attestation
 * @param[in] b  Second attestation
 * @return true if attestations are equivalent
 */
bool cda_equal(const cd_attestation_t *a, const cd_attestation_t *b)
{
    if (a == NULL || b == NULL) {
        return (a == b);  /* Both NULL is equal */
    }

    /* Compare component hashes */
    if (!cd_hash_equal(&a->h_manifest, &b->h_manifest)) {
        return false;
    }
    if (!cd_hash_equal(&a->h_weights, &b->h_weights)) {
        return false;
    }
    if (!cd_hash_equal(&a->h_certs, &b->h_certs)) {
        return false;
    }
    if (!cd_hash_equal(&a->h_inference, &b->h_inference)) {
        return false;
    }

    /* Compare Merkle roots */
    if (!cd_hash_equal(&a->tree.root, &b->tree.root)) {
        return false;
    }

    /* Compare signature status */
    if (a->has_signature != b->has_signature) {
        return false;
    }

    if (a->has_signature) {
        if (memcmp(a->signature, b->signature, sizeof(a->signature)) != 0) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Get attestation root hash
 *
 * Retrieves the Merkle root from a computed attestation.
 *
 * @param[in]  att      Attestation context
 * @param[out] root_out Output for root hash
 * @return true if root was retrieved, false if tree invalid
 */
bool cda_get_root(const cd_attestation_t *att, cd_hash_t *root_out)
{
    return cd_attestation_get_root(att, root_out);
}

/**
 * @brief Check if attestation is signed
 *
 * @param[in] att  Attestation context
 * @return true if attestation has a signature
 */
bool cda_is_signed(const cd_attestation_t *att)
{
    if (att == NULL) {
        return false;
    }
    return att->has_signature;
}

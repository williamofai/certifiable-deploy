/**
 * @file cd_attest.h
 * @brief Merkle tree and attestation API for certifiable-deploy
 * @traceability SRS-002-ATTEST, CD-MATH-001 §5
 *
 * This header defines two API layers:
 *
 * 1. Low-level Merkle primitives (cd_merkle_*)
 *    - Direct tree manipulation
 *    - Used internally and for testing
 *
 * 2. High-level attestation builder (cda_*)
 *    - Builder pattern for constructing attestations
 *    - Recommended for production use
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_ATTEST_H
#define CD_ATTEST_H

#include "cd_types.h"
#include "cd_audit.h"

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Merkle Tree API (Low-Level)
 *============================================================================*/

/**
 * @brief Initialize empty Merkle tree
 *
 * @param[out] tree  Tree structure to initialize
 *
 * @post tree->valid == false
 * @post All hash fields are zero
 */
void cd_merkle_init(cd_merkle_tree_t *tree);

/**
 * @brief Set leaves and compute tree (one-shot)
 *
 * Computes: leaves -> internal nodes -> root
 *
 * Tree structure (CD-MATH-001 §5.2):
 *         R
 *        / \
 *       R1  R2
 *      / \  / \
 *     L_M L_W L_C L_I
 *
 * @param[in,out] tree        Tree to populate
 * @param[in]     h_manifest  Manifest hash (H_M)
 * @param[in]     h_weights   Weights hash (H_W)
 * @param[in]     h_certs     Certificate chain hash (H_C)
 * @param[in]     h_inference Inference set hash (H_I)
 * @param[out]    faults      Fault flags (may be NULL)
 *
 * @traceability FR-ATT-01
 */
void cd_merkle_set_leaves(cd_merkle_tree_t *tree,
                          const cd_hash_t *h_manifest,
                          const cd_hash_t *h_weights,
                          const cd_hash_t *h_certs,
                          const cd_hash_t *h_inference,
                          cd_fault_flags_t *faults);

/**
 * @brief Compute tree from already-set leaves
 *
 * @param[in,out] tree    Tree with leaves already populated
 * @param[out]    faults  Fault flags (may be NULL)
 */
void cd_merkle_compute(cd_merkle_tree_t *tree, cd_fault_flags_t *faults);

/**
 * @brief Verify computed root matches expected
 *
 * @param[in] tree          Computed tree
 * @param[in] expected_root Expected root hash
 * @return true if roots match, false otherwise
 */
bool cd_merkle_verify_root(const cd_merkle_tree_t *tree,
                           const cd_hash_t *expected_root);

/**
 * @brief Get computed root (returns false if tree invalid)
 *
 * @param[in]  tree     Computed tree
 * @param[out] root_out Output for root hash
 * @return true if root retrieved, false if tree invalid
 */
bool cd_merkle_get_root(const cd_merkle_tree_t *tree, cd_hash_t *root_out);

/*============================================================================
 * Attestation API (Low-Level)
 *============================================================================*/

/**
 * @brief Initialize empty attestation
 *
 * @param[out] attest  Attestation structure to initialize
 */
void cd_attestation_init(cd_attestation_t *attest);

/**
 * @brief Set component hashes and build tree
 *
 * @param[in,out] attest      Attestation to populate
 * @param[in]     h_manifest  Manifest hash (H_M)
 * @param[in]     h_weights   Weights hash (H_W)
 * @param[in]     h_certs     Certificate chain hash (H_C)
 * @param[in]     h_inference Inference set hash (H_I)
 * @param[out]    faults      Fault flags (may be NULL)
 */
void cd_attestation_set_hashes(cd_attestation_t *attest,
                               const cd_hash_t *h_manifest,
                               const cd_hash_t *h_weights,
                               const cd_hash_t *h_certs,
                               const cd_hash_t *h_inference,
                               cd_fault_flags_t *faults);

/**
 * @brief Recompute attestation tree from stored hashes
 *
 * @param[in,out] attest  Attestation with hashes already set
 * @param[out]    faults  Fault flags (may be NULL)
 */
void cd_attestation_compute(cd_attestation_t *attest, cd_fault_flags_t *faults);

/**
 * @brief Get attestation root
 *
 * @param[in]  attest   Attestation to query
 * @param[out] root_out Output for root hash
 * @return true if root retrieved, false if tree invalid
 */
bool cd_attestation_get_root(const cd_attestation_t *attest, cd_hash_t *root_out);

/**
 * @brief Verify attestation against expected root
 *
 * @param[in] attest        Attestation to verify
 * @param[in] expected_root Expected root hash
 * @return true if roots match, false otherwise
 */
bool cd_attestation_verify(const cd_attestation_t *attest,
                           const cd_hash_t *expected_root);

/*============================================================================
 * Attestation Builder API (High-Level) - SRS-002-ATTEST §5.1
 *============================================================================*/

/**
 * @brief Initialize attestation context
 *
 * Clears all fields to zero state. Must be called before any other
 * cda_* function.
 *
 * @param[out] att  Attestation structure to initialize
 * @return 0 on success, negative error code otherwise
 *
 * @traceability SRS-002-ATTEST
 */
int cda_init(cd_attestation_t *att);

/**
 * @brief Compute Merkle tree from component hashes
 *
 * Constructs the 4-leaf Merkle tree per CD-MATH-001 §5.2.
 *
 * @param[in,out] att     Attestation context (must be initialized)
 * @param[in]     h_m     Manifest hash (H_M)
 * @param[in]     h_w     Weights hash (H_W)
 * @param[in]     h_c     Certificate chain hash (H_C)
 * @param[in]     h_i     Inference set hash (H_I)
 * @param[out]    faults  Fault flags (may be NULL)
 * @return 0 on success, negative error code otherwise
 *
 * @traceability FR-ATT-01
 */
int cda_compute_merkle(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_fault_flags_t *faults);

/**
 * @brief Compute bundle root hash (H_B)
 *
 * Computes the flat bundle hash per CD-MATH-001 §5.1:
 *   H_B = DH("CD:BUNDLE:v1", H_M || H_W || H_C || H_I)
 *
 * H_B is distinct from the Merkle root R and provides a simpler
 * commitment for systems that don't require Merkle proofs.
 *
 * @param[in,out] att      Attestation context
 * @param[in]     h_m      Manifest hash (H_M)
 * @param[in]     h_w      Weights hash (H_W)
 * @param[in]     h_c      Certificate chain hash (H_C)
 * @param[in]     h_i      Inference set hash (H_I)
 * @param[out]    h_b_out  Output for bundle root hash
 * @param[out]    faults   Fault flags (may be NULL)
 * @return 0 on success, negative error code otherwise
 *
 * @traceability FR-ATT-02
 */
int cda_compute_bundle_root(
    cd_attestation_t *att,
    const cd_hash_t *h_m,
    const cd_hash_t *h_w,
    const cd_hash_t *h_c,
    const cd_hash_t *h_i,
    cd_hash_t *h_b_out,
    cd_fault_flags_t *faults);

/**
 * @brief Sign the Merkle root with Ed25519
 *
 * Generates an Ed25519 signature over the Merkle root R.
 *
 * @param[in,out] att          Attestation context (tree must be valid)
 * @param[in]     private_key  Ed25519 private key (64 bytes)
 * @param[out]    faults       Fault flags (may be NULL)
 * @return 0 on success, negative error code otherwise
 *
 * @traceability FR-ATT-03
 *
 * @warning Current implementation is a STUB. Requires Ed25519 library.
 *
 * @note Signature is over R (Merkle root), NOT H_B (bundle root).
 * @note Private key is NOT stored in the attestation structure.
 */
int cda_sign(
    cd_attestation_t *att,
    const uint8_t *private_key,
    cd_fault_flags_t *faults);

/**
 * @brief Set attestation timestamp
 *
 * Records the attestation timestamp with bounds checking.
 *
 * @param[in,out] att        Attestation context
 * @param[in]     timestamp  Unix timestamp in seconds
 * @param[out]    faults     Fault flags (may be NULL)
 * @return 0 on success, negative error code if out of bounds
 *
 * @traceability FR-ATT-04
 *
 * @pre 0 ≤ timestamp ≤ 4102444800 (year 2100)
 *
 * @note Timestamp is NOT included in the signed payload.
 */
int cda_set_timestamp(
    cd_attestation_t *att,
    uint64_t timestamp,
    cd_fault_flags_t *faults);

/*============================================================================
 * Extended Attestation API
 *============================================================================*/

/**
 * @brief Verify attestation structure integrity
 *
 * Checks internal consistency by recomputing the Merkle tree
 * from stored hashes and comparing roots.
 *
 * @param[in]  att     Attestation to verify
 * @param[out] faults  Fault flags (may be NULL)
 * @return true if attestation is internally consistent
 *
 * @note Does NOT verify signature cryptographically.
 */
bool cda_check_integrity(const cd_attestation_t *att, cd_fault_flags_t *faults);

/**
 * @brief Compare two attestations for equality
 *
 * @param[in] a  First attestation
 * @param[in] b  Second attestation
 * @return true if attestations are equivalent
 */
bool cda_equal(const cd_attestation_t *a, const cd_attestation_t *b);

/**
 * @brief Get attestation root hash
 *
 * @param[in]  att      Attestation context
 * @param[out] root_out Output for root hash
 * @return true if root was retrieved, false if tree invalid
 */
bool cda_get_root(const cd_attestation_t *att, cd_hash_t *root_out);

/**
 * @brief Check if attestation is signed
 *
 * @param[in] att  Attestation context
 * @return true if attestation has a signature
 */
bool cda_is_signed(const cd_attestation_t *att);

#ifdef __cplusplus
}
#endif

#endif /* CD_ATTEST_H */

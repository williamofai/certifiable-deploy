/**
 * @file merkle.c
 * @brief 4-leaf Merkle tree construction per CD-MATH-001 §5.2
 * @traceability SRS-002-ATTEST §8, FR-ATT-01 through FR-ATT-04
 *
 * Tree structure:
 *         R
 *        / \
 *       R1  R2
 *      / \  / \
 *     L_M L_W L_C L_I
 *
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_attest.h"
#include "cd_audit.h"
#include <string.h>

/*============================================================================
 * Leaf Hash Computation (CD-MATH-001 §5.2)
 *============================================================================*/

/**
 * Compute leaf hash: L_x = DH("CD:LEAF:x:v1", H_x)
 */
static void compute_leaf(const char *tag, const cd_hash_t *content_hash,
                         cd_hash_t *leaf_out, cd_fault_flags_t *faults) {
    cd_domain_hash(tag, content_hash->bytes, CD_HASH_SIZE, leaf_out, faults);
}

/*============================================================================
 * Internal Node Computation
 *============================================================================*/

/**
 * Compute internal node: R = DH("CD:MERKLENODE:v1", L || R)
 */
static void compute_node(const cd_hash_t *left, const cd_hash_t *right,
                         cd_hash_t *node_out, cd_fault_flags_t *faults) {
    uint8_t concat[CD_HASH_SIZE * 2];

    memcpy(concat, left->bytes, CD_HASH_SIZE);
    memcpy(concat + CD_HASH_SIZE, right->bytes, CD_HASH_SIZE);

    cd_domain_hash(CD_TAG_MERKLE_NODE, concat, sizeof(concat), node_out, faults);
}

/*============================================================================
 * Public API
 *============================================================================*/

void cd_merkle_init(cd_merkle_tree_t *tree) {
    if (!tree) return;
    memset(tree, 0, sizeof(*tree));
    tree->valid = false;
}

void cd_merkle_set_leaves(cd_merkle_tree_t *tree,
                          const cd_hash_t *h_manifest,
                          const cd_hash_t *h_weights,
                          const cd_hash_t *h_certs,
                          const cd_hash_t *h_inference,
                          cd_fault_flags_t *faults) {
    if (!tree) {
        if (faults) faults->domain = 1;
        return;
    }

    tree->valid = false;

    /* Compute leaf hashes */
    compute_leaf(CD_TAG_LEAF_M, h_manifest, &tree->leaves[0], faults);
    compute_leaf(CD_TAG_LEAF_W, h_weights, &tree->leaves[1], faults);
    compute_leaf(CD_TAG_LEAF_C, h_certs, &tree->leaves[2], faults);
    compute_leaf(CD_TAG_LEAF_I, h_inference, &tree->leaves[3], faults);

    /* Compute internal nodes */
    compute_node(&tree->leaves[0], &tree->leaves[1], &tree->internal[0], faults);
    compute_node(&tree->leaves[2], &tree->leaves[3], &tree->internal[1], faults);

    /* Compute root */
    compute_node(&tree->internal[0], &tree->internal[1], &tree->root, faults);

    if (!faults || !cd_has_fault(faults)) {
        tree->valid = true;
    }
}

void cd_merkle_compute(cd_merkle_tree_t *tree, cd_fault_flags_t *faults) {
    if (!tree) {
        if (faults) faults->domain = 1;
        return;
    }

    /* Leaves should already be set - compute internal nodes and root */
    compute_node(&tree->leaves[0], &tree->leaves[1], &tree->internal[0], faults);
    compute_node(&tree->leaves[2], &tree->leaves[3], &tree->internal[1], faults);
    compute_node(&tree->internal[0], &tree->internal[1], &tree->root, faults);

    if (!faults || !cd_has_fault(faults)) {
        tree->valid = true;
    }
}

bool cd_merkle_verify_root(const cd_merkle_tree_t *tree,
                           const cd_hash_t *expected_root) {
    if (!tree || !expected_root || !tree->valid) {
        return false;
    }
    return cd_hash_equal(&tree->root, expected_root);
}

bool cd_merkle_get_root(const cd_merkle_tree_t *tree, cd_hash_t *root_out) {
    if (!tree || !root_out || !tree->valid) {
        if (root_out) cd_hash_zero(root_out);
        return false;
    }
    cd_hash_copy(root_out, &tree->root);
    return true;
}

/*============================================================================
 * Attestation API
 *============================================================================*/

void cd_attestation_init(cd_attestation_t *attest) {
    if (!attest) return;
    memset(attest, 0, sizeof(*attest));
    attest->has_signature = false;
}

void cd_attestation_set_hashes(cd_attestation_t *attest,
                               const cd_hash_t *h_manifest,
                               const cd_hash_t *h_weights,
                               const cd_hash_t *h_certs,
                               const cd_hash_t *h_inference,
                               cd_fault_flags_t *faults) {
    if (!attest) {
        if (faults) faults->domain = 1;
        return;
    }

    /* Store component hashes */
    cd_hash_copy(&attest->h_manifest, h_manifest);
    cd_hash_copy(&attest->h_weights, h_weights);
    cd_hash_copy(&attest->h_certs, h_certs);
    cd_hash_copy(&attest->h_inference, h_inference);

    /* Build Merkle tree */
    cd_merkle_init(&attest->tree);
    cd_merkle_set_leaves(&attest->tree, h_manifest, h_weights,
                         h_certs, h_inference, faults);
}

void cd_attestation_compute(cd_attestation_t *attest, cd_fault_flags_t *faults) {
    if (!attest) {
        if (faults) faults->domain = 1;
        return;
    }

    cd_merkle_set_leaves(&attest->tree,
                         &attest->h_manifest,
                         &attest->h_weights,
                         &attest->h_certs,
                         &attest->h_inference,
                         faults);
}

bool cd_attestation_get_root(const cd_attestation_t *attest, cd_hash_t *root_out) {
    if (!attest || !root_out) {
        if (root_out) cd_hash_zero(root_out);
        return false;
    }
    return cd_merkle_get_root(&attest->tree, root_out);
}

bool cd_attestation_verify(const cd_attestation_t *attest,
                           const cd_hash_t *expected_root) {
    if (!attest || !expected_root) {
        return false;
    }
    return cd_merkle_verify_root(&attest->tree, expected_root);
}

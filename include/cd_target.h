/**
 * @file cd_target.h
 * @brief Target tuple API for certifiable-deploy
 * @traceability SRS-003-TARGET
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#ifndef CD_TARGET_H
#define CD_TARGET_H

#include "cd_types.h"

/*============================================================================
 * Parsing
 *============================================================================*/

/**
 * Parse target string "arch-vendor-device-abi" into cd_target_t
 * @return 0 on success, -1 on error
 */
int cdt_parse(const char *str, cd_target_t *target, cd_fault_flags_t *faults);

/*============================================================================
 * Encoding
 *============================================================================*/

/**
 * Encode cd_target_t to canonical string
 * @return length on success, -1 on error
 */
int cdt_encode(const cd_target_t *target, char *buf, size_t buf_size,
               cd_fault_flags_t *faults);

/*============================================================================
 * Matching
 *============================================================================*/

/**
 * Match bundle target against device target
 * Bundle may have "generic" wildcards; device must be specific
 */
cd_match_result_t cdt_match(const cd_target_t *bundle, const cd_target_t *device,
                            cd_fault_flags_t *faults);

/**
 * Check if match result indicates compatibility
 */
bool cdt_match_ok(cd_match_result_t result);

/*============================================================================
 * Validation
 *============================================================================*/

/**
 * Validate target has all required fields
 * @return 0 on success, -1 on error
 */
int cdt_validate(const cd_target_t *target, cd_fault_flags_t *faults);

/*============================================================================
 * Initialization
 *============================================================================*/

/**
 * Initialize target to empty state
 */
void cdt_init(cd_target_t *target);

/**
 * Set target fields
 */
void cdt_set(cd_target_t *target, cd_architecture_t arch,
             const char *vendor, const char *device, cd_abi_t abi);

#endif /* CD_TARGET_H */

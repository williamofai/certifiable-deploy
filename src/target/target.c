/**
 * @file target.c
 * @brief Target tuple parsing, encoding, and matching
 * @traceability SRS-003-TARGET
 * 
 * Format: arch-vendor-device-abi
 * Examples:
 *   riscv64-tenstorrent-p150-lp64d
 *   x86_64-generic-cpu-sysv
 *   aarch64-nvidia-orin-lp64
 * 
 * Copyright (c) 2026 The Murray Family Innovation Trust. All rights reserved.
 * Licensed under GPL-3.0 or commercial license.
 */

#include "cd_target.h"
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Architecture Mappings
 *============================================================================*/

static const struct {
    const char *name;
    cd_architecture_t arch;
} arch_map[] = {
    { "x86_64",   CD_ARCH_X86_64 },
    { "aarch64",  CD_ARCH_AARCH64 },
    { "riscv64",  CD_ARCH_RISCV64 },
    { "riscv32",  CD_ARCH_RISCV32 },
    { NULL, CD_ARCH_UNKNOWN }
};

static const struct {
    const char *name;
    cd_abi_t abi;
} abi_map[] = {
    { "sysv",      CD_ABI_SYSV },
    { "lp64d",     CD_ABI_LP64D },
    { "lp64",      CD_ABI_LP64 },
    { "ilp32",     CD_ABI_ILP32 },
    { "linux-gnu", CD_ABI_LINUX_GNU },
    { NULL, CD_ABI_UNKNOWN }
};

/*============================================================================
 * String Utilities
 *============================================================================*/

static size_t safe_strcpy(char *dst, const char *src, size_t dst_size) {
    size_t len = strlen(src);
    if (len >= dst_size) {
        len = dst_size - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return len;
}

static bool is_valid_component(const char *s, size_t len) {
    size_t i;
    if (len == 0 || len >= CD_MAX_VENDOR) return false;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || 
              (c >= '0' && c <= '9') || 
              c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

/*============================================================================
 * Parsing
 *============================================================================*/

static cd_architecture_t parse_arch(const char *s, size_t len) {
    int i;
    for (i = 0; arch_map[i].name != NULL; i++) {
        if (strlen(arch_map[i].name) == len &&
            strncmp(s, arch_map[i].name, len) == 0) {
            return arch_map[i].arch;
        }
    }
    return CD_ARCH_UNKNOWN;
}

static cd_abi_t parse_abi(const char *s, size_t len) {
    int i;
    for (i = 0; abi_map[i].name != NULL; i++) {
        if (strlen(abi_map[i].name) == len &&
            strncmp(s, abi_map[i].name, len) == 0) {
            return abi_map[i].abi;
        }
    }
    return CD_ABI_UNKNOWN;
}

static const char *arch_to_string(cd_architecture_t arch) {
    int i;
    for (i = 0; arch_map[i].name != NULL; i++) {
        if (arch_map[i].arch == arch) {
            return arch_map[i].name;
        }
    }
    return "unknown";
}

static const char *abi_to_string(cd_abi_t abi) {
    int i;
    for (i = 0; abi_map[i].name != NULL; i++) {
        if (abi_map[i].abi == abi) {
            return abi_map[i].name;
        }
    }
    return "unknown";
}

/*============================================================================
 * Public API - Parsing
 *============================================================================*/

int cdt_parse(const char *str, cd_target_t *target, cd_fault_flags_t *faults) {
    const char *p, *start;
    size_t len;
    int component = 0;
    char temp[CD_MAX_PATH];

    if (!str || !target) {
        if (faults) faults->domain = 1;
        return -1;
    }

    memset(target, 0, sizeof(*target));
    target->architecture = CD_ARCH_UNKNOWN;
    target->abi = CD_ABI_UNKNOWN;

    /* Copy to temp buffer for safe tokenization */
    len = strlen(str);
    if (len >= sizeof(temp)) {
        if (faults) faults->parse_error = 1;
        return -1;
    }
    memcpy(temp, str, len + 1);

    p = temp;
    start = p;

    while (*p) {
        if (*p == '-') {
            len = (size_t)(p - start);
            
            switch (component) {
                case 0: /* Architecture */
                    target->architecture = parse_arch(start, len);
                    if (target->architecture == CD_ARCH_UNKNOWN) {
                        if (faults) faults->parse_error = 1;
                        return -1;
                    }
                    break;
                case 1: /* Vendor */
                    if (!is_valid_component(start, len)) {
                        if (faults) faults->parse_error = 1;
                        return -1;
                    }
                    if (len >= CD_MAX_VENDOR) {
                        if (faults) faults->parse_error = 1;
                        return -1;
                    }
                    memcpy(target->vendor, start, len);
                    target->vendor[len] = '\0';
                    break;
                case 2: /* Device */
                    if (!is_valid_component(start, len)) {
                        if (faults) faults->parse_error = 1;
                        return -1;
                    }
                    if (len >= CD_MAX_DEVICE) {
                        if (faults) faults->parse_error = 1;
                        return -1;
                    }
                    memcpy(target->device, start, len);
                    target->device[len] = '\0';
                    break;
                default:
                    if (faults) faults->parse_error = 1;
                    return -1;
            }
            
            component++;
            start = p + 1;
        }
        p++;
    }

    /* Final component (ABI) */
    if (component != 3) {
        if (faults) faults->parse_error = 1;
        return -1;
    }
    
    len = (size_t)(p - start);
    target->abi = parse_abi(start, len);
    if (target->abi == CD_ABI_UNKNOWN) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    return 0;
}

/*============================================================================
 * Public API - Encoding
 *============================================================================*/

int cdt_encode(const cd_target_t *target, char *buf, size_t buf_size,
               cd_fault_flags_t *faults) {
    int ret;

    if (!target || !buf || buf_size == 0) {
        if (faults) faults->domain = 1;
        return -1;
    }

    if (target->architecture == CD_ARCH_UNKNOWN) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    if (target->abi == CD_ABI_UNKNOWN) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    ret = snprintf(buf, buf_size, "%s-%s-%s-%s",
                   arch_to_string(target->architecture),
                   target->vendor,
                   target->device,
                   abi_to_string(target->abi));

    if (ret < 0 || (size_t)ret >= buf_size) {
        if (faults) faults->overflow = 1;
        return -1;
    }

    return ret;
}

/*============================================================================
 * Public API - Matching
 *============================================================================*/

cd_match_result_t cdt_match(const cd_target_t *bundle, const cd_target_t *device,
                            cd_fault_flags_t *faults) {
    bool vendor_match, device_match;
    bool vendor_wildcard, device_wildcard;

    if (!bundle || !device) {
        if (faults) faults->domain = 1;
        return CD_MATCH_FAIL_ARCH;
    }

    /* Architecture must match exactly */
    if (bundle->architecture != device->architecture) {
        return CD_MATCH_FAIL_ARCH;
    }

    /* ABI must match exactly */
    if (bundle->abi != device->abi) {
        return CD_MATCH_FAIL_ABI;
    }

    /* Check vendor */
    vendor_wildcard = (strcmp(bundle->vendor, "generic") == 0);
    vendor_match = vendor_wildcard || (strcmp(bundle->vendor, device->vendor) == 0);
    
    if (!vendor_match) {
        return CD_MATCH_FAIL_VENDOR;
    }

    /* Check device */
    device_wildcard = (strcmp(bundle->device, "generic") == 0);
    device_match = device_wildcard || (strcmp(bundle->device, device->device) == 0);
    
    if (!device_match) {
        return CD_MATCH_FAIL_DEVICE;
    }

    /* Determine match type */
    if (vendor_wildcard && device_wildcard) {
        return CD_MATCH_WILDCARD_BOTH;
    } else if (vendor_wildcard) {
        return CD_MATCH_WILDCARD_VENDOR;
    } else if (device_wildcard) {
        return CD_MATCH_WILDCARD_DEVICE;
    }
    
    return CD_MATCH_EXACT;
}

bool cdt_match_ok(cd_match_result_t result) {
    return result == CD_MATCH_EXACT ||
           result == CD_MATCH_WILDCARD_VENDOR ||
           result == CD_MATCH_WILDCARD_DEVICE ||
           result == CD_MATCH_WILDCARD_BOTH;
}

/*============================================================================
 * Public API - Validation
 *============================================================================*/

int cdt_validate(const cd_target_t *target, cd_fault_flags_t *faults) {
    if (!target) {
        if (faults) faults->domain = 1;
        return -1;
    }

    if (target->architecture == CD_ARCH_UNKNOWN) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    if (target->abi == CD_ABI_UNKNOWN) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    if (strlen(target->vendor) == 0) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    if (strlen(target->device) == 0) {
        if (faults) faults->parse_error = 1;
        return -1;
    }

    return 0;
}

/*============================================================================
 * Public API - Initialization
 *============================================================================*/

void cdt_init(cd_target_t *target) {
    if (!target) return;
    memset(target, 0, sizeof(*target));
    target->architecture = CD_ARCH_UNKNOWN;
    target->abi = CD_ABI_UNKNOWN;
}

void cdt_set(cd_target_t *target, cd_architecture_t arch,
             const char *vendor, const char *device, cd_abi_t abi) {
    if (!target) return;
    
    target->architecture = arch;
    target->abi = abi;
    
    if (vendor) {
        safe_strcpy(target->vendor, vendor, CD_MAX_VENDOR);
    }
    if (device) {
        safe_strcpy(target->device, device, CD_MAX_DEVICE);
    }
}

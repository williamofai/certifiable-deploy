# certifiable-deploy

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/williamofai/certifiable-deploy)
[![Tests](https://img.shields.io/badge/tests-201%20passing-brightgreen)](https://github.com/williamofai/certifiable-deploy)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-x86%20%7C%20ARM%20%7C%20RISC--V-lightgrey)](https://github.com/williamofai/certifiable-deploy)

**Deterministic model packaging and cryptographic attestation for safety-critical ML deployment.**

Pure C99. Zero dynamic allocation. Certifiable for DO-178C, IEC 62304, and ISO 26262.

---

## The Problem

Deploying ML models to safety-critical systems faces fundamental challenges:
- How do you prove the deployed model matches what was certified?
- How do you verify weights haven't been tampered with?
- How do you bind inference artifacts to specific hardware?
- How do you maintain cryptographic provenance from training to deployment?

For safety-critical systems, "trust me, it's the right model" is not certifiable.

**Read more:**
- [Bit-Perfect Reproducibility: Why It Matters and How to Prove It](https://speytech.com/insights/bit-perfect-reproducibility/)
- [Cryptographic Execution Tracing and Evidentiary Integrity](https://speytech.com/insights/cryptographic-proof-execution/)

## The Solution

`certifiable-deploy` implements the **"Execution ⇒ Verification"** invariant:

> The inference API is enabled only after measured hashes of weights and kernels match the certificate claims and attestation root.

### Core Components

**1. Canonical Bundle Format (CBF v1)**
Deterministic container with no ambient metadata. Payloads, TOC, and attestation in a single verifiable package.

**2. Merkle Attestation**
4-leaf Merkle tree binding manifest, weights, certificates, and inference artifacts:
```
        R (root)
       / \
      R₁  R₂
     / \  / \
    L_M L_W L_C L_I
```

**3. JCS Manifest (RFC 8785)**
Canonical JSON manifest with deterministic serialization. Same content = same bytes = same hash.

**4. Target Binding**
Lock bundles to specific platforms: `arch-vendor-device-abi`

**5. Runtime Loader (CD-LOAD)**
JIT hash verification with fail-closed state machine. No execution without verification.

**Read more:** [From Proofs to Code: Mathematical Transcription in C](https://speytech.com/insights/mathematical-proofs-to-code/)

## Status

**All modules complete — 7/7 test suites passing.**

| Module | Description | Status |
|--------|-------------|--------|
| Audit | SHA-256 + domain-separated hashing | ✅ |
| Attest | Merkle tree construction + attestation | ✅ |
| Bundle | CBF v1 builder and reader | ✅ |
| Manifest | JCS canonical JSON (RFC 8785) | ✅ |
| Target | Platform tuple parse/encode/match | ✅ |
| Verify | Offline bundle verification | ✅ |
| Loader | Runtime JIT verification (CD-LOAD) | ✅ |

## Quick Start

### Build
```bash
mkdir build && cd build
cmake ..
make
make test-all  # Run all 7 test suites
```

### Expected Output
```
100% tests passed, 0 tests failed out of 7
Total Test time (real) = 0.02 sec
```

### Create a Bundle
```c
#include "cd_bundle.h"
#include "cd_manifest.h"
#include "cd_attest.h"

// Build manifest
cdm_builder_t mb;
cdm_builder_init(&mb);
cdm_set_mode(&mb, "deterministic");
cdm_set_created_at(&mb, 0);
cdm_set_target(&mb, &target);
cdm_set_weights_hash(&mb, &h_weights);
cdm_set_certs_hash(&mb, &h_certs);
cdm_set_inference_hash(&mb, &h_inference);

uint8_t manifest_json[4096];
size_t manifest_len = sizeof(manifest_json);
cdm_finalize_jcs(&mb, manifest_json, &manifest_len);

// Compute attestation
cd_attestation_t att;
cda_init(&att);
cda_compute_merkle(&att, &h_manifest, &h_weights, &h_certs, &h_inference, NULL);

cd_hash_t merkle_root;
cda_get_root(&att, &merkle_root);

// Build bundle
cd_builder_ctx_t ctx;
cd_builder_init(&ctx, output_file);
cd_builder_add_file(&ctx, "manifest.json", manifest_json, manifest_len, &h_manifest);
cd_builder_add_file(&ctx, "weights.bin", weights_data, weights_len, &h_weights);
cd_builder_finalize(&ctx, &merkle_root, false, NULL);
```

### Load and Verify at Runtime
```c
#include "cd_loader.h"

cd_load_ctx_t ctx;
cd_target_t device_target;

// Set device target
cdt_set(&device_target, CD_ARCH_X86_64, "intel", "xeon", CD_ABI_SYSV);

// Initialize loader
cdl_init(&ctx, &device_target);

// Open bundle (verifies header, TOC, manifest, target)
cdl_open_bundle(&ctx, bundle_data, bundle_len);

// Load weights with JIT hash verification
uint8_t *weights = allocate_weights_buffer(weights_size);
cdl_load_weights(&ctx, weights, weights_size);

// Load inference kernels with JIT hash verification
uint8_t *kernels = allocate_kernel_buffer(kernel_size);
cdl_load_kernels(&ctx, kernels, kernel_size);

// Finalize (verifies Merkle root)
cdl_finalize(&ctx);

// Only now is execution permitted
if (cdl_is_enabled(&ctx)) {
    run_inference(weights, kernels);
}
```

## Architecture

### Domain-Separated Hashing

All hashes use domain separation to prevent cross-protocol attacks:
```
DH(tag, payload) = SHA256(tag || LE64(|payload|) || payload)
```

Domain tags:
- `CD:MANIFEST:v1` — Manifest hash
- `CD:WEIGHTS:v1` — Weights hash
- `CD:CERTSET:v1` — Certificate chain hash
- `CD:INFERSET:v1` — Inference set hash
- `CD:LEAF:*:v1` — Merkle leaf hashes
- `CD:MERKLENODE:v1` — Merkle internal nodes

### CBF v1 Format

```
┌─────────────────────────────────────┐
│           Global Header             │
│  magic(4) | version(4) | offsets    │
├─────────────────────────────────────┤
│          File Payloads              │
│  (raw bytes, no metadata)           │
├─────────────────────────────────────┤
│        Table of Contents            │
│  entry_count | entries[]            │
│  (sorted by normalized path)        │
├─────────────────────────────────────┤
│             Footer                  │
│  merkle_root | signature | magic    │
└─────────────────────────────────────┘
```

### CD-LOAD State Machine

```
INIT → HEADER_READ → TOC_READ → MANIFEST_VERIFIED →
WEIGHTS_STREAMING → WEIGHTS_VERIFIED →
INFERENCE_STREAMING → INFERENCE_VERIFIED →
CHAIN_VERIFIED → ENABLED

Any State --[error]--> FAILED (terminal)
```

**Fail-Closed:** Any verification failure immediately transitions to FAILED state, which cannot be exited.

### Target Tuple

Format: `arch-vendor-device-abi`

Examples:
- `riscv64-tenstorrent-p150-lp64d`
- `x86_64-generic-cpu-sysv`
- `aarch64-nvidia-orin-lp64`

Wildcards (`generic`) allow bundles to match multiple devices while maintaining architecture/ABI safety.

## Integration Points

These interfaces are designed for third-party integration:

### Ed25519 Signing
The `cda_sign()` function provides the interface for signing attestation roots. Integrators provide their own Ed25519 implementation appropriate for their security requirements (HSM, libsodium, certified library).

### Certificate Chain
Certificate parsing requires integration with the deployer's PKI infrastructure. The certificate format is defined by the upstream certifiable-* pipeline (certifiable-quant, certifiable-training, certifiable-data).

## Documentation

- **CD-MATH-001.md** — Mathematical foundations
- **CD-STRUCT-001.md** — Data structure specifications
- **docs/requirements/** — SRS documents with full traceability:
  - SRS-001-BUNDLE — CBF v1 format
  - SRS-002-ATTEST — Merkle attestation
  - SRS-003-TARGET — Target binding
  - SRS-004-MANIFEST — JCS canonicalization
  - SRS-005-VERIFY — Offline verification
  - SRS-006-LOADER — Runtime loader

## Related Projects

| Project | Description |
|---------|-------------|
| [certifiable-data](https://github.com/williamofai/certifiable-data) | Deterministic data pipeline |
| [certifiable-training](https://github.com/williamofai/certifiable-training) | Deterministic training engine |
| [certifiable-quant](https://github.com/williamofai/certifiable-quant) | Deterministic quantization |
| [certifiable-inference](https://github.com/williamofai/certifiable-inference) | Deterministic inference engine |

Together, these projects provide a complete deterministic ML pipeline for safety-critical systems:

```
certifiable-data → certifiable-training → certifiable-quant → certifiable-deploy → certifiable-inference
```

## Why This Matters

### Medical Devices
IEC 62304 Class C requires traceable, reproducible software. Model deployment must be verifiable.

**Read more:** [IEC 62304 Class C: What Medical Device Software Actually Requires](https://speytech.com/insights/iec-62304-class-c/)

### Autonomous Vehicles
ISO 26262 ASIL-D demands provable behavior. Deployed models must match certified models.

**Read more:** [ISO 26262 and ASIL-D: The Role of Determinism](https://speytech.com/insights/iso-26262-asil-d-determinism/)

### Aerospace
DO-178C Level A requires complete requirements traceability. "We deployed the model" is not certifiable — cryptographic proof is required.

**Read more:** [DO-178C Level A Certification: How Deterministic Execution Can Streamline Certification Effort](https://speytech.com/insights/do178c-certification/)

## Compliance Support

This implementation is designed to support certification under:
- **DO-178C** (Aerospace software)
- **IEC 62304** (Medical device software)
- **ISO 26262** (Automotive functional safety)
- **IEC 61508** (Industrial safety systems)

For compliance packages and certification assistance, contact below.

## Contributing

We welcome contributions from systems engineers working in safety-critical domains. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Important:** All contributors must sign a [Contributor License Agreement](CONTRIBUTOR-LICENSE-AGREEMENT.md).

## License

**Dual Licensed:**
- **Open Source:** GNU General Public License v3.0 (GPLv3)
- **Commercial:** Available for proprietary use in safety-critical systems

For commercial licensing and compliance documentation packages, contact below.

## Patent Protection

This implementation is built on the **Murray Deterministic Computing Platform (MDCP)**, protected by UK Patent **GB2521625.0**.

MDCP defines a deterministic computing architecture for safety-critical systems, providing:
- Provable execution bounds
- Resource-deterministic operation
- Certification-ready patterns
- Platform-independent behavior

**Read more:** [MDCP vs. Conventional RTOS](https://speytech.com/insights/mdcp-vs-conventional-rtos/)

For commercial licensing inquiries: william@fstopify.com

## About

Built by **SpeyTech** in the Scottish Highlands.

30 years of UNIX infrastructure experience applied to deterministic computing for safety-critical systems.

Patent: UK GB2521625.0 - Murray Deterministic Computing Platform (MDCP)

**Contact:**
William Murray  
william@fstopify.com  
[speytech.com](https://speytech.com)

**More from SpeyTech:**
- [Technical Articles](https://speytech.com/ai-architecture/)
- [Open Source Projects](https://speytech.com/open-source/)

---

*Building deterministic AI systems for when lives depend on the answer.*

Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.

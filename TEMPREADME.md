## Known Limitations (v1.0.0)

### Attestation Module (SRS-002-ATTEST)

1. **Ed25519 Signing (FR-ATT-03)**: Stub implementation. `cda_sign()` returns 
   `CDA_ERR_SIGNING_DISABLED`. Integration point marked for libsodium or 
   certified Ed25519 library. Signature verification in `verify/` also pending.

2. **Timestamp Storage (FR-ATT-04)**: `cda_set_timestamp()` validates bounds 
   but `cd_attestation_t` lacks a `timestamp` field. Requires `cd_types.h` 
   update before full functionality.

Both items are non-blocking for bundle creation and offline verification 
workflows that don't require signatures.

## Integration Points

### Ed25519 Signing (FR-ATT-03)
The `cda_sign()` function provides the interface for signing attestation roots.
Integrators must provide an Ed25519 implementation appropriate for their 
security requirements (HSM, libsodium, certified library, etc.).

### Certificate Chain (FR-LDR-05)  
Certificate parsing requires integration with the deployer's PKI infrastructure.
The `cdl_finalize()` function defines where chain validation occurs.
Certificate format is defined by the upstream certifiable-* pipeline.

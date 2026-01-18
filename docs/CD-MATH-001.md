# CD-MATH-001: Mathematical Foundations

**Project:** certifiable-deploy  
**Version:** Rev A1  
**Status:** ✅ Final (Unconditionally Approved)  
**Applies to:** CD-ARCH-MATH-001 Rev A1 (including CD-LOAD Secure Loader + CBF v1)

---

## 0. Scope and Hard Constraints

### S0.1 Certified Mode Constraints

This document defines the certified ("audit") mode semantics under these constraints:

- CBF v1 container only (no TAR/ZIP, no compression, no deltas)
- Single target tuple per bundle
- Single model per bundle
- Runtime must load inference kernels from bundle (no system libraries)
- Runtime must verify while loading (JIT hashing) and must enforce atomicity

These constraints are part of the certification boundary.

---

## 1. Cryptographic Primitives

### 1.1 Hash Function

Let H(·) be SHA-256, mapping arbitrary-length byte strings to 32-byte digests.

### 1.2 Domain-Separated, Length-Delimited Hashing

To avoid ambiguity, all hashes use:

```
DH(tag, payload) = H(tag ∥ LE64(|payload|) ∥ payload)
```

Where:
- `tag` is fixed ASCII, e.g. `"CD:MANIFEST:v1"`
- `LE64(n)` is 8-byte little-endian length encoding

This ensures injective framing of concatenations.

---

## 2. Canonical Bundle Format (CBF v1): Mathematical Model

### 2.1 Bundle as a Byte String

A bundle is a single byte string B ∈ {0,1}* with deterministic layout:

```
B = Header ∥ Payloads ∥ TOC ∥ Footer
```

**CBF v1 rules (normative):**
- Payload bytes are raw file contents (no metadata)
- TOC is canonical (normalized paths, sorted order)
- Integers are little-endian
- No timestamps, uid/gid, permissions, xattrs

### 2.2 Canonical Path Function

Let `norm(·)` normalize a path:
- Separators → `/`
- Remove leading `./` and leading `/`
- Reject if contains `..` segments
- Reject duplicate normalized paths

Let `sort(·)` be lexicographic byte-order sort over normalized paths.

**Determinism invariant:**

```
Same input file bytes + same normalized paths ⇒ identical B
```

---

## 3. Component Hashes

Let the bundle contain the following logical components as byte strings extracted from CBF entries:

| Symbol | Description |
|--------|-------------|
| M | Canonical manifest bytes (CBOR canonical or JSON-JCS canonical) |
| W | Weights bytes (weights.bin) |
| Q | Quant certificate bytes (certificates/quant.cert) |
| Tr | Training certificate bytes (optional) |
| Dc | Data certificate bytes (optional) |
| I | Inference artifact set (collection of files under inference/\<T\>/...) |

### 3.1 Manifest Hash

```
H_M = DH("CD:MANIFEST:v1", M)
```

### 3.2 Weights Hash

```
H_W = DH("CD:WEIGHTS:v1", W)
```

### 3.3 Certificate Digests

```
h_Q = DH("CD:CERT:QUANT:v1", Q)

h_T = DH("CD:CERT:TRAIN:v1", Tr)   if present
    = 0^32                          else

h_D = DH("CD:CERT:DATA:v1", Dc)    if present
    = 0^32                          else
```

### 3.4 Certificate Set Hash (Ordered, Null-Filled)

Define fixed order:

```
order = [data, training, quant]
```

Then:

```
H_C = H("CD:CERTSET:v1" ∥ h_D ∥ h_T ∥ h_Q)
```

This is deterministic and independent of file system ordering.

---

## 4. Inference Artifact Set Hash (H_I)

### 4.1 Canonical File Listing

Let inference set be F = {(p_i, b_i)}_{i=1}^{n} where:
- p_i is normalized relative path (under inference/\<T\>/)
- b_i is file byte content

Require canonical ordering:

```
(p_1, ..., p_n) = sort(norm(p_i))
```

### 4.2 Per-File Hash

```
h_i = DH("CD:FILE:v1", p_i ∥ b_i)
```

(Here p_i is encoded as bytes with its length; the domain-hash framing already length-delimits the entire payload, and within payload we encode p_i as LE16(len)||bytes to prevent ambiguity.)

### 4.3 Target Tuple Encoding

Let T be the target tuple bytes in canonical encoding:

```
T = enc(arch, vendor, device, abi)
```

### 4.4 Inference Set Hash

```
H_I = H("CD:INFERSET:v1" ∥ T ∥ (p_1, h_1) ∥ ... ∥ (p_n, h_n))
```

This binds both:
- The target tuple T
- The complete inference payload

---

## 5. Bundle Root Hash and Attestation

### 5.1 Bundle Root Hash

```
H_B = H("CD:BUNDLE:v1" ∥ H_M ∥ H_W ∥ H_C ∥ H_I)
```

### 5.2 Merkle Root (Preferred Attestation Root)

Define four leaves:

```
L_M = DH("CD:LEAF:MANIFEST:v1", H_M)
L_W = DH("CD:LEAF:WEIGHTS:v1", H_W)
L_C = DH("CD:LEAF:CERTS:v1", H_C)
L_I = DH("CD:LEAF:INFER:v1", H_I)
```

Define node hash:

```
Node(a, b) = DH("CD:MERKLENODE:v1", a ∥ b)
```

Then:

```
R_1 = Node(L_M, L_W)
R_2 = Node(L_C, L_I)
R   = Node(R_1, R_2)
```

**Binding rule:** CBF Footer stores R (and optionally signature over R).

### 5.3 Optional Signature

If enabled:

```
σ = Ed25519.Sign(sk, R)
```

Verification:

```
Ed25519.Verify(pk, R, σ) = true
```

---

## 6. Chain Consistency Constraints (Closure Conditions)

Let quant.cert include (at minimum) a claimed digest for the quantized model / weights blob. Denote:

```
H_W^cert = QuantCertClaim(Q)
```

### 6.1 Weight-to-Certificate Consistency

```
H_W = H_W^cert
```

If training/data certificates exist, apply analogous equality constraints defined by their formats (e.g., training cert claims data cert hash, etc.). Denote these collectively as:

```
K(Q, Tr, Dc) = true
```

where K is the conjunction of required link equalities.

---

## 7. Offline Verification Theorem

### 7.1 Offline Verify Procedure Correctness

An offline verifier recomputes H_M, H_W, H_C, H_I from extracted bytes, recomputes R', and checks:

1. R' = R_footer
2. (If signed) VerifySig(R_footer)
3. H_W = H_W^cert
4. K(Q, Tr, Dc) = true
5. Manifest target tuple equals inference payload target tuple

### 7.2 Tamper Evidence (Corollary)

If any component bytes change, the corresponding component hash changes, which changes R, so verification fails unless a collision is found in SHA-256.

---

## 8. Runtime Consumption: CD-LOAD Protocol (Mathematical Contract)

This section is the "last mile" closure.

### 8.1 Runtime Measured Hashes

During load, the Secure Loader streams bytes into memory and simultaneously computes hashes:

- **H_I^measured**: Computed while loading inference artifacts from bundle
- **H_W^measured**: Computed while streaming weights into device memory

### 8.2 Runtime Enforcement Invariants

#### 8.2.1 Target Match

```
T_bundle = T_device
```

#### 8.2.2 Kernel Integrity and Origin (No System Libraries)

```
H_I^measured = H_I
```

and kernels used for execution must be the ones loaded from the bundle (operational constraint).

#### 8.2.3 Weight Integrity (JIT Hash)

```
H_W^measured = H_W^cert
```

### 8.3 Atomic Consumption Requirement (No TOCTOU)

Let `Enable` be the event "inference API becomes available".

**Core safety theorem (Execution ⇒ Verification):**

```
Enable ⇒ (H_I^measured = H_I ∧ H_W^measured = H_W^cert ∧ T_bundle = T_device)
```

This is enforced by the CD-LOAD state machine: the API remains disabled until all asserts pass, and the verified bytes are the exact bytes placed into execution memory.

---

## 9. Main Security Theorems (Audit Statements)

### Theorem 9.1 (Bundle Tamper Detection)

Under SHA-256 collision resistance, any modification of bundle component bytes changes R (and H_B), causing verification failure.

### Theorem 9.2 (Chain of Custody Closure)

If offline verification passes, then the bundle's weights.bin is cryptographically bound to the claim in quant.cert and to the attestation root R.

### Theorem 9.3 (Last Mile Closure: Execution Implies Verification)

If runtime inference is enabled, then the model weights and inference kernels currently in memory are exactly those whose hashes match the certificate chain and the bundle attestation.

---

## 10. Determinism Requirements (Mathematical Form)

### 10.1 Deterministic Build Function

Let Build(·) map input sets (M, W, Q, Tr, Dc, I, T) to a bundle B.

```
Build(X) = Build(X)  (bit-identical)
```

provided:
- Canonical manifest encoding is used
- Canonical path normalization + sorting are applied
- CBF v1 serialization rules are followed
- No ambient fields (timestamps) are included in hashed manifest (or timestamp is an explicit input)

### 10.2 Deterministic Verify Function

```
Verify(B) is deterministic and produces a unique reason code on failure
```

---

## 11. What the Certificate Must Say (Minimal Language)

The deployment manifest/certificate summary must state:

- CBF v1 canonical encoding used
- R (Merkle root) and optional signature details
- Target tuple T bound to inference payload
- Runtime CD-LOAD enforcement (JIT hashing)

**The key implication:**

> **Execution implies Verification:** the inference API is enabled only after measured hashes of weights and kernels match the certificate claims and attestation root.

---

## 12. Compliance Hooks (Optional but Useful)

- Reason codes are stable identifiers suitable for safety logs
- The loader state machine is implementable as a certifiable component (DO-178C/ISO 26262-friendly)

---

## 13. Test Vectors

### 13.1 Domain-Separated Hash

| Tag | Payload | Expected H |
|-----|---------|------------|
| `"CD:MANIFEST:v1"` | `0x00` (1 byte) | (compute reference) |
| `"CD:WEIGHTS:v1"` | `0xFF` × 32 | (compute reference) |

### 13.2 Merkle Tree Construction

Given:
- H_M = 0x01 × 32
- H_W = 0x02 × 32
- H_C = 0x03 × 32
- H_I = 0x04 × 32

Compute:
- L_M, L_W, L_C, L_I
- R_1, R_2
- R

(Reference values to be computed and added during implementation.)

---

## 14. Traceability

| Section | Implements |
|---------|------------|
| §1 | Cryptographic foundation |
| §2 | CBF v1 container specification |
| §3 | Component hash definitions |
| §4 | Inference set hashing |
| §5 | Attestation structure |
| §6 | Chain consistency |
| §7 | Offline verification |
| §8 | Runtime verification (CD-LOAD) |
| §9 | Security theorems |
| §10 | Determinism requirements |

---

## 15. Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| Rev A1 | 2026-01-18 | William Murray | Initial release |

---

*End of CD-MATH-001 (Final)*

*Copyright © 2026 The Murray Family Innovation Trust. All rights reserved.*

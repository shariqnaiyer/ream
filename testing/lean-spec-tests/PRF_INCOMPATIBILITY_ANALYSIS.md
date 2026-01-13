# Python/Rust XMSS Signature Incompatibility - Root Cause Analysis

## Executive Summary

Python-generated XMSS signatures fail verification in Rust due to a **fundamental mismatch in the PRF (Pseudorandom Function) implementation**. The Python leanSpec uses 8 bytes per field element when converting SHAKE128 output, while the Rust leansig library uses 16 bytes per field element.

This causes completely different randomness values during signing, resulting in incompatible signatures.

## Root Cause

### Python Implementation
**File:** `/tmp/leanSpec/src/lean_spec/subspecs/xmss/prf.py`

```python
PRF_BYTES_PER_FE: int = 8  # Line 73

def _bytes_to_field_elements(data: bytes, count: int) -> list[Fp]:
    return [
        Fp(value=int.from_bytes(data[i : i + PRF_BYTES_PER_FE], "big"))  # Line 101
        for i in range(0, count * PRF_BYTES_PER_FE, PRF_BYTES_PER_FE)
    ]
```

**Behavior:** Reads 8 bytes per field element from SHAKE128 output

### Rust Implementation
**File:** `leansig/src/symmetric/prf/shake_to_field.rs`

```rust
const PRF_BYTES_PER_FE: usize = 16;  // Line 12

fn get_domain_element(key: &Self::Key, epoch: u32, index: u64) -> Self::Domain {
    // ... SHAKE128 setup ...
    std::array::from_fn(|_| {
        let mut buf = [0u8; PRF_BYTES_PER_FE];  // 16 bytes
        xof_reader.read(&mut buf);
        F::from_u128(u128::from_be_bytes(buf))  // Line 71
    })
}
```

**Behavior:** Reads 16 bytes per field element from SHAKE128 output

## Impact Analysis

### Data Extraction Difference

For PROD config with `RAND_LEN_FE = 7` field elements:
- **Python:** Reads bytes 0-55 (7 × 8 = 56 bytes) from SHAKE128
- **Rust:** Reads bytes 0-111 (7 × 16 = 112 bytes) from SHAKE128

This results in **completely different field element arrays**, causing:

1. Different `rho` (randomness) values during signing
2. Different hash chain starting points
3. Different signature components
4. **Verification failure** for cross-implementation signatures

### Why Signatures Diverge at Byte 8

The signature structure is:
```
[offset_path (4 bytes)] [rho (28 bytes)] [offset_hashes (4 bytes)] [path] [hashes]
```

Position 8 is where the `rho` data begins. Since `rho` is derived from the PRF with different byte extraction, signatures diverge at exactly this position.

### Evidence

From `test_cross_implementation.rs`:
```
Rust-generated signature verified: true
Python-generated signature verified: false
Signature bytes differ at position 8  ← Where rho starts
```

## Cryptographic Validity

### Koala Bear Field Properties
- Field prime: `P = 2^31 - 2^24 + 1` (31-bit prime)
- Required entropy: ~31 bits per field element

### Statistical Uniformity

Both approaches provide sufficient statistical uniformity:

| Approach | Bytes | Bits | Safety Margin | Assessment |
|----------|-------|------|---------------|------------|
| Python   | 8     | 64   | 2× overhead   | ✅ Sufficient |
| Rust     | 16    | 128  | 4× overhead   | ✅ Overkill |

The extra bits in both cases ensure the modular reduction doesn't introduce statistical bias. Both are cryptographically sound, but **they must match for compatibility**.

## Solution

### Required Changes to leansig

**File:** `leansig/src/symmetric/prf/shake_to_field.rs`

#### Change 1: Update constant (Line 12)
```rust
// BEFORE
const PRF_BYTES_PER_FE: usize = 16;

// AFTER
const PRF_BYTES_PER_FE: usize = 8;
```

#### Change 2: Update get_domain_element (Lines 63-72)
```rust
// BEFORE
std::array::from_fn(|_| {
    let mut buf = [0u8; PRF_BYTES_PER_FE];
    xof_reader.read(&mut buf);
    F::from_u128(u128::from_be_bytes(buf))
})

// AFTER
std::array::from_fn(|_| {
    let mut buf = [0u8; 8];
    xof_reader.read(&mut buf);
    F::from_u64(u64::from_be_bytes(buf))
})
```

#### Change 3: Update get_randomness (Lines 107-116)
```rust
// BEFORE
std::array::from_fn(|_| {
    let mut buf = [0u8; PRF_BYTES_PER_FE];
    xof_reader.read(&mut buf);
    F::from_u128(u128::from_be_bytes(buf))
})

// AFTER
std::array::from_fn(|_| {
    let mut buf = [0u8; 8];
    xof_reader.read(&mut buf);
    F::from_u64(u64::from_be_bytes(buf))
})
```

### Verification Steps

After applying the fix:

1. Rebuild the leansig library
2. Run `cargo test test_fixture_compatibility` - Python signatures should now verify ✅
3. Run `cargo test test_cross_implementation` - Should show byte-for-byte match ✅
4. Run all verify_signatures tests - Should pass ✅

## Investigation Trail

### Tests Created

1. **test_minimal_verify.rs** - Confirmed Rust can verify its own signatures ✅
2. **test_key_compatibility.rs** - Confirmed keys are compatible (round-trip works) ✅
3. **test_fixture_compatibility.rs** - Identified Python signatures fail verification ❌
4. **test_cross_implementation.rs** - Identified signature divergence at byte 8 ❌
5. **test_detailed_verification.rs** - Traced verification process step-by-step
6. **test_prf_compatibility.rs** - **Documented the PRF mismatch (this finding)** 🎯

### Components Verified as Compatible

- ✅ Poseidon2 hash parameters (width, rounds, internal diagonal vectors)
- ✅ Sign/verify algorithm structure
- ✅ Public key serialization/deserialization
- ✅ Message encoding approach
- ✅ SHAKE128 domain separators
- ✅ Signature structure and SSZ encoding
- ❌ **PRF bytes-per-field-element** ← Root cause

## leansig Library Information

**Repository:** https://github.com/leanEthereum/leansig.git
**Branch:** make-stuff-public
**Commit:** 61088f848bb63cf86e39693f6717739e7b7dec7e

**Current dependency in Cargo.lock:**
```toml
[[package]]
name = "leansig"
version = "0.1.0"
source = "git+https://github.com/leanEthereum/leansig.git?branch=make-stuff-public#61088f848bb63cf86e39693f6717739e7b7dec7e"
```

## Next Steps

1. **Contact leanEthereum maintainers** about this incompatibility
2. **Submit a patch** to the leansig repository with the changes above
3. **Alternative:** Fork leansig and apply the patch locally until upstream is fixed

## References

- Python PRF: `/tmp/leanSpec/src/lean_spec/subspecs/xmss/prf.py`
- Rust PRF: `~/.cargo/git/checkouts/leansig-eb6084e1fc0dad4d/61088f8/src/symmetric/prf/shake_to_field.rs`
- Test documentation: `testing/lean-spec-tests/tests/test_prf_compatibility.rs`

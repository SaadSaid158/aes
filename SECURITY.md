# Security Documentation

## AES-GCM Implementation Details

This document provides detailed information about the security properties and implementation of the AES-GCM (Galois/Counter Mode) encryption system.

## Overview

AES-GCM is an authenticated encryption mode that provides both confidentiality and authenticity. Our implementation is built entirely from scratch without using external cryptographic libraries.

## Components

### 1. AES-128 Block Cipher

The core AES-128 block cipher is implemented with:
- **S-box and Inverse S-box**: Substitution tables for SubBytes operations
- **Key Expansion**: Generates 11 round keys from the 128-bit master key
- **Round Operations**: SubBytes, ShiftRows, MixColumns, AddRoundKey
- **10 rounds** of encryption/decryption for AES-128

### 2. Counter (CTR) Mode

CTR mode transforms AES block cipher into a stream cipher:
- Uses a counter that increments for each block
- Encrypts the counter and XORs with plaintext
- Provides parallelizable encryption/decryption
- No padding required (works with any data length)

**Security Properties:**
- IND-CPA secure (indistinguishable under chosen-plaintext attack)
- Nonce reuse is catastrophic: never reuse a nonce with the same key
- Counter must never wrap around

### 3. GHASH Authentication

GHASH provides cryptographic authentication through:
- **GF(2^128) field multiplication**: Operates in the Galois Field with reduction polynomial
- **Universal hash function**: Computes MAC over AAD and ciphertext
- **H value**: Derived by encrypting zero block with the key

**GHASH Algorithm:**
```
1. Generate H = AES_Encrypt(K, 0^128)
2. Process AAD in 128-bit blocks
3. Process ciphertext in 128-bit blocks  
4. Process length block (AAD_len || CT_len)
5. Each block: tag = GF_mul((tag ⊕ block), H)
```

### 4. GCM Construction

GCM combines CTR mode and GHASH:

**Encryption:**
```
1. Generate random 96-bit nonce
2. Compute H = AES_Encrypt(K, 0^128)
3. Initialize counter: nonce || 0x00000001
4. Compute J0 = counter (save for tag encryption)
5. Increment counter for data encryption
6. Encrypt plaintext using CTR mode
7. Compute GHASH(H, AAD, ciphertext)
8. Encrypt tag: final_tag = GHASH ⊕ AES_Encrypt(K, J0)
9. Output: nonce || ciphertext || tag
```

**Decryption:**
```
1. Split input: nonce || ciphertext || tag
2. Compute H = AES_Encrypt(K, 0^128)
3. Verify tag using GHASH
4. If tag matches: decrypt using CTR mode
5. If tag doesn't match: REJECT (return error)
```

## Security Features

### 1. Confidentiality

- **CTR mode encryption** ensures ciphertext is indistinguishable from random
- **128-bit key** provides 2^128 computational security
- **Nonce uniqueness** prevents pattern analysis across multiple encryptions

### 2. Authenticity & Integrity

- **128-bit authentication tag** provides 2^128 brute-force resistance
- **GHASH** detects any modification to ciphertext or AAD
- **Constant-time tag comparison** prevents timing attacks
- **Tag verification before decryption** prevents padding oracle attacks

### 3. Additional Authenticated Data (AAD)

AAD allows authenticating metadata without encrypting it:
- File headers, version numbers, timestamps
- Routing information, session IDs
- Any data that needs authenticity but not confidentiality

**Example Use Cases:**
- Authenticating file metadata (filename, size, permissions)
- Protocol headers in network communications
- Database record identifiers

## Implementation Security

### Constant-Time Operations

The tag comparison is constant-time to prevent timing attacks:
```go
var tagMatch byte = 0
for i := 0; i < 16; i++ {
    tagMatch |= receivedTag[i] ^ expectedTag[i]
}
if tagMatch != 0 {
    return error
}
```

This ensures the comparison time doesn't leak information about where tags differ.

### Nonce Generation

- Uses `crypto/rand` for cryptographically secure random nonces
- 96-bit (12-byte) nonces provide 2^96 unique values
- Random nonces prevent collision attacks
- **Never reuse a nonce** with the same key

### GF(2^128) Multiplication

The field multiplication is implemented correctly:
- Right-shift with conditional XOR of reduction polynomial
- Handles all 128 bits correctly
- Reduction polynomial: 0xE1 || 0^120

## Known Attack Resistance

### ✅ Resistant To:

1. **Chosen-Plaintext Attacks (CPA)**: CTR mode provides IND-CPA security
2. **Chosen-Ciphertext Attacks (CCA)**: Tag verification provides IND-CCA2 security
3. **Timing Attacks**: Constant-time tag comparison
4. **Padding Oracle Attacks**: No padding used; authenticated before decryption
5. **Bit-Flipping Attacks**: Authentication tag detects any modifications
6. **Replay Attacks**: Use nonces or add timestamps to AAD
7. **Forgery Attacks**: 128-bit tag provides strong authentication

### ⚠️ Important Security Requirements:

1. **Never Reuse Nonces**: With same key, nonce reuse breaks confidentiality and authenticity
2. **Secure Key Storage**: Keys must be kept secret and properly managed
3. **Limit Encryptions per Key**: Practical limit ~2^32 messages per key
4. **Random Nonce Generation**: Always use cryptographically secure RNG

## Comparison with CBC Mode

| Feature | GCM Mode | CBC Mode |
|---------|----------|----------|
| Confidentiality | ✅ Yes | ✅ Yes |
| Authentication | ✅ Built-in | ❌ No (need HMAC) |
| Padding | ✅ Not needed | ⚠️ Required (PKCS#7) |
| Parallelization | ✅ Decrypt parallel | ❌ Sequential |
| Error Propagation | ✅ Limited to block | ⚠️ Affects next block |
| Chosen-Ciphertext | ✅ Resistant | ⚠️ Vulnerable |
| Modern Standard | ✅ Recommended | ⚠️ Legacy |

## Performance Characteristics

From benchmarks on test system:
- **Encryption**: ~780 µs for 1KB data
- **Decryption**: ~775 µs for 1KB data
- **Large files (1MB)**: ~790ms encryption, ~787ms decryption

The implementation prioritizes correctness and security over raw performance. Optimizations for production use could include:
- Table-based GF(2^128) multiplication
- SIMD instructions for XOR operations
- Parallel block processing for large files

## Cryptographic Primitives

All implemented from scratch (no external crypto libraries):

1. ✅ AES-128 block cipher
2. ✅ CTR mode encryption
3. ✅ GHASH universal hash function
4. ✅ GF(2^128) field arithmetic
5. ✅ Secure random number generation (uses crypto/rand)
6. ✅ Constant-time comparison
7. ✅ PKCS#7 padding (for CBC mode)

## Standards Compliance

The implementation follows:
- **NIST SP 800-38D**: GCM specification
- **FIPS 197**: AES specification
- **RFC 5116**: AEAD cipher interface

## Testing

Comprehensive test suite includes:
- Basic encryption/decryption round-trips
- Authentication failure scenarios
- Edge cases (empty files, large files)
- Binary data handling
- AAD verification
- Tamper detection
- Invalid input handling

## Recommendations for Use

### ✅ DO:
- Use GCM mode for new applications
- Generate random nonces for each encryption
- Use AAD for metadata that needs authentication
- Verify tag before processing decrypted data
- Keep keys secure and rotate regularly
- Test authentication failure handling

### ❌ DON'T:
- Reuse nonces with the same key
- Ignore authentication failures
- Use CBC mode without HMAC
- Store keys in plaintext
- Skip tag verification
- Use short keys (<128 bits)

## Limitations

As an educational implementation:
- Not optimized for maximum performance
- Not constant-time in all operations (only tag comparison)
- No side-channel attack hardening
- Limited to AES-128 (not 192 or 256)

For production use, consider:
- Professional security audit
- Constant-time implementation of all sensitive operations
- Side-channel resistance
- Hardware acceleration support
- Formal verification

## References

- NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- FIPS 197: Advanced Encryption Standard (AES)
- RFC 5116: An Interface and Algorithms for Authenticated Encryption
- "The Galois/Counter Mode of Operation (GCM)" by David A. McGrew and John Viega

---

**Version:** 1.0  
**Last Updated:** 2024  
**Author:** SaadSaid158

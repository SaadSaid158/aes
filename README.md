# AES-128 Encryption/Decryption in Go with GCM Mode

This project is a comprehensive implementation of AES-128 encryption and decryption in Go, featuring both CBC and GCM modes with PKCS#7 padding. **All cryptographic primitives are implemented from scratch** without using external cryptographic libraries.

## Features

- **AES-128 block cipher** - Complete implementation with S-boxes, key expansion, and round operations
- **CBC (Cipher Block Chaining) mode** - Traditional encryption mode with PKCS#7 padding
- **GCM (Galois/Counter Mode)** - Advanced authenticated encryption mode with:
  - CTR mode encryption for confidentiality
  - GHASH authentication for integrity verification
  - Support for Additional Authenticated Data (AAD)
  - 128-bit authentication tags
- **File integrity checks** - GCM mode provides cryptographic authentication
- **Command-line interface** for encrypting and decrypting files
- Uses a 16-byte key (exactly) for AES-128 encryption

## Security Features

The GCM implementation provides:
- **Confidentiality**: Data is encrypted using CTR mode
- **Integrity**: Authentication tags detect any tampering
- **Authenticity**: Verifies the data comes from someone with the key
- **AAD Support**: Authenticate additional data without encrypting it
- **Constant-time tag comparison**: Resistant to timing attacks

## Usage

### CBC Mode (Traditional)

#### Encrypt a file
```bash
go run aes.go cli.go encrypt -in file.txt -out file.enc -key "your16bytekey123"
```

#### Decrypt a file
```bash
go run aes.go cli.go decrypt -in file.enc -out file.dec.txt -key "your16bytekey123"
```

### GCM Mode (Authenticated Encryption)

#### Encrypt a file with GCM
```bash
go run aes.go cli.go encrypt-gcm -in file.txt -out file.gcm -key "your16bytekey123"
```

#### Decrypt and verify a file with GCM
```bash
go run aes.go cli.go decrypt-gcm -in file.gcm -out file.dec.txt -key "your16bytekey123"
```

#### Using Additional Authenticated Data (AAD)
AAD allows you to authenticate metadata without encrypting it:
```bash
# Encrypt with AAD
go run aes.go cli.go encrypt-gcm -in file.txt -out file.gcm -key "your16bytekey123" -aad "metadata:v1.0"

# Decrypt with AAD - must match exactly or authentication fails
go run aes.go cli.go decrypt-gcm -in file.gcm -out file.dec.txt -key "your16bytekey123" -aad "metadata:v1.0"
```

### Using Hex Keys

You can also use hexadecimal keys (32 hex characters = 16 bytes):
```bash
go run aes.go cli.go encrypt-gcm -in file.txt -out file.gcm -hexkey "0123456789abcdef0123456789abcdef"
```

## Requirements

* Go 1.18+
* Key must be exactly 16 bytes for AES-128

## How it works

### CBC Mode
* Reads input file in blocks of 16 bytes
* Pads input with PKCS#7 if needed
* Encrypts/decrypts using AES-128 in CBC mode
* Prepends a random 16-byte IV to the ciphertext
* On decryption, extracts the IV and reverses the process

### GCM Mode
* Uses CTR (Counter) mode for encryption
* Computes GHASH over AAD and ciphertext for authentication
* Appends a 128-bit authentication tag to the ciphertext
* Prepends a random 12-byte nonce to the output
* On decryption:
  - Verifies the authentication tag (constant-time comparison)
  - Rejects data if tag doesn't match (tampered/wrong key/wrong AAD)
  - Only returns plaintext if authentication succeeds

### File Format

**CBC encrypted files:**
```
[16-byte IV][ciphertext with PKCS#7 padding]
```

**GCM encrypted files:**
```
[12-byte nonce][ciphertext][16-byte authentication tag]
```

## Testing

Run the comprehensive test suite:
```bash
go test -v
```

Run benchmarks:
```bash
go test -bench=. -benchmem
```

## Security Notes

### GCM Mode (Recommended for new applications)
- ✅ Provides authentication (detects tampering)
- ✅ No padding oracle vulnerabilities
- ✅ Secure against chosen-ciphertext attacks
- ✅ Suitable for production use with proper key management
- ⚠️ Never reuse a nonce with the same key
- ⚠️ Each file encryption generates a random nonce

### CBC Mode (Legacy support)
- ⚠️ No built-in authentication
- ⚠️ Vulnerable to padding oracle attacks if error messages leak info
- ⚠️ Should use HMAC for authentication in production
- ✅ Compatible with standard CBC implementations

## Important Notes

* Do **NOT** open or edit encrypted files (`.enc`, `.gcm`) with text editors — they are binary and will corrupt. Use hex viewers like `xxd` to inspect.
* Always keep your key secret.
* For GCM mode, never reuse a nonce with the same key (our implementation generates random nonces automatically).
* The GCM implementation includes constant-time tag comparison to prevent timing attacks.
* This is a **from-scratch implementation** meant for learning and demonstrating cryptographic concepts. For production use, ensure thorough security review.
* All cryptographic primitives (AES block cipher, CTR mode, GHASH, GF(2^128) multiplication) are implemented without external crypto libraries.

## Implementation Details

### What's Implemented from Scratch
- AES-128 core cipher (S-box, ShiftRows, MixColumns, key expansion)
- CBC mode encryption/decryption
- CTR mode encryption
- GHASH authentication function
- GF(2^128) field multiplication for GCM
- PKCS#7 padding
- Constant-time authentication tag comparison

### Why GCM is Secure
1. **Encryption**: CTR mode provides semantic security
2. **Authentication**: GHASH creates a cryptographic checksum
3. **Tag verification**: Any modification is detected
4. **Nonce uniqueness**: Random nonces prevent replay attacks
5. **AAD support**: Authenticate metadata without encryption

---

Made by SaadSaid158 on GitHub


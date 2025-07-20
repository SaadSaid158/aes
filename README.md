# Simple AES-128 Encryption/Decryption in Go

This project is a basic implementation of AES-128 encryption and decryption in Go, with CBC mode and PKCS#7 padding.

## Features

- AES-128 block cipher  
- CBC (Cipher Block Chaining) mode  
- PKCS#7 padding  
- Command-line interface for encrypting and decrypting files  
- Uses a 16-byte key (exactly) for encryption and decryption  

## Usage

### Encrypt a file

```bash
go run aes.go cli.go encrypt -in file.txt -out file.enc -key "your16bytekey123"
````

### Decrypt a file

```bash
go run aes.go cli.go decrypt -in file.enc -out file.dec.txt -key "your16bytekey123"
```

## Requirements

* Go 1.18+
* Key must be exactly 16 bytes for AES-128

## How it works

* Reads input file in blocks of 16 bytes
* Pads input with PKCS#7 if needed
* Encrypts/decrypts using AES-128 in CBC mode
* Prepends a random 16-byte IV to the ciphertext
* On decryption, extracts the IV and reverses the process

## Important Notes

* Do **NOT** open or edit encrypted files (`.enc`) with text editors — they are binary and will corrupt. Use hex viewers like `xxd` to inspect.
* Always keep your key secret.
* This is a simplified AES implementation meant for learning and basic use — do not use it in production without proper security review.

---

Made by SaadSaid158 on GitHub


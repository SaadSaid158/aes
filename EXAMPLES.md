# AES-GCM Usage Examples

This document provides practical examples of using the AES-GCM implementation for various use cases.

## Basic Usage

### Example 1: Simple File Encryption

```bash
# Encrypt a document
echo "My secret document" > document.txt
go run aes.go cli.go encrypt-gcm \
  -in document.txt \
  -out document.gcm \
  -key "mysecretkey12345"

# Decrypt the document
go run aes.go cli.go decrypt-gcm \
  -in document.gcm \
  -out document.txt \
  -key "mysecretkey12345"
```

### Example 2: Using Hexadecimal Keys

```bash
# Generate a random key
KEY=$(openssl rand -hex 16)
echo "Generated key: $KEY"

# Encrypt with hex key
go run aes.go cli.go encrypt-gcm \
  -in secret.txt \
  -out secret.gcm \
  -hexkey "$KEY"

# Decrypt with hex key
go run aes.go cli.go decrypt-gcm \
  -in secret.gcm \
  -out secret.txt \
  -hexkey "$KEY"
```

## Advanced Usage with AAD

### Example 3: Authenticating File Metadata

```bash
# Encrypt a file with metadata in AAD
FILENAME="report.pdf"
VERSION="v2.0"
CHECKSUM=$(md5sum "$FILENAME" | cut -d' ' -f1)

go run aes.go cli.go encrypt-gcm \
  -in "$FILENAME" \
  -out "${FILENAME}.gcm" \
  -key "1234567890123456" \
  -aad "filename:${FILENAME},version:${VERSION},checksum:${CHECKSUM}"

# Decrypt and verify metadata
go run aes.go cli.go decrypt-gcm \
  -in "${FILENAME}.gcm" \
  -out "${FILENAME}.dec" \
  -key "1234567890123456" \
  -aad "filename:${FILENAME},version:${VERSION},checksum:${CHECKSUM}"
```

### Example 4: Database Record Encryption

```bash
# Encrypt sensitive database fields
RECORD_ID="12345"
TABLE_NAME="users"
TIMESTAMP=$(date +%s)

echo "John Doe:john@example.com:555-1234" > record.txt

go run aes.go cli.go encrypt-gcm \
  -in record.txt \
  -out record.gcm \
  -key "dbencryptionkey1" \
  -aad "table:${TABLE_NAME},id:${RECORD_ID},ts:${TIMESTAMP}"

# Decrypt with same metadata
go run aes.go cli.go decrypt-gcm \
  -in record.gcm \
  -out record.dec \
  -key "dbencryptionkey1" \
  -aad "table:${TABLE_NAME},id:${RECORD_ID},ts:${TIMESTAMP}"
```

## Practical Use Cases

### Example 5: Secure File Backup

```bash
#!/bin/bash
# Secure backup script

BACKUP_DIR="/path/to/backup"
KEY="backupkey123456"
DATE=$(date +%Y%m%d)

# Backup and encrypt files
for file in /path/to/important/*; do
    filename=$(basename "$file")
    go run aes.go cli.go encrypt-gcm \
        -in "$file" \
        -out "${BACKUP_DIR}/${filename}.${DATE}.gcm" \
        -key "$KEY" \
        -aad "backup_date:${DATE},original:${filename}"
    echo "Backed up: $filename"
done
```

### Example 6: Secure Log File Storage

```bash
# Encrypt log files with rotation info
LOG_FILE="app.log"
ROTATION_NUM="001"
DATE=$(date +%Y-%m-%d)

go run aes.go cli.go encrypt-gcm \
  -in "$LOG_FILE" \
  -out "logs/${LOG_FILE}.${ROTATION_NUM}.gcm" \
  -key "logencryptionkey" \
  -aad "log_type:application,date:${DATE},rotation:${ROTATION_NUM}"
```

### Example 7: Configuration File Encryption

```bash
# Encrypt configuration with version tracking
CONFIG_FILE="config.json"
APP_VERSION="1.2.3"
ENV="production"

go run aes.go cli.go encrypt-gcm \
  -in "$CONFIG_FILE" \
  -out "${CONFIG_FILE}.gcm" \
  -key "configkey123456" \
  -aad "app_version:${APP_VERSION},environment:${ENV},type:config"
```

## Security Best Practices

### Example 8: Key Management

```bash
# Generate a strong key and store securely
openssl rand -hex 16 > .encryption_key
chmod 600 .encryption_key

# Use the key from file
KEY=$(cat .encryption_key)

go run aes.go cli.go encrypt-gcm \
  -in sensitive.txt \
  -out sensitive.gcm \
  -hexkey "$KEY"

# Clean up the key variable
unset KEY
```

### Example 9: Integrity Verification

```bash
# Encrypt with comprehensive metadata for integrity
FILE="important.doc"
HASH=$(sha256sum "$FILE" | cut -d' ' -f1)
SIZE=$(stat -f%z "$FILE" 2>/dev/null || stat -c%s "$FILE")

go run aes.go cli.go encrypt-gcm \
  -in "$FILE" \
  -out "${FILE}.gcm" \
  -key "1234567890123456" \
  -aad "sha256:${HASH},size:${SIZE},filename:${FILE}"

# Verify on decrypt - will fail if file was modified before encryption
# or if encrypted file was tampered with
go run aes.go cli.go decrypt-gcm \
  -in "${FILE}.gcm" \
  -out "${FILE}.dec" \
  -key "1234567890123456" \
  -aad "sha256:${HASH},size:${SIZE},filename:${FILE}"
```

## Error Handling

### Example 10: Testing Authentication Failures

```bash
# Encrypt a file
echo "Test data" > test.txt
go run aes.go cli.go encrypt-gcm \
  -in test.txt \
  -out test.gcm \
  -key "1234567890123456" \
  -aad "correct-aad"

# Try to decrypt with wrong AAD (will fail)
go run aes.go cli.go decrypt-gcm \
  -in test.gcm \
  -out test.dec \
  -key "1234567890123456" \
  -aad "wrong-aad"
# Output: "decrypt: authentication failed: tag mismatch"

# Try to decrypt with wrong key (will fail)
go run aes.go cli.go decrypt-gcm \
  -in test.gcm \
  -out test.dec \
  -key "wrongkey1234567" \
  -aad "correct-aad"
# Output: "decrypt: authentication failed: tag mismatch"
```

## Batch Processing

### Example 11: Encrypt Multiple Files

```bash
#!/bin/bash
# Batch encryption script

KEY="batchkey1234567"
INPUT_DIR="./sensitive_data"
OUTPUT_DIR="./encrypted_data"

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        timestamp=$(date +%s)
        
        go run aes.go cli.go encrypt-gcm \
            -in "$file" \
            -out "${OUTPUT_DIR}/${filename}.gcm" \
            -key "$KEY" \
            -aad "original:${filename},timestamp:${timestamp}"
        
        if [ $? -eq 0 ]; then
            echo "✓ Encrypted: $filename"
        else
            echo "✗ Failed: $filename"
        fi
    fi
done
```

### Example 12: Decrypt and Verify Batch

```bash
#!/bin/bash
# Batch decryption with verification

KEY="batchkey1234567"
INPUT_DIR="./encrypted_data"
OUTPUT_DIR="./decrypted_data"

mkdir -p "$OUTPUT_DIR"

for file in "$INPUT_DIR"/*.gcm; do
    if [ -f "$file" ]; then
        filename=$(basename "$file" .gcm)
        
        # Extract metadata from filename if needed
        # This is a simple example
        go run aes.go cli.go decrypt-gcm \
            -in "$file" \
            -out "${OUTPUT_DIR}/${filename}" \
            -key "$KEY"
        
        if [ $? -eq 0 ]; then
            echo "✓ Decrypted and verified: $filename"
        else
            echo "✗ Authentication failed: $filename"
        fi
    fi
done
```

## Integration Examples

### Example 13: Pipeline Integration

```bash
# Use in a data processing pipeline
cat input.txt | \
  go run aes.go cli.go encrypt-gcm \
    -in /dev/stdin \
    -out - \
    -key "pipelinekey1234" | \
  base64 > encrypted_output.b64
```

### Example 14: Backup with Compression

```bash
# Compress then encrypt for efficient backups
tar czf - /path/to/data | \
  go run aes.go cli.go encrypt-gcm \
    -in /dev/stdin \
    -out backup.tar.gz.gcm \
    -key "backupkey123456" \
    -aad "type:compressed_backup,date:$(date +%Y%m%d)"

# Decrypt and decompress
go run aes.go cli.go decrypt-gcm \
  -in backup.tar.gz.gcm \
  -out /dev/stdout \
  -key "backupkey123456" \
  -aad "type:compressed_backup,date:$(date +%Y%m%d)" | \
  tar xzf -
```

## Testing and Validation

### Example 15: Round-trip Testing

```bash
#!/bin/bash
# Verify encryption/decryption integrity

echo "Testing AES-GCM implementation..."

# Create test data
echo "The quick brown fox jumps over the lazy dog" > test_input.txt

# Encrypt
go run aes.go cli.go encrypt-gcm \
  -in test_input.txt \
  -out test_encrypted.gcm \
  -key "testkey123456789"

# Decrypt
go run aes.go cli.go decrypt-gcm \
  -in test_encrypted.gcm \
  -out test_output.txt \
  -key "testkey123456789"

# Compare
if diff test_input.txt test_output.txt > /dev/null; then
    echo "✓ Round-trip test PASSED"
else
    echo "✗ Round-trip test FAILED"
fi

# Cleanup
rm test_input.txt test_encrypted.gcm test_output.txt
```

## Performance Testing

### Example 16: Benchmark Different File Sizes

```bash
#!/bin/bash
# Benchmark encryption/decryption performance

KEY="benchmarkkey123"

for size in 1k 10k 100k 1M 10M; do
    echo "Testing ${size} file..."
    
    # Generate test file
    dd if=/dev/urandom of=test_${size}.bin bs=${size%k}k count=1 2>/dev/null || \
    dd if=/dev/urandom of=test_${size}.bin bs=${size%M}M count=1 2>/dev/null
    
    # Time encryption
    echo -n "  Encryption: "
    time go run aes.go cli.go encrypt-gcm \
        -in test_${size}.bin \
        -out test_${size}.gcm \
        -key "$KEY" 2>&1 | grep real
    
    # Time decryption
    echo -n "  Decryption: "
    time go run aes.go cli.go decrypt-gcm \
        -in test_${size}.gcm \
        -out test_${size}.dec \
        -key "$KEY" 2>&1 | grep real
    
    # Cleanup
    rm test_${size}.bin test_${size}.gcm test_${size}.dec
done
```

## Summary

These examples demonstrate:
- Basic encryption/decryption workflows
- Advanced features using AAD
- Practical use cases (backups, logs, configs)
- Security best practices
- Batch processing
- Integration with other tools
- Testing and validation
- Performance benchmarking

For more information, see:
- README.md - General usage and features
- SECURITY.md - Security details and implementation
- aes_test.go - Unit tests and examples

---

**Note:** These examples use placeholder keys for demonstration. In production, always use properly generated and securely stored keys.

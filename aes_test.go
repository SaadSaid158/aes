package main

import (
	"bytes"
	"testing"
)

func TestGCMEncryptDecrypt(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := []byte("Hello, AES-GCM!")
	aad := []byte("")

	ciphertext, err := GCMEncrypt(plaintext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	decrypted, err := GCMDecrypt(ciphertext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match. Got %s, want %s", decrypted, plaintext)
	}
}

func TestGCMWithAAD(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := []byte("Secret message with AAD")
	aad := []byte("metadata:version=1.0")

	ciphertext, err := GCMEncrypt(plaintext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	decrypted, err := GCMDecrypt(ciphertext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match")
	}
}

func TestGCMAuthenticationFailure(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := []byte("Authenticated message")
	aad := []byte("correct-aad")

	ciphertext, err := GCMEncrypt(plaintext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// Test with wrong AAD
	wrongAAD := []byte("wrong-aad")
	_, err = GCMDecrypt(ciphertext, key, nonce, wrongAAD)
	if err == nil {
		t.Error("Expected authentication failure with wrong AAD, but got success")
	}

	// Test with wrong key
	wrongKey := []byte("6543210987654321")
	_, err = GCMDecrypt(ciphertext, wrongKey, nonce, aad)
	if err == nil {
		t.Error("Expected authentication failure with wrong key, but got success")
	}

	// Test with tampered ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[5] ^= 0x01 // Flip a bit
	_, err = GCMDecrypt(tampered, key, nonce, aad)
	if err == nil {
		t.Error("Expected authentication failure with tampered ciphertext, but got success")
	}
}

func TestGCMEmptyPlaintext(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := []byte("")
	aad := []byte("metadata")

	ciphertext, err := GCMEncrypt(plaintext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	decrypted, err := GCMDecrypt(ciphertext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match for empty plaintext")
	}
}

func TestGCMLargePlaintext(t *testing.T) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := make([]byte, 10000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	aad := []byte("large-data")

	ciphertext, err := GCMEncrypt(plaintext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	decrypted, err := GCMDecrypt(ciphertext, key, nonce, aad)
	if err != nil {
		t.Fatalf("GCMDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match for large plaintext")
	}
}

func TestGCMInvalidInputs(t *testing.T) {
	validKey := []byte("1234567890123456")
	invalidKey := []byte("short")
	validNonce := []byte("123456789012")
	invalidNonce := []byte("short")
	plaintext := []byte("test")
	aad := []byte("")

	// Test invalid key length
	_, err := GCMEncrypt(plaintext, invalidKey, validNonce, aad)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}

	// Test invalid nonce length
	_, err = GCMEncrypt(plaintext, validKey, invalidNonce, aad)
	if err == nil {
		t.Error("Expected error for invalid nonce length")
	}

	// Test decryption with short ciphertext
	shortCiphertext := []byte("short")
	_, err = GCMDecrypt(shortCiphertext, validKey, validNonce, aad)
	if err == nil {
		t.Error("Expected error for short ciphertext")
	}
}

func TestCTRMode(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	plaintext := []byte("CTR mode test data")

	// Encrypt
	ciphertext, err := CTREncrypt(plaintext, key, iv)
	if err != nil {
		t.Fatalf("CTREncrypt failed: %v", err)
	}

	// Decrypt (CTR is symmetric)
	decrypted, err := CTREncrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("CTREncrypt (decrypt) failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CTR mode decryption failed")
	}
}

func TestGFMul(t *testing.T) {
	// Test with zero
	zero := make([]byte, 16)
	x := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	result := gfMul(x, zero)
	if !bytes.Equal(result, zero) {
		t.Error("Multiplication with zero should yield zero")
	}

	// Test commutativity
	y := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	result1 := gfMul(x, y)
	result2 := gfMul(y, x)
	if !bytes.Equal(result1, result2) {
		t.Error("GF multiplication should be commutative")
	}
}

func TestCBCEncryptDecrypt(t *testing.T) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	plaintext := []byte("Test CBC mode encryption")

	ciphertext, err := CBCEncrypt(plaintext, key, iv)
	if err != nil {
		t.Fatalf("CBCEncrypt failed: %v", err)
	}

	decrypted, err := CBCDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("CBCDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CBC mode decryption failed")
	}
}

func TestPKCS7Padding(t *testing.T) {
	data := []byte("test")
	blockSize := 16

	padded := PKCS7Pad(data, blockSize)
	if len(padded)%blockSize != 0 {
		t.Error("Padded data length is not a multiple of block size")
	}

	unpadded, err := PKCS7Unpad(padded, blockSize)
	if err != nil {
		t.Fatalf("PKCS7Unpad failed: %v", err)
	}

	if !bytes.Equal(data, unpadded) {
		t.Errorf("Unpadded data doesn't match original")
	}
}

func BenchmarkGCMEncrypt(b *testing.B) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := make([]byte, 1024)
	aad := []byte("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GCMEncrypt(plaintext, key, nonce, aad)
	}
}

func BenchmarkGCMDecrypt(b *testing.B) {
	key := []byte("1234567890123456")
	nonce := []byte("123456789012")
	plaintext := make([]byte, 1024)
	aad := []byte("benchmark")
	ciphertext, _ := GCMEncrypt(plaintext, key, nonce, aad)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GCMDecrypt(ciphertext, key, nonce, aad)
	}
}

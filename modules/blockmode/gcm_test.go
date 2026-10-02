package blockmode

import (
	"testing"

	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func TestGCMMode(t *testing.T) {
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}

	nonce := []byte{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b,
	}

	plain := []byte{
		0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
		0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
		0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	}

	a, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	std, err := cipher.NewGCM(a)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}
	ciphertext1 := std.Seal(nil, nonce, plain, nil)

	gcm, err := NewGCM(a)
	if err != nil {
		t.Fatalf("Failed to create custom GCM: %v", err)
	}
	ciphertext2 := gcm.Seal(nil, nonce, plain, nil)

	if len(ciphertext1) != len(ciphertext2) {
		t.Fatalf("Ciphertext lengths differ: %d <=> %d", len(ciphertext1), len(ciphertext2))
	}

	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Fatalf("Ciphertexts differ:\nStd: %x\nGCM: %x", ciphertext1, ciphertext2)
	}
}

package hash

import (
	"testing"

	"bytes"
	"crypto/sha1"
)

func TestHashAlgorithmSum(t *testing.T) {
	data := []byte("lorem ipsum dolor sit amet")

	got := SHA1.Sum(data)
	exp := sha1.Sum(data)
	if !bytes.Equal(got, exp[:]) {
		t.Errorf("SHA1.Sum() = %x, want %x", got, exp)
	}
}

func TestHashAlgorithmSumInvalid(t *testing.T) {
	data := []byte("lorem ipsum dolor sit amet")

	crashed := false

	defer func() {
		if r := recover(); r != nil {
			crashed = true
		}

		if !crashed {
			t.Errorf("HashInvalid.Sum() did not panic")
		}
	}()

	got := HashInvalid.Sum(data)
	if got != nil {
		t.Errorf("HashInvalid.Sum() = %v, want %v", got, nil)
	}
}

func TestHashAlgorithmInfoValid(t *testing.T) {
	if SHA1.Name() != "SHA-1" {
		t.Errorf("SHA1.Name() = %s, want %s", SHA1.Name(), "SHA-1")
	}

	if SHA1.BlockSize() != 64 {
		t.Errorf("SHA1.BlockSize() = %d, want %d", SHA1.BlockSize(), 64)
	}

	if SHA1.Size() != 20 {
		t.Errorf("SHA1.Size() = %d, want %d", SHA1.Size(), 20)
	}
}

func TestHashAlgorithmInfoInvalid(t *testing.T) {
	if HashInvalid.Name() != "unknown" {
		t.Errorf("HashInvalid.Name() = %s, want %s", HashInvalid.Name(), "unknown")
	}

	if HashInvalid.BlockSize() != 0 {
		t.Errorf("HashInvalid.BlockSize() = %d, want %d", HashInvalid.BlockSize(), 0)
	}

	if HashInvalid.Size() != 0 {
		t.Errorf("HashInvalid.Size() = %d, want %d", HashInvalid.Size(), 0)
	}
}

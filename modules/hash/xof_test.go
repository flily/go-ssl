package hash

import (
	"testing"

	"bytes"
	"crypto/sha3"
)

func TestXOFSum(t *testing.T) {
	data := []byte("lorem ipsum dolor sit amet")
	length := 32

	got := SHAKE128.Sum(data, length)
	if len(got) != length {
		t.Errorf("expected sum length %d, got %d", length, len(got))
	}

	exp := sha3.SumSHAKE128(data, length)
	if !bytes.Equal(got, exp) {
		t.Errorf("expected sum %x, got %x", exp, got)
	}
}

func TestXOFAlgorithmSumInvalid(t *testing.T) {
	data := []byte("lorem ipsum dolor sit amet")
	length := 32

	crash := false

	defer func() {
		if r := recover(); r != nil {
			crash = true
		}

		if !crash {
			t.Errorf("XOFInvalid.Sum() did not panic")
		}
	}()

	got := XOFInvalid.Sum(data, length)
	if got != nil {
		t.Errorf("expected panic, but got result %x", got)
	}
}

func TestXOFAlgorithmInfoValid(t *testing.T) {
	if SHAKE128.Name() != "SHAKE128" {
		t.Errorf("SHAKE128.Name() = %s, want %s", SHAKE128.Name(), "SHAKE128")
	}

	if SHAKE128.BlockSize() != 168 {
		t.Errorf("SHAKE128.BlockSize() = %d, want %d", SHAKE128.BlockSize(), 64)
	}

	if SHAKE128.Size() != 32 {
		t.Errorf("SHAKE128.Size() = %d, want %d", SHAKE128.Size(), 32)
	}
}

func TestXOFAlgorithmInfoInvalid(t *testing.T) {
	if XOFInvalid.Name() != "XOFInvalid" {
		t.Errorf("XOFInvalid.Name() = %s, want %s", XOFInvalid.Name(), "XOFInvalid")
	}

	if XOFInvalid.BlockSize() != 0 {
		t.Errorf("XOFInvalid.BlockSize() = %d, want %d", XOFInvalid.BlockSize(), 0)
	}

	if XOFInvalid.Size() != 0 {
		t.Errorf("XOFInvalid.Size() = %d, want %d", XOFInvalid.Size(), 0)
	}
}

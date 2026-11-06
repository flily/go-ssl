package hash

import (
	"testing"

	"bytes"
	"crypto/sha3"
	"hash"
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
		t.Errorf("SHAKE128.BlockSize() = %d, want %d", SHAKE128.BlockSize(), 168)
	}

	if SHAKE128.Size() != 32 {
		t.Errorf("SHAKE128.Size() = %d, want %d", SHAKE128.Size(), 32)
	}
}

func TestXOFAlgorithmInfoInvalid(t *testing.T) {
	if XOFInvalid.Name() != "unknown" {
		t.Errorf("XOFInvalid.Name() = %s, want %s", XOFInvalid.Name(), "unknown")
	}

	if XOFInvalid.BlockSize() != 0 {
		t.Errorf("XOFInvalid.BlockSize() = %d, want %d", XOFInvalid.BlockSize(), 0)
	}

	if XOFInvalid.Size() != 0 {
		t.Errorf("XOFInvalid.Size() = %d, want %d", XOFInvalid.Size(), 0)
	}
}

func TestXOFRegister(t *testing.T) {
	x := XOFInvalid - 1
	if CheckXOFRegistered(x) {
		t.Errorf("XOF %v should not be registered", x)
	}

	RegisterXOFAlgorithm(x, AlgorithmInfo[hash.XOF]{
		Name:      "TestXOF",
		BlockSize: 64,
		Size:      32,
		New:       xofWrap(sha3.NewSHAKE128),
	})

	if !CheckXOFRegistered(x) {
		t.Errorf("XOF %v should be registered", x)
	}

	if x.Name() != "TestXOF" {
		t.Errorf("x.Name() = %s, want %s", x.Name(), "TestXOF")
	}

	if x.BlockSize() != 64 {
		t.Errorf("x.BlockSize() = %d, want %d", x.BlockSize(), 64)
	}

	if x.Size() != 32 {
		t.Errorf("x.Size() = %d, want %d", x.Size(), 32)
	}
}

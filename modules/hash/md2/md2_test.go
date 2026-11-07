package md2

import (
	"bytes"
	"testing"

	"encoding/hex"
)

func TestMD2BasicInfo(t *testing.T) {
	md2 := NewMD2State()

	if md2.Size() != MD2OutputSize {
		t.Errorf("MD2 size = %d; want %d", md2.Size(), MD2OutputSize)
	}

	if md2.BlockSize() != MD2BlockSize {
		t.Errorf("MD2 block size = %d; want %d", md2.BlockSize(), MD2BlockSize)
	}
}

func calcHashSum(input string) []byte {
	s := New()
	s.Write([]byte(input))
	return s.Sum(nil)
}

func TestMD2(t *testing.T) {
	testSuite := []struct {
		input    string
		expected string
	}{
		{"", "8350e5a3e24c153df2275c9f80692773"},
		{"a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"},
		{"abc", "da853b0d3f88d99b30283a69e6ded6bb"},
		{"message digest", "ab4f496bfb2a530b219ff33031fe06b0"},
		{"abcdefghijklmnopqrstuvwxyz",
			"4e8ddff3650292ab5a4108c3aa47940b"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"da33def2a42df13975352846c30338cd"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			"d5976f79d83d3a0dc9806c3c66f3efd8"},
	}

	for _, tt := range testSuite {
		input := []byte(tt.input)
		output := Sum(input)

		got1 := hex.EncodeToString(output)
		if got1 != tt.expected {
			t.Errorf("MD2(%q) = %s; want %s", tt.input, got1, tt.expected)
		}

		got2 := calcHashSum(tt.input)
		if !bytes.Equal(got2, output) {
			t.Errorf("MD2(calcHashSum) %q = %x; want %s", tt.input, got2, tt.expected)
		}
	}
}

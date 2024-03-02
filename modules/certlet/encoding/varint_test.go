package encoding

import (
	"testing"

	"bytes"
	"encoding/binary"
)

func TestEncodeVarUint(t *testing.T) {
	cases := []uint64{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		100, 1000, 1000, 10000, 100000, 1000000, 10000000, 100000000,
		0x7fffffff, 0xffffffffffffffff,
	}

	for _, caseValue := range cases {
		buffer := make([]byte, 10)
		exp := make([]byte, 10)
		offset := 0
		size := EncodeVarUint(caseValue, buffer, offset)

		expSize := binary.PutUvarint(exp, caseValue)
		if !bytes.Equal(buffer[:size], exp[:expSize]) {
			t.Errorf("EncodeVarUint(%d) -> %v, expected %v", caseValue, buffer[:size], exp[:expSize])
		}

		value, length := DecodeVarUint(exp, 0)
		if value != caseValue {
			t.Errorf("DecodeVarUint(%v) -> %d, expected %d", buffer, value, caseValue)
		}

		if length != size {
			t.Errorf("DecodeVarUint(%v) shift %d, expected %d", buffer, length, size)
		}
	}
}

func TestEncodeVarInt(t *testing.T) {
	cases := []int64{
		0,
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
		100, 1000, 1000, 10000, 100000, 1000000, 10000000, 100000000,
		0x7fffffff,
		-1, -2, -3, -4, -5, -6, -7, -8, -9, -10,
		-100, -1000, -1000, -10000, -100000, -1000000, -10000000, -100000000,
		-0x7fffffff,
	}

	for _, c := range cases {
		buffer := make([]byte, 10)
		exp := make([]byte, 10)
		offset := 0
		size := EncodeVarInt(c, buffer, offset)

		expSize := binary.PutVarint(exp, c)
		if !bytes.Equal(buffer[:size], exp[:expSize]) {
			t.Errorf("EncodeVarInt(%d) -> %v, expected %v", c, buffer[:size], exp[:expSize])
		}

		value, length := DecodeVarInt(buffer, 0)
		if value != c {
			t.Errorf("DecodeVarInt(%v) -> %d, expected %d", buffer, value, c)
		}

		if length != size {
			t.Errorf("DecodeVarInt(%v) shift %d, expected %d", buffer, length, size)
		}
	}
}

package asn1

import (
	"math/big"
	"testing"

	"bytes"
)

func TestBooleanContentEncoding(t *testing.T) {
	cases := []struct {
		value    bool
		expected []byte
	}{
		{true, []byte{0xff}},
		{false, []byte{0x00}},
	}

	buffer := make([]byte, 10)
	for _, c := range cases {
		b0 := ASN1Boolean(c.value)
		wNext, err := b0.WriteContentTo(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if wNext != len(c.expected) {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				wNext, len(c.expected), c.value)
		}

		if !bytes.Equal(buffer[:wNext], c.expected) {
			t.Errorf("wrong encoding result: %x, expected %x, case: %+v",
				buffer[:wNext], c.expected, c.value)
		}

		info := &ASN1ObjectInfo{
			Tag:    b0.Tag(),
			Length: Length(len(c.expected)),
		}

		b1 := ASN1Boolean(false)
		err = b1.ReadContentFrom(buffer, 0, info)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if b1 != b0 {
			t.Errorf("wrong content parsed: %+v, expected %+v", b1, b0)
		}
	}
}

func TestIntegerContentEncoding(t *testing.T) {
	cases := []struct {
		value    string
		expected []byte
	}{
		{"0", []byte{0x00}},
		{"1", []byte{0x01}},
		{"65537", []byte{0x01, 0x00, 0x01}},
		{
			"660120406528392010727777090606429476144773442509892602153340612912441438508344516" +
				"5102057553180206149348965242768485",
			[]byte{
				0x2a, 0xe3, 0x8e, 0x2e, 0x39, 0xb0, 0x1a, 0x0b,
				0x63, 0x1b, 0xa4, 0x80, 0x48, 0x5e, 0x16, 0xd9,
				0xef, 0x0a, 0xb5, 0x06, 0x40, 0x35, 0x1b, 0x18,
				0x5c, 0xc5, 0xc9, 0x0c, 0x6c, 0x01, 0x0a, 0x2f,
				0x5f, 0x33, 0xb4, 0x32, 0x4b, 0xd7, 0x6f, 0x94,
				0x52, 0xf0, 0xad, 0xc0, 0xe0, 0xd6, 0x0c, 0x65,
			},
		},
		{
			"353209003965517638468589608377663767683273299268719472909261807022798720986911776" +
				"42687624258287709119380894217091237",
			[]byte{
				0x00, 0xe5, 0x7c, 0x09, 0x8a, 0x46, 0xe9, 0x93,
				0xfa, 0xb2, 0x41, 0xea, 0xf3, 0x79, 0x4b, 0x29,
				0xb9, 0x92, 0xa1, 0xaa, 0x1d, 0x4a, 0x3e, 0xe8,
				0xf6, 0xb8, 0x17, 0x69, 0xf2, 0xf8, 0x9c, 0xb8,
				0x1c, 0x6e, 0x4c, 0x95, 0x1d, 0xd5, 0x6f, 0x9d,
				0xdc, 0xb9, 0xa2, 0x90, 0xe5, 0x20, 0x1b, 0x38,
				0xa5,
			},
		},
	}

	buffer := make([]byte, 100)
	for _, c := range cases {
		num := big.NewInt(0)
		_, ok := num.SetString(c.value, 10)
		if !ok {
			t.Fatalf("failed to parse number '%s'", c.value)
		}

		i0 := NewInteger(num)
		wNext, err := i0.WriteContentTo(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if wNext != len(c.expected) {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				wNext, len(c.expected), c.value)
		}

		if !bytes.Equal(buffer[:wNext], c.expected) {
			t.Errorf("wrong encoding result: %x, expected %x, case: %+v",
				buffer[:wNext], c.expected, c.value)
		}

		info := &ASN1ObjectInfo{
			Tag:    i0.Tag(),
			Length: Length(len(c.expected)),
		}

		i1 := NewIntegerFromInt64(0)
		err = i1.ReadContentFrom(buffer, 0, info)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if !i0.Equal(i1) {
			t.Errorf("wrong content parsed: %+v, expected %+v", i1, i0)
		}
	}
}

func TestBitStringPrimitiveEncoding(t *testing.T) {
	cases := []struct {
		data     []byte
		length   int
		expected []byte
	}{
		{
			data:     []byte{0x0a, 0x3b, 0x5f, 0x29, 0xc1, 0xd0},
			length:   44,
			expected: []byte{0x04, 0x0a, 0x3b, 0x5f, 0x29, 0xc1, 0xd0},
		},
		{
			data:     []byte{0x0a, 0x3b, 0x5f, 0x29, 0xc1, 0xd0},
			length:   48,
			expected: []byte{0x00, 0x0a, 0x3b, 0x5f, 0x29, 0xc1, 0xd0},
		},
	}

	buffer := make([]byte, 100)
	for _, c := range cases {
		bs := NewBitString(c.data, c.length)
		wNext, err := bs.WriteContentTo(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.data)
		}

		if wNext != len(c.expected) {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				wNext, len(c.expected), c.data)
		}

		if !bytes.Equal(buffer[:wNext], c.expected) {
			t.Errorf("wrong encoding result: %x, expected %x, case: %+v",
				buffer[:wNext], c.expected, c.data)
		}

		info := &ASN1ObjectInfo{
			Tag:    bs.Tag(),
			Length: Length(len(c.expected)),
		}

		bs1 := NewBitString(nil, 0)
		err = bs1.ReadContentFrom(buffer, 0, info)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.data)
		}

		if !bytes.Equal(bs1.Data, c.data) {
			t.Errorf("wrong content parsed: %+v, expected %+v", bs1.Data, bs.Data)
		}
	}
}

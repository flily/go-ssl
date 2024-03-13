package asn1

import (
	"testing"

	"bytes"
)

func TestLengthEncoding(t *testing.T) {
	cases := []struct {
		length   int
		expected []byte
	}{
		{3, []byte{0x03}},
		{38, []byte{38}},          // example in X.690 8.1.3.4
		{201, []byte{0x81, 0xc9}}, // example in X.690 8.1.3.5
		{257, []byte{0x82, 0x01, 0x01}},
		{1212, []byte{0x82, 0x04, 0xbc}},
	}

	buffer := make([]byte, 10)
	for _, c := range cases {
		l0 := Length(c.length)
		wNext, err := l0.WriteTo(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.length)
		}

		if wNext != len(c.expected) {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				wNext, len(c.expected), c.length)
		}

		if !bytes.Equal(buffer[:wNext], c.expected) {
			t.Errorf("wrong encoding result: %x, expected %x, case: %+v",
				buffer[:wNext], c.expected, c.length)
		}

		l1 := Length(0)
		rNext, err := l1.ReadFrom(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.length)
		}

		if rNext != wNext {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				rNext, wNext, c.length)
		}

		if l1 != l0 {
			t.Errorf("wrong length parsed: %+v, expected %+v", l1, l0)
		}

		if l1.Int() != c.length {
			t.Errorf("wrong length parsed: %+v, expected %+v", l1, c.length)
		}
	}
}

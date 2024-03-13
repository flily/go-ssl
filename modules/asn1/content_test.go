package asn1

import (
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

		b1 := ASN1Boolean(false)
		err = b1.ReadContentFrom(buffer, 0, 1)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if b1 != b0 {
			t.Errorf("wrong content parsed: %+v, expected %+v", b1, b0)
		}
	}
}

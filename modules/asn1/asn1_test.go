package asn1

import (
	"testing"

	"bytes"
)

func TestBooleanEncoding(t *testing.T) {
	cases := []struct {
		value    bool
		expected []byte
	}{
		{true, []byte{0x01, 0x01, 0xff}},
		{false, []byte{0x01, 0x01, 0x00}},
	}

	buffer := make([]byte, 10)
	for _, c := range cases {
		b0 := NewBoolean(c.value)
		wNext, err := WriteASN1Objects(buffer, 0, b0)
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

		results, rNext, err := ReadASN1Objects(buffer, 0, wNext)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if rNext != wNext {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				rNext, wNext, c.value)
		}

		if len(results) != 1 {
			t.Errorf("wrong number of objects parsed: %d, expected 1", len(results))
		}

		b1, typeOk := results[0].(*ASN1Boolean)
		if !typeOk {
			t.Errorf("wrong type parsed: %T, expected *ASN1Boolean", results[0])
			continue
		}

		if b1 == nil {
			t.Errorf("nil object parsed")
			continue
		}

		if *b1 != *b0 {
			t.Errorf("wrong content parsed: %+v, expected %+v", b1, b0)
		}
	}
}

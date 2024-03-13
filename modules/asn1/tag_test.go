package asn1

import (
	"testing"

	"bytes"
)

func TestTagEncoding(t *testing.T) {
	cases := []struct {
		tag      *Tag
		expected []byte
	}{
		{
			&Tag{TagClassUniversal, TagSequence, true},
			[]byte{0x30},
		},
		{
			&Tag{TagClassPrivate, 0x1234, false},
			//   0001 0010   0011 0100
			// [1]010 0100 [0]011 0100
			[]byte{0xdf, 0xa4, 0x34},
		},
	}

	buffer := make([]byte, 10)
	for _, c := range cases {
		wNext, err := c.tag.WriteTo(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.tag)
		}

		if wNext != len(c.expected) {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				wNext, len(c.expected), c.tag)
		}

		if !bytes.Equal(buffer[:wNext], c.expected) {
			t.Errorf("wrong encoding result: %x, expected %x, case: %+v",
				buffer[:wNext], c.expected, c.tag)
		}

		tag, rNext, err := ParseTag(buffer, 0)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.tag)
		}

		if rNext != wNext {
			t.Errorf("wrong next offset %d returned, expected %d, case: %+v",
				rNext, wNext, c.tag)
		}

		if *tag != *c.tag {
			t.Errorf("wrong tag parsed: %+v, expected %+v", *tag, *c.tag)
		}
	}
}

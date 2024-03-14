package asn1

import (
	"testing"

	"bytes"
)

func TestObjectIdentifierEncoding(t *testing.T) {
	cases := []struct {
		value    []uint64
		expected []byte
	}{
		{
			[]uint64{2, 5, 4, 6},
			[]byte{0x55, 0x04, 0x06},
		},
	}

	buffer := make([]byte, 100)
	for _, c := range cases {
		obj0 := ASN1ObjectIdentifier(c.value)
		wNext, err := obj0.WriteContentTo(buffer, 0)
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
			Tag:    obj0.Tag(),
			Length: Length(len(c.expected)),
		}
		obj1 := &ASN1ObjectIdentifier{}
		err = obj1.ReadContentFrom(buffer, 0, info)
		if err != nil {
			t.Errorf("unexpected error '%v' on case: %+v", err, c.value)
		}

		if !obj0.Equal(obj1) {
			t.Errorf("wrong content parsed: %+v, expected %+v", obj1, obj0)
		}
	}
}

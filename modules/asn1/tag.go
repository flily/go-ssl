package asn1

import (
	"fmt"
)

type TagClass uint8

type Tag struct {
	Class       TagClass
	Number      uint64
	Constructed bool
}

const (
	// Defined X.690 8.1.2.2.a Table 1
	TagClassUniversal       TagClass = 0
	TagClassApplication     TagClass = 1
	TagClassContextSpecific TagClass = 2
	TagClassPrivate         TagClass = 3

	// Defined X.680 8.4 Table 1
	TagReserved0          = 0
	TagBoolean            = 1
	TagInteger            = 2
	TagBitString          = 3
	TagOctetString        = 4
	TagNull               = 5
	TagObjectIdentifier   = 6
	TagObjectDescriptor   = 7
	TagExternalInstanceOf = 8
	TagReal               = 9
	TagEnumerated         = 10
	TagEmbeddedPDV        = 11
	TagUTF8String         = 12
	TagRelativeOID        = 13
	TagTime               = 14
	TagReserved15         = 15
	TagSequence           = 16
	TagSet                = 17
	TagNumericString      = 18
	TagPrintableString    = 19
	TagT61String          = 20
	TagIA5String          = 22
	TagUTCTime            = 23
	TagGeneralizedTime    = 24
	TagGeneralString      = 27
	TagBMPString          = 30

	TagMaskClass       = 0xc0
	TagMaskConstructed = 0x20
	TagMaskNumber      = 0x1f
)

func (c TagClass) String() string {
	switch c {
	case TagClassUniversal:
		return "Universal"
	case TagClassApplication:
		return "Application"
	case TagClassContextSpecific:
		return "ContextSpecific"
	case TagClassPrivate:
		return "Private"
	}

	// This should never happen
	return fmt.Sprintf("UnknownClass(%d)", c)
}

var tagNames = map[uint64]string{
	TagBoolean:          "Boolean",
	TagInteger:          "Integer",
	TagBitString:        "BitString",
	TagOctetString:      "OctetString",
	TagNull:             "Null",
	TagObjectIdentifier: "ObjectIdentifier",
	TagEnumerated:       "Enumerated",
	TagUTF8String:       "UTF8String",
	TagSequence:         "Sequence",
	TagSet:              "Set",
	TagNumericString:    "NumericString",
	TagPrintableString:  "PrintableString",
	TagT61String:        "T61String",
	TagIA5String:        "IA5String",
	TagUTCTime:          "UTCTime",
	TagGeneralizedTime:  "GeneralizedTime",
	TagGeneralString:    "GeneralString",
	TagBMPString:        "BMPString",
}

func getTagNumberName(n uint64) string {
	if name, ok := tagNames[n]; ok {
		return name
	}

	return fmt.Sprintf("UnknownTag(%d)", n)
}

func (t *Tag) String() string {
	c := ""
	if t.Constructed {
		c = " C"
	}
	s := fmt.Sprintf("Tag[class=%s number=%s%s]",
		t.Class, getTagNumberName(t.Number), c)

	return s
}

func (t *Tag) WireLength() int {
	if t.Number <= 30 {
		return 1
	}

	return 1 + getBase128UintByteSize(t.Number)

}

func (t *Tag) ReadFrom(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, 1); err != nil {
		return -1, err
	}

	firstOctet := buffer[offset]

	t.Class = TagClass(firstOctet >> 6)
	t.Constructed = (firstOctet & TagMaskConstructed) != 0
	num := uint64(firstOctet & 0x1f)
	if num <= 30 {
		t.Number = num
		return offset + 1, nil
	}

	num, i := 0, offset+1
	finished := false
	for i < len(buffer) && !finished {
		b := buffer[i]
		i += 1
		num = (num << 7) | uint64(b&0x7f)
		if b&0x80 == 0 {
			finished = true
		}
	}

	if !finished {
		return -1, fmt.Errorf("asn1: invalid tag number at byte %d", i)
	}

	t.Number = num
	return i, nil
}

func ReadTag(buffer []byte, offset int) (*Tag, int, error) {
	t := &Tag{}
	next, err := t.ReadFrom(buffer, offset)
	if err != nil {
		return nil, -1, err
	}

	return t, next, nil
}

func (t *Tag) WriteTo(buffer []byte, offset int) (int, error) {

	mask := byte(t.Class) << 6
	if t.Constructed {
		mask |= TagMaskConstructed
	}

	if t.Number <= 30 {
		if err := checkBufferSize(buffer, offset, 1); err != nil {
			return -1, err
		}

		buffer[offset] = mask | byte(t.Number)
		return offset + 1, nil
	}

	num := t.Number
	size := getBase128UintByteSize(num)
	if err := checkBufferSize(buffer, offset, size+1); err != nil {
		return -1, err
	}

	buffer[offset] = mask | 0x1f
	for i := 0; i < size; i++ {
		b := num >> uint((size-i-1)*7)
		if i < size-1 {
			b |= 0x80
		}

		buffer[offset+i+1] = byte(b)
	}

	return offset + size + 1, nil
}

func ParseTag(buffer []byte, offset int) (*Tag, int, error) {
	t := &Tag{}
	next, err := t.ReadFrom(buffer, offset)
	if err != nil {
		return nil, -1, err
	}

	return t, next, nil
}

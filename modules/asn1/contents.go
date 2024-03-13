package asn1

type ASN1Boolean bool

func NewBoolean(value bool) *ASN1Boolean {
	b := ASN1Boolean(value)
	return &b
}

func (b *ASN1Boolean) Tag() Tag {
	t := Tag{
		Class:       TagClassUniversal,
		Constructed: false, // X.690 8.2.1, boolen value SHALL BE primitive
		Number:      TagBoolean,
	}

	return t
}

func (b *ASN1Boolean) ContentLength() Length {
	return 1
}

func (b *ASN1Boolean) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, 1); err != nil {
		return -1, err
	}

	if *b {
		buffer[offset] = 0xff
	} else {
		buffer[offset] = 0x00
	}

	return offset + 1, nil
}

func (b *ASN1Boolean) ReadContentFrom(buffer []byte, offset int, length Length) error {
	if err := checkBufferSize(buffer, offset, 1); err != nil {
		return err
	}

	v := buffer[offset]
	if v == 0x00 {
		*b = false
	} else {
		*b = true
	}

	return nil
}

func (b *ASN1Boolean) String() string {
	if *b {
		return "Boolean[true]"
	} else {
		return "Boolean[false]"
	}
}

func (b *ASN1Boolean) PrettyString(indent string) string {
	return indent + b.String()
}

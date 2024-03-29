package asn1

// asn1 implements DER encoding and decoding of ASN.1 data structures.
// Reference:
//   - ITU-T X.680, ISO/IEC 8824-1:2021
//   - ITU-T X.690, ISO/IEC 8825-1:2021

type ASN1ObjectInfo struct {
	Tag    *Tag
	Length Length
}

func NewASN1ObjectInfo(tag *Tag, length Length) *ASN1ObjectInfo {
	i := &ASN1ObjectInfo{
		Tag:    tag,
		Length: length,
	}

	return i
}

type ASN1Object interface {
	Tag() *Tag
	ContentLength() Length
	WriteContentTo(buffer []byte, offset int) (int, error)
	ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error
	String() string
	PrettyString(indent string) string
	Equal(other ASN1Object) bool
}

func WriteASN1Objects(buffer []byte, offset int, objects ...ASN1Object) (int, error) {
	for _, obj := range objects {
		tag := obj.Tag()
		wNext, err := tag.WriteTo(buffer, offset)
		if err != nil {
			return -1, err
		}
		offset = wNext

		length := obj.ContentLength()
		wNext, err = length.WriteTo(buffer, offset)
		if err != nil {
			return -1, err
		}
		offset = wNext

		wNext, err = obj.WriteContentTo(buffer, offset)
		if err != nil {
			return -1, err
		}
		offset = wNext
	}

	return offset, nil
}

func makeASN1Object(tag *Tag) ASN1Object {
	var o ASN1Object
	switch tag.Number {
	case TagBoolean:
		o = new(ASN1Boolean)

	case TagInteger:
		o = NewIntegerFromInt64(0)

	case TagBitString:
		o = new(ASN1BitString)

	case TagNull:
		o = NewNull()

	case TagOctetString:
		o = NewOctetString(nil)

	case TagObjectIdentifier:
		o = new(ASN1ObjectIdentifier)

	case TagSequence:
		o = new(ASN1Sequence)

	case TagSet:
		o = new(ASN1Set)

	case TagPrintableString:
		o = new(ASN1PrintableString)

	default:
		o = new(ASN1GenericData)
	}

	return o
}

func ReadASN1Object(buffer []byte, offset int) (ASN1Object, int, error) {
	tag, next, err := ReadTag(buffer, offset)
	if err != nil {
		return nil, -1, err
	}

	objLength, next, err := ReadLength(buffer, next)
	if err != nil {
		return nil, -1, err
	}

	info := NewASN1ObjectInfo(tag, objLength)
	obj := makeASN1Object(tag)

	err = obj.ReadContentFrom(buffer, next, info)
	if err != nil {
		return nil, -1, err
	}

	next += objLength.Int()
	return obj, next, nil
}

func ReadASN1Objects(buffer []byte, offset int, length int) ([]ASN1Object, int, error) {
	objects := make([]ASN1Object, 0)
	next := offset
	var err error
	for next < length {
		var obj ASN1Object
		obj, next, err = ReadASN1Object(buffer, next)
		if err != nil {
			return nil, -1, err
		}

		objects = append(objects, obj)
	}

	return objects, next, nil
}

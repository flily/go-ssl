package asn1

import (
	"fmt"
)

// asn1 implements DER encoding and decoding of ASN.1 data structures.
// Reference:
//   - ITU-T X.680, ISO/IEC 8824-1:2021
//   - ITU-T X.690, ISO/IEC 8825-1:2021

type ASN1Object interface {
	Tag() Tag
	ContentLength() Length
	WriteContentTo(buffer []byte, offset int) (int, error)
	ReadContentFrom(buffer []byte, offset int, length Length) error
	String() string
	PrettyString(indent string) string
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

func makeASN1Object(tag *Tag) (ASN1Object, error) {
	var o ASN1Object
	var err error
	switch tag.Number {
	case TagBoolean:
		o = new(ASN1Boolean)

	default:
		err = fmt.Errorf("asn1: unsupported tag %s", tag)
	}

	return o, err
}

func ReadASN1Objects(buffer []byte, offset int, length int) ([]ASN1Object, int, error) {
	objects := make([]ASN1Object, 0)
	next := offset
	var err error
	for next < length {
		tag := &Tag{}
		next, err = tag.ReadFrom(buffer, next)
		if err != nil {
			return nil, -1, err
		}

		length := Length(0)
		next, err = length.ReadFrom(buffer, next)
		if err != nil {
			return nil, -1, err
		}

		obj, err := makeASN1Object(tag)
		if err != nil {
			return nil, -1, err
		}

		err = obj.ReadContentFrom(buffer, next, length)
		if err != nil {
			return nil, -1, err
		}

		next += length.Int()
		objects = append(objects, obj)
	}

	return objects, next, nil
}

package asn1

import (
	"fmt"
	"math/big"
	"strings"
)

type ASN1Boolean bool

func NewBoolean(value bool) *ASN1Boolean {
	b := ASN1Boolean(value)
	return &b
}

func (b *ASN1Boolean) Tag() *Tag {
	t := &Tag{
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

type ASN1Integer struct {
	value *big.Int
}

func NewInteger(value *big.Int) *ASN1Integer {
	i := &ASN1Integer{value}
	return i
}

func NewIntegerFromInt64(value int64) *ASN1Integer {
	i := &ASN1Integer{big.NewInt(value)}
	return i
}

func (i *ASN1Integer) Tag() *Tag {
	t := &Tag{
		Class:       TagClassUniversal,
		Constructed: false, // X.690 8.3.1, integer value SHALL BE primitive
		Number:      TagInteger,
	}

	return t
}

func (i *ASN1Integer) contentLength() (int, int) {
	l := i.value.BitLen()
	msb := uint(0)
	byteLength := 1
	if l > 0 {
		msb = i.value.Bit(l - 1)
		byteLength = (l + 7) / 8
	}

	if msb == 1 && l%8 == 0 {
		return 1, byteLength
	} else {
		return 0, byteLength
	}
}

func (i *ASN1Integer) ContentLength() Length {
	padLength, numLength := i.contentLength()
	return Length(padLength + numLength)
}

func (i *ASN1Integer) WriteContentTo(buffer []byte, offset int) (int, error) {
	padLength, numLength := i.contentLength()
	if err := checkBufferSize(buffer, offset, padLength+numLength); err != nil {
		return -1, err
	}

	if i.value.IsInt64() && i.value.Int64() == 0 {
		buffer[offset] = 0x00
		return offset + 1, nil
	}

	next := offset
	if padLength == 1 {
		buffer[next] = 0x00
		next++
	}

	numBytes := i.value.Bytes()
	copy(buffer[next:], numBytes)
	next += len(numBytes)

	return next, nil
}

func (i *ASN1Integer) ReadContentFrom(buffer []byte, offset int, length Length) error {
	if err := checkBufferSize(buffer, offset, length.Int()); err != nil {
		return err
	}

	i.value.SetBytes(buffer[offset : offset+length.Int()])
	return nil
}

func (i *ASN1Integer) String() string {
	return fmt.Sprintf("Integer[%s]", i.value.String())
}

func (i *ASN1Integer) PrettyString(indent string) string {
	return indent + i.String()
}

func (i *ASN1Integer) Equal(other ASN1Object) bool {
	if otherInt, ok := other.(*ASN1Integer); ok {
		return i.value.Cmp(otherInt.value) == 0
	}

	return false

}

type ASN1Sequence []ASN1Object

func NewSequence(objects ...ASN1Object) *ASN1Sequence {
	seq := ASN1Sequence(objects)
	return &seq
}

func (s *ASN1Sequence) Tag() *Tag {
	t := &Tag{
		Class:       TagClassUniversal,
		Constructed: true, // X.690 8.2.2, sequence value SHALL BE constructed
		Number:      TagSequence,
	}

	return t
}

func (s *ASN1Sequence) ContentLength() Length {
	length := 0
	for _, obj := range *s {
		objTag := obj.Tag()
		objContentLength := obj.ContentLength()
		objLengthLength := objContentLength.WireLength()
		length += objTag.WireLength() + objLengthLength + objContentLength.Int()
	}

	return Length(length)
}

func (s *ASN1Sequence) WriteContentTo(buffer []byte, offset int) (int, error) {
	return WriteASN1Objects(buffer, offset, *s...)
}

func (s *ASN1Sequence) ReadContentFrom(buffer []byte, offset int, length Length) error {
	objects, _, err := ReadASN1Objects(buffer, offset, offset+length.Int())
	if err != nil {
		return err
	}

	*s = objects
	return nil
}

func (s *ASN1Sequence) String() string {
	return fmt.Sprintf("Sequence [%d elements]", len(*s))
}

func (s *ASN1Sequence) PrettyString(indent string) string {
	lead := ""
	if len(*s) > 1 {
		lead = "+ "
	}

	buffer := make([]string, len(*s))
	for i, obj := range *s {
		buffer[i] = lead + obj.PrettyString(indent+"  ")
	}

	return strings.Join(buffer, "\n")
}

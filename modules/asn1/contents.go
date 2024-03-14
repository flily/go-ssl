package asn1

import (
	"fmt"
	"math/big"
	"strings"
)

type objectInnerKind int

const (
	objectInnerKindInvalid objectInnerKind = iota
	objectInnerKindASN1Object
	objectInnerKindBytes
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

func (b *ASN1Boolean) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
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

func (i *ASN1Integer) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	length := info.Length.Int()
	if err := checkBufferSize(buffer, offset, length); err != nil {
		return err
	}

	i.value.SetBytes(buffer[offset : offset+length])
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

type ASN1OctetString struct {
	kind        objectInnerKind
	valueBytes  []byte
	valueObject ASN1Object
	Constructed bool
}

func NewOctetStringFromBytes(value []byte) *ASN1OctetString {
	s := &ASN1OctetString{
		kind:        objectInnerKindBytes,
		valueBytes:  value,
		Constructed: false,
	}

	return s
}

func NewOctetStringFromObject(obj ASN1Object) *ASN1OctetString {
	s := &ASN1OctetString{
		kind:        objectInnerKindASN1Object,
		valueObject: obj,
		Constructed: true,
	}

	return s
}

func NewOctetString(value any) *ASN1OctetString {
	if v, ok := value.([]byte); !ok {
		return NewOctetStringFromBytes(v)
	}

	if v, ok := value.(ASN1Object); !ok {
		return NewOctetStringFromObject(v)
	}

	return nil
}

func (s *ASN1OctetString) Tag() *Tag {
	t := &Tag{
		Class:       TagClassUniversal,
		Constructed: s.Constructed, // X.690 8.7.1, octet string value SHALL BE primitive or constructed
		Number:      TagOctetString,
	}

	return t
}

func (s *ASN1OctetString) ContentLength() Length {
	switch s.kind {
	case objectInnerKindBytes:
		return Length(len(s.valueBytes))

	case objectInnerKindASN1Object:
		s.valueObject.ContentLength()
	}

	return 0
}

func (s *ASN1OctetString) WriteContentTo(buffer []byte, offset int) (int, error) {
	switch s.kind {
	case objectInnerKindBytes:
		if err := checkBufferSize(buffer, offset, len(s.valueBytes)); err != nil {
			return -1, err
		}

		copy(buffer[offset:], s.valueBytes)
		return offset + len(s.valueBytes), nil

	case objectInnerKindASN1Object:
		return s.valueObject.WriteContentTo(buffer, offset)
	}

	return -1, fmt.Errorf("asn1: invalid octet string inner kind")
}

func (s *ASN1OctetString) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	var err error
	if info.Tag.Constructed {
		s.kind = objectInnerKindASN1Object
		s.Constructed = true
		s.valueObject = nil
		s.valueObject, _, err = ReadASN1Object(buffer, offset)

	} else {
		s.kind = objectInnerKindBytes
		s.valueBytes = make([]byte, info.Length.Int())
		copy(s.valueBytes, buffer[offset:offset+info.Length.Int()])
	}

	return err
}

func (s *ASN1OctetString) String() string {
	r := "OctetString"
	switch s.kind {
	case objectInnerKindBytes:
		r = fmt.Sprintf("OctetString[%d bytes]", len(s.valueBytes))

	case objectInnerKindASN1Object:
		r = fmt.Sprintf("OctetString[%s]", s.valueObject.String())
	}

	return r
}

func (s *ASN1OctetString) PrettyString(indent string) string {
	r := "OctetString"
	switch s.kind {
	case objectInnerKindBytes:
		r = fmt.Sprintf("OctetString[%d bytes]", len(s.valueBytes))

	case objectInnerKindASN1Object:
		r = fmt.Sprintf("OctetString[%s]", s.valueObject.PrettyString(indent))
	}

	return indent + r
}

type ASN1Null int

func NewNull() *ASN1Null {
	n := ASN1Null(0)
	return &n
}

func (n *ASN1Null) Tag() *Tag {
	t := &Tag{
		Class:       TagClassUniversal,
		Constructed: false, // X.690 8.8.1, null value SHALL BE primitive
		Number:      TagNull,
	}

	return t
}

func (n *ASN1Null) ContentLength() Length {
	return 0
}

func (n *ASN1Null) WriteContentTo(buffer []byte, offset int) (int, error) {
	return offset, nil
}

func (n *ASN1Null) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	return nil
}

func (n *ASN1Null) String() string {
	return "Null"
}

func (n *ASN1Null) PrettyString(indent string) string {
	return indent + n.String()
}

func (n *ASN1Null) Equal(other ASN1Object) bool {
	_, ok := other.(*ASN1Null)
	return ok
}

type ASN1ObjectIdentifier []uint64

func NewObjectIdentifier(ids ...uint64) *ASN1ObjectIdentifier {
	if len(ids) < 2 {
		return nil
	}

	oid := ASN1ObjectIdentifier(ids)
	return &oid
}

func (i *ASN1ObjectIdentifier) Tag() *Tag {
	t := &Tag{
		Class:       TagClassUniversal,
		Constructed: false, // X.690 8.19.1, object identifier value SHALL BE primitive
		Number:      TagObjectIdentifier,
	}

	return t
}

func (i *ASN1ObjectIdentifier) ContentLength() Length {
	length := 1

	for j := 2; j < len(*i); j++ {
		length += getBase128UintByteSize((*i)[j])
	}

	return Length(length)
}

func (i *ASN1ObjectIdentifier) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, i.ContentLength().Int()); err != nil {
		return -1, err
	}

	firstOctet := (*i)[0]*40 + (*i)[1]
	buffer[offset] = byte(firstOctet)
	next := offset + 1
	for j := 2; j < len(*i); j++ {
		n := (*i)[j]
		size := getBase128UintByteSize(n)
		next = writeBase128Uint(buffer, next, n, size)
	}

	return next, nil
}

func (i *ASN1ObjectIdentifier) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	length := info.Length.Int()
	if err := checkBufferSize(buffer, offset, length); err != nil {
		return err
	}

	firstOctet := buffer[offset]
	*i = append((*i)[:0], uint64(firstOctet/40), uint64(firstOctet%40))
	next := offset + 1
	for next < offset+length {
		var n uint64
		n, next = readBase128Uint(buffer, next)
		if next < 0 {
			return fmt.Errorf("asn1: invalid object identifier at byte %d", next)
		}

		*i = append(*i, n)
	}

	return nil
}

func (i *ASN1ObjectIdentifier) String() string {
	parts := make([]string, len(*i))
	for j, id := range *i {
		parts[j] = fmt.Sprintf("%d", id)
	}

	return fmt.Sprintf("ObjectIdentifier[%s]", strings.Join(parts, "."))
}

func (i *ASN1ObjectIdentifier) PrettyString(indent string) string {
	return indent + i.String()
}

func (i *ASN1ObjectIdentifier) Equal(other ASN1Object) bool {
	if otherOID, ok := other.(*ASN1ObjectIdentifier); ok {
		if len(*i) != len(*otherOID) {
			return false
		}

		for j, id := range *i {
			if id != (*otherOID)[j] {
				return false
			}
		}

		return true
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

func (s *ASN1Sequence) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	objects, _, err := ReadASN1Objects(buffer, offset, offset+info.Length.Int())
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

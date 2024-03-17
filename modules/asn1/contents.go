package asn1

import (
	"bytes"
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
		Class:  TagClassUniversal,
		PC:     TagPrimitive, // X.690 8.2.1, boolen value SHALL BE primitive
		Number: TagBoolean,
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

func (b *ASN1Boolean) Equal(other ASN1Object) bool {
	otherBool, ok := other.(*ASN1Boolean)
	if !ok {
		return false
	}

	return *b == *otherBool
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
		Class:  TagClassUniversal,
		PC:     TagPrimitive, // X.690 8.3.1, integer value SHALL BE primitive
		Number: TagInteger,
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

type ASN1BitString struct {
	Data      []byte
	Object    ASN1Object
	PC        ContentType
	BitLength int
}

func NewBitStringFromBitArray(data []byte, bitLength int) *ASN1BitString {
	byteLength := (bitLength + 7) / 8
	if byteLength > len(data) {
		byteLength = len(data)
		bitLength = byteLength * 8
	}

	s := &ASN1BitString{
		Data:      make([]byte, byteLength),
		BitLength: bitLength,
	}

	copy(s.Data, data[:byteLength])
	return s
}

func NewBitStringFromBytes(data []byte) *ASN1BitString {
	s := &ASN1BitString{
		Data:      data,
		BitLength: len(data) * 8,
		PC:        TagPrimitive,
	}

	return s
}

func NewBitStringFromObject(obj ASN1Object) *ASN1BitString {
	s := &ASN1BitString{
		Object: obj,
		PC:     TagConstructed,
	}

	return s
}

func NewBitString(data any) *ASN1BitString {
	if v, ok := data.([]byte); ok {
		return NewBitStringFromBytes(v)
	}

	if v, ok := data.(ASN1Object); ok {
		return NewBitStringFromObject(v)
	}

	return nil
}

func (s *ASN1BitString) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     s.PC, // X.690 8.6.1, bit string value SHALL BE primitive or constructed
		Number: TagBitString,
	}

	return t
}

func (s *ASN1BitString) ContentLength() Length {
	length := Length(0)
	if s.Object != nil {
		length += Length(s.Object.Tag().WireLength())
		objLength := s.Object.ContentLength()

		length += Length(objLength.WireLength())
		length += objLength

		if s.PC == TagPrimitive {
			length += 1
		}

	} else {
		length = Length(len(s.Data) + 1)
	}

	return length
}

func (s *ASN1BitString) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, len(s.Data)+1); err != nil {
		return -1, err
	}

	next := offset
	if s.Object != nil {
		if s.PC == TagPrimitive {
			buffer[next] = 0x00
			next++
		}

		wNext, err := WriteASN1Objects(buffer, next, s.Object)
		if err != nil {
			return -1, err
		}

		next = wNext

	} else {
		if s.PC == TagPrimitive {
			byteBitLength := len(s.Data) * 8
			buffer[next] = byte(byteBitLength - s.BitLength)
			next++
		}

		copy(buffer[next:], s.Data)
		next += len(s.Data)
	}

	return next, nil
}

func (s *ASN1BitString) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	s.PC = info.Tag.PC
	var err error
	if s.PC == TagConstructed {
		s.Object, _, err = ReadASN1Object(buffer, offset)

	} else {
		diff := buffer[offset]
		length := info.Length.Int()
		s.Data = make([]byte, length-1)
		copy(s.Data, buffer[offset+1:offset+length])
		s.BitLength = (length-1)*8 - int(diff)
	}

	return err
}

func (s *ASN1BitString) String() string {
	return fmt.Sprintf("BitString[%d bits]", s.BitLength)
}

func (s *ASN1BitString) PrettyString(indent string) string {
	if s.PC == TagConstructed || s.Object != nil {
		return s.Object.PrettyString(indent)
	} else {
		return indent + s.String()
	}
}

func (s *ASN1BitString) Equal(o ASN1Object) bool {
	other, ok := o.(*ASN1BitString)
	if !ok {
		return false
	}

	if other.PC != s.PC {
		return false
	}

	if s.Object != nil {
		return s.Object.Equal(other.Object)
	}

	return bytes.Equal(s.Data, other.Data)
}

type ASN1OctetString struct {
	kind        objectInnerKind
	valueBytes  []byte
	valueObject ASN1Object
	PC          ContentType
}

func NewOctetStringFromBytes(value []byte) *ASN1OctetString {
	s := &ASN1OctetString{
		kind:       objectInnerKindBytes,
		valueBytes: value,
		PC:         TagPrimitive,
	}

	return s
}

func NewOctetStringFromObject(obj ASN1Object) *ASN1OctetString {
	s := &ASN1OctetString{
		kind:        objectInnerKindASN1Object,
		valueObject: obj,
		PC:          TagConstructed,
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
		Class:  TagClassUniversal,
		PC:     s.PC, // X.690 8.7.1, octet string value SHALL BE primitive or constructed
		Number: TagOctetString,
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
	if info.Tag.PC {
		s.kind = objectInnerKindASN1Object
		s.PC = TagConstructed
		s.valueObject = nil
		s.valueObject, _, err = ReadASN1Object(buffer, offset)

	} else {
		s.kind = objectInnerKindBytes
		s.PC = TagPrimitive
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

func (s *ASN1OctetString) Equal(o ASN1Object) bool {
	other, ok := o.(*ASN1OctetString)
	if !ok {
		return false
	}

	if other.PC != s.PC {
		return false
	}

	if s.kind == objectInnerKindBytes {
		return bytes.Equal(s.valueBytes, other.valueBytes)
	}

	return s.valueObject.Equal(other.valueObject)
}

type ASN1Null int

func NewNull() *ASN1Null {
	n := ASN1Null(0)
	return &n
}

func (n *ASN1Null) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     TagPrimitive, // X.690 8.8.1, null value SHALL BE primitive
		Number: TagNull,
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

type ASN1Sequence []ASN1Object

func NewSequence(objects ...ASN1Object) *ASN1Sequence {
	seq := ASN1Sequence(objects)
	return &seq
}

func (s *ASN1Sequence) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     TagConstructed, // X.690 8.9.1, sequence value SHALL BE constructed
		Number: TagSequence,
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
	if len(indent) <= 0 {
		indent = "+ "
	}
	buffer := make([]string, len(*s)+1)
	buffer[0] = indent + s.String()
	for i, obj := range *s {
		buffer[i+1] = obj.PrettyString("| " + indent)
	}

	return strings.Join(buffer, "\n")
}

func (s *ASN1Sequence) Equal(other ASN1Object) bool {
	otherSeq, ok := other.(*ASN1Sequence)
	if !ok {
		return false
	}

	if len(*s) != len(*otherSeq) {
		return false
	}

	for i, obj := range *s {
		if !obj.Equal((*otherSeq)[i]) {
			return false
		}
	}

	return true
}

type ASN1Set []ASN1Object

func NewASN1Set(objects ...ASN1Object) *ASN1Sequence {
	seq := ASN1Sequence(objects)
	return &seq
}

func (s *ASN1Set) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     TagConstructed, // X.690 8.11.2, sequence value SHALL BE constructed
		Number: TagSet,
	}

	return t
}

func (s *ASN1Set) ContentLength() Length {
	length := 0
	for _, obj := range *s {
		objTag := obj.Tag()
		objContentLength := obj.ContentLength()
		objLengthLength := objContentLength.WireLength()
		length += objTag.WireLength() + objLengthLength + objContentLength.Int()
	}

	return Length(length)
}

func (s *ASN1Set) WriteContentTo(buffer []byte, offset int) (int, error) {
	return WriteASN1Objects(buffer, offset, *s...)
}

func (s *ASN1Set) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	objects, _, err := ReadASN1Objects(buffer, offset, offset+info.Length.Int())
	if err != nil {
		return err
	}

	*s = objects
	return nil
}

func (s *ASN1Set) String() string {
	return fmt.Sprintf("Set [%d elements]", len(*s))
}

func (s *ASN1Set) PrettyString(indent string) string {
	if len(indent) <= 0 {
		indent = "+ "
	}
	buffer := make([]string, len(*s)+1)
	buffer[0] = indent + s.String()
	for i, obj := range *s {
		buffer[i+1] = obj.PrettyString("| " + indent)
	}

	return strings.Join(buffer, "\n")
}

func (s *ASN1Set) Equal(other ASN1Object) bool {
	otherSeq, ok := other.(*ASN1Set)
	if !ok {
		return false
	}

	if len(*s) != len(*otherSeq) {
		return false
	}

	for i, obj := range *s {
		if !obj.Equal((*otherSeq)[i]) {
			return false
		}
	}

	return true
}

type ASN1PrintableString string

func NewPrintableString(value string) *ASN1PrintableString {
	s := ASN1PrintableString(value)
	return &s
}

func (s *ASN1PrintableString) Tag() *Tag {
	t := &Tag{
		Class:  TagClassUniversal,
		PC:     TagPrimitive, // X.690 8.19.1, printable string value SHALL BE primitive
		Number: TagPrintableString,
	}

	return t
}

func (s *ASN1PrintableString) ContentLength() Length {
	return Length(len(*s))
}

func (s *ASN1PrintableString) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, len(*s)); err != nil {
		return -1, err
	}

	copy(buffer[offset:], *s)
	return offset + len(*s), nil
}

func (s *ASN1PrintableString) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	length := info.Length.Int()
	if err := checkBufferSize(buffer, offset, length); err != nil {
		return err
	}

	*s = ASN1PrintableString(buffer[offset : offset+length])
	return nil
}

func (s *ASN1PrintableString) String() string {
	return fmt.Sprintf("PrintableString[%s]", string(*s))
}

func (s *ASN1PrintableString) PrettyString(indent string) string {
	return indent + s.String()
}

func (s *ASN1PrintableString) Equal(other ASN1Object) bool {
	otherString, ok := other.(*ASN1PrintableString)
	if !ok {
		return false
	}

	return *s == *otherString
}

type ASN1GenericData struct {
	tag  *Tag
	Data []byte
}

func NewGenericData(tag *Tag, data []byte) *ASN1GenericData {
	g := &ASN1GenericData{
		tag:  tag,
		Data: data,
	}

	return g
}

func (g *ASN1GenericData) Tag() *Tag {
	return g.tag
}

func (g *ASN1GenericData) ContentLength() Length {
	return Length(len(g.Data))
}

func (g *ASN1GenericData) WriteContentTo(buffer []byte, offset int) (int, error) {
	if err := checkBufferSize(buffer, offset, len(g.Data)); err != nil {
		return -1, err
	}

	copy(buffer[offset:], g.Data)
	return offset + len(g.Data), nil
}

func (g *ASN1GenericData) ReadContentFrom(buffer []byte, offset int, info *ASN1ObjectInfo) error {
	length := info.Length.Int()
	if err := checkBufferSize(buffer, offset, length); err != nil {
		return err
	}

	g.tag = info.Tag
	g.Data = make([]byte, length)
	copy(g.Data, buffer[offset:offset+length])
	return nil
}

func (g *ASN1GenericData) String() string {
	return fmt.Sprintf("GenericData[%s (%d bytes)]", g.tag, len(g.Data))
}

func (g *ASN1GenericData) PrettyString(indent string) string {
	return indent + g.String()
}

func (g *ASN1GenericData) Equal(other ASN1Object) bool {
	otherData, ok := other.(*ASN1GenericData)
	if !ok {
		return false
	}

	if g.tag != otherData.tag {
		return false
	}

	return bytes.Equal(g.Data, otherData.Data)
}

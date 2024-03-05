package encoding

import (
	"fmt"
	"math/big"
	"reflect"
)

type WireType uint8

const (
	WireTypeFixedLength    WireType = 0
	WireTypeVariableLength WireType = 1
	WireTypeBlob           WireType = 2
	WireTypeInnerStructure WireType = 3

	WireRepeatedFlag = 0x40
	WireHasNameFlag  = 0x80
)

func (t WireType) String() string {
	switch t {
	case WireTypeFixedLength:
		return "FixedLength"
	case WireTypeVariableLength:
		return "Varint"
	case WireTypeBlob:
		return "Blob"
	case WireTypeInnerStructure:
		return "InnerStruture"
	default:
		return "unknown"
	}
}

type FixedLengthType uint8

const (
	FixedLengthTypeNull      FixedLengthType = 0x00
	FixedLengthTypeInteger   FixedLengthType = 0x40
	FixedLengthTypeFloat     FixedLengthType = 0x80
	FixedLengthTypeTimestamp FixedLengthType = 0xc0
)

type FieldValue interface {
	uint8
	uint16
	uint32
	uint64
	int8
	int16
	int32
	int64
	float32
	float64
	string
	[]byte
	*big.Int
}

type MemoryType int

const (
	MemoryTypeUint MemoryType = iota
	MemoryTypeInt
	MemoryTypeBigInt
	MemoryTypeFloat
	MemoryTypeBlob
)

type WireID uint64

func (i WireID) FieldID() uint64 {
	return uint64(i) >> 4
}

func (i WireID) WireType() WireType {
	return WireType(uint64(i) & 0x03)
}

func (i WireID) Repeated() bool {
	return (uint64(i) & WireRepeatedFlag) != 0
}

func (i WireID) HasName() bool {
	return (uint64(i) & WireHasNameFlag) != 0
}

func (i WireID) AsUint() uint64 {
	return uint64(i)
}

type Field struct {
	wType      WireType
	mType      MemoryType
	fieldID    uint64
	name       string
	Repeated   bool
	HasName    bool
	kind       FixedLengthType
	length     int
	raw        []byte
	valueUint  uint64
	valueInt   int64
	valueFloat float64
	valueBlob  []byte
}

func NewFixedLengthField(fieldID uint64, value any) *Field {
	f := &Field{
		fieldID: fieldID,
		name:    "",
		wType:   WireTypeFixedLength,
	}

	if err := f.setFixedLengthValue(value); err != nil {
		return nil
	}

	return f
}

func NewVarint(fieldID uint64, value any) *Field {
	f := &Field{
		fieldID: fieldID,
		name:    "",
		wType:   WireTypeVariableLength,
	}

	refValue := reflect.ValueOf(value)
	switch value.(type) {
	case uint8, uint16, uint32, uint64:
		f.valueUint = refValue.Uint()
		f.mType = MemoryTypeUint

	case int64:
		f.valueInt = refValue.Int()
		f.mType = MemoryTypeInt

	default:
		return nil
	}

	return f
}

func NewBlob(fieldID uint64, value any) *Field {
	f := &Field{
		fieldID: fieldID,
		name:    "",
		wType:   WireTypeBlob,
	}

	if err := f.setBlobValue(value); err != nil {
		return nil
	}

	return f
}

func NewField(fieldID uint64, value any) *Field {
	f := &Field{
		fieldID: fieldID,
		name:    "",
	}

	return f
}

func ParseField(buffer []byte, offset int) (*Field, int) {
	f := &Field{}
	next := f.ReadFrom(buffer, offset)
	if next < 0 {
		return nil, -1
	}

	return f, next
}

func (f *Field) setFixedLengthValue(value any) error {
	if f.wType != WireTypeFixedLength {
		return fmt.Errorf("field type can not be set to fixed length: %s", f.wType.String())
	}

	refValue := reflect.ValueOf(value)
	f.length = int(refValue.Type().Size())

	switch value.(type) {
	case uint8, uint16, uint32, uint64:
		f.kind = FixedLengthTypeInteger
		f.valueUint = refValue.Uint()
		f.mType = MemoryTypeUint

	case int8, int16, int32, int64:
		f.kind = FixedLengthTypeInteger
		f.valueInt = refValue.Int()
		f.mType = MemoryTypeInt

	case float32, float64:
		f.kind = FixedLengthTypeFloat
		f.valueFloat = refValue.Float()
		f.mType = MemoryTypeFloat

	default:
		return fmt.Errorf("field type %T can not be set to fixed length: %s",
			value, f.wType.String())
	}

	return nil
}

func (f *Field) setBlobValue(value any) error {
	if f.wType != WireTypeBlob {
		return fmt.Errorf("field type can not be set to blob: %s", f.wType.String())
	}

	switch v := value.(type) {
	case string:
		f.valueBlob = []byte(v)
		f.mType = MemoryTypeBlob

	case []byte:
		f.valueBlob = v
		f.mType = MemoryTypeBlob

	default:
		return fmt.Errorf("field type %T can not be set to blob: %s",
			value, f.wType.String())
	}

	return nil
}

func (f *Field) WithName(name string) *Field {
	f.name = name
	f.HasName = true
	return f
}

func (f *Field) FieldID() uint64 {
	return f.fieldID
}

func (f *Field) WireID() WireID {
	wid := uint64(f.wType)
	if f.Repeated {
		wid |= WireRepeatedFlag
	}

	if len(f.name) > 0 {
		wid |= WireHasNameFlag
	}

	return WireID(wid | (f.fieldID << 4))
}

func (f *Field) Name() string {
	return f.name
}

func (f *Field) Uint() uint64 {
	if f.mType != MemoryTypeUint {
		return 0
	}

	return f.valueUint
}

func (f *Field) Int() int64 {
	if f.mType != MemoryTypeInt {
		return 0
	}

	return f.valueInt
}

func (f *Field) String() string {
	switch f.mType {
	case MemoryTypeBlob:
		return string(f.valueBlob)

	default:
		return ""
	}
}

func (f *Field) Blob() []byte {
	switch f.mType {
	case MemoryTypeBlob:
		return f.valueBlob

	default:
		return nil
	}
}

func (f *Field) makeBytes() []byte {
	return nil
}

func (f *Field) Bytes() []byte {
	if f.raw != nil {
		return f.raw
	}

	return f.makeBytes()
}

func (f *Field) writeFixedLength(encoder *Encoder) int {
	switch f.mType {
	case MemoryTypeUint:
		flag := uint8(f.kind) | uint8(f.length)
		if encoder.EncodeByte(flag) < 0 {
			return -1
		}

		return encoder.EncodeUintLE(f.valueUint, f.length)

	case MemoryTypeInt:
		flag := uint8(f.kind) | uint8(f.length)
		if encoder.EncodeByte(flag) < 0 {
			return -1
		}

		return encoder.EncodeIntLE(f.valueInt, f.length)

	case MemoryTypeFloat:
		flag := uint8(f.kind) | uint8(f.length)
		if encoder.EncodeByte(flag) < 0 {
			return -1
		}

		return encoder.EncodeFloatLE(f.valueFloat, f.length)

	}
	return 0
}

func (f *Field) writeVarint(encoder *Encoder) int {
	switch f.mType {
	case MemoryTypeUint:
		return encoder.EncodeVarUint(f.valueUint)

	case MemoryTypeInt:
		return encoder.EncodeVarInt(f.valueInt)
	}

	return 0
}

func (f *Field) writeBlob(encoder *Encoder) int {
	return encoder.EncodeBinary(f.valueBlob)
}

func (f *Field) WriteTo(buffer []byte, offset int) int {
	encoder := NewEncoder(buffer, offset)
	wireID := f.WireID()
	if encoder.EncodeVarUint(wireID.AsUint()) < 0 {
		return -1
	}

	if f.HasName {
		if encoder.EncodeBinary([]byte(f.name)) < 0 {
			return -1
		}
	}

	var result int
	switch f.wType {
	case WireTypeFixedLength:
		result = f.writeFixedLength(encoder)

	case WireTypeVariableLength:
		result = f.writeVarint(encoder)

	case WireTypeBlob:
		result = f.writeBlob(encoder)
	}

	return result
}

func (f *Field) readBlob(decoder *Decoder) int {
	data, next := decoder.DecodeBinary()
	if next < 0 {
		return -1
	}

	f.valueBlob = data
	f.mType = MemoryTypeBlob
	return next
}

func (f *Field) ReadFrom(buffer []byte, offset int) int {
	decoder := NewDecoder(buffer, offset)

	wireID, next := decoder.DecodeWireID()
	if next < 0 {
		return -1
	}

	f.fieldID = wireID.FieldID()
	f.wType = wireID.WireType()
	f.Repeated = wireID.Repeated()

	var result int
	switch wireID.WireType() {
	case WireTypeBlob:
		result = f.readBlob(decoder)
	}

	return result
}

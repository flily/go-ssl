package encoding

import (
	"testing"

	"bytes"
)

func TestEncodeStringField(t *testing.T) {
	//        2    a    WireID
	//      0010 1010
	// 0010 1010 0000   left shifted 4 bit
	//           0010   wire type blob
	// 0010 1010 0010   wire id
	// 0010 1 | [1]010 0010
	//  05         A2

	v := "expecto patronum"
	f := NewBlob(42, v)
	b := make([]byte, 20)
	exp := []byte{
		0xa2, 0x05, // WireID
		0x10, // Length
		0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x6f, 0x20,
		0x70, 0x61, 0x74, 0x72, 0x6f, 0x6e, 0x75, 0x6d,
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.String() != v {
		t.Errorf("f.String() -> %v, expected %v", f.String(), v)
	}

	if f.Uint() != 0 {
		t.Errorf("f.Uint() -> %v, expected %v", f.Uint(), 0)
	}

	if f.Int() != 0 {
		t.Errorf("f.Int() -> %v, expected %v", f.Int(), 0)
	}
}

func TestDecodeStringField(t *testing.T) {
	v := "expecto patronum"
	data := []byte{
		0xa2, 0x05, // WireID
		0x10, // Length
		0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x6f, 0x20,
		0x70, 0x61, 0x74, 0x72, 0x6f, 0x6e, 0x75, 0x6d,
	}

	f, next := ParseField(data, 0)
	if next != len(data) {
		t.Errorf("ParseField(b, 0) size %v, expected %v", next, len(data))
	}

	if f.WireID().WireType() != WireTypeBlob {
		t.Errorf("f.WireID().WireType() -> %v, expected %v", f.WireID().WireType(), WireTypeBlob)
	}

	if f.String() != v {
		t.Errorf("f.String() -> %v, expected %v", f.String(), v)
	}
}

func TestEncodeNamedStringField(t *testing.T) {
	v := "expecto patronum"
	f := NewBlob(42, v).WithName("spell")
	b := make([]byte, 30)
	exp := []byte{
		0xa2, 0x05, // WireID
		0x05,                         // Name length
		0x73, 0x70, 0x65, 0x6c, 0x6c, // Name
		0x10, // Length
		0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x6f, 0x20,
		0x70, 0x61, 0x74, 0x72, 0x6f, 0x6e, 0x75, 0x6d,
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.String() != v {
		t.Errorf("f.String() -> %v, expected %v", f.String(), v)
	}
}

func TestEncodeNamedStringFieldWithoutName(t *testing.T) {
	f := NewBlob(42, "expecto patronum").WithName("spell")
	b := make([]byte, 30)
	exp := []byte{
		0xa2, 0x05, // WireID
		0x10, // Length
		0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x6f, 0x20,
		0x70, 0x61, 0x74, 0x72, 0x6f, 0x6e, 0x75, 0x6d,
	}

	f.HasName = false
	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}
}

func TestEncodeUint8Field(t *testing.T) {
	//        2    a    WireID
	//      0010 1010
	// 0010 1010 0000   left shifted 4 bit
	//           0000   wire type blob
	// 0010 1010 0000   wire id
	// 0010 1 | [1]010 0000
	//  05         A0
	v := uint8(0x12)
	f := NewFixedLengthField(42, v)
	b := make([]byte, 10)
	exp := []byte{
		0xA0, 0x05, // WireID
		0x41, // Length and type
		0x12, // Value
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.Uint() != uint64(v) {
		t.Errorf("f.Uint() -> %v, expected %v", f.Uint(), v)
	}

	if f.String() != "" {
		t.Errorf("f.String() -> %v, expected %v", f.String(), "")
	}
}

func TestEncodeUint16Field(t *testing.T) {
	v := uint16(0x1234)
	f := NewFixedLengthField(42, v)
	b := make([]byte, 10)
	exp := []byte{
		0xA0, 0x05, // WireID
		0x42,       // Length and type
		0x34, 0x12, // Value
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.Uint() != uint64(v) {
		t.Errorf("f.Uint() -> %v, expected %v", f.Uint(), v)
	}
}

func TestEncodeUint32Field(t *testing.T) {
	v := uint32(0x12345678)
	f := NewFixedLengthField(42, v)
	b := make([]byte, 10)
	exp := []byte{
		0xA0, 0x05, // WireID
		0x44,                   // Length and type
		0x78, 0x56, 0x34, 0x12, // Value
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.Uint() != uint64(v) {
		t.Errorf("f.Uint() -> %v, expected %v", f.Uint(), v)
	}
}

func TestEncodeUint64Field(t *testing.T) {
	v := uint64(0x0f1e2d3c4b5a6978)
	f := NewFixedLengthField(42, v)
	b := make([]byte, 12)
	exp := []byte{
		0xA0, 0x05, // WireID
		0x48,                                           // Length and type
		0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f, // Value
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.Uint() != uint64(v) {
		t.Errorf("f.Uint() -> %v, expected %v", f.Uint(), v)
	}
}

func TestEncodeInt32Field(t *testing.T) {
	v := -int32(0x12345678)
	f := NewFixedLengthField(42, v)
	b := make([]byte, 10)
	exp := []byte{
		0xA0, 0x05, // WireID
		0x44,                   // Length and type
		0x88, 0xa9, 0xcb, 0xed, // Value
	}

	size := f.WriteTo(b, 0)
	if size != len(exp) {
		t.Errorf("f.WriteTo(b, 0) -> %v, expected %v", size, len(exp))
	}

	if !bytes.Equal(b[:size], exp) {
		t.Errorf("f.WriteTo(b, 0) wrong\n     got: %x\nexpected: %x", b[:size], exp)
	}

	if f.Int() != int64(v) {
		t.Errorf("f.Int() -> %v, expected %v", f.Int(), v)
	}
}

func TestEncodeVarUintField(t *testing.T) {
}

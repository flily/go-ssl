package encoding

import (
	"math"
)

type Encoder struct {
	buffer []byte
	offset int
}

func NewEncoder(buffer []byte, offset int) *Encoder {
	e := &Encoder{
		buffer: buffer,
		offset: offset,
	}

	return e
}

func (e *Encoder) CheckBufferSize(size int) bool {
	return e.offset+size <= len(e.buffer)
}

func (e *Encoder) EncodeVarUint(value uint64) int {
	size := EncodeVarUintSize(value)
	if !e.CheckBufferSize(size) {
		return -1
	}

	next := EncodeVarUint(value, e.buffer, e.offset)
	e.offset = next
	return next
}

func (e *Encoder) EncodeVarInt(value int64) int {
	size := EncodeVarIntSize(value)
	if !e.CheckBufferSize(size) {
		return -1
	}

	next := EncodeVarInt(value, e.buffer, e.offset)
	e.offset = next
	return next
}

func (e *Encoder) EncodeRawBinary(value []byte) int {
	size := len(value)
	if !e.CheckBufferSize(size) {
		return -1
	}

	copy(e.buffer[e.offset:], value)
	e.offset += size
	return e.offset
}

func (e *Encoder) EncodeByte(value uint8) int {
	if !e.CheckBufferSize(1) {
		return -1
	}

	e.buffer[e.offset] = value
	e.offset++
	return e.offset

}

func (e *Encoder) EncodeBinary(value []byte) int {
	dataSize := len(value)
	lengthSize := EncodeVarUintSize(uint64(dataSize))
	totalSize := dataSize + lengthSize
	if !e.CheckBufferSize(totalSize) {
		return -1
	}

	next := e.EncodeVarUint(uint64(dataSize))
	copy(e.buffer[next:], value)
	e.offset = next + dataSize
	return e.offset
}

func (e *Encoder) EncodeUintLE(value uint64, size int) int {
	if !e.CheckBufferSize(size) {
		return -1
	}

	for i := 0; i < size; i++ {
		e.buffer[e.offset] = byte(value)
		value >>= 8
		e.offset++
	}

	return e.offset
}

func (e *Encoder) EncodeIntLE(value int64, size int) int {
	if !e.CheckBufferSize(size) {
		return -1
	}

	for i := 0; i < size; i++ {
		e.buffer[e.offset] = byte(value)
		value >>= 8
		e.offset++
	}

	return e.offset
}

func (e *Encoder) EncodeFloatLE(value float64, size int) int {
	switch size {
	case 8:
		// float64
		uintFloat64 := math.Float64bits(value)
		return e.EncodeUintLE(uintFloat64, size)

	case 4:
		// float32
		uintFloat32 := math.Float32bits(float32(value))
		return e.EncodeUintLE(uint64(uintFloat32), size)

	default:
		return -1
	}
}

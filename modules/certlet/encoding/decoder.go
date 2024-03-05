package encoding

type Decoder struct {
	buffer []byte
	offset int
}

func NewDecoder(buffer []byte, offset int) *Decoder {
	d := &Decoder{
		buffer: buffer,
		offset: offset,
	}

	return d
}

func (d *Decoder) SetOffset(offset int) {
	d.offset = offset
}

func (d *Decoder) EOF() bool {
	return d.offset >= len(d.buffer)
}

func (d *Decoder) CheckBufferSize(size int) bool {
	return d.offset+size <= len(d.buffer)
}

func (d *Decoder) DecodeVarUint() (uint64, int) {
	value, next := DecodeVarUint(d.buffer, d.offset)
	d.offset = next
	return value, next
}

func (d *Decoder) DecodeVarInt() (int64, int) {
	value, next := DecodeVarInt(d.buffer, d.offset)
	d.offset = next
	return value, next
}

func (d *Decoder) DecodeRawBinary(size int) ([]byte, int) {
	if d.offset+size > len(d.buffer) {
		return nil, -1
	}

	value := make([]byte, size)
	copy(value, d.buffer[d.offset:])
	d.offset += size
	return value, d.offset
}

func (d *Decoder) DecodeByte() (uint8, int) {
	value := d.buffer[d.offset]
	d.offset++
	return value, d.offset
}

func (d *Decoder) DecodeBinary() ([]byte, int) {
	size, next := d.DecodeVarUint()
	if next < 0 {
		return nil, -1
	}

	return d.DecodeRawBinary(int(size))
}

func (d *Decoder) DecodeUintLE(size int) (uint64, int) {
	if d.offset+size > len(d.buffer) {
		return 0, -1
	}

	value := uint64(0)
	for i := 0; i < size; i++ {
		value |= uint64(d.buffer[d.offset]) << (i * 8)
		d.offset++
	}

	return value, d.offset
}

func (d *Decoder) DecodeWireID() (WireID, int) {
	if d.offset+1 > len(d.buffer) {
		return 0, -1
	}

	value, next := DecodeVarUint(d.buffer, d.offset)
	d.offset = next
	return WireID(value), next
}

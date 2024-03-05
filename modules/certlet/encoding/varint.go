package encoding

func EncodeVarUintSize(value uint64) int {
	i := 0
	for value > 0 {
		value >>= 7
		i += 1
	}

	if i == 0 {
		i += 1
	}

	return i
}

func EncodeVarUint(value uint64, buffer []byte, offset int) int {
	buffer[offset] = uint8(value & 0x7f)
	value >>= 7
	i := 1
	for value > 0 {
		buffer[offset+i-1] |= 0x80
		buffer[offset+i] = uint8(value & 0x7f)
		value >>= 7
		i += 1
	}

	return offset + i
}

func DecodeVarUint(buffer []byte, offset int) (uint64, int) {
	var value uint64
	var shift uint
	var b byte

	for offset < len(buffer) {
		b = buffer[offset]
		offset += 1
		value |= uint64(b&0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}

	return value, offset
}

func EncodeVarIntSize(value int64) int {
	if value < 0 {
		return EncodeVarUintSize((uint64(-value) - 1) << 1)
	}

	return EncodeVarUintSize(uint64(value) << 1)
}

func EncodeVarInt(value int64, buffer []byte, offset int) int {
	var uvalue uint64

	if value < 0 {
		uvalue = 1 + ((uint64(-value) - 1) << 1)
	} else {
		uvalue = uint64(value << 1)
	}

	return EncodeVarUint(uvalue, buffer, offset)
}

func DecodeVarInt(buffer []byte, offset int) (int64, int) {
	value, offset := DecodeVarUint(buffer, offset)
	if value&1 == 0 {
		return int64(value >> 1), offset
	}

	return -int64(value>>1) - 1, offset
}

func EncodeUnifiedVarUintSize(value uint64) int {
	i := 1
	value >>= 6
	for value > 0 {
		value >>= 7
		i += 1
	}

	return i
}

func EncodeUnifiedVarUint(value uint64, buffer []byte, offset int) int {
	if offset+EncodeUnifiedVarUintSize(value) > len(buffer) {
		return offset
	}

	buffer[offset] = uint8(value&0x3f) << 1
	value >>= 6

	i := 1
	for value > 0 {
		buffer[offset+i-1] |= 0x80
		buffer[offset+i] = uint8(value & 0x7f)
		value >>= 7
		i += 1
	}

	return offset + i
}

func DecodeUnifiedVarUint(buffer []byte, offset int) (uint64, int) {
	b := buffer[offset]
	value := uint64((b & 0x7e) >> 1)
	i := 1
	for offset+i < len(buffer) && b&0x80 != 0 {
		b = buffer[offset+i]
		value |= uint64(b&0x7f) << ((i-1)*7 + 6)
		i += 1
	}

	return value, offset + i
}

func EncodeUnifiedVarIntSize(value int64) int {
	i := 1
	if value < 0 {
		value = -value
	}

	value >>= 6
	for value > 0 {
		value >>= 7
		i += 1
	}

	return i
}

func EncodeUnifiedVarInt(value int64, buffer []byte, offset int) int {
	b := uint8(0)
	if value < 0 {
		b = 1
		value = -value - 1
	}

	b |= uint8(value&0x3f) << 1
	buffer[offset] = b
	value >>= 6

	i := 1
	for value > 0 {
		buffer[offset+i-1] |= 0x80
		buffer[offset+i] = uint8(value & 0x7f)
		value >>= 7
		i += 1
	}

	return offset + i
}

func DecodeUnifiedVarInt(buffer []byte, offset int) (int64, int) {
	b := buffer[offset]
	sign := b & 1
	value := int64((b & 0x7e) >> 1)
	i := 1
	for offset+i < len(buffer) && b&0x80 != 0 {
		b = buffer[offset+i]
		value |= int64(b&0x7f) << ((i-1)*7 + 6)
		i += 1
	}

	if sign != 0 {
		value = -value - 1
	}

	return value, offset + i
}

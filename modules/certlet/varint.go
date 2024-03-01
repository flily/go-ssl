package certlet

func EncodeVarUint(value uint64, buffer []byte, offset int) int {
	i := 0
	for value > 0 {
		b := byte(value & 0x7f)
		value >>= 7
		if value > 0 {
			b |= 0x80
		}

		buffer[offset+i] = b
		i += 1
	}

	if i == 0 {
		buffer[offset] = 0
		i += 1
	}

	return offset + i
}

func DecodeVarUint(buffer []byte, offset int) (uint64, int) {
	var value uint64
	var shift uint
	var b byte

	for {
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

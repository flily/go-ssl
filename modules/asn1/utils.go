package asn1

func getBase128UintByteSize(n uint64) int {
	size := 0
	for n > 0 {
		size++
		n >>= 7
	}

	return size
}

func writeBase128Uint(buffer []byte, offset int, n uint64, size int) int {
	for i := 0; i < size; i++ {
		b := n >> uint((size-i-1)*7)
		if i < size-1 {
			b |= 0x80
		}

		buffer[offset+i] = byte(b)
	}

	return offset + size
}

func readBase128Uint(buffer []byte, offset int) (uint64, int) {
	n := uint64(0)
	finished := false
	i := offset
	for i < len(buffer) && !finished {
		b := buffer[i]
		i += 1
		n = (n << 7) | uint64(b&0x7f)
		if b&0x80 == 0 {
			finished = true
		}
	}

	if !finished {
		return 0, -1
	}

	return n, i
}

func getBase256UintByteSize(n uint64) int {
	size := 0
	for n > 0 {
		size++
		n >>= 8
	}

	return size
}

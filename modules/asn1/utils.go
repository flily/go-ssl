package asn1

func getBase128UintByteSize(n uint64) int {
	size := 0
	for n > 0 {
		size++
		n >>= 7
	}

	return size
}

func getBase256UintByteSize(n uint64) int {
	size := 0
	for n > 0 {
		size++
		n >>= 8
	}

	return size
}

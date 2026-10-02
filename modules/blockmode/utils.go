package blockmode

func sliceForAppend(in []byte, n int) ([]byte, []byte) {
	var head, tail []byte

	if total := len(in) + n; cap(in) >= total {
		head = in[:total]

	} else {
		head = make([]byte, total)
		copy(head, in)
	}

	tail = head[len(in):]
	return head, tail
}

// get the n-th bit of a byte array
func bitn(a []byte, n int) byte {
	return (a[n/8] >> (7 - (n % 8))) & 1
}

// dst = dst xor src
func xor(dst []byte, src []byte) {
	l := min(len(dst), len(src))
	for i := 0; i < l; i++ {
		dst[i] ^= src[i]
	}
}

// logical right shift by 1
func lrshift(a []byte) {
	carry := byte(0)
	for i := 0; i < len(a); i++ {
		newCarry := (a[i] & 1) << 7
		a[i] = (a[i] >> 1) | carry
		carry = newCarry
	}
}

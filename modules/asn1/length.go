package asn1

import (
	"fmt"
)

type Length int64

func IndefiniteLength() Length {
	return -1
}

func (l Length) Int() int {
	return int(l)
}

func (l Length) String() string {
	return fmt.Sprintf("Length[%d]", l.Int())
}

func (l Length) IsIndefinite() bool {
	return l < 0
}

func (l Length) WireLength() int {
	n := int64(l)
	if n < 0x80 {
		return 1
	}

	return 1 + getBase256UintByteSize(uint64(n))
}

func ReadLength(buffer []byte, offset int) (Length, int, error) {
	if err := checkBufferSize(buffer, offset, 1); err != nil {
		return 0, -1, err
	}

	firstOctet := buffer[offset]
	if firstOctet == 0x80 {
		// Indefinite length
		return IndefiniteLength(), offset + 1, nil
	}

	if firstOctet < 0x80 {
		// Raw length
		l := Length(firstOctet)
		return l, offset + 1, nil
	}

	if firstOctet == 0xff {
		// In 8.1.3.5.c, the value 0xFF is reserved for future use and shall not be used.
		return 0, -1, fmt.Errorf("asn1: invalid length value 0xFF")
	}

	lengthLength := int(firstOctet & 0x7f)
	if lengthLength >= 8 {
		// In ITU-T X.690, the length of the length can be as long as 127 bytes, but actually
		// no machine can allocate such a large buffer, so we limit the length to 8 bytes.
		return 0, -1, fmt.Errorf("asn1: too large size of length: %d", lengthLength)
	}

	if err := checkBufferSize(buffer, offset+1, lengthLength); err != nil {
		return 0, -1, err
	}

	n := uint64(0)
	for i := 0; i < lengthLength; i++ {
		n = (n << 8) | uint64(buffer[offset+1+i])
	}

	l := Length(n)
	return l, offset + 1 + lengthLength, nil
}

func (l Length) WriteTo(buffer []byte, offset int) (int, error) {
	if l < 0 {
		buffer[offset] = 0x80
		return offset + 1, nil
	}

	n := uint64(l)
	if n < 0x80 {
		buffer[offset] = byte(n)
		return offset + 1, nil
	}

	size := getBase256UintByteSize(n)
	if err := checkBufferSize(buffer, offset, 1+size); err != nil {
		return -1, err
	}

	buffer[offset] = byte(0x80 | size)
	for i := size - 1; i >= 0; i-- {
		buffer[offset+1+i] = byte(n)
		n >>= 8
	}

	return offset + 1 + size, nil
}

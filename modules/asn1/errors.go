package asn1

import (
	"fmt"
)

func errInsufficientBuffer(size int, actual int) error {
	err := fmt.Errorf("asn1: insufficient buffer size: expected %d, got %d",
		size, actual)
	return err
}

func checkBufferSize(buffer []byte, offset int, required int) error {
	if offset+required > len(buffer) {
		return errInsufficientBuffer(required, len(buffer)-offset)
	}

	return nil
}

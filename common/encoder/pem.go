package encoder

import (
	"encoding/pem"
)

func PEMEncode(name string, data []byte) []byte {
	block := &pem.Block{
		Type:  name,
		Bytes: data,
	}

	result := pem.EncodeToMemory(block)
	return result
}
func PEMDecode(data []byte) ([]byte, []byte) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil
	}

	return block.Bytes, rest
}

package hmac

import (
	"hash"
)

const (
	HMACInputPaddingUnit  byte = 0x36
	HMACOutputPaddingUnit byte = 0x5c
	HMACBlockSize         int  = 64
)

func xorBytesPadding(data []byte, message []byte, unit byte) []byte {
	dataSize := max(len(data), HMACBlockSize)
	outSize := dataSize + len(message)
	out := make([]byte, dataSize, outSize)

	copy(out, data)
	for i := range out {
		out[i] ^= unit
	}

	out = append(out, message...)
	return out
}

func HMAC[H func() hash.Hash](h H, key []byte, message []byte) []byte {
	h1 := h()
	_, _ = h1.Write(xorBytesPadding(key, message, HMACInputPaddingUnit))
	r1 := h1.Sum(nil)

	h2 := h()
	_, _ = h2.Write(xorBytesPadding(key, r1, HMACOutputPaddingUnit))
	r2 := h2.Sum(nil)

	return r2
}

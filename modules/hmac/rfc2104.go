package hmac

import (
	"hash"
)

const (
	HMACInputPaddingUnit  byte = 0x36
	HMACOutputPaddingUnit byte = 0x5c
	HMACBlockSize         int  = 64
)

func xorBytesPadding(data []byte, message []byte, unit byte, blockSize int) []byte {
	dataSize := max(len(data), blockSize)
	outSize := dataSize + len(message)
	out := make([]byte, dataSize, outSize)

	copy(out, data)
	for i := range out {
		out[i] ^= unit
	}

	out = append(out, message...)
	return out
}

func HMAC[H hash.Hash](h func() H, key []byte, message []byte) []byte {
	h1 := h()
	b := h1.BlockSize()

	k := key
	if len(k) > b {
		hk := h()
		_, _ = hk.Write(k)
		k = hk.Sum(nil)
	}

	_, _ = h1.Write(xorBytesPadding(k, message, HMACInputPaddingUnit, b))
	r1 := h1.Sum(nil)

	h2 := h()
	_, _ = h2.Write(xorBytesPadding(k, r1, HMACOutputPaddingUnit, b))
	r2 := h2.Sum(nil)

	return r2
}

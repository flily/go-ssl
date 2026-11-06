package hash

import (
	"crypto/sha3"
	"fmt"
	"hash"
)

type XOF int

const (
	XOFInvalid XOF = iota
	SHAKE128
	SHAKE256
)

func xofWrap[T hash.XOF](f func() T) func() hash.XOF {
	return func() hash.XOF {
		return f()
	}
}

var xofInfo = map[XOF]AlgorithmInfo[hash.XOF]{
	SHAKE128: {
		Name:      "SHAKE128",
		BlockSize: 168,
		Size:      32,
		New:       xofWrap(sha3.NewSHAKE128),
	},
	SHAKE256: {
		Name:      "SHAKE256",
		BlockSize: 136,
		Size:      64,
		New:       xofWrap(sha3.NewSHAKE256),
	},
}

func CheckXOFRegistered(x XOF) bool {
	_, ok := xofInfo[x]
	return ok
}

func RegisterXOFAlgorithm(x XOF, info AlgorithmInfo[hash.XOF]) {
	xofInfo[x] = info
}

func (x XOF) Name() string {
	if info, ok := xofInfo[x]; ok {
		return info.Name
	}

	return "unknown"
}

func (x XOF) BlockSize() int {
	if info, ok := xofInfo[x]; ok {
		return info.BlockSize
	}

	return 0
}

func (x XOF) Size() int {
	if info, ok := xofInfo[x]; ok {
		return info.Size
	}

	return 0
}

func (x XOF) New() hash.XOF {
	if info, ok := xofInfo[x]; ok {
		return info.New()
	}

	err := fmt.Errorf("unsupported XOF algorithm: %v", x)
	panic(err)
}

func (x XOF) Sum(data []byte, length int) []byte {
	h := x.New()
	_, _ = h.Write(data)

	sum := make([]byte, length)
	_, _ = h.Read(sum)
	return sum
}

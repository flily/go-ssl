package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
)

type AlgorithmInfo[T any] struct {
	Name      string
	BlockSize int
	Size      int
	New       func() T
}

type Hash int

const (
	HashInvalid Hash = iota
	MD5
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
	SHA512_224
	SHA512_256
	SHA3_224
	SHA3_256
	SHA3_384
	SHA3_512
)

func hashWrap[T hash.Hash](f func() T) func() hash.Hash {
	return func() hash.Hash {
		return f()
	}
}

var hashInfo = map[Hash]AlgorithmInfo[hash.Hash]{
	MD5: {
		Name:      "MD5",
		BlockSize: 64,
		Size:      16,
		New:       hashWrap(md5.New),
	},
	SHA1: {
		Name:      "SHA-1",
		BlockSize: 64,
		Size:      20,
		New:       hashWrap(sha1.New),
	},
	SHA224: {
		Name:      "SHA-224",
		BlockSize: 64,
		Size:      28,
		New:       hashWrap(sha256.New224),
	},
	SHA256: {
		Name:      "SHA-256",
		BlockSize: 64,
		Size:      32,
		New:       hashWrap(sha256.New),
	},
	SHA384: {
		Name:      "SHA-384",
		BlockSize: 128,
		Size:      48,
		New:       hashWrap(sha512.New384),
	},
	SHA512: {
		Name:      "SHA-512",
		BlockSize: 128,
		Size:      64,
		New:       hashWrap(sha512.New),
	},
	SHA512_224: {
		Name:      "SHA-512/224",
		BlockSize: 128,
		Size:      28,
		New:       hashWrap(sha512.New512_224),
	},
	SHA512_256: {
		Name:      "SHA-512/256",
		BlockSize: 128,
		Size:      32,
		New:       hashWrap(sha512.New512_256),
	},
	SHA3_224: {
		Name:      "SHA3-224",
		BlockSize: 144,
		Size:      28,
		New:       hashWrap(sha3.New224),
	},
	SHA3_256: {
		Name:      "SHA3-256",
		BlockSize: 136,
		Size:      32,
		New:       hashWrap(sha3.New256),
	},
	SHA3_384: {
		Name:      "SHA3-384",
		BlockSize: 104,
		Size:      48,
		New:       hashWrap(sha3.New384),
	},
	SHA3_512: {
		Name:      "SHA3-512",
		BlockSize: 72,
		Size:      64,
		New:       hashWrap(sha3.New512),
	},
}

func CheckHashRegistered(h Hash) bool {
	_, ok := hashInfo[h]
	return ok
}

func RegisterHashAlgorithm(h Hash, info AlgorithmInfo[hash.Hash]) {
	hashInfo[h] = info
}

func (h Hash) Name() string {
	if info, ok := hashInfo[h]; ok {
		return info.Name
	}

	return "unknown"
}

func (h Hash) BlockSize() int {
	if info, ok := hashInfo[h]; ok {
		return info.BlockSize
	}

	return 0
}

func (h Hash) Size() int {
	if info, ok := hashInfo[h]; ok {
		return info.Size
	}

	return 0
}

func (h Hash) New() hash.Hash {
	if info, ok := hashInfo[h]; ok {
		return info.New()
	}

	err := fmt.Errorf("unsupported hash algorithm: %v", h)
	panic(err)
}

func (h Hash) Sum(data []byte) []byte {
	hasher := h.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

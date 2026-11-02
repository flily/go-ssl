package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

// FixedHash is a common interface for hash algorithms with fixed output size.
// Interface equivalent to hash.Hash
type FixedHash interface {
	// Write updates data to the hash.
	// It never returns an error.
	io.Writer

	// Sum appends the current hash to b and returns the resulting slice.
	// It does not change the underlying hash state.
	Sum(b []byte) []byte

	// Reset resets the Hash to its initial state.
	Reset()

	// Size returns the number of bytes Sum will return.
	Size() int

	// BlockSize returns the hash's underlying block size.
	// The Write method must be able to accept any amount
	// of data, but it may operate more efficiently if all writes
	// are a multiple of the block size.
	BlockSize() int
}

type Hash interface {
	Name() string
	Sum([]byte) []byte
	BlockSize() int
	Size() int
	New() FixedHash
}

type HashAlgorithmInfo struct {
	Name         string
	BlockSize    int
	Size         int
	NewHash      func() hash.Hash
	NewFixedHash func() FixedHash
}

type HashAlgorithm int

const (
	HashInvalid HashAlgorithm = iota
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
	SHAKE128
	SHAKE256
)

func fixedHashWrapper[T FixedHash](f func() T) func() FixedHash {
	return func() FixedHash {
		return f()
	}
}

func hashWrap[T FixedHash](f func() T) func() hash.Hash {
	return func() hash.Hash {
		return f()
	}
}

var hashInfo = map[HashAlgorithm]HashAlgorithmInfo{
	MD5: {
		Name:         "MD5",
		BlockSize:    64,
		Size:         16,
		NewHash:      hashWrap(md5.New),
		NewFixedHash: fixedHashWrapper(md5.New),
	},
	SHA1: {
		Name:         "SHA-1",
		BlockSize:    64,
		Size:         20,
		NewFixedHash: fixedHashWrapper(sha1.New),
		NewHash:      hashWrap(sha1.New),
	},
	SHA224: {
		Name:         "SHA-224",
		BlockSize:    64,
		Size:         28,
		NewHash:      hashWrap(sha256.New224),
		NewFixedHash: fixedHashWrapper(sha256.New224),
	},
	SHA256: {
		Name:         "SHA-256",
		BlockSize:    64,
		Size:         32,
		NewHash:      hashWrap(sha256.New),
		NewFixedHash: fixedHashWrapper(sha256.New),
	},
	SHA384: {
		Name:         "SHA-384",
		BlockSize:    128,
		Size:         48,
		NewHash:      hashWrap(sha512.New384),
		NewFixedHash: fixedHashWrapper(sha512.New384),
	},
	SHA512: {
		Name:         "SHA-512",
		BlockSize:    128,
		Size:         64,
		NewHash:      hashWrap(sha512.New),
		NewFixedHash: fixedHashWrapper(sha512.New),
	},
	SHA512_224: {
		Name:         "SHA-512/224",
		BlockSize:    128,
		Size:         28,
		NewHash:      hashWrap(sha512.New512_224),
		NewFixedHash: fixedHashWrapper(sha512.New512_224),
	},
	SHA512_256: {
		Name:         "SHA-512/256",
		BlockSize:    128,
		Size:         32,
		NewFixedHash: fixedHashWrapper(sha512.New512_256),
		NewHash:      hashWrap(sha512.New512_256),
	},
	SHA3_224: {
		Name:         "SHA3-224",
		BlockSize:    144,
		Size:         28,
		NewFixedHash: fixedHashWrapper(sha3.New224),
		NewHash:      hashWrap(sha3.New224),
	},
	SHA3_256: {
		Name:         "SHA3-256",
		BlockSize:    136,
		Size:         32,
		NewHash:      hashWrap(sha3.New256),
		NewFixedHash: fixedHashWrapper(sha3.New256),
	},
	SHA3_384: {
		Name:         "SHA3-384",
		BlockSize:    104,
		Size:         48,
		NewHash:      hashWrap(sha3.New384),
		NewFixedHash: fixedHashWrapper(sha3.New384),
	},
	SHA3_512: {
		Name:         "SHA3-512",
		BlockSize:    72,
		Size:         64,
		NewHash:      hashWrap(sha3.New512),
		NewFixedHash: fixedHashWrapper(sha3.New512),
	},
}

func RegisterHashAlgorithm(h HashAlgorithm, info HashAlgorithmInfo) {
	hashInfo[h] = info
}

func (h HashAlgorithm) Name() string {
	if info, ok := hashInfo[h]; ok {
		return info.Name
	}

	return "unknown"
}

func (h HashAlgorithm) BlockSize() int {
	if info, ok := hashInfo[h]; ok {
		return info.BlockSize
	}

	return 0
}

func (h HashAlgorithm) Size() int {
	if info, ok := hashInfo[h]; ok {
		return info.Size
	}

	return 0
}

func (h HashAlgorithm) New() FixedHash {
	if info, ok := hashInfo[h]; ok {
		return info.NewFixedHash()
	}

	err := fmt.Errorf("unsupported hash algorithm: %v", h)
	panic(err)
}

func (h HashAlgorithm) NewHash() hash.Hash {
	if info, ok := hashInfo[h]; ok {
		return info.NewHash()
	}

	err := fmt.Errorf("unsupported hash algorithm: %v", h)
	panic(err)
}

func (h HashAlgorithm) Sum(data []byte) []byte {
	hasher := h.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

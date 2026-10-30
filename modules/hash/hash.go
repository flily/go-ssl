package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type Hash interface {
	Name() string
	Sum([]byte) []byte
	BlockSize() int
	Size() int
	New() hash.Hash
}

type HashAlgorithmInfo struct {
	Name      string
	BlockSize int
	Size      int
	New       func() hash.Hash
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
)

var hashInfo = map[HashAlgorithm]HashAlgorithmInfo{
	MD5: {
		Name:      "MD5",
		BlockSize: 64,
		Size:      16,
		New:       md5.New,
	},
	SHA1: {
		Name:      "SHA-1",
		BlockSize: 64,
		Size:      20,
		New:       sha1.New,
	},
	SHA224: {
		Name:      "SHA-224",
		BlockSize: 64,
		Size:      28,
		New:       sha256.New224,
	},
	SHA256: {
		Name:      "SHA-256",
		BlockSize: 64,
		Size:      32,
		New:       sha256.New,
	},
	SHA384: {
		Name:      "SHA-384",
		BlockSize: 128,
		Size:      48,
		New:       sha512.New384,
	},
	SHA512: {
		Name:      "SHA-512",
		BlockSize: 128,
		Size:      64,
		New:       sha512.New,
	},
	SHA512_224: {
		Name:      "SHA-512/224",
		BlockSize: 128,
		Size:      28,
		New:       sha512.New512_224,
	},
	SHA512_256: {
		Name:      "SHA-512/256",
		BlockSize: 128,
		Size:      32,
		New:       sha512.New512_256,
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

func (h HashAlgorithm) New() hash.Hash {
	if info, ok := hashInfo[h]; ok {
		return info.New()
	}

	err := fmt.Errorf("unsupported hash algorithm: %v", h)
	panic(err)
}

func (h HashAlgorithm) Sum(data []byte) []byte {
	hasher := h.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}

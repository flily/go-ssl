package digest

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/md4" //nolint:all
	"golang.org/x/crypto/sha3"
)

var algorithmMap = map[string]func() hash.Hash{
	"md4":        md4.New,
	"md5":        md5.New,
	"sha1":       sha1.New,
	"sha224":     sha256.New224,
	"sha256":     sha256.New,
	"sha384":     sha512.New384,
	"sha512":     sha512.New,
	"sha512-224": sha512.New512_224,
	"sha512-256": sha512.New512_256,
	"sha3-224":   sha3.New224,
	"sha3-256":   sha3.New256,
	"sha3-384":   sha3.New384,
	"sha3-512":   sha3.New512,
}

func getHasher(algo string) (hash.Hash, error) {
	newFunc, found := algorithmMap[strings.ToLower(algo)]
	if !found {
		err := fmt.Errorf("no algorithm '%s'", algo)
		return nil, err
	}

	return newFunc(), nil
}

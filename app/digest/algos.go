package digest

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/md4"
)

var algorithmMap = map[string]func() hash.Hash{
	"md4":    md4.New,
	"md5":    md5.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
}

func getHasher(algo string) (hash.Hash, error) {
	newFunc, found := algorithmMap[strings.ToLower(algo)]
	if !found {
		err := fmt.Errorf("no algorithm '%s'", algo)
		return nil, err
	}

	return newFunc(), nil
}

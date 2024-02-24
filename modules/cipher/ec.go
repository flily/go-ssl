package cipher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/flily/go-ssl/common/encoder"
)

type ECPrivateKey struct {
	dsa *ecdsa.PrivateKey
}

func GenerateECKey(curve elliptic.Curve) (*ECPrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	k := &ECPrivateKey{
		dsa: privateKey,
	}

	return k, nil
}

func (k *ECPrivateKey) DER() []byte {
	result, err := x509.MarshalECPrivateKey(k.dsa)
	if err != nil {
		return nil
	}

	return result
}

func (k *ECPrivateKey) PEM() []byte {
	der := k.DER()
	if der == nil {
		return nil
	}

	return encoder.PEMEncode("EC PRIVATE KEY", der)
}

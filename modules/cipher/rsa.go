package cipher

import (
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/flily/go-ssl/common/encoder"
)

type RSAPrivateKey struct {
	rsa.PrivateKey
}

func GenerateRSAKey(random io.Reader, bits int) (*RSAPrivateKey, error) {
	privateKey, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return nil, err
	}

	k := &RSAPrivateKey{
		PrivateKey: *privateKey,
	}

	return k, nil
}

func (k *RSAPrivateKey) DER() []byte {
	return k.PKCS8PrivateKey()
}

func (k *RSAPrivateKey) PEM() []byte {
	return k.PKCS8PrivateKeyPEM()
}

func (k *RSAPrivateKey) PKCS1PrivateKey() []byte {
	return x509.MarshalPKCS1PrivateKey(&k.PrivateKey)
}

func (k *RSAPrivateKey) PKCS1PrivateKeyPEM() []byte {
	content := k.PKCS1PrivateKey()
	return encoder.PEMEncode("RSA PRIVATE KEY", content)
}

func (k *RSAPrivateKey) PKCS1PublicKey() []byte {
	return x509.MarshalPKCS1PublicKey(&k.PrivateKey.PublicKey)
}

func (k *RSAPrivateKey) PKCS1PublicKeyPEM() []byte {
	content := k.PKCS1PublicKey()
	return encoder.PEMEncode("RSA PUBLIC KEY", content)
}

func (k *RSAPrivateKey) PKCS8PrivateKey() []byte {
	content, _ := x509.MarshalPKCS8PrivateKey(&k.PrivateKey)
	return content
}

func (k *RSAPrivateKey) PKCS8PrivateKeyPEM() []byte {
	content := k.PKCS8PrivateKey()
	return encoder.PEMEncode("PRIVATE KEY", content)
}

func (k *RSAPrivateKey) PKIXPrivateKey() []byte {
	content, _ := x509.MarshalPKIXPublicKey(&k.PrivateKey.PublicKey)
	return content
}

func (k *RSAPrivateKey) PKIXPrivateKeyPEM() []byte {
	content := k.PKIXPrivateKey()
	return encoder.PEMEncode("PUBLIC KEY", content)
}

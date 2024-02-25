package encoder

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
)

func ReadRSAKey(filename string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}

	content, err := io.ReadAll(fd)
	_ = fd.Close()
	if err != nil {
		return nil, nil, err
	}

	// Ensure ASN.1 DER encoding
	content, _ = PEMTryDecode(content)

	if key, err := x509.ParsePKCS1PrivateKey(content); err == nil {
		return key, &key.PublicKey, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(content); err == nil {
		return nil, key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(content); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not a RSA PKCS8 private prkey")
		}

		return rsaKey, &rsaKey.PublicKey, nil
	}

	if key, err := x509.ParsePKIXPublicKey(content); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("not a RSA PKIX public key")
		}

		return nil, rsaKey, nil
	}

	return nil, nil, fmt.Errorf("unknown key format")
}

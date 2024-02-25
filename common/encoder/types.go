package encoder

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
)

type KeyFileFormat int

const (
	KeyFileFormatInvalid KeyFileFormat = iota
	KeyFileFormatPKCS1RSAPrivateKey
	KeyFileFormatPKCS1RSAPublicKey
	KeyFileFormatPKCS7Message
	KeyFileFormatPKCS8PrivateKey
	KeyFileFormatPKIXPublicKey
	KeyFileFormatECPrivateKey
	KeyFileFormatECPublicKey
	KeyFileFormatECParameters
	KeyFileFormatCertificate
	KeyFileFormatPEM
)

func (f KeyFileFormat) String() string {
	switch f {
	case KeyFileFormatInvalid:
		return "INVALID"
	case KeyFileFormatPKCS1RSAPrivateKey:
		return "RSAPrivateKey[PKCS1]"
	case KeyFileFormatPKCS1RSAPublicKey:
		return "RSAPublicKey[PKCS1]"
	case KeyFileFormatPKCS7Message:
		return "PKCS7Message"
	case KeyFileFormatPKCS8PrivateKey:
		return "PrivateKey[PKCS8]"
	case KeyFileFormatPKIXPublicKey:
		return "PublicKey[PKIX]"
	case KeyFileFormatECPrivateKey:
		return "ECPrivateKey"
	case KeyFileFormatECPublicKey:
		return "ECPublicKey"
	case KeyFileFormatECParameters:
		return "ECParameters"
	case KeyFileFormatCertificate:
		return "Certificate"
	case KeyFileFormatPEM:
		return "PEM"

	default:
		return fmt.Sprintf("KeyFileFormat(%d)", int(f))
	}
}

func canParseKey[T any](data []byte, loader func([]byte) (T, error)) bool {
	_, err := loader(data)
	return err == nil
}

func derDetect(data []byte) KeyFileFormat {
	result := KeyFileFormatInvalid
	if canParseKey(data, x509.ParsePKCS1PrivateKey) {
		result = KeyFileFormatPKCS1RSAPrivateKey

	} else if canParseKey(data, x509.ParsePKCS1PublicKey) {
		result = KeyFileFormatPKCS1RSAPublicKey

	} else if canParseKey(data, pkcs7.Parse) {
		result = KeyFileFormatPKCS7Message

	} else if canParseKey(data, x509.ParsePKCS8PrivateKey) {
		result = KeyFileFormatPKCS8PrivateKey

	} else if canParseKey(data, x509.ParsePKIXPublicKey) {
		result = KeyFileFormatPKIXPublicKey

	} else if canParseKey(data, x509.ParseECPrivateKey) {
		result = KeyFileFormatECPrivateKey

	} else if canParseKey(data, x509.ParseCertificate) {
		result = KeyFileFormatCertificate
	}

	return result
}

func TypeDetect(data []byte) []KeyFileFormat {
	outTypes := make([]KeyFileFormat, 0)
	block, rest := pem.Decode(data)
	if block != nil {
		keyType := derDetect(block.Bytes)
		outTypes = append(outTypes,
			KeyFileFormatPEM,
			keyType,
		)

		if len(rest) > 0 {
			outTypes = append(outTypes, TypeDetect(rest)...)
		}

	} else {
		outTypes = append(outTypes, derDetect(data))
	}

	return outTypes
}

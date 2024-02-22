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
	KeyFileFormatPKIXPrivateKey
	KeyFileFormatECPrivateKey
	KeyFileFormatECPublicKey
	KeyFileFormatCertificate
	KeyFileFormatPEM
)

func (f KeyFileFormat) String() string {
	switch f {
	case KeyFileFormatInvalid:
		return "Invalid"
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
	case KeyFileFormatCertificate:
		return "Certificate"
	case KeyFileFormatPEM:
		return "PEM"
	default:
		return fmt.Sprintf("KeyFileFormat(%d)", f)
	}
}

func canParseKey[T any](data []byte, loader func([]byte) (T, error)) bool {
	_, err := loader(data)
	return err == nil
}

func TypeDetect(data []byte, outTypes ...KeyFileFormat) []KeyFileFormat {
	block, _ := pem.Decode(data)
	if block != nil {
		return TypeDetect(block.Bytes, append(outTypes, KeyFileFormatPEM)...)
	}

	if canParseKey(data, x509.ParsePKCS1PrivateKey) {
		outTypes = append(outTypes, KeyFileFormatPKCS1RSAPrivateKey)

	} else if canParseKey(data, x509.ParsePKCS1PublicKey) {
		outTypes = append(outTypes, KeyFileFormatPKCS1RSAPublicKey)

	} else if canParseKey(data, pkcs7.Parse) {
		outTypes = append(outTypes, KeyFileFormatPKCS7Message)

	} else if canParseKey(data, x509.ParsePKCS8PrivateKey) {
		outTypes = append(outTypes, KeyFileFormatPKCS8PrivateKey)

	} else if canParseKey(data, x509.ParsePKIXPublicKey) {
		outTypes = append(outTypes, KeyFileFormatPKIXPublicKey)

	} else if canParseKey(data, x509.ParseECPrivateKey) {
		outTypes = append(outTypes, KeyFileFormatECPrivateKey)

	} else if canParseKey(data, x509.ParseCertificate) {
		outTypes = append(outTypes, KeyFileFormatCertificate)

	}

	return outTypes
}

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
	KeyFileFormatCertificateRequest
	KeyFileFormatPEM
)

var keyFileFormatNameMap = map[KeyFileFormat]string{
	KeyFileFormatInvalid:            "INVALID",
	KeyFileFormatPKCS1RSAPrivateKey: "RSAPrivateKey[PKCS1]",
	KeyFileFormatPKCS1RSAPublicKey:  "RSAPublicKey[PKCS1]",
	KeyFileFormatPKCS7Message:       "PKCS7Message",
	KeyFileFormatPKCS8PrivateKey:    "PrivateKey[PKCS8]",
	KeyFileFormatPKIXPublicKey:      "PublicKey[PKIX]",
	KeyFileFormatECPrivateKey:       "ECPrivateKey",
	KeyFileFormatECPublicKey:        "ECPublicKey",
	KeyFileFormatECParameters:       "ECParameters",
	KeyFileFormatCertificate:        "Certificate",
	KeyFileFormatCertificateRequest: "CertificateRequest",
	KeyFileFormatPEM:                "PEM",
}

func (f KeyFileFormat) String() string {
	name, known := keyFileFormatNameMap[f]
	if known {
		return name
	}

	return fmt.Sprintf("KeyFileFormat(%d)", int(f))
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

	} else if canParseKey(data, x509.ParseCertificateRequest) {
		result = KeyFileFormatCertificateRequest

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

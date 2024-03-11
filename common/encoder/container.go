package encoder

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"go.mozilla.org/pkcs7"
)

type KeyType int

const (
	KeyTypeInvalid KeyType = iota
	KeyTypeRSAPrivateKey
	KeyTypeRSAPublicKey
	KeyTypeECPrivateKey
	KeyTypeECPublicKey
	KeyTypeECParameters
	KeyTypeCertificate
)

func (t KeyType) String() string {
	switch t {
	case KeyTypeInvalid:
		return "INVALID"
	case KeyTypeRSAPrivateKey:
		return "RSA PrivateKey"
	case KeyTypeRSAPublicKey:
		return "RSA PublicKey"
	case KeyTypeECPrivateKey:
		return "EC PrivateKey"
	case KeyTypeECPublicKey:
		return "EC PublicKey"
	case KeyTypeECParameters:
		return "EC Parameters"
	case KeyTypeCertificate:
		return "Certificate"

	default:
		return fmt.Sprintf("KeyType(%d)", int(t))
	}
}

type Container struct {
	format  KeyFileFormat
	isPEM   bool
	pemType string

	keyType KeyType
	rsaPri  *rsa.PrivateKey
	rsaPub  *rsa.PublicKey
	ecdPri  *ecdsa.PrivateKey
	ecdPub  *ecdsa.PublicKey
	cert    *x509.Certificate
	binary  []byte

	next *Container
}

func NewRSAPrivateKeyContainer(key *rsa.PrivateKey) *Container {
	c := &Container{
		rsaPri: key,
	}

	return c
}

func NewRSAPublicKeyContainer(key *rsa.PublicKey) *Container {
	c := &Container{
		rsaPub: key,
	}

	return c
}

func NewECDSAPrivateKeyContainer(key *ecdsa.PrivateKey) *Container {
	c := &Container{
		ecdPri: key,
	}

	return c
}

func NewECDSAPublicKeyContainer(key *ecdsa.PublicKey) *Container {
	c := &Container{
		ecdPub: key,
	}

	return c
}

func makeKeyParser[T any](loader func([]byte) (T, error)) func(data []byte) (any, error) {
	return func(data []byte) (any, error) {
		key, err := loader(data)
		if err != nil {
			return nil, err
		}

		return key, err
	}
}

func NewDERContainer(data []byte) (*Container, error) {
	c := &Container{}
	err := c.parseDERFormat(data)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func ParseContainerChain(data []byte) (*Container, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		// DER format
		return NewDERContainer(data)
	}

	c := &Container{
		isPEM:   true,
		pemType: block.Type,
	}

	if block.Type == "EC PARAMETERS" {
		c.setECParamter(block.Bytes)

	} else {
		err := c.parseDERFormat(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	if len(rest) > 0 {
		next, err := ParseContainerChain(rest)
		if err != nil {
			return nil, err
		}

		c.next = next
	}

	return c, nil
}

func ParseContainerChainFromFile(filename string) (*Container, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	defer fd.Close()

	content, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	return ParseContainerChain(content)
}

func (c *Container) setECParamter(data []byte) {
	c.format = KeyFileFormatECParameters
	c.keyType = KeyTypeECParameters
	c.binary = data
}

func (c *Container) parseDERFormat(data []byte) error {
	tryParsers := []struct {
		parser func([]byte) (any, error)
		kind   KeyFileFormat
	}{
		{makeKeyParser(x509.ParsePKCS1PrivateKey), KeyFileFormatPKCS1RSAPrivateKey},
		{makeKeyParser(x509.ParsePKCS1PublicKey), KeyFileFormatPKCS1RSAPublicKey},
		{makeKeyParser(pkcs7.Parse), KeyFileFormatPKCS7Message},
		{makeKeyParser(x509.ParsePKCS8PrivateKey), KeyFileFormatPKCS8PrivateKey},
		{makeKeyParser(x509.ParsePKIXPublicKey), KeyFileFormatPKIXPublicKey},
		{makeKeyParser(x509.ParseECPrivateKey), KeyFileFormatECPrivateKey},
		{makeKeyParser(x509.ParseCertificate), KeyFileFormatCertificate},
	}

	found := false
	for _, parser := range tryParsers {
		key, err := parser.parser(data)
		if err == nil {
			_ = c.setKeyWithFormat(key, parser.kind)
			found = true
			break
		}
	}

	if !found {
		err := fmt.Errorf("can not parse data as DER format")
		return err
	}

	return nil
}

func (c *Container) setKeyWithFormat(key any, format KeyFileFormat) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		c.keyType = KeyTypeRSAPrivateKey
		c.rsaPri = k

	case *rsa.PublicKey:
		c.keyType = KeyTypeRSAPublicKey
		c.rsaPub = k

	case *ecdsa.PrivateKey:
		c.keyType = KeyTypeECPrivateKey
		c.ecdPri = k

	case *ecdsa.PublicKey:
		c.keyType = KeyTypeECPublicKey
		c.ecdPub = k

	case *x509.Certificate:
		c.keyType = KeyTypeCertificate
		c.cert = k

	case []byte:
		if format != KeyFileFormatECParameters {
			err := fmt.Errorf("Unknown binary data got: %s",
				format.String())
			return err
		}

		c.binary = k
		c.keyType = KeyTypeECParameters
	}

	c.format = format
	return nil
}

func (c *Container) KeyType() KeyType {
	return c.keyType
}

func (c *Container) KeyTypeString() string {
	if c.isPEM {
		return fmt.Sprintf("PEM[(%s) %s %s]",
			c.pemType, c.format, c.keyType)
	} else {
		return fmt.Sprintf("DER[%s %s]", c.format, c.keyType)
	}
}

func (c *Container) Next() *Container {
	return c.next
}

func (c *Container) RSAPrivateKey() *rsa.PrivateKey {
	return c.rsaPri
}

func (c *Container) RSAPublicKey() *rsa.PublicKey {
	return c.rsaPub
}

func (c *Container) ECDSAPrivateKey() *ecdsa.PrivateKey {
	return c.ecdPri
}

func (c *Container) ECDSAPublicKey() *ecdsa.PublicKey {
	return c.ecdPub
}

package keygen

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"

	"github.com/flily/go-ssl/modules/cipher"
)

type GenerateRSAKeyConfigure struct {
	Random io.Reader
	Bits   int
}

func DefaultGenerateRSAKeyConfigure() *GenerateRSAKeyConfigure {
	c := &GenerateRSAKeyConfigure{
		Random: rand.Reader,
		Bits:   2048,
	}

	return c
}

func GenerateRSAKey(conf *GenerateRSAKeyConfigure) {
	privateKey, err := cipher.GenerateRSAKey(conf.Random, conf.Bits)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", string(privateKey.PKCS8PrivateKeyPEM()))
	// fmt.Printf("%s\n", string(privateKey.PKCS1PrivateKey()))
}

func MainGenRSA(args []string) error {
	set := flag.NewFlagSet("genrsa", flag.ExitOnError)

	err := set.Parse(args)
	if err != nil {
		return err
	}

	conf := DefaultGenerateRSAKeyConfigure()
	GenerateRSAKey(conf)

	return nil
}

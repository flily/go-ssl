package cipher

import (
	"crypto/ecdsa"
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
	"github.com/flily/go-ssl/common/prettyprint"
)

func showECPrivateKey(privateKey *ecdsa.PrivateKey) {
	fmt.Printf("curve: %s\n", privateKey.Curve.Params().Name)
	prettyprint.PrintBinary("X", privateKey.X.Bytes())
	prettyprint.PrintBinary("Y", privateKey.Y.Bytes())
	prettyprint.PrintBinary("D", privateKey.D.Bytes())
}

func showECPublicKey(publicKey *ecdsa.PublicKey) {
	fmt.Printf("curve: %s\n", publicKey.Curve.Params().Name)
	prettyprint.PrintBinary("X", publicKey.X.Bytes())
	prettyprint.PrintBinary("Y", publicKey.Y.Bytes())
}

func loadECKey(filename string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	container, err := encoder.ParseContainerChainFromFile(filename)
	if err != nil {
		return nil, nil, err
	}

	c := container
	for c != nil {
		switch c.KeyType() {
		case encoder.KeyTypeECPrivateKey:
			key := c.ECDSAPrivateKey()
			return key, &key.PublicKey, nil

		case encoder.KeyTypeECPublicKey:
			return nil, c.ECDSAPublicKey(), nil
		}

		c = c.Next()
	}

	return nil, nil, fmt.Errorf("No EC key found")
}

func ecCommandShow(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("ec show", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	showPublic := set.Bool("public", false, "Show public key")
	err := ctx.Parse(set)
	if err != nil {
		return err
	}

	privateKey, publicKey, err := loadECKey(*inFile)
	if err != nil {
		return err
	}

	if *showPublic || privateKey == nil {
		showECPublicKey(publicKey)
	} else {
		showECPrivateKey(privateKey)
	}

	return nil
}

var ecCommands = map[string]clicontext.CommandEntryFunc{
	"show": ecCommandShow,
}

func MainEC(ctx *clicontext.CommandContext) error {
	return ctx.Invoke(ecCommands)
}

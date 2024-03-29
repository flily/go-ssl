package cipher

import (
	"crypto/ecdsa"
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
	"github.com/flily/go-ssl/common/prettyprint"
)

func showECPublicKeyXY(publicKey *ecdsa.PublicKey, showQ bool, showQCompress bool) {
	if showQ {
		if showQCompress {
			prettyprint.PrintBinaries("Q (Public, Compressed)",
				[]byte{0x02}, publicKey.X.Bytes())
		} else {
			prettyprint.PrintBinaries("Q (Public, Uncompressed)",
				[]byte{0x04}, publicKey.X.Bytes(), publicKey.Y.Bytes())
		}
	} else {
		prettyprint.PrintBinary("X (Public)", publicKey.X.Bytes())
		prettyprint.PrintBinary("Y (Public)", publicKey.Y.Bytes())
	}
}

func showECPrivateKey(privateKey *ecdsa.PrivateKey, showQ bool, showQCompress bool) {
	fmt.Printf("curve: %s\n", privateKey.Curve.Params().Name)
	prettyprint.PrintBinary("D (Private)", privateKey.D.Bytes())

	showECPublicKeyXY(&privateKey.PublicKey, showQ, showQCompress)
}

func showECPublicKey(publicKey *ecdsa.PublicKey, showQ bool, showQCompress bool) {
	fmt.Printf("curve: %s\n", publicKey.Curve.Params().Name)
	showECPublicKeyXY(publicKey, showQ, showQCompress)
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
	showQ := set.Bool("q", false, "Show public key in Q (x || y) format")
	showQCompress := set.Bool("qcompress", false, "Show public key in Q compressed format")
	err := ctx.Parse(set)
	if err != nil {
		return err
	}

	privateKey, publicKey, err := loadECKey(*inFile)
	if err != nil {
		return err
	}

	if *showPublic || privateKey == nil {
		showECPublicKey(publicKey, *showQ, *showQCompress)
	} else {
		showECPrivateKey(privateKey, *showQ, *showQCompress)
	}

	return nil
}

var ecCommands = map[string]clicontext.CommandEntryFunc{
	"show": ecCommandShow,
}

func MainEC(ctx *clicontext.CommandContext) error {
	return ctx.Invoke(ecCommands)
}

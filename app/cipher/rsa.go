package cipher

import (
	"crypto/rsa"
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
	"github.com/flily/go-ssl/common/prettyprint"
)

func showRSAPublicKeyEN(publicKey *rsa.PublicKey) {
	fmt.Printf("E (public exponent): %d (0x%x)\n", publicKey.E, publicKey.E)
	prettyprint.PPrintBinary("N (modulus)", publicKey.N.Bytes())
}

func showRSAPrivateKey(privateKey *rsa.PrivateKey) {
	d := privateKey.D.Bytes()
	prettyprint.PPrintBinary("D (private exponent)", d)

	showRSAPublicKeyEN(&privateKey.PublicKey)

	for i, prime := range privateKey.Primes {
		title := fmt.Sprintf("Prime %d (private)", i+1)
		prettyprint.PPrintBinary(title, prime.Bytes())
	}

	prettyprint.PPrintBinary("Dp (private D mod P-1)", privateKey.Precomputed.Dp.Bytes())
	prettyprint.PPrintBinary("Dq (private D mod Q-1)", privateKey.Precomputed.Dq.Bytes())
	prettyprint.PPrintBinary("QInv (private Q^-1 mod P)", privateKey.Precomputed.Qinv.Bytes())
}

func showRSAPublicKey(publicKey *rsa.PublicKey) {
	showRSAPublicKeyEN(publicKey)
}

func loadRSAKey(filename string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	container, err := encoder.ParseContainerChainFromFile(filename)
	if err != nil {
		return nil, nil, err
	}

	c := container
	for c != nil {
		switch c.KeyType() {
		case encoder.KeyTypeRSAPrivateKey:
			key := c.RSAPrivateKey()
			return key, &key.PublicKey, nil

		case encoder.KeyTypeRSAPublicKey:
			return nil, c.RSAPublicKey(), nil
		}

		c = c.Next()
	}

	return nil, nil, fmt.Errorf("No RSA key found")
}

func rsaCommandShow(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("rsa show", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	showPublic := set.Bool("public", false, "Show public key")
	_ = ctx.Parse(set)

	privateKey, publicKey, err := loadRSAKey(*inFile)
	if err != nil {
		return err
	}

	if privateKey != nil {
		if *showPublic {
			fmt.Printf("RSA Private key found.\n")
			showRSAPublicKey(publicKey)

		} else {
			showRSAPrivateKey(privateKey)
		}
	} else if publicKey != nil {
		showRSAPublicKey(publicKey)

	} else {
		return fmt.Errorf("No RSA key found")
	}

	return nil
}

var rsaCommands = map[string]clicontext.CommandEntryFunc{
	"show": rsaCommandShow,
}

func MainRSA(ctx *clicontext.CommandContext) error {
	return ctx.Invoke(rsaCommands)
}

package cipher

import (
	"crypto/rsa"
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
)

func showRSAPrivateKey(privateKey *rsa.PrivateKey) {
	d := privateKey.D.Bytes()
	n := privateKey.N.Bytes()
	fmt.Printf("E: %x\n", privateKey.E)
	fmt.Printf("D: [%d] %x\n", len(d), d)
	fmt.Printf("N: [%d] %x\n", len(n), n)
}

func showRSAPublicKey(publicKey *rsa.PublicKey) {
	e := publicKey.E
	n := publicKey.N.Bytes()
	fmt.Printf("E: %x\n", e)
	fmt.Printf("N: [%d] %x\n", len(n), n)
}

func rsaCommandShow(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("rsa show", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	showPublic := set.Bool("public", false, "Show public key")
	_ = ctx.Parse(set)

	privateKey, publicKey, err := encoder.ReadRSAKey(*inFile)
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

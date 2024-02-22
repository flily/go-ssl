package cipher

import (
	"crypto/rsa"
	"flag"
	"fmt"

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

func rsaCommandShow(args []string) error {
	set := flag.NewFlagSet("rsa show", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	showPublic := set.Bool("public", false, "Show public key")
	_ = set.Parse(args)

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

var rsaCommands = map[string]func([]string) error{
	"show": rsaCommandShow,
}

func MainRSA(args []string) error {
	set := flag.NewFlagSet("rsa", flag.ExitOnError)
	_ = set.Parse(args)

	nextArgs := set.Args()
	cmd := "show"
	if len(args) > 0 {
		cmd = nextArgs[0]
		nextArgs = nextArgs[1:]
	}

	fn, found := rsaCommands[cmd]
	if !found {
		return fmt.Errorf("Invalid command: %s", cmd)
	}

	return fn(nextArgs)
}

package cipher

import (
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/encoder"
)

func MainRSA(args []string) error {
	set := flag.NewFlagSet("rsa", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	_ = set.Parse(args)

	privateKey, publicKey, err := encoder.ReadRSAKey(*inFile)
	if err != nil {
		return err
	}

	fmt.Printf("private key: %v\n", privateKey)
	fmt.Printf("public key: %v\n", publicKey)
	return nil
}

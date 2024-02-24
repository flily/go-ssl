package keygen

import (
	"crypto/elliptic"
	"flag"
	"fmt"
	"strings"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/modules/cipher"
)

var curves = map[string]elliptic.Curve{
	"p224":       elliptic.P224(),
	"secp224r1":  elliptic.P224(),
	"p256":       elliptic.P256(),
	"secp256r1":  elliptic.P256(),
	"prime256v1": elliptic.P256(),
	"p384":       elliptic.P384(),
	"secp384r1":  elliptic.P384(),
	"p521":       elliptic.P521(),
	"secp521r1":  elliptic.P521(),
}

func MainGenEC(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("genec", flag.ExitOnError)
	curveName := set.String("curve", "P256", "Curve name, one of P224, P256, P384 and P521")
	err := ctx.Parse(set)
	if err != nil {
		return err
	}

	curve, found := curves[strings.ToLower(*curveName)]
	if !found {
		return fmt.Errorf("Unknown curve name: %s", *curveName)
	}

	privateKey, err := cipher.GenerateECKey(curve)
	if err != nil {
		return err
	}

	fmt.Printf("%s", privateKey.PEM())

	return nil
}

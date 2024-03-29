package main

import (
	"fmt"
	"os"

	"github.com/flily/go-ssl/app/cert"
	"github.com/flily/go-ssl/app/cipher"
	"github.com/flily/go-ssl/app/digest"
	"github.com/flily/go-ssl/app/keygen"
	"github.com/flily/go-ssl/app/utils/asn1"
	"github.com/flily/go-ssl/app/utils/format"
	"github.com/flily/go-ssl/cmd/gossl/commands/version"
	"github.com/flily/go-ssl/common/clicontext"
)

type Entry func(args []string) error

var commands map[string]clicontext.CommandEntryFunc

func init() {
	commands = map[string]clicontext.CommandEntryFunc{
		"version":  version.MainVersion,
		"digest":   digest.Main,
		"genrsa":   keygen.MainGenRSA,
		"rsa":      cipher.MainRSA,
		"genecdsa": keygen.MainGenEC,
		"ec":       cipher.MainEC,
		"format":   format.MainFormat,
		"asn1":     asn1.MainASN1,
		"cert":     cert.MainCert,
		"help":     showHelp,
	}
}

func showHelp(ctx *clicontext.CommandContext) error {
	help()
	return nil
}

func help() {
	fmt.Printf("Usage: %s <command> [options]\n", os.Args[0])
	fmt.Println("Commands:")
	for name := range commands {
		fmt.Printf("  %s\n", name)
	}
}

func main() {
	ctx := clicontext.NewCommandContext(os.Args)
	err := ctx.Invoke(commands)
	if err != nil {
		fmt.Printf("gossl error: %s\n", err)
	}
}

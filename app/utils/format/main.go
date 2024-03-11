package format

import (
	"flag"
	"fmt"
	"strings"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
)

func detectFileType(filename string) error {
	container, err := encoder.ParseContainerChainFromFile(filename)
	if err != nil {
		return err
	}

	typeChain := make([]string, 0, 10)
	c := container
	for c != nil {
		typeChain = append(typeChain, c.KeyTypeString())
		c = c.Next()
	}
	fmt.Printf("%s: %s\n", filename, strings.Join(typeChain, " -> "))
	return nil
}

func MainFormat(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("format", flag.ExitOnError)
	_ = ctx.Parse(set)

	for _, filename := range set.Args() {
		err := detectFileType(filename)
		if err != nil {
			return err
		}
	}

	return nil
}

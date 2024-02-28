package format

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
)

func detectFileType(filename string) error {
	fd, err := os.Open(filename)
	if err != nil {
		return err
	}

	defer fd.Close()

	content, err := io.ReadAll(fd)
	if err != nil {
		return err
	}

	container := encoder.ParseContainerChain(content)
	if container == nil {
		fmt.Printf("%s NIL\n", filename)
		return nil
	}

	typeChain := make([]string, 0, 10)
	c := container
	for c != nil {
		typeChain = append(typeChain, c.KeyType())
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

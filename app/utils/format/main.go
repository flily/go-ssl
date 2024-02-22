package format

import (
	"flag"
	"fmt"
	"io"
	"os"

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

	typeList := encoder.TypeDetect(content)
	fmt.Printf("%s: %v\n", filename, typeList)
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

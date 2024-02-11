package version

import (
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
)

var Version = "0.0.0 (on development)"

func MainVersion(ctx *clicontext.Context, args []string) error {
	fmt.Printf("gossl %s\n", Version)
	return nil
}

package version

import (
	"fmt"
)

var Version = "0.0.0 (on development)"

func MainVersion(args []string) error {
	fmt.Printf("gossl %s\n", Version)
	return nil
}

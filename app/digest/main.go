package digest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/flily/go-ssl/common/clicontext"
)

func hashFile(ctx *clicontext.Context, name string, filename string) error {
	var fd *os.File
	var err error
	if filename == "-" {
		fd = os.Stdin
	} else {
		fd, err = os.Open(filename)
		if err != nil {
			return err
		}
	}

	defer fd.Close()

	hasher, _ := getHasher(name)
	buffer := make([]byte, 1024)
	for {
		var n int
		n, err = fd.Read(buffer)
		if err != nil {
			break
		}

		if n > 0 {
			hasher.Write(buffer[:n])
		}
	}

	if errors.Is(err, io.EOF) {
		err = nil
	}

	if err == nil {
		checksum := hasher.Sum(nil)
		if filename == "-" {
			fmt.Printf("%x\n", checksum)
		} else {
			fmt.Printf("%s(%s)= %x\n",
				strings.ToUpper(name), filename, checksum)
		}
	}

	return err
}

func algoHandler(array *[]string, name string) func(string) error {
	return func(_ string) error {
		*array = append(*array, name)
		return nil
	}
}

func Main(ctx *clicontext.Context, args []string) error {
	algorithms := make([]string, 0, len(algorithmMap))

	for name := range algorithmMap {
		ctx.Set.BoolFunc(name, fmt.Sprintf("use %s algorithm", name),
			algoHandler(&algorithms, name))
	}

	err := ctx.Set.Parse(args)
	if err != nil {
		return err
	}

	if len(algorithms) > 1 {
		fmt.Printf("gossl:Error: only one algorithm can be specified, got: %s\n",
			strings.Join(algorithms, ", "))
	}

	hashAlgo := "sha256"
	if len(algorithms) > 0 {
		hashAlgo = algorithms[0]
	}

	if ctx.Set.NArg() <= 0 {
		return hashFile(ctx, hashAlgo, "-")
	} else {
		for _, filename := range ctx.Set.Args() {
			err = hashFile(ctx, hashAlgo, filename)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

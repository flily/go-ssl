package digest

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func hashFile(name string, filename string) error {
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

func Main(args []string) error {
	set := flag.NewFlagSet("digest", flag.ExitOnError)
	algorithms := make([]string, 0, len(algorithmMap))

	for name := range algorithmMap {
		set.BoolFunc(name, fmt.Sprintf("use %s algorithm", name),
			algoHandler(&algorithms, name))
	}

	err := set.Parse(args)
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

	if set.NArg() <= 0 {
		return hashFile(hashAlgo, "-")
	} else {
		for _, filename := range set.Args() {
			err = hashFile(hashAlgo, filename)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

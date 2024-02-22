package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/flily/go-ssl/app/cipher"
	"github.com/flily/go-ssl/app/digest"
	"github.com/flily/go-ssl/app/keygen"
	"github.com/flily/go-ssl/app/utils/format"
	"github.com/flily/go-ssl/cmd/gossl/commands/version"
)

type Entry func(args []string) error

var commands map[string]Entry

func init() {
	commands = map[string]Entry{
		"version": version.MainVersion,
		"digest":  digest.Main,
		"genrsa":  keygen.MainGenRSA,
		"rsa":     cipher.MainRSA,
		"format":  format.MainFormat,
		"help":    showHelp,
	}
}

func showHelp(_ []string) error {
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
	flag.Parse()
	rawArgs := flag.Args()
	if len(rawArgs) <= 0 {
		help()
		return
	}

	command := rawArgs[0]
	args := rawArgs[1:]

	entry, found := commands[command]
	if !found {
		fmt.Printf("gossl:Error: '%s' is an invalid command.\n", command)
		help()
		return
	}

	err := entry(args)
	if err != nil {
		fmt.Printf("gossl:Error: %s\n", err)
	}
}

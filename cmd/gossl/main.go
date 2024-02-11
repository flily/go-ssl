package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/flily/go-ssl/app/digest"
	"github.com/flily/go-ssl/cmd/gossl/commands/version"
	"github.com/flily/go-ssl/common/clicontext"
)

type Entry func(ctx *clicontext.Context, args []string) error

var commands map[string]Entry

func init() {
	commands = map[string]Entry{
		"version": version.MainVersion,
		"digest":  digest.Main,
		"help":    showHelp,
	}
}

func showHelp(_ *clicontext.Context, _ []string) error {
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

	ctx := clicontext.New("gossl")
	ctx.Set.String("in", "", "input file, default or '-' is stdin")
	ctx.Set.String("out", "", "output file, default or '-' is stdout")
	command := rawArgs[0]
	args := rawArgs[1:]

	entry, found := commands[command]
	if !found {
		fmt.Printf("gossl:Error: '%s' is an invalid command.\n", command)
		help()
		return
	}

	err := entry(ctx, args)
	if err != nil {
		fmt.Printf("gossl:Error: %s\n", err)
	}
}

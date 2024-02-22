package clicontext

import (
	"flag"
	"fmt"
	"strings"
)

type CommandEntryFunc func(*CommandContext) error

type CommandContext struct {
	Command        string
	Args           []string
	context        []string
	defaultCommand string
}

func NewCommandContext(args []string) *CommandContext {
	if len(args) <= 0 {
		return nil
	}

	command := args[0]
	nextArgs := args[1:]
	c := &CommandContext{
		Command:        command,
		Args:           nextArgs,
		context:        []string{},
		defaultCommand: "",
	}
	return c
}

func (c *CommandContext) CurrentCommand() string {
	return strings.Join(c.context, " ")
}

func (c *CommandContext) SetDefaultCommand(name string) {
	c.defaultCommand = name
}

func (c *CommandContext) showHelp(commands map[string]CommandEntryFunc) error {
	fmt.Printf("Usage:  %s <command> [options]\n", c.CurrentCommand())
	fmt.Println("Commands:")
	for name := range commands {
		fmt.Printf("  %s\n", name)
	}

	return nil
}

func (c *CommandContext) NextContext(name string, args []string) *CommandContext {
	next := &CommandContext{
		Command:        name,
		Args:           args,
		context:        append(c.context, c.Command),
		defaultCommand: "",
	}

	return next
}

func (c *CommandContext) Parse(set *flag.FlagSet) error {
	return set.Parse(c.Args)
}

func (c *CommandContext) Invoke(commands map[string]CommandEntryFunc) error {
	set := flag.NewFlagSet(c.CurrentCommand(), flag.ExitOnError)
	err := set.Parse(c.Args)
	if err != nil {
		return err
	}

	rawArgs := set.Args()
	command := ""
	var nextArgs []string
	if len(rawArgs) <= 0 {
		if c.defaultCommand != "" {
			command = c.defaultCommand
		} else {
			return c.showHelp(commands)
		}
	} else {
		command = rawArgs[0]
		nextArgs = rawArgs[1:]
	}

	entry, found := commands[command]
	if !found {
		_ = c.showHelp(commands)
		return fmt.Errorf("unknown command: %s", command)
	}

	ctx := c.NextContext(command, nextArgs)
	return entry(ctx)
}

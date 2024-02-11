package clicontext

import (
	"flag"
	"os"
)

type Context struct {
	In          *os.File
	InFilename  string
	Out         *os.File
	OutFilename string
	Set         *flag.FlagSet
}

func New(name string) *Context {
	ctx := &Context{
		In:          os.Stdin,
		InFilename:  "-",
		Out:         os.Stdout,
		OutFilename: "-",
		Set:         flag.NewFlagSet(name, flag.ExitOnError),
	}

	return ctx
}

func (c *Context) SetIn(inFile string) error {
	if inFile == "-" {
		c.In = os.Stdin
		c.InFilename = "-"
		return nil
	}

	in, err := os.Open(inFile)
	if err != nil {
		return err
	}

	c.In = in
	c.InFilename = inFile
	return nil
}

func (c *Context) SetOut(outFile string) error {
	if outFile == "-" {
		c.Out = os.Stdout
		c.OutFilename = "-"
		return nil
	}

	out, err := os.Create(outFile)
	if err != nil {
		return err
	}

	c.Out = out
	c.OutFilename = outFile
	return nil
}

func (c *Context) Close() {
	c.In.Close()
	c.Out.Close()
}

func (c *Context) CloseNonDefault() {
	if c.InFilename != "-" {
		c.In.Close()
	}

	if c.OutFilename != "-" {
		c.Out.Close()
	}
}

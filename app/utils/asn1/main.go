package asn1

import (
	"flag"
	"fmt"
	"io"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/cliutils"
	asn1decode "github.com/flily/go-ssl/modules/asn1"
)

func decodeASN1ObjectFromFile(filename string) (asn1decode.ASN1Object, error) {
	fd, err := cliutils.CLIReadFile(filename)
	if err != nil {
		return nil, err
	}

	defer fd.Close()
	content, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}

	result, length, err := asn1decode.ReadASN1Object(content, 0)
	if err != nil {
		return nil, err
	}

	if length != len(content) {
		return nil, fmt.Errorf("asn1: not all data parsed: %d/%d bytes parsed", length, len(content))
	}

	return result, nil
}

func showASN1Decode(filename string) error {
	obj, err := decodeASN1ObjectFromFile(filename)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", obj.PrettyString(""))
	return nil
}

func asn1CommandShow(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("asn1", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	_ = ctx.Parse(set)

	return showASN1Decode(*inFile)
}

func asn1CommandGuess(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("asn1", flag.ExitOnError)
	inFile := set.String("in", "-", "Input file")
	_ = ctx.Parse(set)

	obj, err := decodeASN1ObjectFromFile(*inFile)
	if err != nil {
		return err
	}

	fmt.Printf("%s\n", obj.PrettyString(""))
	err = asn1decode.CanBeX509Certificate(obj)
	if err != nil {
		fmt.Printf("Not a X.509 certificate: %s\n", err)
	} else {
		fmt.Printf("X.509 certificate\n")
	}

	return nil
}

var asn1Commands = map[string]clicontext.CommandEntryFunc{
	"show":  asn1CommandShow,
	"guess": asn1CommandGuess,
}

func MainASN1(ctx *clicontext.CommandContext) error {
	return ctx.Invoke(asn1Commands)
}

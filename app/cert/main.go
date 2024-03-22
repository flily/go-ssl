package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/flily/go-ssl/common/clicontext"
	"github.com/flily/go-ssl/common/encoder"
	"github.com/flily/go-ssl/common/prettyprint"
)

func showPublicKey(publicKey any) {
	if key, ok := publicKey.(*rsa.PublicKey); ok {
		fmt.Printf("      Public-Key: (%d bit)\n", key.N.BitLen())
		prettyprint.PrintBinaryWithIndent("Modulus", "      ", key.N.Bytes())
		fmt.Printf("      Exponent: %d (0x%x)\n", key.E, key.E)
	}
}

func showCSR(filename string) error {
	chain, err := encoder.ParseContainerChainFromFile(filename)
	if err != nil {
		return err
	}

	if chain.KeyType() != encoder.KeyTypeCertificateRequest {
		return fmt.Errorf("Not a CSR file")
	}

	request := chain.CertificateRequest()
	fmt.Printf("Certificate Request:\n")
	fmt.Printf("  Data:\n")
	fmt.Printf("    Version: %d (0x%x)\n", request.Version, request.Version)
	fmt.Printf("    Subject: %s\n", request.Subject.String())
	fmt.Printf("    Subject Public Key Info:\n")
	fmt.Printf("      Public Key Algorithm: %s\n", request.PublicKeyAlgorithm)
	showPublicKey(request.PublicKey)

	fmt.Printf("    Attributes:\n")
	for _, attr := range request.Attributes {
		fmt.Printf("      %s: %s\n", attr.Type, attr.Value)
	}

	fmt.Printf("  Signature Algorithm: %s\n", request.SignatureAlgorithm)
	prettyprint.PrintBinaryWithIndent("Signature", "  ", request.Signature)
	return nil
}

func certCommandCSR(ctx *clicontext.CommandContext) error {
	set := flag.NewFlagSet("csr", flag.ExitOnError)
	inFile := set.String("in", "", "Input file")
	key := set.String("key", "", "Private key file")

	_ = ctx.Parse(set)

	if len(*inFile) > 0 {
		return showCSR(*inFile)
	}

	if len(*key) <= 0 {
		return fmt.Errorf("Private key file is required")
	}

	keyContainer, err := encoder.ParseContainerChainFromFile(*key)
	if err != nil {
		return err
	}

	template := &x509.CertificateRequest{
		PublicKey: keyContainer.FirstPublicKey(),
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, keyContainer.FirstPrivateKey())
	if err != nil {
		return err
	}

	fmt.Printf("%s", encoder.PEMEncode("CERTIFICATE REQUEST", csr))
	return nil
}

var certCommands = map[string]clicontext.CommandEntryFunc{
	"csr": certCommandCSR,
}

func MainCert(ctx *clicontext.CommandContext) error {
	return ctx.Invoke(certCommands)
}

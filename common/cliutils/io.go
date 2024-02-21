package cliutils

import (
	"os"
)

func CLIReadFile(filename string) (*os.File, error) {
	if filename == "-" {
		return os.Stdin, nil
	}

	return os.Open(filename)
}

func CLIWriteFile(filename string) (*os.File, error) {
	if filename == "-" {
		return os.Stdout, nil
	}

	return os.Create(filename)
}

func CLIFileList(filenames []string) []string {
	if len(filenames) == 0 {
		return []string{"-"}
	}

	return filenames
}

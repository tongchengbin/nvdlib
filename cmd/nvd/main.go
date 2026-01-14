package main

import (
	"os"

	"github.com/vehemont/nvdlib-go/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

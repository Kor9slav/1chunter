package main

import (
	"os"

	"github.com/Kor9slav/1chunter/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

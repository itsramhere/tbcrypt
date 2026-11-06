// Command tbcrypt strips metadata and encrypts or decrypts files.
package main

import (
	"fmt"
	"github.com/ramst/tbcrypt/internal/cli"
	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/tray"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		attachConsole()
		os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	dir, err := config.DefaultDir()
	if err == nil {
		err = tray.Run(dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

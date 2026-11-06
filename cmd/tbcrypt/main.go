// Command tbcrypt starts the local web UI or runs a headless file command.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/itsramhere/tbcrypt/internal/cli"
	"github.com/itsramhere/tbcrypt/internal/config"
	"github.com/itsramhere/tbcrypt/internal/web"
)

func main() { os.Exit(run()) }
func run() int {
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "serve" && args[0] != "--no-browser" {
		return cli.Run(args, os.Stdin, os.Stdout, os.Stderr)
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 8737, "local port (tries the next ten ports if busy)")
	noBrowser := flags.Bool("no-browser", false, "print the link without opening a browser")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || *port < 1 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "Usage: tbcrypt serve [--port 8737] [--no-browser]")
		return 2
	}
	dir, err := config.DefaultDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := web.Serve(ctx, web.Options{Addr: "127.0.0.1:" + strconv.Itoa(*port), ConfigDir: dir, OpenBrowser: !*noBrowser, Logger: logger}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

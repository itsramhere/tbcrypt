// Package cli implements the reusable command-line entry point.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ramst/tbcrypt/internal/config"
	"github.com/ramst/tbcrypt/internal/keystore"
	"github.com/ramst/tbcrypt/internal/pipeline"
	"github.com/ramst/tbcrypt/internal/tbx"
	"github.com/ramst/tbcrypt/internal/watcher"
	"golang.org/x/term"
)

const usage = `Usage: tbcrypt <command>
  init                         Create a password-protected encryption key
  export <dest>                Back up the keyfile (refuses overwrite)
  passwd                       Change the keyfile password
  encrypt <dir> [-o dir] [-done dir] [-exiftool path]
                               Strip, encrypt, verify, then archive originals
  watch <dir> [-o dir] [-done dir] [-exiftool path]
                               Watch recursively; Ctrl+C stops
  encrypt-file <file> [-o dir] [-exiftool path]
                               Strip, encrypt, verify; retain the original
  decrypt <file.tbx|dir> [-o dir]
                               Decrypt files (default: ./decrypted)
  help                         Show this usage
`

// Run dispatches commands and returns an exit status without exiting the process.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	err := run(args, stdin, stdout, stderr, logger)
	if err != nil {
		logger.Error("command failed", "error", err)
		return 1
	}
	return 0
}

func password(stdin io.Reader, stderr io.Writer, env, prompt string, confirm bool) (string, error) {
	if p := os.Getenv(env); p != "" {
		return p, nil
	}
	f, ok := stdin.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", fmt.Errorf("password requires a terminal or %s", env)
	}
	read := func(label string) (string, error) {
		fmt.Fprint(stderr, label)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(stderr)
		defer clear(b)
		return string(b), err
	}
	p, err := read(prompt)
	if err != nil {
		return "", err
	}
	if confirm {
		again, err := read("Confirm password: ")
		if err != nil {
			return "", err
		}
		if p != again {
			return "", errors.New("passwords do not match")
		}
	}
	return p, nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, logger *slog.Logger) error {
	dir, err := config.DefaultDir()
	if err != nil {
		return err
	}
	cmd := args[0]
	switch cmd {
	case "init":
		if len(args) != 1 {
			return errors.New("usage: tbcrypt init")
		}
		p, err := password(stdin, stderr, "TBCRYPT_PASSWORD", "New password: ", true)
		if err != nil {
			return err
		}
		if err = keystore.Init(dir, p); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "WARNING: Losing EITHER the keyfile OR the password means permanent data loss.")
		fmt.Fprintln(stdout, "Keyfile:", filepath.Join(dir, "keyfile.json"))
		fmt.Fprintln(stdout, "Back up your keyfile with: tbcrypt export <dest>")
		return nil
	case "export":
		if len(args) != 2 {
			return errors.New("usage: tbcrypt export <dest>")
		}
		if err = keystore.Export(dir, args[1]); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Keyfile exported to", args[1])
		return nil
	case "passwd":
		if len(args) != 1 {
			return errors.New("usage: tbcrypt passwd")
		}
		old, err := password(stdin, stderr, "TBCRYPT_PASSWORD", "Old password: ", false)
		if err != nil {
			return err
		}
		next, err := password(stdin, stderr, "TBCRYPT_NEW_PASSWORD", "New password: ", true)
		if err != nil {
			return err
		}
		if err = keystore.ChangePassword(dir, old, next); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "Password changed.")
		return nil
	case "encrypt", "encrypt-file", "decrypt", "watch":
		return files(cmd, args[1:], dir, stdin, stdout, stderr, logger)
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// parse accepts flags before or after the positional path, as documented.
func parse(cmd string, args []string, stderr io.Writer) (path, out, done, exif string, err error) {
	flags := flag.NewFlagSet(cmd, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&out, "o", "", "output directory")
	if cmd == "encrypt" || cmd == "watch" {
		flags.StringVar(&done, "done", "", "archive directory")
	}
	if cmd != "decrypt" {
		flags.StringVar(&exif, "exiftool", "", "exiftool executable")
	}
	var options, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			options = append(options, a)
			if !strings.Contains(a, "=") && a != "-h" && a != "--help" {
				i++
				if i >= len(args) {
					return "", "", "", "", fmt.Errorf("missing value for %s", a)
				}
				options = append(options, args[i])
			}
		} else {
			positionals = append(positionals, a)
		}
	}
	if err = flags.Parse(options); err != nil {
		return
	}
	if len(positionals) != 1 {
		err = fmt.Errorf("usage: tbcrypt %s <path> [flags]", cmd)
		return
	}
	path = positionals[0]
	return
}

func files(cmd string, args []string, dir string, stdin io.Reader, stdout, stderr io.Writer, logger *slog.Logger) error {
	path, out, done, exif, err := parse(cmd, args, stderr)
	if err != nil {
		return err
	}
	c, err := config.Load(dir)
	if err != nil {
		return err
	}
	p, err := password(stdin, stderr, "TBCRYPT_PASSWORD", "Password: ", false)
	if err != nil {
		return err
	}
	key, err := keystore.Unlock(dir, p)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if cmd == "decrypt" {
		if out == "" {
			out = filepath.Join(".", "decrypted")
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		var paths []string
		if info.IsDir() {
			err = filepath.WalkDir(path, func(p string, d fs.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if d.Type().IsRegular() && strings.EqualFold(filepath.Ext(p), ".tbx") {
					paths = append(paths, p)
				}
				return nil
			})
			if err != nil {
				return err
			}
		} else {
			paths = []string{path}
		}
		success, failed := 0, 0
		for _, src := range paths {
			dest := out
			if info.IsDir() {
				rel, err := filepath.Rel(path, filepath.Dir(src))
				if err != nil {
					return err
				}
				dest = filepath.Join(out, rel)
			}
			target, err := tbx.DecryptFile(src, dest, key.Identity())
			if err != nil {
				failed++
				logger.Error("decrypt failed", "source", src, "error", err)
				continue
			}
			success++
			fmt.Fprintln(stdout, "Decrypted:", target)
		}
		fmt.Fprintf(stdout, "Decrypted %d file(s); %d failed.\n", success, failed)
		if failed > 0 {
			return fmt.Errorf("%d file(s) failed", failed)
		}
		return nil
	}
	if cmd == "encrypt-file" {
		c.WatchDir = filepath.Dir(path)
	} else {
		c.WatchDir = path
	}
	if out != "" {
		c.OutputDir = out
	}
	if done != "" {
		c.DoneDir = done
	}
	if exif != "" {
		c.ExiftoolPath = exif
	}
	c = c.Resolved()
	opts := pipeline.Options{WatchDir: c.WatchDir, OutputDir: c.OutputDir, DoneDir: c.DoneDir, ExiftoolPath: config.FindExiftool(c), Recipient: key.Recipient(), Identity: key.Identity(), Logger: logger}
	if err := pipeline.CleanTemp(opts); err != nil {
		return err
	}
	if cmd == "watch" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fmt.Fprintln(stdout, "Watching:", c.WatchDir, "(Ctrl+C to stop)")
		return watcher.New(opts, logger).Run(ctx)
	}
	paths := []string{path}
	if cmd == "encrypt" {
		paths, err = pipeline.ScanDir(opts)
		if err != nil {
			return err
		}
	}
	success, failed, warnings := 0, 0, 0
	for _, src := range paths {
		var result pipeline.Result
		if cmd == "encrypt" {
			result, err = pipeline.ProcessOne(ctx, opts, src)
		} else {
			result, err = pipeline.EncryptOne(ctx, opts, src)
		}
		if err != nil {
			failed++
			logger.Error("encrypt failed", "source", src, "error", err)
			continue
		}
		success++
		if result.Warning != nil {
			warnings++
		}
		fmt.Fprintln(stdout, "Encrypted:", result.Output)
	}
	fmt.Fprintf(stdout, "Encrypted %d file(s); %d warning(s); %d failed.\n", success, warnings, failed)
	if failed > 0 {
		return fmt.Errorf("%d file(s) failed", failed)
	}
	return nil
}

// Package pipeline coordinates copying, metadata removal, encryption and archival.
package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/itsramhere/tbcrypt/internal/fsutil"
	"github.com/itsramhere/tbcrypt/internal/strip"
	"github.com/itsramhere/tbcrypt/internal/tbx"
)

// Options supplies paths, keys and an optional logger; it has no global state.
type Options struct {
	WatchDir, OutputDir, DoneDir, ExiftoolPath, TempDir string
	Recipient                                           age.Recipient
	Identity                                            age.Identity
	Logger                                              *slog.Logger
}

// Result reports a completed encryption and any non-fatal metadata warning.
type Result struct {
	Src, Output, DoneAt string
	Stripped            bool
	Warning             error
}

func absolute(path string) string {
	p, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

func within(dir, path string) bool {
	if dir == "" {
		return false
	}
	d, p := absolute(dir), absolute(path)
	if d == "" || p == "" {
		return false
	}
	rel, err := filepath.Rel(d, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// Ignored recognizes transient, generated, hidden and already encrypted paths.
func Ignored(opts Options, path string) bool {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(name, "~$") || name == "desktop.ini" || name == "thumbs.db" {
		return true
	}
	for _, suffix := range []string{".tmp", ".part", ".crdownload", ".tbx"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return within(opts.OutputDir, path) || within(opts.DoneDir, path) || within(tempPath(opts), path) || hidden(path)
}

// ScanDir returns regular inputs, pruning generated directories and symlinks.
func ScanDir(opts Options) ([]string, error) {
	info, err := os.Stat(opts.WatchDir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("watch path is not a directory")
	}
	var files []string
	err = filepath.WalkDir(opts.WatchDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != opts.WatchDir && Ignored(opts, path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ProcessOne verifies encrypted output before moving the original to DoneDir.
func ProcessOne(ctx context.Context, opts Options, path string) (Result, error) {
	return process(ctx, opts, path, true)
}

// EncryptOne uses the same strip/encrypt/verify steps but retains the original.
func EncryptOne(ctx context.Context, opts Options, path string) (Result, error) {
	return process(ctx, opts, path, false)
}

func process(ctx context.Context, opts Options, path string, archive bool) (result Result, err error) {
	result.Src = path
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if opts.WatchDir == "" || opts.OutputDir == "" || (archive && opts.DoneDir == "") {
		return result, errors.New("pipeline directories are required")
	}
	if opts.Recipient == nil || opts.Identity == nil {
		return result, errors.New("recipient and verification identity are required")
	}
	if archive {
		out, err := physical(opts.OutputDir)
		if err != nil {
			return result, err
		}
		done, err := physical(opts.DoneDir)
		if err != nil {
			return result, err
		}
		if within(out, done) {
			return result, errors.New("DoneDir must not be within OutputDir: archives contain plaintext")
		}
	}
	if !within(opts.WatchDir, path) {
		return result, errors.New("source must be inside WatchDir")
	}
	if within(opts.OutputDir, path) || within(opts.DoneDir, path) {
		return result, errors.New("source is inside an output directory")
	}
	watch, err := filepath.Abs(opts.WatchDir)
	if err != nil {
		return result, err
	}
	src, err := filepath.Abs(path)
	if err != nil {
		return result, err
	}
	rel, err := filepath.Rel(watch, src)
	if err != nil {
		return result, err
	}
	info, err := os.Lstat(src)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("source must be a regular file, not a symlink")
	}
	tmp, err := prepareTemp(opts)
	if err != nil {
		return result, err
	}
	if within(tmp, src) {
		return result, errors.New("source is inside the temporary directory")
	}
	clean, stripped, stripErr := strip.Strip(ctx, opts.ExiftoolPath, src, tmp)
	if clean != "" {
		defer os.Remove(clean)
	}
	if stripErr != nil {
		var warning *strip.Warning
		if !errors.As(stripErr, &warning) {
			return result, stripErr
		}
		result.Warning = warning
		if opts.Logger != nil {
			opts.Logger.Warn("metadata stripping unavailable", "path", path, "error", warning)
		}
	}
	result.Stripped = stripped
	in, err := os.Open(clean)
	if err != nil {
		return result, err
	}
	defer in.Close()
	cleanInfo, err := in.Stat()
	if err != nil {
		return result, err
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, fsutil.Reader{Context: ctx, Source: in}); err != nil {
		return result, err
	}
	expected := hash.Sum(nil)
	if _, err = in.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	dest := filepath.Join(opts.OutputDir, rel+".tbx")
	if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return result, err
	}
	output, err := tbx.EncryptUnique(dest, filepath.Base(src), cleanInfo.Size(), fsutil.Reader{Context: ctx, Source: in}, opts.Recipient)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			os.Remove(output)
		}
	}()
	encrypted, err := os.Open(output)
	if err != nil {
		return result, err
	}
	hash.Reset()
	h, verifyErr := tbx.Decrypt(hash, fsutil.Reader{Context: ctx, Source: encrypted}, opts.Identity)
	closeErr := encrypted.Close()
	if verifyErr != nil {
		return result, fmt.Errorf("verify encrypted output: %w", verifyErr)
	}
	if closeErr != nil {
		return result, closeErr
	}
	if !bytes.Equal(hash.Sum(nil), expected) || h.Name != filepath.Base(src) || h.Size != cleanInfo.Size() {
		return result, errors.New("encrypted output verification mismatch")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if archive {
		// Avoid moving an original changed by another program during encryption.
		current, statErr := os.Lstat(src)
		if statErr != nil {
			return result, statErr
		}
		if !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
			return result, errors.New("original changed during processing")
		}
		done := filepath.Join(opts.DoneDir, rel)
		if err = os.MkdirAll(filepath.Dir(done), 0700); err != nil {
			return result, err
		}
		result.DoneAt, err = moveUnique(ctx, src, done)
		if err != nil {
			return result, err
		}
	}
	result.Output = output
	if opts.Logger != nil {
		opts.Logger.Info("encrypted and verified", "source", path, "output", output)
	}
	return result, nil
}

func moveUnique(ctx context.Context, src, dest string) (string, error) {
	return moveWithRename(ctx, src, dest, os.Rename)
}

// A per-call rename function allows testing cross-volume fallback on one volume.
func moveWithRename(ctx context.Context, src, dest string, rename func(string, string) error) (path string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err = fsutil.Reserve(dest, true)
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.Remove(path)
		}
	}()
	err = rename(src, path)
	if err == nil {
		return path, nil
	}
	if !crossVolume(err) {
		return path, err
	}
	in, err := os.Open(src)
	if err != nil {
		return path, err
	}
	defer in.Close()
	out, err := os.OpenFile(path+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return path, err
	}
	defer func() { out.Close(); os.Remove(out.Name()) }()
	if _, err = io.Copy(out, fsutil.Reader{Context: ctx, Source: in}); err != nil {
		return path, err
	}
	if err = out.Sync(); err != nil {
		return path, err
	}
	if err = out.Close(); err != nil {
		return path, err
	}
	if err = in.Close(); err != nil {
		return path, err
	}
	if err = ctx.Err(); err != nil {
		return path, err
	}
	if err = os.Rename(out.Name(), path); err != nil {
		return path, err
	}
	if err = ctx.Err(); err != nil {
		return path, err
	}
	err = os.Remove(src)
	return path, err
}

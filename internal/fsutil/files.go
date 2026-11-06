// Package fsutil provides internal filesystem operations shared by the pipeline.
package fsutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Atomic writes a file through a temporary file in the same directory.
func Atomic(path string, data []byte) (err error) {
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tbcrypt-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Reserve exclusively creates a destination, optionally choosing a unique name.
// The caller owns the empty reservation and must replace or remove it.
func Reserve(path string, unique bool) (string, error) {
	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	// Keep the original extension next to the .tbx suffix.
	if strings.EqualFold(ext, ".tbx") {
		inner := filepath.Ext(stem)
		stem = strings.TrimSuffix(stem, inner)
		ext = inner + ext
	}
	for n := 1; ; n++ {
		candidate := path
		if n > 1 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, n, ext)
		}
		f, err := os.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(err) && unique {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := f.Close(); err != nil {
			os.Remove(candidate)
			return "", err
		}
		return candidate, nil
	}
}

// Reader adds cooperative cancellation between streaming reads.
type Reader struct {
	Context context.Context
	Source  io.Reader
}

// Read checks cancellation before reading from Source.
func (r Reader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	return r.Source.Read(p)
}

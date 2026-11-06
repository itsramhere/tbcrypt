// Package logging provides a bounded rotating text log without external helpers.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Open creates tbcrypt.log, rotating at 5 MiB and keeping three old logs.
func Open(configDir string) (*slog.Logger, io.Closer, error) {
	w, err := openWriter(filepath.Join(configDir, "tbcrypt.log"), 5*1024*1024, 3)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewTextHandler(w, nil)), w, nil
}

type rotatingWriter struct {
	mu        sync.Mutex
	path      string
	max, size int64
	keep      int
	file      *os.File
}

func openWriter(path string, max int64, keep int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	w := &rotatingWriter{path: path, max: max, keep: keep}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}
func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = info.Size()
	return nil
}
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, os.ErrClosed
	}
	if w.size > 0 && w.size+int64(len(p)) > w.max {
		if err := w.file.Close(); err != nil {
			return 0, err
		}
		w.file = nil
		if err := os.Remove(fmt.Sprintf("%s.%d", w.path, w.keep)); err != nil && !os.IsNotExist(err) {
			w.open()
			return 0, err
		}
		for i := w.keep - 1; i >= 0; i-- {
			from := w.path
			if i > 0 {
				from = fmt.Sprintf("%s.%d", w.path, i)
			}
			to := fmt.Sprintf("%s.%d", w.path, i+1)
			if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
				w.open()
				return 0, err
			}
		}
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

package pipeline

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func tempPath(opts Options) string {
	if opts.TempDir != "" {
		return opts.TempDir
	}
	return filepath.Join(opts.WatchDir, ".tbcrypt-tmp")
}

// physical resolves existing ancestors so a symlink cannot redirect plaintext.
func physical(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	root, err := physical(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, filepath.Base(abs)), nil
}

func prepareTemp(opts Options) (string, error) {
	tmp, err := physical(tempPath(opts))
	if err != nil {
		return "", err
	}
	out, err := physical(opts.OutputDir)
	if err != nil {
		return "", err
	}
	if within(out, tmp) {
		return "", errors.New("TempDir must not be within OutputDir")
	}
	watch, err := physical(opts.WatchDir)
	if err != nil {
		return "", err
	}
	if within(tmp, watch) {
		return "", errors.New("TempDir must be a dedicated directory, not WatchDir or its ancestor")
	}
	if err := os.MkdirAll(tmp, 0700); err != nil {
		return "", err
	}
	if err := hideDirectory(tmp); err != nil {
		return "", err
	}
	return tmp, nil
}

// CleanTemp removes owned crash leftovers before processing starts. Call only
// when no pipeline operation is using this temporary directory.
func CleanTemp(opts Options) error {
	tmp, err := prepareTemp(opts)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (strings.HasPrefix(name, "tbcrypt-") || strings.HasSuffix(name, "_exiftool_tmp")) {
			if err := os.Remove(filepath.Join(tmp, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

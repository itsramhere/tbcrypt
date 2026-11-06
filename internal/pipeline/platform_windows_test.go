//go:build windows

package pipeline

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func crossVolumeError() error { return syscall.Errno(17) }

func TestHiddenAndCaseInsensitivePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hidden.txt")
	os.WriteFile(path, nil, 0600)
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.SetFileAttributes(p, syscall.FILE_ATTRIBUTE_HIDDEN); err != nil {
		t.Fatal(err)
	}
	defer syscall.SetFileAttributes(p, syscall.FILE_ATTRIBUTE_NORMAL)
	if !Ignored(Options{}, path) {
		t.Fatal("hidden file not ignored")
	}
	opts := Options{OutputDir: filepath.Join(dir, "OUTPUT")}
	if !Ignored(opts, filepath.Join(dir, "output", "x.jpg")) {
		t.Fatal("path comparison is case sensitive")
	}
	if !crossVolume(&os.LinkError{Err: syscall.Errno(17)}) {
		t.Fatal("cross-volume detection")
	}
}

func TestStagingDirectoryHidden(t *testing.T) {
	dir := t.TempDir()
	opts := Options{WatchDir: dir, OutputDir: filepath.Join(dir, "encrypted")}
	if err := CleanTemp(opts); err != nil {
		t.Fatal(err)
	}
	if !hidden(tempPath(opts)) {
		t.Fatal("plaintext staging directory is not hidden")
	}
}

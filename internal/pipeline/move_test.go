package pipeline

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCrossVolumeCopyAndCleanup(t *testing.T) {
	for _, failCopy := range []bool{false, true} {
		name := "success"
		if failCopy {
			name = "copy-failure"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "src")
			dest := filepath.Join(dir, "done")
			data := bytes.Repeat([]byte("archive"), 10000)
			if err := os.WriteFile(src, data, 0600); err != nil {
				t.Fatal(err)
			}
			rename := func(from, to string) error {
				if failCopy { // A preexisting .part must be preserved and cause safe failure.
					if err := os.WriteFile(to+".part", []byte("owned elsewhere"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return &os.LinkError{Op: "rename", Old: from, New: to, Err: crossVolumeError()}
			}
			path, err := moveWithRename(context.Background(), src, dest, rename)
			if failCopy {
				if err == nil {
					t.Fatal("expected failure")
				}
				original, e := os.ReadFile(src)
				if e != nil || !bytes.Equal(original, data) {
					t.Fatal("lost original")
				}
				if _, e := os.Stat(path); !os.IsNotExist(e) {
					t.Fatal("destination left")
				}
				part, e := os.ReadFile(path + ".part")
				if e != nil || string(part) != "owned elsewhere" {
					t.Fatal("modified existing part")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			copied, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(copied, data) {
				t.Fatalf("copy: %v", e)
			}
			if _, e := os.Stat(src); !os.IsNotExist(e) {
				t.Fatal("original not moved")
			}
			if _, e := os.Stat(path + ".part"); !os.IsNotExist(e) {
				t.Fatal("part left")
			}
		})
	}
}

func TestNonCrossVolumeMoveFailure(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dest := filepath.Join(dir, "done")
	os.WriteFile(src, []byte("safe"), 0600)
	injected := errors.New("rename blocked")
	path, err := moveWithRename(context.Background(), src, dest, func(string, string) error { return injected })
	if !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("reservation left")
	}
	if b, err := os.ReadFile(src); err != nil || string(b) != "safe" {
		t.Fatal("original modified")
	}
}

func TestCancelledArchiveCopyKeepsOriginal(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dest := filepath.Join(dir, "done")
	if err := os.WriteFile(src, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path, err := moveWithRename(ctx, src, dest, func(string, string) error { cancel(); return crossVolumeError() })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(src); err != nil || string(b) != "safe" {
		t.Fatal("lost original")
	}
	for _, p := range []string{path, path + ".part"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("left %s", p)
		}
	}
}

package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateTempAndCleanup(t *testing.T) {
	opts, _, src, _ := setup(t)
	opts.TempDir = filepath.Join(opts.OutputDir, "plaintext")
	if _, err := ProcessOne(context.Background(), opts, src); err == nil {
		t.Fatal("accepted plaintext in output")
	}
	if _, err := os.Stat(opts.OutputDir); !os.IsNotExist(err) {
		t.Fatal("created unsafe output")
	}
	opts.TempDir = ""
	if err := CleanTemp(opts); err != nil {
		t.Fatal(err)
	}
	tmp := tempPath(opts)
	for _, name := range []string{"tbcrypt-old.jpg", "photo.jpg_exiftool_tmp", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(tmp, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if !Ignored(opts, filepath.Join(tmp, "keep.txt")) {
		t.Fatal("temp not ignored")
	}
	files, err := ScanDir(opts)
	if err != nil || len(files) != 1 {
		t.Fatalf("scan: %v %v", files, err)
	}
	if err := CleanTemp(opts); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 1 || entries[0].Name() != "keep.txt" {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
	os.Remove(filepath.Join(tmp, "keep.txt"))
	opts.Recipient = failRecipient{}
	if _, err := ProcessOne(context.Background(), opts, src); err == nil {
		t.Fatal("expected failure")
	}
	assertNoTemps(t, opts)
	entries, err = os.ReadDir(tmp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temp leftovers: %v %v", entries, err)
	}
}

func TestUnsafeDirectoriesDoNotTouchOriginals(t *testing.T) {
	opts, _, src, _ := setup(t)
	opts.TempDir = opts.WatchDir
	input := filepath.Join(opts.WatchDir, "tbcrypt-original.txt")
	if err := os.WriteFile(input, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CleanTemp(opts); err == nil {
		t.Fatal("accepted input directory as staging")
	}
	if b, err := os.ReadFile(input); err != nil || string(b) != "original" {
		t.Fatal("cleanup touched original")
	}
	opts.TempDir = ""
	opts.DoneDir = filepath.Join(opts.OutputDir, "done")
	if _, err := ProcessOne(context.Background(), opts, src); err == nil {
		t.Fatal("accepted plaintext archive in upload folder")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("lost original")
	}
}

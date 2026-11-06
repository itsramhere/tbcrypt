package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/itsramhere/tbcrypt/internal/tbx"
)

func setup(t *testing.T) (Options, *age.X25519Identity, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{WatchDir: dir, OutputDir: filepath.Join(dir, "encrypted"), DoneDir: filepath.Join(dir, "done"), Recipient: id.Recipient(), Identity: id}
	src := filepath.Join(dir, "nested", "photo.jpg")
	data := bytes.Repeat([]byte("image bytes"), 20000)
	if err := os.MkdirAll(filepath.Dir(src), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0600); err != nil {
		t.Fatal(err)
	}
	return opts, id, src, data
}
func assertNoTemps(t *testing.T, opts Options) {
	t.Helper()
	err := filepath.WalkDir(opts.OutputDir, func(path string, d os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !d.IsDir() && !strings.HasSuffix(path, ".tbx") || (d.IsDir() && filepath.Base(path) == ".tmp") {
			t.Errorf("temporary file left: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(tempPath(opts))
	if err != nil || len(entries) != 0 {
		t.Fatalf("plaintext temp leftovers: %v %v", entries, err)
	}
}

func TestProcessOne(t *testing.T) {
	opts, id, src, data := setup(t)
	result, err := ProcessOne(context.Background(), opts, src)
	if err != nil {
		t.Fatal(err)
	}
	if result.Output != filepath.Join(opts.OutputDir, "nested", "photo.jpg.tbx") || result.DoneAt != filepath.Join(opts.DoneDir, "nested", "photo.jpg") {
		t.Fatalf("result: %+v", result)
	}
	if result.Stripped || result.Warning == nil {
		t.Fatal("expected absent exiftool warning")
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("source not moved")
	}
	done, err := os.ReadFile(result.DoneAt)
	if err != nil || !bytes.Equal(done, data) {
		t.Fatalf("archive: %v", err)
	}
	in, err := os.Open(result.Output)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	var out bytes.Buffer
	h, err := tbx.Decrypt(&out, in, id)
	if err != nil || !bytes.Equal(out.Bytes(), data) || h.Name != "photo.jpg" || h.Size != int64(len(data)) {
		t.Fatalf("output: %+v %v", h, err)
	}
	assertNoTemps(t, opts)
}

func TestCollisions(t *testing.T) {
	opts, _, src, data := setup(t)
	for _, path := range []string{filepath.Join(opts.OutputDir, "nested", "photo.jpg.tbx"), filepath.Join(opts.DoneDir, "nested", "photo.jpg")} {
		os.MkdirAll(filepath.Dir(path), 0700)
		os.WriteFile(path, []byte("existing"), 0600)
	}
	result, err := ProcessOne(context.Background(), opts, src)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(result.Output) != "photo (2).jpg.tbx" || filepath.Base(result.DoneAt) != "photo (2).jpg" {
		t.Fatalf("collision: %+v", result)
	}
	b, _ := os.ReadFile(result.DoneAt)
	if !bytes.Equal(b, data) {
		t.Fatal("bad archive")
	}
	for _, path := range []string{filepath.Join(opts.OutputDir, "nested", "photo.jpg.tbx"), filepath.Join(opts.DoneDir, "nested", "photo.jpg")} {
		b, _ := os.ReadFile(path)
		if string(b) != "existing" {
			t.Fatal("overwrote existing file")
		}
	}
	assertNoTemps(t, opts)
}

type failRecipient struct{}

func (failRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return nil, errors.New("injected recipient failure")
}

func TestFailuresPreserveOriginal(t *testing.T) {
	for _, kind := range []string{"recipient", "verify", "output", "archive", "outside", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			opts, _, src, data := setup(t)
			ctx := context.Background()
			switch kind {
			case "recipient":
				opts.Recipient = failRecipient{}
			case "verify":
				other, _ := age.GenerateX25519Identity()
				opts.Identity = other
			case "output":
				os.WriteFile(opts.OutputDir, []byte("not a directory"), 0600)
			case "archive":
				os.WriteFile(opts.DoneDir, []byte("not a directory"), 0600)
			case "outside":
				opts.WatchDir = filepath.Join(opts.WatchDir, "different")
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := ProcessOne(ctx, opts, src); err == nil {
				t.Fatal("expected failure")
			}
			b, err := os.ReadFile(src)
			if err != nil || !bytes.Equal(b, data) {
				t.Fatalf("original changed: %v", err)
			}
			if kind != "output" {
				filepath.WalkDir(opts.OutputDir, func(p string, d os.DirEntry, e error) error {
					if e == nil && !d.IsDir() {
						t.Errorf("failed pipeline left %s", p)
					}
					return nil
				})
			}
		})
	}
}

func TestEncryptOneRetainsOriginal(t *testing.T) {
	opts, _, src, data := setup(t)
	r, err := EncryptOne(context.Background(), opts, src)
	if err != nil {
		t.Fatal(err)
	}
	if r.DoneAt != "" {
		t.Fatal("archived single file")
	}
	b, err := os.ReadFile(src)
	if err != nil || !bytes.Equal(b, data) {
		t.Fatal("original modified")
	}
	assertNoTemps(t, opts)
}

func TestIgnoredAndScan(t *testing.T) {
	opts, _, src, _ := setup(t)
	for _, name := range []string{"~$doc.docx", "a.TMP", "a.PaRt", "a.CRDOWNLOAD", "DESKTOP.INI", "Thumbs.DB", "a.TBX"} {
		path := filepath.Join(opts.WatchDir, name)
		os.WriteFile(path, nil, 0600)
		if !Ignored(opts, path) {
			t.Errorf("not ignored: %s", name)
		}
	}
	for _, dir := range []string{opts.OutputDir, opts.DoneDir} {
		os.MkdirAll(filepath.Join(dir, "nested"), 0700)
		p := filepath.Join(dir, "nested", "file.jpg")
		os.WriteFile(p, nil, 0600)
		if !Ignored(opts, p) {
			t.Errorf("not ignored: %s", p)
		}
	}
	if Ignored(opts, src) || Ignored(opts, opts.OutputDir+"-other"+string(filepath.Separator)+"file.jpg") {
		t.Fatal("overbroad ignore")
	}
	files, err := ScanDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != src {
		t.Fatalf("scan: %v", files)
	}
	if _, err := ScanDir(Options{WatchDir: src}); err == nil {
		t.Fatal("accepted file as watch directory")
	}
}

func TestMoveUnique(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dest := filepath.Join(dir, "dest")
	os.WriteFile(src, []byte("archive"), 0600)
	os.WriteFile(dest, []byte("old"), 0600)
	path, err := moveUnique(context.Background(), src, dest)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "dest (2)" {
		t.Fatal(path)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil || string(b) != "archive" {
		t.Fatal("bad move")
	}
}

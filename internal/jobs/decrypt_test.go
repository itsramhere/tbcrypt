package jobs

import (
	"bytes"
	"context"
	"errors"
	"filippo.io/age"
	"github.com/itsramhere/tbcrypt/internal/tbx"
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptTreeMirrorsAndIgnoresOtherFiles(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	out := filepath.Join(root, "restore")
	source := filepath.Join(root, "encrypted")
	data := map[string][]byte{"hello.txt": []byte("hello"), filepath.Join("nested", "photo.bin"): bytes.Repeat([]byte("data"), 20000)}
	for rel, b := range data {
		plain := filepath.Join(t.TempDir(), filepath.Base(rel))
		if err := os.WriteFile(plain, b, 0600); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(source, rel+".tbx")
		os.MkdirAll(filepath.Dir(dest), 0700)
		if err := tbx.EncryptFile(plain, dest, filepath.Base(rel), id.Recipient()); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(source, "ignore.txt"), []byte("not encrypted"), 0600)
	plan, err := PlanDecrypt(context.Background(), []string{source, source}, out)
	if err != nil || len(plan) != 2 {
		t.Fatal(err, plan)
	}
	for _, file := range plan {
		if _, err := DecryptOne(context.Background(), file, id); err != nil {
			t.Fatal(err)
		}
	}
	for rel, b := range data {
		got, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil || !bytes.Equal(got, b) {
			t.Fatal(rel, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PlanDecrypt(ctx, []string{source}, out); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := DecryptOne(ctx, plan[0], id); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

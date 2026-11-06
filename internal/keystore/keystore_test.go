package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ramst/tbcrypt/internal/tbx"
)

const testPassword = "test password with length"

func TestLifecycle(t *testing.T) {
	dir := t.TempDir()
	p := Params{1, 64, 1}
	if err := InitWithParams(dir, "short", p); !errors.Is(err, ErrWeakPassword) {
		t.Fatal(err)
	}
	if err := InitWithParams(dir, testPassword, p); err != nil {
		t.Fatal(err)
	}
	if err := InitWithParams(dir, testPassword, p); !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	k, err := Unlock(dir, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	r, err := LoadRecipient(dir)
	if err != nil || r.String() != k.Recipient().String() {
		t.Fatalf("recipient: %v", err)
	}
	if _, err := Unlock(dir, "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	if err := tbx.Encrypt(&enc, bytes.NewBufferString("unchanged"), "file", 9, r); err != nil {
		t.Fatal(err)
	}
	before, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ChangePassword(dir, testPassword, "tiny"); !errors.Is(err, ErrWeakPassword) {
		t.Fatal(err)
	}
	if err := ChangePassword(dir, "incorrect", testPassword); !errors.Is(err, ErrWrongPassword) {
		t.Fatal(err)
	}
	next := "different strong password"
	if err := ChangePassword(dir, testPassword, next); err != nil {
		t.Fatal(err)
	}
	after, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Salt, after.Salt) || bytes.Equal(before.Nonce, after.Nonce) || before.Recipient != after.Recipient {
		t.Fatal("rewrap did not preserve identity with fresh randomness")
	}
	if _, err := Unlock(dir, testPassword); !errors.Is(err, ErrWrongPassword) {
		t.Fatal(err)
	}
	updated, err := Unlock(dir, next)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := tbx.Decrypt(&out, &enc, updated.Identity()); err != nil || out.String() != "unchanged" {
		t.Fatalf("old ciphertext: %v", err)
	}
	export := filepath.Join(t.TempDir(), "backup.json")
	if err := Export(dir, export); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(dir, "keyfile.json"))
	b, _ := os.ReadFile(export)
	if !bytes.Equal(a, b) {
		t.Fatal("export mismatch")
	}
	if err := Export(dir, export); !os.IsExist(err) {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestProductionDefaultsAndValidation(t *testing.T) {
	if got := (Params{}).resolved(); got != (Params{3, 65536, 4}) {
		t.Fatal(got)
	}
	dir := t.TempDir()
	if err := InitWithParams(dir, testPassword, Params{1, 1, 4}); err == nil {
		t.Fatal("invalid params accepted")
	}
	if err := InitWithParams(dir, testPassword, Params{1, 64, 1}); err != nil {
		t.Fatal(err)
	}
	original, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*keyfile){
		func(f *keyfile) { f.Version = 2 }, func(f *keyfile) { f.KDF = "bad" }, func(f *keyfile) { f.Salt = nil }, func(f *keyfile) { f.Nonce = nil },
		func(f *keyfile) { f.Time = 0 }, func(f *keyfile) { f.MemoryKiB = ^uint32(0) }, func(f *keyfile) { f.Threads = 0 },
	} {
		f := original
		change(&f)
		b, _ := json.Marshal(f)
		os.WriteFile(filepath.Join(dir, "keyfile.json"), b, 0600)
		if _, err := Unlock(dir, testPassword); err == nil {
			t.Fatal("accepted invalid keyfile")
		}
	}
}

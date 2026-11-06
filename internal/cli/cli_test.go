package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func invoke(t *testing.T, args ...string) string {
	t.Helper()
	var out, stderr bytes.Buffer
	if status := Run(args, strings.NewReader(""), &out, &stderr); status != 0 {
		t.Fatalf("%v: status %d\n%s\n%s", args, status, &out, &stderr)
	}
	return out.String()
}

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TBCRYPT_HOME", filepath.Join(dir, "home"))
	t.Setenv("TBCRYPT_PASSWORD", "a sufficiently strong test password")
	output := invoke(t, "init")
	if !strings.Contains(output, "permanent data loss") || !strings.Contains(output, "export") {
		t.Fatal(output)
	}
	watch := filepath.Join(dir, "watch")
	src := filepath.Join(watch, "nested", "hello.txt")
	data := []byte("private contents\n")
	os.MkdirAll(filepath.Dir(src), 0700)
	os.WriteFile(src, data, 0600)
	output = invoke(t, "encrypt", watch)
	if !strings.Contains(output, "Encrypted 1 file(s)") {
		t.Fatal(output)
	}
	out := filepath.Join(dir, "restored")
	output = invoke(t, "decrypt", filepath.Join(watch, "encrypted"), "-o", out)
	if !strings.Contains(output, "Decrypted 1 file(s)") {
		t.Fatal(output)
	}
	b, err := os.ReadFile(filepath.Join(out, "nested", "hello.txt"))
	if err != nil || !bytes.Equal(b, data) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original not archived")
	}
	b, err = os.ReadFile(filepath.Join(watch, "done", "nested", "hello.txt"))
	if err != nil || !bytes.Equal(b, data) {
		t.Fatal("archive mismatch")
	}
	backup := filepath.Join(dir, "backup.json")
	invoke(t, "export", backup)
	t.Setenv("TBCRYPT_NEW_PASSWORD", "another sufficiently strong password")
	invoke(t, "passwd")
	t.Setenv("TBCRYPT_PASSWORD", os.Getenv("TBCRYPT_NEW_PASSWORD"))
	invoke(t, "decrypt", filepath.Join(watch, "encrypted", "nested", "hello.txt.tbx"), "-o", filepath.Join(dir, "after-change"))
	single := filepath.Join(dir, "single.txt")
	os.WriteFile(single, data, 0600)
	invoke(t, "encrypt-file", single, "-o", filepath.Join(dir, "single-encrypted"))
	if b, err := os.ReadFile(single); err != nil || !bytes.Equal(b, data) {
		t.Fatal("encrypt-file changed original")
	}
}

func TestUsageAndErrors(t *testing.T) {
	t.Setenv("TBCRYPT_HOME", t.TempDir())
	t.Setenv("TBCRYPT_PASSWORD", "")
	if out := invoke(t); !strings.Contains(out, "Usage:") {
		t.Fatal(out)
	}
	if out := invoke(t, "help"); !strings.Contains(out, "Usage:") {
		t.Fatal(out)
	}
	for _, args := range [][]string{{"init"}, {"unknown"}, {"export"}, {"passwd", "extra"}, {"encrypt"}, {"encrypt", "dir", "-o"}, {"decrypt", "a", "b"}, {"encrypt-file", "file", "-bad=x"}} {
		var out, stderr bytes.Buffer
		if status := Run(args, strings.NewReader("no password input"), &out, &stderr); status == 0 || stderr.Len() == 0 {
			t.Fatalf("expected error for %v", args)
		}
	}
}

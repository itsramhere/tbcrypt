package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tbcrypt.log")
	w, err := openWriter(path, 12, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"first-log\n", "second-log\n", "third-log\n", "fourth-log\n", "fifth-log\n"} {
		if _, err := w.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for suffix, want := range map[string]string{"": "fifth-log\n", ".1": "fourth-log\n", ".2": "third-log\n", ".3": "second-log\n"} {
		b, err := os.ReadFile(path + suffix)
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", suffix, b, err)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatal("too many backups")
	}
	logger, closer, err := Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("ready")
	closer.Close()
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "msg=ready") {
		t.Fatal("logger not writing")
	}
}

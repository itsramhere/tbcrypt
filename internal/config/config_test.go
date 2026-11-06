package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TBCRYPT_HOME", dir)
	if got, err := DefaultDir(); err != nil || got != dir {
		t.Fatalf("home: %s %v", got, err)
	}
	c, err := Load(dir)
	if err != nil || c != (Config{}) {
		t.Fatalf("missing: %+v %v", c, err)
	}
	c = Config{WatchDir: filepath.Join(dir, "watch"), ExiftoolPath: "path", StartWithWindows: true}
	if err := Save(dir, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil || loaded != c {
		t.Fatalf("load: %+v %v", loaded, err)
	}
	r := c.Resolved()
	if r.OutputDir != filepath.Join(c.WatchDir, "encrypted") || r.DoneDir != filepath.Join(c.WatchDir, "done") {
		t.Fatal(r)
	}
	r.OutputDir = "custom"
	r.DoneDir = "archive"
	if r.Resolved() != r {
		t.Fatal("overrode explicit directories")
	}
	if err := Save(dir, r); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary file left")
	}
	os.WriteFile(filepath.Join(dir, "config.json"), []byte("bad json"), 0600)
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted malformed config")
	}
}

func TestDefaultUserDir(t *testing.T) {
	t.Setenv("TBCRYPT_HOME", "")
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip(err)
	}
	got, err := DefaultDir()
	if err != nil || got != filepath.Join(base, "tbcrypt") {
		t.Fatalf("%s %v", got, err)
	}
}

func TestFindExiftool(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "custom-tool.exe")
	os.WriteFile(f, []byte("test"), 0700)
	if got := FindExiftool(Config{ExiftoolPath: f}); got != f {
		t.Fatal(got)
	}
	t.Setenv("PATH", dir)
	if got := FindExiftool(Config{ExiftoolPath: dir}); got != "" {
		t.Fatal(got)
	}
	tool := filepath.Join(dir, "exiftool(-k).exe")
	os.WriteFile(tool, []byte("test"), 0700)
	if got := FindExiftool(Config{}); got != tool {
		t.Fatalf("PATH search: %q", got)
	}
}

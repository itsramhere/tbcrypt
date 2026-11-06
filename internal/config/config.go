// Package config loads and saves tbcrypt configuration.
package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ramst/tbcrypt/internal/fsutil"
)

// Config contains reusable directory and application settings.
type Config struct {
	WatchDir         string `json:"watch_dir"`
	OutputDir        string `json:"output_dir"`
	DoneDir          string `json:"done_dir"`
	ExiftoolPath     string `json:"exiftool_path"`
	StartWithWindows bool   `json:"start_with_windows"`
	LastEncryptSrc   string `json:"last_encrypt_src,omitempty"`
	LastEncryptOut   string `json:"last_encrypt_out,omitempty"`
	LastDecryptSrc   string `json:"last_decrypt_src,omitempty"`
	LastDecryptOut   string `json:"last_decrypt_out,omitempty"`
}

// DefaultDir returns TBCRYPT_HOME or the user's tbcrypt configuration directory.
func DefaultDir() (string, error) {
	if d := os.Getenv("TBCRYPT_HOME"); d != "" {
		return d, nil
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "tbcrypt"), nil
}

// Load reads config.json; a missing file yields an empty configuration.
func Load(dir string) (Config, error) {
	var c Config
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}

// Save atomically replaces config.json.
func Save(dir string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.Atomic(filepath.Join(dir, "config.json"), append(b, '\n'))
}

// Resolved supplies default output and done directories.
func (c Config) Resolved() Config {
	if c.OutputDir == "" {
		c.OutputDir = filepath.Join(c.WatchDir, "encrypted")
	}
	if c.DoneDir == "" {
		c.DoneDir = filepath.Join(c.WatchDir, "done")
	}
	return c
}

// FindExiftool finds the configured executable or an executable on PATH.
func FindExiftool(c Config) string {
	if c.ExiftoolPath != "" {
		if s, err := os.Stat(c.ExiftoolPath); err == nil && !s.IsDir() {
			return c.ExiftoolPath
		}
	}
	for _, name := range []string{"exiftool", "exiftool(-k).exe", "exiftool(-k)"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

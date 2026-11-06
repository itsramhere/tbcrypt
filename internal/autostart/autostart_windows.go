//go:build windows

// Package autostart controls the current user's Windows login startup entry.
package autostart

import (
	"errors"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"strings"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Enable registers a quoted executable path for the current user.
func Enable(exePath string) error { return enable("tbcrypt", exePath) }

// Disable removes the current user's tbcrypt startup entry.
func Disable() error { return disable("tbcrypt") }

// Enabled reports whether the current user has a tbcrypt startup entry.
func Enabled() (bool, error) { return enabled("tbcrypt") }

func enable(name, exe string) error {
	if !filepath.IsAbs(exe) || strings.ContainsAny(exe, "\"\x00\r\n") {
		return errors.New("startup executable must be an absolute unquoted path")
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(name, `"`+exe+`"`)
}
func disable(name string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	err = key.DeleteValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}
func enabled(name string) (bool, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	_, _, err = key.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

//go:build !windows

// Package autostart controls login startup on Windows.
package autostart

import "errors"

// Enable is unsupported outside Windows.
func Enable(string) error { return errors.New("autostart is only supported on Windows") }

// Disable is unsupported outside Windows.
func Disable() error { return errors.New("autostart is only supported on Windows") }

// Enabled reports that autostart is unavailable outside Windows.
func Enabled() (bool, error) { return false, nil }

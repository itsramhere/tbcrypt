//go:build !windows

// Package tray runs the Windows notification-area application.
package tray

import "errors"

// Run is unsupported outside Windows.
func Run(string) error { return errors.New("tray is only supported on Windows") }

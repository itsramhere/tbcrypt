//go:build !windows

package pipeline

import (
	"errors"
	"syscall"
)

func hidden(path string) bool         { return false }
func hideDirectory(path string) error { return nil }
func crossVolume(err error) bool      { return errors.Is(err, syscall.EXDEV) }

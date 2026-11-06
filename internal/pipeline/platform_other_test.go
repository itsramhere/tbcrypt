//go:build !windows

package pipeline

import "syscall"

func crossVolumeError() error { return syscall.EXDEV }

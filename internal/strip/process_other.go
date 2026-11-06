//go:build !windows

package strip

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}

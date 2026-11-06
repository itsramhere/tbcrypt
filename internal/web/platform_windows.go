//go:build windows

package web

import (
	"os/exec"
	"syscall"
)

func launch(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
func openBrowser(url string) error { return launch("rundll32.exe", "url.dll,FileProtocolHandler", url) }
func openDirectory(path string) error {
	// A folder is a user-requested window; only the browser launcher is hidden.
	cmd := exec.Command("explorer.exe", path)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

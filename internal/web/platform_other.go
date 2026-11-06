//go:build !windows

package web

import "os/exec"

func openBrowser(url string) error {
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
func openDirectory(path string) error { return openBrowser(path) }

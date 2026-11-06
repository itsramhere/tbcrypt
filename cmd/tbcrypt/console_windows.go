//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"os"
)

func attachConsole() {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	// ERROR_ACCESS_DENIED means this process is already attached to a console.
	proc.Call(uintptr(^uint32(0)))
	// Preserve valid inherited pipe/file handles (PowerShell redirection and tests).
	// GUI-subsystem launches often have no handles; repair those with console files.
	repair := func(current **os.File, device string, flags int, std uint32) {
		if *current != nil {
			if _, err := (*current).Stat(); err == nil {
				return
			}
		}
		f, err := os.OpenFile(device, flags, 0)
		if err != nil {
			return
		}
		*current = f
		_ = windows.SetStdHandle(std, windows.Handle(f.Fd()))
	}
	repair(&os.Stdout, "CONOUT$", os.O_WRONLY, windows.STD_OUTPUT_HANDLE)
	repair(&os.Stderr, "CONOUT$", os.O_WRONLY, windows.STD_ERROR_HANDLE)
	repair(&os.Stdin, "CONIN$", os.O_RDONLY, windows.STD_INPUT_HANDLE)
}

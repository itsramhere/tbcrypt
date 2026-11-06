//go:build windows

package watcher

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveFileWaitsForRelease(t *testing.T) {
	w, opts := fixture(t)
	start(t, w)
	path := filepath.Join(opts.WatchDir, "locked.txt")
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}()
	var n uint32
	if err = windows.WriteFile(h, []byte("locked"), &n, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * w.StableFor)
	if w.Status().Done != 0 {
		t.Fatal("processed exclusively held file")
	}
	if err = windows.CloseHandle(h); err != nil {
		t.Fatal(err)
	}
	h = 0
	waitFor(t, "released file", func() bool { return w.Status().Done == 1 })
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("source not moved")
	}
}

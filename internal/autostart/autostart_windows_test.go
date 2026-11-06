//go:build windows

package autostart

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"testing"
	"time"
)

func TestStartupValue(t *testing.T) {
	name := fmt.Sprintf("tbcrypt-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	exe := `C:\Program Files\tbcrypt\tbcrypt.exe`
	if err := enable(name, exe); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skip("sandbox denies HKCU Run registry writes")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := disable(name); err != nil {
			t.Error(err)
		}
	})
	if ok, err := enabled(name); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	got, _, err := key.GetStringValue(name)
	if err != nil || got != `"`+exe+`"` {
		t.Fatalf("%q %v", got, err)
	}
	if err := disable(name); err != nil {
		t.Fatal(err)
	}
	if ok, err := enabled(name); err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
}

//go:build windows

package keystore

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestNamespaceShortNameSpellingOfTheDefaultHome (WINFIX2 audit finding 6):
// an 8.3 short-name spelling of the account's home is the same home, so it
// keeps the unsuffixed names.
func TestNamespaceShortNameSpellingOfTheDefaultHome(t *testing.T) {
	real := filepath.Join(t.TempDir(), "a long home folder name")
	if err := os.MkdirAll(filepath.Join(real, ".observer"), 0o700); err != nil {
		t.Fatal(err)
	}
	lp, err := syscall.UTF16PtrFromString(real)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := syscall.GetShortPathName(lp, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Skipf("no short name here: %v", err)
	}
	short := syscall.UTF16ToString(buf[:n])
	if short == real {
		t.Skip("this volume makes no 8.3 names")
	}
	withHomes(t, filepath.Join(short, ".observer"), filepath.Join(real, ".observer"))
	if got := Namespace("sbo-change-record-v1"); got != "sbo-change-record-v1" {
		t.Fatalf("the short spelling %s got %q, want the unsuffixed name", short, got)
	}
}

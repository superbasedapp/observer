//go:build unix

package hook

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestAutohandRefusesFIFO: a FIFO at the config path is refused without
// blocking or writing.
func TestAutohandRefusesFIFO(t *testing.T) {
	home := t.TempDir()
	p := autohandPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	res := autohandRegistry(t, home).Register("autohand")
	if res.Error == nil || !strings.Contains(res.Error.Error(), "not a regular settings file") {
		t.Errorf("FIFO: %+v", res)
	}
}

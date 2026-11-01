//go:build unix

package proxyroute

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestMemberRouteRefusesFIFO: a FIFO at the route path is refused without
// blocking or writing.
func TestMemberRouteRefusesFIFO(t *testing.T) {
	runLiveGated(t)
	spec, _ := memberSpecFor("poolside", false)
	home := t.TempDir()
	path := memberPath(t, home, spec.artifact)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip("no mkfifo")
	}
	if res := runMember(memberRegistrar(t, home, false), spec); res.Error == nil || !strings.Contains(res.Error.Error(), "not a regular settings file") {
		t.Errorf("fifo: %+v", res)
	}
}

//go:build unix

package diag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestInspectCaptureIntegrityRefusesFIFOWithoutBlocking (FU-132): the
// registry and a registered hook config are read through the one capped
// regular-file reader (internal/regularfile), so a FIFO planted at either
// path is refused without a blocking read: the check reads it as unreadable
// and returns, with no writer on the other end. The old local copy refused
// it at the stat too; what the fold adds is the descriptor re-check and the
// non-blocking open for a FIFO swapped in after the stat, which no test can
// time.
func TestInspectCaptureIntegrityRefusesFIFOWithoutBlocking(t *testing.T) {
	for _, tc := range []struct {
		name string
		fifo func(home string) string
		want string
	}{
		{"registry", func(home string) string { return filepath.Join(home, ".observer", "hook_checksums.json") }, orgcontract.CaptureUnknownRegistryUnreadable},
		{"registered config", func(home string) string { return filepath.Join(home, "settings.json") }, orgcontract.CaptureUnknownConfigUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			observerDir := filepath.Join(home, ".observer")
			if err := os.MkdirAll(observerDir, 0o755); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(home, "settings.json")
			if tc.want == orgcontract.CaptureUnknownConfigUnreadable {
				raw, err := json.Marshal(map[string]captureRegistryEntry{config: {SHA256: "00", BinaryPath: "/current/observer"}})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(observerDir, "hook_checksums.json"), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := syscall.Mkfifo(tc.fifo(home), 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			done := make(chan CaptureIntegritySignals, 1)
			go func() { done <- InspectCaptureIntegrity(home, "/current/observer") }()
			select {
			case got := <-done:
				found := false
				for _, u := range got.Unknown {
					found = found || u == tc.want
				}
				if !found {
					t.Fatalf("FIFO at the %s: risks %v unknown %v, want %q", tc.name, got.Risks, got.Unknown, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("the check blocked on a FIFO at the %s", tc.name)
			}
		})
	}
}

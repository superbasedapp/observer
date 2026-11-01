package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestRecordedRepairNamesTheKeptCopy pins T-884: a repair the registry
// records with the copy it kept is reported as hook_repaired with that copy
// as a home-relative label; a repair recorded without one carries none.
func TestRecordedRepairNamesTheKeptCopy(t *testing.T) {
	now := time.Date(2026, 10, 17, 18, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		keptCopy func(home string) string
		want     string
	}{
		{"a kept copy is named", func(home string) string {
			return filepath.Join(home, ".config", "opencode", "plugins", "superbased-observer.ts.displaced-20261017T171840.123456789Z")
		}, "~/.config/opencode/plugins/superbased-observer.ts.displaced-20261017T171840.123456789Z"},
		{"no copy, no label", func(string) string { return "" }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			p := filepath.Join(home, ".config", "opencode", "plugins", "superbased-observer.ts")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			body := []byte("// shim\n")
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			writeRegistry(t, home, map[string]captureRegistryEntry{p: {
				SHA256: hex.EncodeToString(sum[:]), BinaryPath: "/current/observer", Tool: "opencode",
				LastRepairedAt: now.Add(-time.Hour).Format(time.RFC3339), LastRepairedEvents: []string{"tool.execute.before"},
				LastRepairedCopy: tc.keptCopy(home),
			}})
			sig := InspectCaptureIntegrityWith(home, CaptureIntegrityOptions{BinaryPath: "/current/observer", Now: now})
			for _, it := range sig.Items {
				if it.Risk != orgcontract.CaptureRiskHookRepaired {
					continue
				}
				if it.KeptCopy != tc.want {
					t.Fatalf("kept_copy = %q, want %q", it.KeptCopy, tc.want)
				}
				return
			}
			t.Fatalf("no hook_repaired item in %+v", sig.Items)
		})
	}
}

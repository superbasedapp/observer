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

// TestRepairedItemCarriesRepairTime pins the node half of T-886: the
// hook_repaired item carries the repair time the registry recorded, so the
// organization can tell a second repair of the same hook from the first.
// Standing items carry no time.
func TestRepairedItemCarriesRepairTime(t *testing.T) {
	now := time.Date(2026, 10, 17, 17, 20, 0, 0, time.UTC)
	repairedAt := now.Add(-100 * time.Second).Format(time.RFC3339)
	home := t.TempDir()
	p := filepath.Join(home, ".cline", "plugins", "guard.js")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`module.exports = {}`)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	writeRegistry(t, home, map[string]captureRegistryEntry{p: {
		SHA256: hex.EncodeToString(sum[:]), BinaryPath: "/old/observer", Tool: "cline-cli",
		LastRepairedAt: repairedAt, LastRepairedEvents: []string{"PreToolUse"},
	}})
	got := InspectCaptureIntegrityWith(home, CaptureIntegrityOptions{BinaryPath: "/current/observer", Now: now})
	var sawRepair, sawStanding bool
	for _, it := range got.Items {
		switch it.Risk {
		case orgcontract.CaptureRiskHookRepaired:
			sawRepair = true
			if it.At != repairedAt {
				t.Errorf("hook_repaired At = %q, want %q", it.At, repairedAt)
			}
		case orgcontract.CaptureRiskHookBinaryMismatch:
			sawStanding = true
			if it.At != "" {
				t.Errorf("a standing item carries a time: %+v", it)
			}
		}
	}
	if !sawRepair || !sawStanding {
		t.Fatalf("items = %+v, want hook_repaired and hook_binary_mismatch", got.Items)
	}
}

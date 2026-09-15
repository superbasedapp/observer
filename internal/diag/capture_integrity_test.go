package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestInspectCaptureIntegritySeparatesObservedAndUnknown(t *testing.T) {
	home := t.TempDir()
	observerDir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(observerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	changedConfig := filepath.Join(home, "tool-config.json")
	if err := os.WriteFile(changedConfig, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := map[string]captureRegistryEntry{
		changedConfig: {
			SHA256:     hex.EncodeToString(sha256.New().Sum(nil)),
			BinaryPath: "/old/observer",
			LastResult: "error",
		},
		filepath.Join(home, "missing.json"): {
			SHA256:     "00",
			BinaryPath: "/current/observer",
		},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(observerDir, "hook_checksums.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got := InspectCaptureIntegrity(home, "/current/observer")
	wantRisks := map[string]bool{
		orgcontract.CaptureRiskHookRegistrationError: true,
		orgcontract.CaptureRiskHookBinaryMismatch:    true,
		orgcontract.CaptureRiskHookConfigMissing:     true,
		orgcontract.CaptureRiskHookConfigChanged:     true,
	}
	if len(got.Risks) != len(wantRisks) {
		t.Fatalf("risks = %v, want %v", got.Risks, wantRisks)
	}
	for _, label := range got.Risks {
		if !wantRisks[label] {
			t.Errorf("unexpected risk label %q", label)
		}
	}
	if len(got.Unknown) != 0 {
		t.Errorf("unknown = %v, want none", got.Unknown)
	}
}

func TestInspectCaptureIntegrityMissingRegistryIsUnknown(t *testing.T) {
	got := InspectCaptureIntegrity(t.TempDir(), "")
	if len(got.Risks) != 0 {
		t.Errorf("risks = %v, want none", got.Risks)
	}
	if len(got.Unknown) != 1 || got.Unknown[0] != orgcontract.CaptureUnknownRegistryMissing {
		t.Errorf("unknown = %v, want only %q", got.Unknown, orgcontract.CaptureUnknownRegistryMissing)
	}
}

func TestInspectCaptureIntegrityRejectsNonRegularRegisteredPath(t *testing.T) {
	home := t.TempDir()
	observerDir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(observerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries := map[string]captureRegistryEntry{
		home: {SHA256: "00", BinaryPath: "/current/observer"},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(observerDir, "hook_checksums.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got := InspectCaptureIntegrity(home, "/current/observer")
	if len(got.Risks) != 0 || len(got.Unknown) != 1 || got.Unknown[0] != orgcontract.CaptureUnknownConfigUnreadable {
		t.Fatalf("non-regular path = risks %v unknown %v", got.Risks, got.Unknown)
	}
}

func TestInspectCaptureIntegrityBoundsRegistryRead(t *testing.T) {
	home := t.TempDir()
	observerDir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(observerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(observerDir, "hook_checksums.json"),
		make([]byte, maxCaptureRegistryBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	got := InspectCaptureIntegrity(home, "/current/observer")
	if len(got.Risks) != 0 || len(got.Unknown) != 1 || got.Unknown[0] != orgcontract.CaptureUnknownRegistryUnreadable {
		t.Fatalf("oversized registry = risks %v unknown %v", got.Risks, got.Unknown)
	}
}

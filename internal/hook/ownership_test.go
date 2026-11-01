package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookdigest"
)

// TestConflictRules pins conflictRules (T-872), one case per row and per
// fact that must NOT be enough on its own.
func TestConflictRules(t *testing.T) {
	cases := []struct {
		name     string
		facts    conflictFacts
		want     conflictAction
		wantRule string
	}{
		{"force overwrites a content-only slot", conflictFacts{force: true, identity: identityContent}, conflictOverwrite, "force"},
		{"force overwrites an owned slot", conflictFacts{force: true, repairOwned: true, identity: identityOwnedName, installedByObserver: true}, conflictOverwrite, "force"},
		{"managed pass repairs an owned, installed artifact", conflictFacts{repairOwned: true, identity: identityOwnedName, installedByObserver: true}, conflictRepair, ownedRepairRule},
		{"managed pass refuses an owned name Observer never installed", conflictFacts{repairOwned: true, identity: identityOwnedName}, conflictRefuse, "foreign"},
		{"managed pass refuses a content-only slot", conflictFacts{repairOwned: true, identity: identityContent, installedByObserver: true}, conflictRefuse, "foreign"},
		{"individual node refuses an owned, installed artifact", conflictFacts{identity: identityOwnedName, installedByObserver: true}, conflictRefuse, "foreign"},
		{"individual node refuses a content-only slot", conflictFacts{identity: identityContent}, conflictRefuse, "foreign"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, rule := decideConflict(tc.facts)
			if got != tc.want || rule != tc.wantRule {
				t.Fatalf("decideConflict(%+v) = %v (%s), want %v (%s)", tc.facts, got, rule, tc.want, tc.wantRule)
			}
		})
	}
}

// TestObserverInstalled pins the registry evidence the repair row needs: a
// recorded checksum or recorded events, never a failed attempt alone.
func TestObserverInstalled(t *testing.T) {
	cases := []struct {
		name  string
		entry map[string]any
		want  bool
	}{
		{"whole-file checksum", map[string]any{"sha256": "ab12"}, true},
		{"hooks-subtree digest", map[string]any{hookdigest.KeyScope: hookdigest.Scope, hookdigest.KeyDigest: "cd34"}, true},
		{"recorded events", map[string]any{"events": []any{"PreToolUse"}}, true},
		{"failed attempt only", map[string]any{"last_result": "error", "last_error": "conflict", "tool": "opencode"}, false},
		{"no entry", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			cs := filepath.Join(home, ".observer", "hook_checksums.json")
			target := filepath.Join(home, "artifact")
			if tc.entry != nil {
				body, err := json.Marshal(map[string]map[string]any{target: tc.entry})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(cs), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cs, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := NewRegistry(Options{BinaryPath: "/opt/observer", HomeDir: home, ChecksumsPath: cs})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.observerInstalled(target); got != tc.want {
				t.Fatalf("observerInstalled = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveConflictReadsRegistryOnlyForOwnedRepair pins that a writer's
// answer for a content-only slot, and for any slot on an individual node, is
// independent of the registry (the pre-T-872 refusal, unchanged).
func TestResolveConflictReadsRegistryOnlyForOwnedRepair(t *testing.T) {
	home := t.TempDir()
	cs := filepath.Join(home, ".observer", "hook_checksums.json")
	target := filepath.Join(home, "artifact")
	if err := os.MkdirAll(filepath.Dir(cs), 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]map[string]any{target: {"sha256": "ab12"}})
	if err := os.WriteFile(cs, body, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		repair bool
		id     artifactIdentity
		want   conflictAction
	}{
		{false, identityOwnedName, conflictRefuse},
		{false, identityContent, conflictRefuse},
		{true, identityContent, conflictRefuse},
		{true, identityOwnedName, conflictRepair},
	} {
		r, err := NewRegistry(Options{BinaryPath: "/opt/observer", HomeDir: home, ChecksumsPath: cs, RepairOwnedArtifacts: tc.repair})
		if err != nil {
			t.Fatal(err)
		}
		if got := r.resolveConflict(target, tc.id); got != tc.want {
			t.Errorf("repair=%v identity=%v: got %v, want %v", tc.repair, tc.id, got, tc.want)
		}
	}
}

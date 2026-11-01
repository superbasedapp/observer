package diag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func writeRegistry(t *testing.T, home string, entries map[string]captureRegistryEntry) {
	t.Helper()
	dir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hook_checksums.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasItem(sig CaptureIntegritySignals, risk, tool, file string) bool {
	for _, it := range sig.Items {
		if it.Risk == risk && it.Tool == tool && it.File == file {
			return true
		}
	}
	return false
}

// TestInspectCaptureIntegrityWithLocatesEveryRisk is the T-847 table: each
// row is one tamper shape, and the risk must name the tool and the file.
func TestInspectCaptureIntegrityWithLocatesEveryRisk(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		setup    func(t *testing.T, home string) []ExpectedHook
		risk     string
		tool     string
		file     string
		unknown  string
		noRisk   bool
		withTime bool
	}{
		{
			name: "deleted registry on a node that registers hooks is a risk (audit c3)",
			setup: func(t *testing.T, home string) []ExpectedHook {
				return []ExpectedHook{{Tool: "codex", ConfigPath: filepath.Join(home, ".codex", "hooks.json"), Drift: []string{"PreToolUse"}}}
			},
			risk: orgcontract.CaptureRiskHookRegistryMissing, tool: HookRegistryTool, file: "~/.observer/hook_checksums.json",
		},
		{
			name: "the same deletion also reports the dry-run drift with the tool and file",
			setup: func(t *testing.T, home string) []ExpectedHook {
				return []ExpectedHook{{Tool: "codex", ConfigPath: filepath.Join(home, ".codex", "hooks.json"), Drift: []string{"PreToolUse"}}}
			},
			risk: orgcontract.CaptureRiskHookRegistrationDrift, tool: "codex", file: "~/.codex/hooks.json",
		},
		{
			name:    "no expected hooks keeps the pre-T-847 unknown",
			setup:   func(*testing.T, string) []ExpectedHook { return nil },
			unknown: orgcontract.CaptureUnknownRegistryMissing, noRisk: true,
		},
		{
			name: "a deleted hook file names the tool recorded in the entry (audit c2)",
			setup: func(t *testing.T, home string) []ExpectedHook {
				writeRegistry(t, home, map[string]captureRegistryEntry{
					filepath.Join(home, ".cursor", "hooks.json"): {SHA256: "00", BinaryPath: "/current/observer", Tool: "cursor"},
				})
				return nil
			},
			risk: orgcontract.CaptureRiskHookConfigMissing, tool: "cursor", file: "~/.cursor/hooks.json",
		},
		{
			name: "an entry without a tool takes it from the expected target",
			setup: func(t *testing.T, home string) []ExpectedHook {
				p := filepath.Join(home, ".claude", "settings.json")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(`{"hooks":{}}`), 0o600); err != nil {
					t.Fatal(err)
				}
				writeRegistry(t, home, map[string]captureRegistryEntry{p: {SHA256: "00", BinaryPath: "/current/observer"}})
				return []ExpectedHook{{Tool: "claude-code", ConfigPath: p}}
			},
			risk: orgcontract.CaptureRiskHookConfigChanged, tool: "claude-code", file: "~/.claude/settings.json",
		},
		{
			name: "a detected target with no registry entry is a risk",
			setup: func(t *testing.T, home string) []ExpectedHook {
				writeRegistry(t, home, map[string]captureRegistryEntry{})
				return []ExpectedHook{{Tool: "gemini-cli", ConfigPath: filepath.Join(home, ".gemini", "settings.json")}}
			},
			risk: orgcontract.CaptureRiskHookRegistryEntryMissing, tool: "gemini-cli", file: "~/.gemini/settings.json",
		},
		{
			name: "a recorded repair inside the window is reported",
			setup: func(t *testing.T, home string) []ExpectedHook {
				p := filepath.Join(home, ".cursor", "hooks.json")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				body := []byte(`{"hooks":{}}`)
				if err := os.WriteFile(p, body, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(body)
				writeRegistry(t, home, map[string]captureRegistryEntry{p: {
					SHA256: hex.EncodeToString(sum[:]), BinaryPath: "/current/observer", Tool: "cursor",
					LastRepairedAt: now.Add(-time.Hour).Format(time.RFC3339), LastRepairedEvents: []string{"preToolUse"},
				}})
				return nil
			},
			risk: orgcontract.CaptureRiskHookRepaired, tool: "cursor", file: "~/.cursor/hooks.json", withTime: true,
		},
		{
			name: "a repair older than the window is not",
			setup: func(t *testing.T, home string) []ExpectedHook {
				p := filepath.Join(home, ".cursor", "hooks.json")
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				body := []byte(`{"hooks":{}}`)
				if err := os.WriteFile(p, body, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(body)
				writeRegistry(t, home, map[string]captureRegistryEntry{p: {
					SHA256: hex.EncodeToString(sum[:]), BinaryPath: "/current/observer", Tool: "cursor",
					LastRepairedAt: now.Add(-25 * time.Hour).Format(time.RFC3339),
				}})
				return nil
			},
			noRisk: true, withTime: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			exp := tc.setup(t, home)
			opts := CaptureIntegrityOptions{BinaryPath: "/current/observer", Expected: exp}
			if tc.withTime {
				opts.Now = now
			}
			got := InspectCaptureIntegrityWith(home, opts)
			if tc.noRisk && len(got.Risks) != 0 {
				t.Fatalf("risks = %v, want none", got.Risks)
			}
			if tc.risk != "" && !hasItem(got, tc.risk, tc.tool, tc.file) {
				t.Fatalf("want %s (%s %s); risks=%v items=%+v", tc.risk, tc.tool, tc.file, got.Risks, got.Items)
			}
			if tc.unknown != "" {
				found := false
				for _, u := range got.Unknown {
					found = found || u == tc.unknown
				}
				if !found {
					t.Fatalf("unknown = %v, want %s", got.Unknown, tc.unknown)
				}
			}
			for _, it := range got.Items {
				if it.File != "" && !orgcontract.ValidRiskFileLabel(it.File) {
					t.Fatalf("item file %q breaks the content floor", it.File)
				}
			}
		})
	}
}

// TestRiskFileLabel pins the label rule: never a user name, never an
// absolute path.
func TestRiskFileLabel(t *testing.T) {
	cases := []struct{ home, path, want string }{
		{"/home/alice", "/home/alice/.cursor/hooks.json", "~/.cursor/hooks.json"},
		{"/home/alice", "/mnt/c/Users/Alice B/.claude/settings.json", "~win/.claude/settings.json"},
		{`C:\Users\alice`, `C:\Users\alice\.codex\hooks.json`, "~/.codex/hooks.json"},
		{"/home/alice", `D:\Users\bob\.kiro\agents\a.json`, "~win/.kiro/agents/a.json"},
		{"/home/alice", "/opt/tool/conf/hooks.json", "?/conf/hooks.json"},
		{"/home/alice", "", ""},
	}
	for _, tc := range cases {
		if got := RiskFileLabel(tc.home, tc.path); got != tc.want {
			t.Errorf("RiskFileLabel(%q, %q) = %q, want %q", tc.home, tc.path, got, tc.want)
		}
	}
}

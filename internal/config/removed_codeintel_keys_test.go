package config

import (
	"os"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// TestRemovedCodeIntelKeys is the P4 disposition proof for
// codeintel.index.disk_budget_mb (corpus-archival design §9 P4). The knob is
// REMOVED — not renamed, not implemented — so three things must hold at once:
// a config still carrying it LOADS, it warns exactly once, and the warning
// tells the operator what to use instead.
func TestRemovedCodeIntelKeys(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		body        string
		wantWarns   int
		wantContain []string
	}{
		{
			name: "removed key warns once and names the replacements",
			body: `
[codeintel.index]
disk_budget_mb = 500
`,
			wantWarns: 1,
			wantContain: []string{
				"codeintel.index.disk_budget_mb is removed",
				"never implemented",
				"codeintel.retention_days",
				"[archive].enabled",
			},
		},
		{
			// The same key at zero — the "no cap" value the old doc comment
			// advertised — is still a key the operator wrote, so it still
			// warns. Silence here would leave them believing an uncapped
			// index was a decision they made.
			name: "zero value still warns",
			body: `
[codeintel.index]
disk_budget_mb = 0
`,
			wantWarns:   1,
			wantContain: []string{"codeintel.index.disk_budget_mb is removed"},
		},
		{
			name: "sibling keys in the same block do not warn",
			body: `
[codeintel.index]
on_start = false
workers = 4
`,
			wantWarns: 0,
		},
		{
			name:      "absent key is silent",
			body:      "",
			wantWarns: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			meta, err := toml.Decode(tc.body, &cfg)
			if err != nil {
				t.Fatalf("decode: %v — a config carrying a removed key must still LOAD", err)
			}
			warns := migrateRemovedCodeIntelKeys(&cfg, []toml.MetaData{meta})
			if len(warns) != tc.wantWarns {
				t.Fatalf("warnings = %d, want %d\n%v", len(warns), tc.wantWarns, warns)
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(warns[0], want) {
					t.Errorf("warning does not mention %q:\n%s", want, warns[0])
				}
			}
		})
	}
}

// TestRemovedDiskBudgetLoadsThroughLoad pins the same contract through the REAL
// Load path rather than the migration helper alone: the operator's live config
// carries `disk_budget_mb = 500` today, and removing the struct field must not
// turn their next `observer start` into a config error.
func TestRemovedDiskBudgetLoadsThroughLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/config.toml"
	body := `
[codeintel]
enabled = true

[codeintel.index]
disk_budget_mb = 500
on_start = false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("Load with a removed key: %v — this is the operator's live config shape", err)
	}
	// The rest of the block must still decode; a removed key must not poison
	// its siblings.
	if cfg.CodeIntel.Index.OnStart {
		t.Error("codeintel.index.on_start = true, want false — the sibling key in the same block was lost")
	}
	if !cfg.CodeIntel.Enabled {
		t.Error("codeintel.enabled = false, want true")
	}
}

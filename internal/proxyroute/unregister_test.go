package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

func newUnregTestRegistrar(t *testing.T, home string, dryRun, force bool) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{
		ProxyPort: 8820, HomeDir: home, DryRun: dryRun, Force: force, Writer: routeprov.WriterSetup,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readCodexTOML(t *testing.T, path string) map[string]any {
	t.Helper()
	root := map[string]any{}
	if _, err := toml.DecodeFile(path, &root); err != nil {
		t.Fatal(err)
	}
	return root
}

func provenanceRecords(t *testing.T, r *Registrar) []routeprov.Record {
	t.Helper()
	f, err := loadProvenance(r.ProvenancePath())
	if err != nil {
		t.Fatal(err)
	}
	return f.Records
}

// TestUnregisterCodex is the table of the codex route undo: it removes only
// the route this install wrote, puts model_provider back to what it was, and
// keeps every other key.
func TestUnregisterCodex(t *testing.T) {
	cases := []struct {
		name        string
		seed        string // config.toml before the register step ("" = none)
		register    bool   // run RegisterCodex (with force) first
		dryRun      bool
		wantRemoved bool
		wantAlready bool
		wantModel   string // expected top-level model_provider after ("" = absent)
		wantKept    string // a key that must survive
		wantOurs    bool   // our provider block still present after
	}{
		{
			name: "restores the prior provider", seed: "model = \"gpt-5\"\nmodel_provider = \"corp\"\n",
			register: true, wantRemoved: true, wantModel: "corp", wantKept: "model",
		},
		{
			name: "removes model_provider when it was unset", seed: "model = \"gpt-5\"\n",
			register: true, wantRemoved: true, wantModel: "", wantKept: "model",
		},
		{
			name: "dry run writes nothing", seed: "model = \"gpt-5\"\n",
			register: true, dryRun: true, wantRemoved: true, wantModel: ProviderName, wantKept: "model", wantOurs: true,
		},
		{
			name:        "another observer's port is left alone",
			seed:        "model_provider = \"openai-observer\"\n[model_providers.openai-observer]\nbase_url = \"http://127.0.0.1:9999/v1\"\n",
			wantAlready: true, wantModel: ProviderName, wantOurs: true,
		},
		{
			name: "no route is a no-op", seed: "model = \"gpt-5\"\n",
			wantAlready: true, wantModel: "", wantKept: "model",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.seed), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.register {
				if res := newUnregTestRegistrar(t, home, false, true).RegisterCodex(); res.Error != nil || !res.Added {
					t.Fatalf("register: %+v", res)
				}
			}
			r := newUnregTestRegistrar(t, home, tc.dryRun, false)
			res := r.UnregisterCodex()
			if res.Error != nil {
				t.Fatalf("unregister error: %v", res.Error)
			}
			if res.Added != tc.wantRemoved || res.AlreadySet != tc.wantAlready {
				t.Fatalf("result %+v, want removed=%v already=%v", res, tc.wantRemoved, tc.wantAlready)
			}
			root := readCodexTOML(t, path)
			if mp, _ := root["model_provider"].(string); mp != tc.wantModel {
				t.Errorf("model_provider = %q, want %q", mp, tc.wantModel)
			}
			providers, _ := root["model_providers"].(map[string]any)
			if _, ours := providers[ProviderName]; ours != tc.wantOurs {
				t.Errorf("our provider block present = %v, want %v", ours, tc.wantOurs)
			}
			if tc.wantKept != "" {
				if _, ok := root[tc.wantKept]; !ok {
					t.Errorf("key %q was not preserved", tc.wantKept)
				}
			}
			if tc.register && !tc.dryRun {
				for _, rec := range provenanceRecords(t, r) {
					if rec.Tool == "codex" {
						t.Errorf("provenance still records the removed codex route: %+v", rec)
					}
				}
			}
		})
	}
}

// TestUnregisterCodexIsSurgical pins review M3-16: the undo edits only our
// provider table and model_provider, keeping the operator's comments, other
// keys and layout byte for byte, keeps the file mode, leaves no temp file and
// runs under the injected settings-file lock.
func TestUnregisterCodexIsSurgical(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// The route as a hand edit (or RegisterCodex, which edits surgically
	// since T-394) leaves it.
	const seed = "# my codex settings, keep this note\nmodel = \"gpt-5\"   # pinned for the team\nmodel_provider = \"openai-observer\"\n\n" +
		"[model_providers.corp]\n# corporate gateway\nbase_url = \"https://gw.corp.example/v1\"\n\n" +
		"[model_providers.openai-observer]\nname = \"observer\"\nbase_url = \"http://127.0.0.1:8820/v1\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	var locked []string
	r, err := NewRegistrar(RegisterOptions{
		ProxyPort: 8820, HomeDir: home, Writer: routeprov.WriterSetup,
		Lock: func(p string) (func(), error) { locked = append(locked, p); return func() {}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.UnregisterCodex()
	if res.Error != nil || !res.Added {
		t.Fatalf("unregister: %+v", res)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# my codex settings, keep this note", "# pinned for the team", "# corporate gateway", "[model_providers.corp]"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("undo lost %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), ProviderName) {
		t.Fatalf("our route is still there:\n%s", got)
	}
	if root := readCodexTOML(t, path); root["model_provider"] != nil {
		t.Fatalf("model_provider = %v, want removed (no prior recorded)", root["model_provider"])
	}
	// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644 kept", fi.Mode().Perm())
	}
	if len(locked) != 1 || locked[0] != path {
		t.Fatalf("lock calls = %v, want one on %s", locked, path)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a temp file was left behind: %s", e.Name())
		}
	}
}

// TestUnregisterClaudeCodeDropsProvenance: the Claude Code undo removes the
// route and forgets the record of who wrote it (a stale record would let a
// later Leave treat a hand-set route as enrolment's).
func TestUnregisterClaudeCodeDropsProvenance(t *testing.T) {
	home := t.TempDir()
	if res := newUnregTestRegistrar(t, home, false, false).RegisterClaudeCode(); res.Error != nil || !res.Added {
		t.Fatalf("register: %+v", res)
	}
	r := newUnregTestRegistrar(t, home, false, false)
	if len(provenanceRecords(t, r)) == 0 {
		t.Fatal("register left no provenance record")
	}
	res := r.UnregisterClaudeCode()
	if res.Error != nil || !res.Added {
		t.Fatalf("unregister: %+v", res)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]json.RawMessage
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s["env"]), "ANTHROPIC_BASE_URL") {
		t.Errorf("route still present: %s", raw)
	}
	for _, rec := range provenanceRecords(t, r) {
		if rec.Tool == "claude-code" {
			t.Errorf("provenance still records the removed route: %+v", rec)
		}
	}
}

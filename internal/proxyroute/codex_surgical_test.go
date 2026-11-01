package proxyroute

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
)

// TestRegisterCodexIsSurgical pins T-394: RegisterCodex edits only the keys it
// owns in ~/.codex/config.toml and keeps every comment, other key and the
// file's mode, the way the M3-16 undo already does. Before the fix the writer
// re-encoded the whole file through the TOML encoder, which dropped every
// comment and rewrote the file 0600.
func TestRegisterCodexIsSurgical(t *testing.T) {
	cases := []struct {
		name  string
		seed  string
		force bool
		// keep must survive byte for byte; gone must not appear afterwards.
		keep []string
		gone []string
	}{
		{
			name: "no provider yet",
			seed: "# my codex settings, keep this note\nmodel = \"gpt-5\"   # pinned for the team\n\n" +
				"[model_providers.corp]\n# corporate gateway\nbase_url = \"https://gw.corp.example/v1\"\n\n" +
				"[tui]\n# quiet please\nnotifications = false\n",
			keep: []string{
				"# my codex settings, keep this note", "model = \"gpt-5\"   # pinned for the team",
				"# corporate gateway", "[model_providers.corp]", "# quiet please", "notifications = false",
			},
		},
		{
			name: "our table already has an extra key",
			seed: "# header comment\nmodel_provider = \"openai-observer\"\n\n" +
				"[model_providers.openai-observer]\n# keep my note\nname = \"mine\"\nstream_idle_timeout_ms = 300000\n",
			keep: []string{"# header comment", "# keep my note", "stream_idle_timeout_ms = 300000"},
		},
		{
			name: "forced removal of the reserved openai table",
			seed: "# top note\nmodel_provider = \"openai\"\n\n[model_providers.openai]\nbase_url = \"https://api.openai.com/v1\"\n\n" +
				"[profiles.fast]\n# a profile comment\nmodel = \"gpt-5-mini\"\n",
			force: true,
			keep:  []string{"# top note", "[profiles.fast]", "# a profile comment", "model = \"gpt-5-mini\""},
			gone:  []string{"[model_providers.openai]\n"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".codex", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.seed), 0o644); err != nil {
				t.Fatal(err)
			}
			var locked []string
			r, err := NewRegistrar(RegisterOptions{
				ProxyPort: 8820, HomeDir: home, Force: c.force, Writer: routeprov.WriterSetup,
				Lock: func(p string) (func(), error) { locked = append(locked, p); return func() {}, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			res := r.RegisterCodex()
			if res.Error != nil || !res.Added {
				t.Fatalf("register: %+v", res)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range c.keep {
				if !strings.Contains(string(got), want) {
					t.Fatalf("register lost %q:\n%s", want, got)
				}
			}
			for _, bad := range c.gone {
				if strings.Contains(string(got), bad) {
					t.Fatalf("register kept %q:\n%s", bad, got)
				}
			}
			root := readCodexTOML(t, path)
			if root["model_provider"] != ProviderName {
				t.Fatalf("model_provider = %v", root["model_provider"])
			}
			providers, _ := root["model_providers"].(map[string]any)
			ours, _ := providers[ProviderName].(map[string]any)
			if ours["base_url"] != "http://127.0.0.1:8820/v1" || ours["wire_api"] != "responses" ||
				ours["requires_openai_auth"] != true || ours["name"] != providerDisplayName {
				t.Fatalf("provider table = %v", ours)
			}
			if _, reserved := providers["openai"]; reserved {
				t.Fatalf("reserved openai table survived: %v", providers)
			}
			// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
			if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o644 {
				t.Fatalf("mode = %v, want 0644 kept", fi.Mode().Perm())
			}
			if len(locked) != 1 || locked[0] != path {
				t.Fatalf("lock taken on %v, want once on %s", locked, path)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".tmp") {
					t.Fatalf("temp file left behind: %s", e.Name())
				}
			}
			// Idempotent: a second run is AlreadySet and changes no byte.
			again := r.RegisterCodex()
			if again.Error != nil || !again.AlreadySet {
				t.Fatalf("second register: %+v", again)
			}
			if after, _ := os.ReadFile(path); string(after) != string(got) {
				t.Fatalf("second register changed the file:\n%s", after)
			}
		})
	}
}

// TestLeaveRemovesCodexRouteSurgically: Leave's removal of an enrolment-
// written Codex route (removeCodexRouteAt) keeps the operator's comments and
// the file mode too (T-394, same edit as UnregisterCodex).
func TestLeaveRemovesCodexRouteSurgically(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := "# keep me\nmodel = \"gpt-5\" # pinned\n\n[tui]\n# tui note\nnotifications = false\n"
	if err := os.WriteFile(cfg, []byte(seed), 0o640); err != nil {
		t.Fatal(err)
	}
	if res := provReg(t, home, routeprov.WriterEnrolment).RegisterCodex(); !res.Added {
		t.Fatalf("register = %+v", res)
	}
	done, err := provReg(t, home, "").LeaveRoutes(true)
	if err != nil {
		t.Fatal(err)
	}
	if d := onlyRoute(t, done, "codex"); !d.Removed {
		t.Fatalf("codex route not removed: %+v", d)
	}
	got, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Byte for byte up to the trailing blank line the appended provider
	// section was separated by (the line editor removes the section, not the
	// separator before it).
	if strings.TrimRight(string(got), "\n")+"\n" != seed {
		t.Fatalf("register then Leave did not restore the file:\n%q\nwant\n%q", got, seed)
	}
	// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
	if fi, _ := os.Stat(cfg); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640 kept", fi.Mode().Perm())
	}
}

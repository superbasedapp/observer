package mcpregister

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// t384Fake is a fake credential: the fixtures below put it where a real
// sibling-server token or provider key would sit, and every assertion checks
// that the MCP writers keep it in place and never surface it (review T-384).
//
//nolint:gosec // G101: a fake fixture value, not a credential.
const t384Fake = "sk-fake-t384-not-real"

// filesUnder lists every regular file under root, relative.
func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// jsonSeed is a credential-bearing JSON MCP config: an unrelated member
// before and after the server object (so a re-sort shows), a sibling server
// whose env holds the fake token, and, for OpenCode, a provider key.
func jsonSeed(topKey string) string {
	sibling := `{"command": "npx", "args": ["x"], "env": {"OTHER_TOKEN": "` + t384Fake + `"}}`
	extra := ""
	if topKey == "mcp" {
		sibling = `{"type": "local", "command": ["npx", "x"], "environment": {"OTHER_TOKEN": "` + t384Fake + `"}}`
		extra = `  "provider": {"x": {"options": {"apiKey": "` + t384Fake + `"}}},` + "\n"
	}
	return "{\n" +
		`  "zeta": {"note": "keep me first"},` + "\n" +
		extra +
		`  "` + topKey + `": {` + "\n" +
		`    "other": ` + sibling + "\n" +
		"  },\n" +
		`  "alpha": 1` + "\n" +
		"}\n"
}

// TestMCPRegistrarFollowsCredentialFileRules pins review T-384 for every
// JSON MCP client: only the server subtree changes, the unrelated members
// keep their bytes and order, the sibling's fake token stays, the file mode
// is kept, and nothing else is written under home (no backup, no checksum,
// no temp file).
func TestMCPRegistrarFollowsCredentialFileRules(t *testing.T) {
	for _, loc := range locate.Locations("/x") {
		if loc.Format == locate.FormatCodexTOML {
			continue
		}
		t.Run(loc.Client, func(t *testing.T) {
			home := t.TempDir()
			l, _ := locate.ForClient(loc.Client, home)
			topKey := "mcpServers"
			if l.Format == locate.FormatOpenCodeJSON {
				topKey = "mcp"
			}
			seed := jsonSeed(topKey)
			if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(l.Path, []byte(seed), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(l.Path, 0o640); err != nil {
				t.Fatal(err)
			}
			r, err := NewRegistrar(RegisterOptions{BinaryPath: "/opt/observer", HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			check := func(stage string, wantObserver bool) {
				t.Helper()
				got, err := os.ReadFile(l.Path)
				if err != nil {
					t.Fatalf("%s: %v", stage, err)
				}
				s := string(got)
				if strings.Count(s, t384Fake) != strings.Count(seed, t384Fake) {
					t.Errorf("%s: the fake credential was not kept in place:\n%s", stage, s)
				}
				if !strings.Contains(s, `"zeta": {"note": "keep me first"}`) || !strings.Contains(s, `"alpha": 1`) {
					t.Errorf("%s: an unrelated member lost its bytes:\n%s", stage, s)
				}
				if z, m, a := strings.Index(s, `"zeta"`), strings.Index(s, `"`+topKey+`"`), strings.Index(s, `"alpha"`); !(z < m && m < a) {
					t.Errorf("%s: unrelated keys were re-sorted:\n%s", stage, s)
				}
				var doc map[string]json.RawMessage
				var servers map[string]json.RawMessage
				if err := json.Unmarshal(got, &doc); err != nil {
					t.Fatalf("%s: result does not parse: %v", stage, err)
				}
				if err := json.Unmarshal(doc[topKey], &servers); err != nil {
					t.Fatalf("%s: %s does not parse: %v", stage, topKey, err)
				}
				if _, ok := servers["other"]; !ok {
					t.Errorf("%s: sibling server dropped", stage)
				}
				if _, ok := servers[ServerName]; ok != wantObserver {
					t.Errorf("%s: observer entry present = %v, want %v", stage, ok, wantObserver)
				}
				// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
				if fi, _ := os.Stat(l.Path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
					t.Errorf("%s: mode = %v, want 0640 kept", stage, fi.Mode().Perm())
				}
				rel, _ := filepath.Rel(home, l.Path)
				if files := filesUnder(t, home); len(files) != 1 || files[0] != rel {
					t.Errorf("%s: files under home = %v, want only %s (no backup, checksum or temp file)", stage, files, rel)
				}
			}

			res := r.Register(loc.Client)
			if res.Error != nil || !res.Added {
				t.Fatalf("Register: %+v", res)
			}
			check("register", true)
			before, _ := os.ReadFile(l.Path)
			if again := r.Register(loc.Client); again.Error != nil || !again.AlreadySet {
				t.Fatalf("second Register: %+v", again)
			}
			if after, _ := os.ReadFile(l.Path); string(after) != string(before) {
				t.Error("an already-set registration rewrote the file")
			}
			if un := r.Unregister(loc.Client); un.Error != nil || !un.Removed {
				t.Fatalf("Unregister: %+v", un)
			}
			check("unregister", false)
		})
	}
}

// codexSeed is a credential-bearing config.toml: a comment, a provider key
// and a sibling server whose env holds the fake token.
const codexSeed = "# my codex config\nmodel = \"o3\"\n\n[model_providers.x]\nname = \"X\"\napi_key = \"" + t384Fake + "\"\n\n[mcp_servers.other]\ncommand = \"npx\"\nenv = { OTHER_TOKEN = \"" + t384Fake + "\" }\n"

// TestCodexMCPEditsOnlyItsTable pins review T-384 for Codex: config.toml is
// edited line by line, so the comment, the key order and the fake key keep
// their bytes; removal restores the original text; the mode is kept.
func TestCodexMCPEditsOnlyItsTable(t *testing.T) {
	home := t.TempDir()
	l, _ := locate.ForClient("codex", home)
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.Path, []byte(codexSeed), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(l.Path, 0o640); err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/opt/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("codex"); res.Error != nil || !res.Added {
		t.Fatalf("Register: %+v", res)
	}
	got, _ := os.ReadFile(l.Path)
	if !strings.HasPrefix(string(got), codexSeed) {
		t.Errorf("an unrelated line changed:\n%s", got)
	}
	var doc map[string]any
	if _, err := toml.Decode(string(got), &doc); err != nil {
		t.Fatalf("result does not parse: %v", err)
	}
	servers, _ := doc["mcp_servers"].(map[string]any)
	if obs, _ := servers[ServerName].(map[string]any); obs["command"] != "/opt/observer" {
		t.Errorf("observer entry = %v", servers[ServerName])
	}
	// POSIX-only: Windows has no mode bits (Perm reports 0666 or 0444).
	if fi, _ := os.Stat(l.Path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640 kept", fi.Mode().Perm())
	}
	if res := r.Register("codex"); res.Error != nil || !res.AlreadySet {
		t.Fatalf("second Register: %+v", res)
	}
	if un := r.Unregister("codex"); un.Error != nil || !un.Removed {
		t.Fatalf("Unregister: %+v", un)
	}
	got, _ = os.ReadFile(l.Path)
	if strings.TrimRight(string(got), "\n") != strings.TrimRight(codexSeed, "\n") {
		t.Errorf("unregister did not restore the original text:\n%s", got)
	}
	if files := filesUnder(t, home); len(files) != 1 {
		t.Errorf("files under home = %v, want only config.toml", files)
	}
}

// TestMCPErrorsNeverQuoteTheFile pins the no-surfacing rule: a file that
// does not parse, an observer entry that points elsewhere and a Codex
// observer table in a form the line editor does not own all fail without
// the fake credential in the message, and the file is left as it was.
func TestMCPErrorsNeverQuoteTheFile(t *testing.T) {
	cases := []struct {
		name, tool, body string
		force            bool
		withheld         bool
	}{
		{"malformed JSON", "cursor", `{"mcpServers": {"other": {"env": {"T": "` + t384Fake + `"}}}, ` + t384Fake + `}`, false, true},
		{"conflicting observer command", "cursor", `{"mcpServers": {"observer": {"command": "/x/` + t384Fake + `", "args": ["serve"]}}}`, false, false},
		{"malformed TOML", "codex", "api_key = \"" + t384Fake + "\"\n[[[ " + t384Fake + "\n", false, true},
		{"codex observer as an inline table", "codex", "api_key = \"" + t384Fake + "\"\n[mcp_servers]\nobserver = { command = \"/x/" + t384Fake + "\" }\n", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			l, _ := locate.ForClient(tc.tool, home)
			if err := os.MkdirAll(filepath.Dir(l.Path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(l.Path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			// The conflicting command must exist: a missing one is a stale
			// Observer entry that init now refreshes (U2, ownership.go).
			r, err := NewRegistrar(RegisterOptions{BinaryPath: "/opt/observer", HomeDir: home, Force: tc.force, commandExists: func(string) bool { return true }})
			if err != nil {
				t.Fatal(err)
			}
			res := r.Register(tc.tool)
			if res.Error == nil {
				t.Fatal("Register succeeded, want a refusal")
			}
			if strings.Contains(res.Error.Error(), t384Fake) {
				t.Errorf("error quotes the file: %v", res.Error)
			}
			if tc.withheld && !errors.Is(res.Error, credfile.ErrDetailWithheld) {
				t.Errorf("error = %v, want the withheld-detail error", res.Error)
			}
			if got, _ := os.ReadFile(l.Path); string(got) != tc.body {
				t.Error("a refused write changed the file")
			}
			if un := r.Unregister(tc.tool); un.Error != nil && strings.Contains(un.Error.Error(), t384Fake) {
				t.Errorf("unregister error quotes the file: %v", un.Error)
			}
		})
	}
}

// TestEveryMCPTargetIsADeclaredBinding pins "only declared bindings may
// write such a file": every client the registrar can write (each locate row
// and the cross-OS cline bridge) is declared on its registry row, and an
// undeclared tool is refused before any read.
func TestEveryMCPTargetIsADeclaredBinding(t *testing.T) {
	for _, loc := range locate.Locations("/x") {
		if !integration.MCPSharesCredentialFile(loc.Client) {
			t.Errorf("%s: the registrar writes this MCP config but the row does not declare it", loc.Client)
		}
	}
	if !integration.MCPSharesCredentialFile("cline-windows") {
		t.Error("cline-windows is not declared")
	}
	for _, c := range integration.Capabilities() {
		if c.MCP != nil && c.MCP.Implemented && (!c.MCP.SharesCredentialFile || c.MCP.CredentialFileReason == "") {
			t.Errorf("%s: an implemented MCP target without a declared credential-file reason", c.Tool)
		}
	}
	if err := declaredMCPFile("not-a-tool"); err == nil {
		t.Error("an undeclared tool was allowed to write")
	}
}

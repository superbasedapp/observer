package hook

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// xcodeHomes are the two Xcode agent homes under a user home (the
// catalogued darwin paths, spelled here only to build the fixture).
var xcodeHomes = map[string]string{
	"claude-code-xcode": filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "ClaudeAgentConfig"),
	"codex-xcode":       filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "codex"),
}

// xcodeFixture builds a home holding both Xcode agent homes with the files
// the MAC-1 read found (no settings.json, no config.toml, no hooks.json),
// plus a ~/.claude and ~/.codex the targets must never touch.
func xcodeFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	files := map[string]string{
		filepath.Join(xcodeHomes["claude-code-xcode"], ".claude.json"):         `{"numStartups":3}`,
		filepath.Join(xcodeHomes["claude-code-xcode"], "policy-limits.json"):   `{}`,
		filepath.Join(xcodeHomes["claude-code-xcode"], "projects", "p", "x"):   "transcript",
		filepath.Join(xcodeHomes["codex-xcode"], "installation_id"):            "abc",
		filepath.Join(xcodeHomes["codex-xcode"], "rules", "xcode.rules"):       "rule",
		filepath.Join(xcodeHomes["codex-xcode"], "sessions", "2026", "r.json"): "{}",
		filepath.Join(".claude", "settings.json"):                              `{"model":"x"}`,
		filepath.Join(".codex", "config.toml"):                                 "model = \"x\"\n",
	}
	for rel, body := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// xcodeTree hashes every file (sha256) and directory under root.
func xcodeTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newXcodeRegistry(t *testing.T, home, goos string) *Registry {
	t.Helper()
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home, GOOS: goos,
		ConfigPath:    "/etc/observer/config.toml",
		ChecksumsPath: filepath.Join(t.TempDir(), "hook_checksums.json"),
		Getenv:        func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestXcodeTargetsAreSwitchedOn: LCR-89 and LCR-90 passed on 2026-10-28
// (Mac round 5b), so the only WriterKindHostHooks row left is the Gemini
// one (LCR-91, FU-160), neither the Claude nor the Codex target has a gate,
// Installed lists each where its home exists, and InstalledLiveGated names
// neither.
func TestXcodeTargetsAreSwitchedOn(t *testing.T) {
	for _, w := range integration.LiveGatedWriters() {
		if w.Kind == integration.WriterKindHostHooks && (w.Tool != "gemini-cli" || w.Gate != "LCR-91") {
			t.Errorf("a host_hooks row other than the Gemini one waits: %+v", w)
		}
	}
	home := xcodeFixture(t)
	r := newXcodeRegistry(t, home, "darwin")
	for target := range xcodeHomes {
		if g, ok := LiveCheckGate(target); ok {
			t.Errorf("%s is still gated on %s", target, g)
		}
		if !containsString(r.Installed(), target) {
			t.Errorf("Installed does not list %s with its home present: %v", target, r.Installed())
		}
		for _, g := range r.InstalledLiveGated() {
			if g.Target == target {
				t.Errorf("InstalledLiveGated still names %s", target)
			}
		}
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestXcodeClaudeWriter: the native settings writer's entries land in
// ClaudeAgentConfig/settings.json only (the file the LCR-89 run used),
// every command is one isObserverClaudeEntry owns, a re-run changes
// nothing, ~/.claude is untouched, and Unregister removes exactly them.
func TestXcodeClaudeWriter(t *testing.T) {
	home := xcodeFixture(t)
	nativeBefore := xcodeTree(t, filepath.Join(home, ".claude"))
	r := newXcodeRegistry(t, home, "darwin")
	if !containsString(r.installedAll(true), "claude-code-xcode") {
		t.Fatalf("installedAll = %v", r.installedAll(true))
	}
	res := r.Register("claude-code-xcode")
	want := filepath.Join(home, xcodeHomes["claude-code-xcode"], "settings.json")
	if res.Error != nil || res.ConfigPath != want || len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Fatalf("Register = %+v", res)
	}
	raw, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]claudeHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for ev, groups := range doc.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if !isObserverClaudeEntry(h.Command) || !strings.Contains(h.Command, " hook claude-code ") {
					t.Errorf("%s: entry %q is not one the claude-code matcher owns", ev, h.Command)
				}
			}
		}
	}
	if again := r.Register("claude-code-xcode"); len(again.HooksAdded) != 0 || again.Error != nil {
		t.Errorf("re-run = %+v", again)
	}
	if after := xcodeTree(t, filepath.Join(home, ".claude")); !mapsEqual(nativeBefore, after) {
		t.Error("claude-code-xcode touched ~/.claude")
	}
	un := r.Unregister("claude-code-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(claudeCodeEvents) {
		t.Fatalf("Unregister = %+v", un)
	}
	if _, err := os.Stat(want); !os.IsNotExist(err) {
		t.Errorf("settings.json left after removing every entry: %v", err)
	}
}

// TestXcodeCodexWriter: hooks.json, the config.toml [features] hooks
// switch and the trust records in the Xcode Codex home, every command owned
// by the native codex matcher, ~/.codex untouched, and Unregister removing
// exactly the entries.
func TestXcodeCodexWriter(t *testing.T) {
	home := xcodeFixture(t)
	nativeBefore := xcodeTree(t, filepath.Join(home, ".codex"))
	r := newXcodeRegistry(t, home, "darwin")
	res := r.Register("codex-xcode")
	dir := filepath.Join(home, xcodeHomes["codex-xcode"])
	if res.Error != nil || res.ConfigPath != filepath.Join(dir, codexHooksFile) || len(res.HooksAdded) != len(codexEvents) {
		t.Fatalf("Register = %+v", res)
	}
	cfg, err := readCodexHooks(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	for ev, groups := range cfg.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if !isObserverCodexEntryNative(h.Command) || !IsObserverCodexHookCommand(h.Command) {
					t.Errorf("%s: entry %q is not one the codex matchers own", ev, h.Command)
				}
			}
		}
	}
	toml, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil || !strings.Contains(string(toml), "hooks = true") {
		t.Errorf("config.toml = %q, %v", toml, err)
	}
	if after := xcodeTree(t, filepath.Join(home, ".codex")); !mapsEqual(nativeBefore, after) {
		t.Error("codex-xcode touched ~/.codex")
	}
	un := r.Unregister("codex-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(codexEvents) {
		t.Fatalf("Unregister = %+v", un)
	}
}

// TestXcodeTargetsNeedTheFolder: a machine without the Xcode home, a
// symlinked home, or a non-macOS host gets nothing written and no
// directory created.
func TestXcodeTargetsNeedTheFolder(t *testing.T) {
	for target := range xcodeHomes {
		t.Run(target+" absent", func(t *testing.T) {
			home := t.TempDir()
			before := xcodeTree(t, home)
			r := newXcodeRegistry(t, home, "darwin")
			if containsString(r.installedAll(true), target) {
				t.Errorf("detected %s with no folder", target)
			}
			res := r.Register(target)
			if !res.Skipped || res.SkipKind != SkipNotApplicable {
				t.Errorf("Register = %+v", res)
			}
			if after := xcodeTree(t, home); !mapsEqual(before, after) {
				t.Errorf("tree changed: %v", after)
			}
		})
		t.Run(target+" symlinked", func(t *testing.T) {
			if runtime.GOOS == "windows" {
				t.Skip("symlinks need privileges on Windows")
			}
			home := t.TempDir()
			elsewhere := t.TempDir()
			link := filepath.Join(home, xcodeHomes[target])
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, link); err != nil {
				t.Fatal(err)
			}
			r := newXcodeRegistry(t, home, "darwin")
			if res := r.Register(target); !res.Skipped || res.SkipKind != SkipNotApplicable || !strings.Contains(res.SkipReason, "refused: ") {
				t.Errorf("Register = %+v", res)
			}
			if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
				t.Errorf("wrote through the link: %v", entries)
			}
		})
		t.Run(target+" linux", func(t *testing.T) {
			home := xcodeFixture(t)
			before := xcodeTree(t, home)
			r := newXcodeRegistry(t, home, "linux")
			if containsString(r.installedAll(true), target) {
				t.Errorf("detected %s on linux", target)
			}
			if res := r.Register(target); res.Error != nil || !res.Skipped || res.SkipKind != SkipNotApplicable || !strings.Contains(res.SkipReason, "macOS only") {
				t.Errorf("Register on linux = %+v, want the not-applicable skip", res)
			}
			if after := xcodeTree(t, home); !mapsEqual(before, after) {
				t.Errorf("tree changed on linux")
			}
		})
	}
}

// TestXcodeClaudeFollowsTheCredentialFileRules (audit item 2): the Xcode
// Claude target answers for claude-code's credential-file exception, so an
// existing settings.json with an env block is spliced member by member (its
// other bytes kept), the checksum entry is the hooks-subtree digest, not a
// whole-file hash, and Unregister gives the original bytes back.
func TestXcodeClaudeFollowsTheCredentialFileRules(t *testing.T) {
	if !hooksShareCredentialFile("claude-code-xcode") || !hooksShareCredentialFile("codex-xcode") {
		t.Fatal("an Xcode target does not answer for its base tool's credential-file rule")
	}
	home := xcodeFixture(t)
	settings := filepath.Join(home, xcodeHomes["claude-code-xcode"], "settings.json")
	orig := "{\n    \"env\":   {\"ANTHROPIC_API_KEY\": \"sk-ant-SECRET\"},\n    \"model\": \"opus\"\n}\n"
	if err := os.WriteFile(settings, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newXcodeRegistry(t, home, "darwin")
	res := r.Register("claude-code-xcode")
	if res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	got, _ := os.ReadFile(settings)
	if !bytes.Contains(got, []byte(`"env":   {"ANTHROPIC_API_KEY": "sk-ant-SECRET"}`)) {
		t.Errorf("the env member lost its bytes:\n%s", got)
	}
	raw, err := os.ReadFile(r.opts.ChecksumsPath)
	if err != nil {
		t.Fatal(err)
	}
	var sums map[string]map[string]any
	if err := json.Unmarshal(raw, &sums); err != nil {
		t.Fatal(err)
	}
	entry := sums[settings]
	if entry == nil || entry[hookdigest.KeyScope] != hookdigest.Scope || entry["sha256"] != nil {
		t.Errorf("checksum entry = %v, want the hooks-subtree digest", entry)
	}
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Error("the checksum file carries a value from settings.json")
	}
	if un := r.Unregister("claude-code-xcode"); un.Error != nil {
		t.Fatalf("Unregister = %+v", un)
	}
	if after, _ := os.ReadFile(settings); string(after) != orig {
		t.Errorf("Unregister did not give back the original bytes:\n%s", after)
	}
}

// TestXcodeCodexUnregisterRemovesItsLoneSwitch (audit item 10): a
// config.toml the writer created holding only the hooks switch is removed
// with the entries; one with any other content is kept.
func TestXcodeCodexUnregisterRemovesItsLoneSwitch(t *testing.T) {
	for _, tc := range []struct {
		name, before string
		kept         bool
	}{
		{"created by the writer", "", false},
		{"the user's own config", "model = \"gpt-5\"\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := xcodeFixture(t)
			toml := filepath.Join(home, xcodeHomes["codex-xcode"], "config.toml")
			if tc.before != "" {
				if err := os.WriteFile(toml, []byte(tc.before), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r := newXcodeRegistry(t, home, "darwin")
			if res := r.Register("codex-xcode"); res.Error != nil {
				t.Fatalf("Register = %+v", res)
			}
			if un := r.Unregister("codex-xcode"); un.Error != nil {
				t.Fatalf("Unregister = %+v", un)
			}
			_, err := os.Stat(toml)
			if tc.kept && err != nil {
				t.Errorf("the user's config.toml was removed")
			}
			if !tc.kept && !os.IsNotExist(err) {
				b, _ := os.ReadFile(toml)
				t.Errorf("config.toml left with only the switch:\n%s", b)
			}
		})
	}
	for _, tc := range []struct {
		body string
		want bool
	}{
		{"[features]\nhooks = true\n", true},
		{"[features]\nhooks = true\n\n[hooks.state]\n", true},
		{"# mine\n[features]\nhooks = true\n", false},
		{"[features]\nhooks = true\nweb_search = true\n", false},
		{"", false},
	} {
		if got := onlyObserverCodexSwitch([]byte(tc.body)); got != tc.want {
			t.Errorf("onlyObserverCodexSwitch(%q) = %v", tc.body, got)
		}
	}
}

// xcodeCodexKeys is what Xcode 26.6 writes into codex/config.toml at every
// session start (Mac round 5b, key names only; values are stand-ins):
// top-level keys above every table, its sandbox and MCP tables and a
// project trust row for the cwd it runs Codex in when no project is open.
const xcodeCodexKeys = `cli_auth_credentials_store = "keyring"
developer_instructions = "stand-in"
sandbox_mode = "workspace-write"
approval_policy = "on-request"
web_search = "disabled"
model = "gpt-5.4-mini"

[sandbox_workspace_write]
network_access = false

[mcp_servers.xcode-tools]
command = "xcrun"
args = ["mcpbridge"]

[projects."/Users/u/Library/Autosave Information"]
trust_level = "trusted"

`

// TestXcodeCodexWriterOnAFileXcodeRewrote pins the round 5b facts: Xcode
// rewrites codex/config.toml at every session start, puts its own keys
// above Observer's lines, and keeps [features] hooks = true and the
// [hooks.state] trust records. Register works on a file Xcode wrote first,
// a re-run after an Xcode rewrite changes nothing Xcode wrote and adds
// nothing twice, and Unregister removes exactly Observer's entries and
// trust records and keeps every Xcode key (and the file).
func TestXcodeCodexWriterOnAFileXcodeRewrote(t *testing.T) {
	home := xcodeFixture(t)
	dir := filepath.Join(home, xcodeHomes["codex-xcode"])
	toml := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(toml, []byte(xcodeCodexKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newXcodeRegistry(t, home, "darwin")
	res := r.Register("codex-xcode")
	if res.Error != nil || len(res.HooksAdded) != len(codexEvents) || len(res.TrustRecorded) == 0 {
		t.Fatalf("Register on Xcode's config.toml = %+v", res)
	}
	first, _ := os.ReadFile(toml)
	if !strings.HasPrefix(string(first), xcodeCodexKeys) {
		t.Errorf("Register moved or changed Xcode's keys:\n%s", first)
	}
	if strings.Count(string(first), "hooks = true") != 1 || !strings.Contains(string(first), "[hooks.state") {
		t.Errorf("config.toml lacks one hooks switch and the trust records:\n%s", first)
	}

	// Xcode's next session start: its keys again above everything
	// Observer wrote, which it keeps.
	observerPart := strings.TrimPrefix(string(first), xcodeCodexKeys)
	rewritten := xcodeCodexKeys + observerPart
	if err := os.WriteFile(toml, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	again := r.Register("codex-xcode")
	if again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != len(codexEvents) {
		t.Fatalf("re-run after an Xcode rewrite = %+v", again)
	}
	if after, _ := os.ReadFile(toml); string(after) != rewritten {
		t.Errorf("a re-run changed the file Xcode rewrote:\n%s\nwant\n%s", after, rewritten)
	}

	un := r.Unregister("codex-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(codexEvents) {
		t.Fatalf("Unregister = %+v", un)
	}
	left, err := os.ReadFile(toml)
	if err != nil {
		t.Fatalf("Unregister removed a config.toml holding Xcode's keys: %v", err)
	}
	if !strings.HasPrefix(string(left), xcodeCodexKeys) {
		t.Errorf("Unregister changed Xcode's keys:\n%s", left)
	}
	if strings.Contains(string(left), "hook codex") || strings.Contains(string(left), filepath.Join(dir, codexHooksFile)) {
		t.Errorf("Unregister left an Observer trust record:\n%s", left)
	}
	if cfg, err := readCodexHooks(filepath.Join(dir, codexHooksFile)); err == nil {
		for ev, groups := range cfg.Hooks {
			for _, g := range groups {
				for _, h := range g.Hooks {
					if isObserverCodexEntryNative(h.Command) {
						t.Errorf("%s: Observer entry left in hooks.json: %q", ev, h.Command)
					}
				}
			}
		}
	}
}

// TestXcodeClaudeWriterSplicesAnExistingSettings: a settings.json already in
// the Xcode Claude home (Xcode kept the writer's file byte for byte in round
// 5b; a user or a later Xcode may add one) gets Observer's hooks spliced in
// beside its other members and its own hooks, and Unregister removes only
// Observer's entries.
func TestXcodeClaudeWriterSplicesAnExistingSettings(t *testing.T) {
	home := xcodeFixture(t)
	settings := filepath.Join(home, xcodeHomes["claude-code-xcode"], "settings.json")
	orig := `{
  "permissions": {"allow": ["Bash(ls:*)"]},
  "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/my-hook"}]}]}
}
`
	if err := os.WriteFile(settings, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newXcodeRegistry(t, home, "darwin")
	if res := r.Register("claude-code-xcode"); res.Error != nil || len(res.HooksAdded) != len(claudeCodeEvents) {
		t.Fatalf("Register = %+v", res)
	}
	got, _ := os.ReadFile(settings)
	for _, keep := range []string{`"permissions": {"allow": ["Bash(ls:*)"]}`, "/usr/local/bin/my-hook", " hook claude-code pre-tool "} {
		if !strings.Contains(string(got), keep) {
			t.Errorf("settings.json lacks %q:\n%s", keep, got)
		}
	}
	un := r.Unregister("claude-code-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(claudeCodeEvents) {
		t.Fatalf("Unregister = %+v", un)
	}
	left, _ := os.ReadFile(settings)
	if strings.Contains(string(left), " hook claude-code ") || !strings.Contains(string(left), "/usr/local/bin/my-hook") || !strings.Contains(string(left), "Bash(ls:*)") {
		t.Errorf("after Unregister:\n%s", left)
	}
}

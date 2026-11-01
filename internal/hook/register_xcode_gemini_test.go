package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookdigest"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// xcodeGeminiHome is the Xcode Gemini home under a user home (the catalogued
// darwin path, spelled here only to build the fixture).
var xcodeGeminiHome = filepath.Join("Library", "Developer", "Xcode", "CodingAssistant", "gemini", ".gemini")

// xcodeGeminiSettings is a stand-in for the settings.json Xcode's Gemini
// writes (its real contents are not grounded; fixture values only, the key
// is fake), spaced oddly so a re-render would show.
const xcodeGeminiSettings = "{\n  \"security\":   {\"auth\": {\"selectedType\": \"oauth-personal\"}},\n  \"apiKey\": \"AIza-FIXTURE-SECRET\"\n}\n"

// xcodeGeminiFixture builds a home holding the Xcode Gemini home with the
// files Mac round 5b listed (settings is its settings.json, "" for none),
// plus a ~/.gemini the target must never touch.
func xcodeGeminiFixture(t *testing.T, settings string) string {
	t.Helper()
	home := t.TempDir()
	files := map[string]string{
		filepath.Join(xcodeGeminiHome, "GEMINI.md"):              "# notes",
		filepath.Join(xcodeGeminiHome, "projects.json"):          `{"projects":{}}`,
		filepath.Join(xcodeGeminiHome, "history", "p", "x"):      "h",
		filepath.Join(xcodeGeminiHome, "tmp", "p", "chats", "s"): "c",
		filepath.Join(".gemini", "settings.json"):                `{"model":{"name":"x"}}`,
	}
	if settings != "" {
		files[filepath.Join(xcodeGeminiHome, "settings.json")] = settings
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

// runGatedWriters lets this test run gated writers' real logic.
func runGatedWriters(t *testing.T) {
	t.Helper()
	runLiveGatedHookWriters = true
	t.Cleanup(func() { runLiveGatedHookWriters = false })
}

// geminiCommands lists every hook command in a Gemini settings.json.
func geminiCommands(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc struct {
		Hooks map[string][]claudeHookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, groups := range doc.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				out = append(out, h.Command)
			}
		}
	}
	return out
}

// TestXcodeGeminiTargetWaitsOnLCR91 (FU-160, FU-195): gemini-cli-xcode is
// built and switched off. Its one integration row is the host_hooks gate
// LCR-91, whose run (MAC-6) found no BeforeTool, so the gate now carries
// that finding: Register refuses before reading anything (--force
// included), Installed does not list it, and InstalledLiveGated (what the
// doctor prints) names it with the LCR-91 result where the home exists,
// and only there.
func TestXcodeGeminiTargetWaitsOnLCR91(t *testing.T) {
	const want = "built, not enforceable: live check LCR-91 found that Xcode 26.6's Gemini runs the BeforeAgent hook but not BeforeTool"
	if g := integration.RowlessWriterGates("gemini-cli", integration.WriterKindHostHooks); !strings.HasPrefix(g.Text(), want) {
		t.Fatalf("gemini-cli host_hooks gates = %v (%q)", g, g.Text())
	}
	if id, ok := LiveCheckGate("gemini-cli-xcode"); !ok || id != "LCR-91" {
		t.Fatalf("LiveCheckGate = %q, %v; want LCR-91", id, ok)
	}
	for _, force := range []bool{false, true} {
		home := xcodeGeminiFixture(t, xcodeGeminiSettings)
		before := xcodeTree(t, home)
		r, err := NewRegistry(Options{
			BinaryPath: "/opt/observer/bin/observer", HomeDir: home, GOOS: "darwin", Force: force,
			ChecksumsPath: filepath.Join(t.TempDir(), "hook_checksums.json"),
			Getenv:        func(string) string { return "" },
		})
		if err != nil {
			t.Fatal(err)
		}
		res := r.Register("gemini-cli-xcode")
		if !res.Skipped || res.SkipKind != SkipLiveGated || !strings.Contains(res.SkipReason, want) || strings.Contains(res.SkipReason, "until that check passes") {
			t.Errorf("force=%v Register = %+v, want the LCR-91 finding skip", force, res)
		}
		if after := xcodeTree(t, home); !mapsEqual(before, after) {
			t.Errorf("force=%v: the gated Register changed the tree", force)
		}
		if containsString(r.Installed(), "gemini-cli-xcode") {
			t.Errorf("Installed lists the gated target: %v", r.Installed())
		}
		named := false
		for _, g := range r.InstalledLiveGated() {
			if g.Target == "gemini-cli-xcode" && g.LiveCheck == "LCR-91" && strings.HasPrefix(g.Note(), want) {
				named = true
			}
		}
		if !named {
			t.Errorf("InstalledLiveGated = %+v, want gemini-cli-xcode on LCR-91", r.InstalledLiveGated())
		}
		if u := r.Unregister("gemini-cli-xcode"); u.Error != nil {
			t.Errorf("Unregister (never gated) = %+v", u)
		}
	}
	for _, goos := range []string{"darwin", "linux"} {
		home := t.TempDir()
		if goos == "linux" {
			home = xcodeGeminiFixture(t, xcodeGeminiSettings)
		}
		r := newXcodeRegistry(t, home, goos)
		for _, g := range r.InstalledLiveGated() {
			if g.Target == "gemini-cli-xcode" {
				t.Errorf("%s: InstalledLiveGated names gemini-cli-xcode with no Xcode Gemini home", goos)
			}
		}
	}
}

// TestXcodeGeminiWriter (gate lifted for the test): the native Gemini
// settings writer's entries land in the Xcode Gemini home's settings.json
// only, every command is one isObserverAnyHookEntry owns for gemini-cli,
// Xcode's other members keep their bytes (the D-268 splice the host-owned
// file is under), the checksum entry is the hooks-subtree digest with no
// value from the file, a re-run changes nothing, ~/.gemini is untouched,
// and Unregister gives Xcode's file back byte for byte.
func TestXcodeGeminiWriter(t *testing.T) {
	runGatedWriters(t)
	if !hooksShareCredentialFile("gemini-cli-xcode") {
		t.Fatal("the Xcode Gemini target is not under the credential-file rules")
	}
	if hooksShareCredentialFile("gemini-cli") {
		t.Fatal("the base gemini-cli row changed its credential-file declaration")
	}
	home := xcodeGeminiFixture(t, xcodeGeminiSettings)
	nativeBefore := xcodeTree(t, filepath.Join(home, ".gemini"))
	r := newXcodeRegistry(t, home, "darwin")
	if !containsString(r.installedAll(true), "gemini-cli-xcode") {
		t.Fatalf("installedAll = %v", r.installedAll(true))
	}
	settings := filepath.Join(home, xcodeGeminiHome, "settings.json")
	res := r.Register("gemini-cli-xcode")
	if res.Error != nil || res.Tool != "gemini-cli-xcode" || res.ConfigPath != settings || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	if !containsString(res.HooksAdded, "BeforeAgent") {
		t.Errorf("HooksAdded = %v, want the prompt-submit event", res.HooksAdded)
	}
	got, _ := os.ReadFile(settings)
	for _, keep := range []string{`"security":   {"auth": {"selectedType": "oauth-personal"}}`, `"apiKey": "AIza-FIXTURE-SECRET"`} {
		if !bytes.Contains(got, []byte(keep)) {
			t.Errorf("settings.json lost the bytes of %q:\n%s", keep, got)
		}
	}
	cmds := geminiCommands(t, got)
	if len(cmds) != len(res.HooksAdded) {
		t.Errorf("%d commands for %d events", len(cmds), len(res.HooksAdded))
	}
	for _, c := range cmds {
		if !isObserverAnyHookEntry(c, "gemini-cli") || !strings.Contains(c, " hook gemini-cli ") {
			t.Errorf("entry %q is not one the gemini-cli matcher owns", c)
		}
	}
	raw, err := os.ReadFile(r.opts.ChecksumsPath)
	if err != nil {
		t.Fatal(err)
	}
	var sums map[string]map[string]any
	if err := json.Unmarshal(raw, &sums); err != nil {
		t.Fatal(err)
	}
	if e := sums[settings]; e == nil || e[hookdigest.KeyScope] != hookdigest.Scope || e["sha256"] != nil {
		t.Errorf("checksum entry = %v, want the hooks-subtree digest", sums[settings])
	}
	if bytes.Contains(raw, []byte("SECRET")) {
		t.Error("the checksum file carries a value from settings.json")
	}
	again := r.Register("gemini-cli-xcode")
	if again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != len(res.HooksAdded) {
		t.Errorf("re-run = %+v", again)
	}
	if after, _ := os.ReadFile(settings); !bytes.Equal(after, got) {
		t.Error("a re-run changed settings.json")
	}
	if after := xcodeTree(t, filepath.Join(home, ".gemini")); !mapsEqual(nativeBefore, after) {
		t.Error("gemini-cli-xcode touched ~/.gemini")
	}
	un := r.Unregister("gemini-cli-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(res.HooksAdded) {
		t.Fatalf("Unregister = %+v", un)
	}
	if after, _ := os.ReadFile(settings); string(after) != xcodeGeminiSettings {
		t.Errorf("Unregister did not give back Xcode's bytes:\n%s", after)
	}
}

// TestXcodeGeminiWriterKeepsOtherHooks: a hook already in Xcode's
// settings.json on another event, or on the same event, stays through
// Register and Unregister; only Observer's entries go. Without --force a
// foreign entry on an event Observer writes blocks, as for ~/.gemini.
func TestXcodeGeminiWriterKeepsOtherHooks(t *testing.T) {
	runGatedWriters(t)
	orig := `{
  "hooks": {"AfterAgent": [{"hooks": [{"type": "command", "command": "/usr/local/bin/my-hook"}]}]}
}
`
	home := xcodeGeminiFixture(t, orig)
	settings := filepath.Join(home, xcodeGeminiHome, "settings.json")
	r := newXcodeRegistry(t, home, "darwin")
	res := r.Register("gemini-cli-xcode")
	if res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	mid, _ := os.ReadFile(settings)
	if !strings.Contains(string(mid), "/usr/local/bin/my-hook") || !strings.Contains(string(mid), " hook gemini-cli ") {
		t.Errorf("after Register:\n%s", mid)
	}
	un := r.Unregister("gemini-cli-xcode")
	if un.Error != nil || len(un.HooksRemoved) != len(res.HooksAdded) {
		t.Fatalf("Unregister = %+v", un)
	}
	left, _ := os.ReadFile(settings)
	if strings.Contains(string(left), " hook gemini-cli ") || !strings.Contains(string(left), "/usr/local/bin/my-hook") {
		t.Errorf("after Unregister:\n%s", left)
	}

	clash := `{"hooks": {"BeforeAgent": [{"hooks": [{"type": "command", "command": "/usr/local/bin/mine"}]}]}}`
	home = xcodeGeminiFixture(t, clash)
	r = newXcodeRegistry(t, home, "darwin")
	if res := r.Register("gemini-cli-xcode"); res.Error == nil {
		t.Errorf("a foreign BeforeAgent entry did not block without --force: %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(home, xcodeGeminiHome, "settings.json")); string(b) != clash {
		t.Errorf("the refused Register changed the file:\n%s", b)
	}
}

// TestXcodeGeminiWriterWithNoSettings: an Xcode Gemini home with no
// settings.json gets one holding only Observer's hooks, which Unregister
// removes again.
func TestXcodeGeminiWriterWithNoSettings(t *testing.T) {
	runGatedWriters(t)
	home := xcodeGeminiFixture(t, "")
	settings := filepath.Join(home, xcodeGeminiHome, "settings.json")
	r := newXcodeRegistry(t, home, "darwin")
	if res := r.Register("gemini-cli-xcode"); res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	if un := r.Unregister("gemini-cli-xcode"); un.Error != nil {
		t.Fatalf("Unregister = %+v", un)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		b, _ := os.ReadFile(settings)
		t.Errorf("settings.json left after removing every entry (%v):\n%s", err, b)
	}
}

// TestXcodeGeminiNeedsTheFolder: no Xcode Gemini home, a symlinked one, or a
// non-macOS host gets nothing written and no directory created, with the
// gate lifted.
func TestXcodeGeminiNeedsTheFolder(t *testing.T) {
	runGatedWriters(t)
	t.Run("absent", func(t *testing.T) {
		home := t.TempDir()
		before := xcodeTree(t, home)
		r := newXcodeRegistry(t, home, "darwin")
		if containsString(r.installedAll(true), "gemini-cli-xcode") {
			t.Error("detected with no folder")
		}
		if res := r.Register("gemini-cli-xcode"); !res.Skipped || res.SkipKind != SkipNotApplicable {
			t.Errorf("Register = %+v", res)
		}
		if after := xcodeTree(t, home); !mapsEqual(before, after) {
			t.Errorf("tree changed: %v", after)
		}
	})
	t.Run("symlinked", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks need privileges on Windows")
		}
		home := t.TempDir()
		elsewhere := t.TempDir()
		link := filepath.Join(home, xcodeGeminiHome)
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, link); err != nil {
			t.Fatal(err)
		}
		r := newXcodeRegistry(t, home, "darwin")
		if res := r.Register("gemini-cli-xcode"); !res.Skipped || res.SkipKind != SkipNotApplicable || !strings.Contains(res.SkipReason, "refused: ") {
			t.Errorf("Register = %+v", res)
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
			t.Errorf("wrote through the link: %v", entries)
		}
	})
	t.Run("linux", func(t *testing.T) {
		home := xcodeGeminiFixture(t, xcodeGeminiSettings)
		before := xcodeTree(t, home)
		r := newXcodeRegistry(t, home, "linux")
		if containsString(r.installedAll(true), "gemini-cli-xcode") {
			t.Error("detected on linux")
		}
		if res := r.Register("gemini-cli-xcode"); res.Error != nil || !res.Skipped || res.SkipKind != SkipNotApplicable || !strings.Contains(res.SkipReason, "macOS only") {
			t.Errorf("Register on linux = %+v, want the not-applicable skip", res)
		}
		if after := xcodeTree(t, home); !mapsEqual(before, after) {
			t.Error("tree changed on linux")
		}
	})
}

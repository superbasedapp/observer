package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
)

// codexTrustReport classifies the Observer entries in dir/hooks.json against
// dir/config.toml, keyed by keyPath, the way `observer doctor` does.
func codexTrustReport(t *testing.T, dir, keyPath string) codextrust.Report {
	t.Helper()
	hooksRaw, err := os.ReadFile(filepath.Join(dir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfgRaw, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := codextrust.Classify(codextrust.Input{
		HooksPath: keyPath, HooksJSON: hooksRaw, ConfigTOML: cfgRaw,
		Expected: CodexHookEvents(), Owned: isObserverCodexEntry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func newCodexTrustRegistry(t *testing.T, home string) *Registry {
	t.Helper()
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ConfigPath:    "/etc/observer/config.toml",
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRegisterCodexRecordsTrust is the live check 2026-10-20 fix: Codex
// runs no untrusted hook, so registering Observer's Codex hooks also records
// Codex's trust for exactly those entries. Every Observer event then
// classifies as trusted (the doctor's reading), the operator's other
// config.toml lines keep their bytes and the file its mode, no copy of the
// credential-bearing file is left behind, a re-run changes nothing, and an entry the user
// turned off in /hooks is never re-enabled or trusted.
func TestRegisterCodexRecordsTrust(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(dir, "hooks.json")
	stopKey := hooksPath + ":stop:0:0"
	// A stand-in credential line (not a real key) and a comment that must
	// survive byte for byte, plus the user's "off" for Stop.
	prior := "# my codex config\nmodel = \"gpt-x\"\napi_key = \"sk-placeholder-not-a-key\"\n\n[features]\nhooks = true\n\n[hooks.state." +
		strconv.Quote(stopKey) + "]\nenabled = false\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(prior), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newCodexTrustRegistry(t, home)
	res := r.Register("codex")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	want := slices.DeleteFunc(CodexHookEvents(), func(e string) bool { return e == "Stop" })
	slices.Sort(want)
	if !slices.Equal(res.TrustRecorded, want) {
		t.Errorf("TrustRecorded = %v, want %v (Stop is off in /hooks)", res.TrustRecorded, want)
	}
	if !strings.Contains(res.TrustNote, "Stop (turned off in codex /hooks)") {
		t.Errorf("TrustNote = %q, want it to name the switched-off Stop", res.TrustNote)
	}
	rep := codexTrustReport(t, dir, hooksPath)
	for _, e := range rep.Entries {
		wantState := codextrust.StateTrusted
		if e.Event == "Stop" {
			wantState = codextrust.StateDisabled
		}
		if e.State != wantState {
			t.Errorf("%s: state %s, want %s", e.Event, e.State, wantState)
		}
	}
	if !rep.HashVerified {
		t.Error("the recorded hashes did not verify")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(after), "# my codex config\nmodel = \"gpt-x\"\napi_key = \"sk-placeholder-not-a-key\"\n") {
		t.Errorf("the operator's lines were not kept byte for byte:\n%s", after)
	}
	// config.toml is credential-bearing (D-268): no copy of it is left.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		n := e.Name()
		if n != "hooks.json" && n != "config.toml" && !strings.HasSuffix(n, settingsLockSuffix) {
			t.Errorf(".codex holds %q: no copy of the credential-bearing config.toml may be left", n)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "config.toml")); err != nil || posixModes && fi.Mode().Perm() != 0o600 {
		t.Errorf("config.toml mode = %v, %v; want 0600 kept", fi, err)
	}

	again := r.Register("codex")
	if again.Error != nil || len(again.TrustRecorded) != 0 {
		t.Errorf("second Register = %v recorded %v, want nothing new", again.Error, again.TrustRecorded)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "config.toml")); string(b) != string(after) {
		t.Error("a second registration rewrote an already-trusted config.toml")
	}
}

// TestRegisterCodexTrustNeverCoversUserHooks: a user's own hook in the same
// hooks.json gets no trust record, and unregistering removes only the
// records Observer wrote (a record for the user's hook stays).
func TestRegisterCodexTrustNeverCoversUserHooks(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(dir, "hooks.json")
	userHooks := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"my-own-hook"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(userHooks), 0o600); err != nil {
		t.Fatal(err)
	}
	userKey := hooksPath + ":pre_tool_use:0:0"
	userRecord := "[hooks.state." + strconv.Quote(userKey) + "]\ntrusted_hash = \"sha256:users-own\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(userRecord), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newCodexTrustRegistry(t, home)
	r.opts.Force = true // the user's PreToolUse group is a foreign entry
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	if !strings.Contains(string(cfg), `trusted_hash = "sha256:users-own"`) {
		t.Fatalf("the user's own trust record changed:\n%s", cfg)
	}
	if n := strings.Count(string(cfg), "trusted_hash"); n != len(CodexHookEvents())+1 {
		t.Errorf("%d trusted_hash lines, want one per Observer event plus the user's:\n%s", n, cfg)
	}

	un := r.Unregister("codex")
	if un.Error != nil {
		t.Fatalf("Unregister: %v", un.Error)
	}
	if len(un.TrustRemoved) != len(CodexHookEvents()) {
		t.Errorf("TrustRemoved = %v, want every Observer event", un.TrustRemoved)
	}
	cfg, _ = os.ReadFile(filepath.Join(dir, "config.toml"))
	if n := strings.Count(string(cfg), "trusted_hash"); n != 1 || !strings.Contains(string(cfg), "sha256:users-own") {
		t.Errorf("after Unregister want only the user's record, got:\n%s", cfg)
	}
}

// TestRegisterCodexWindowsTrustKey: the Windows target keys trust with the
// path the Windows Codex itself displays (C:\...), not the /mnt view the
// WSL daemon writes through. Driven through registerCodexAt with the
// target's trustKey pinned, since a test never writes under /mnt/c. A
// target whose Windows spelling is unknown records nothing and says so.
func TestRegisterCodexWindowsTrustKey(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, "win", ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const winHooks = `C:\Users\op\.codex\hooks.json`
	r := newCodexTrustRegistry(t, home)
	target := codexHookTarget{
		tool: "codex-windows", dir: dir, wrapper: "wsl.exe -d Ubuntu-20.04 -- ",
		quote: cmdQuoteIfNeeded, errPrefix: "hook.registerCodexWindows", matchMine: isObserverCodexEntry,
		trustKey: func(string) (string, bool) { return winHooks, true },
	}
	res := r.registerCodexAt(target)
	if res.Error != nil || len(res.TrustRecorded) != len(CodexHookEvents()) {
		t.Fatalf("registerCodexAt = %v recorded %v", res.Error, res.TrustRecorded)
	}
	// Classify compares keys byte for byte (no normalizer), so a trusted
	// reading under winHooks proves the records use the Windows spelling.
	for _, e := range codexTrustReport(t, dir, winHooks).Entries {
		if e.State != codextrust.StateTrusted {
			t.Errorf("%s: %s, want trusted under the Windows key", e.Event, e.State)
		}
	}

	other := t.TempDir()
	target.dir = filepath.Join(other, ".codex")
	target.trustKey = func(string) (string, bool) { return "", false }
	res = r.registerCodexAt(target)
	if res.Error != nil || len(res.TrustRecorded) != 0 || !strings.Contains(res.TrustNote, "unknown") {
		t.Errorf("unknown key spelling: err %v recorded %v note %q, want no trust and a note", res.Error, res.TrustRecorded, res.TrustNote)
	}
}

package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// codexTrustPrior is a config.toml whose [features] flag is already on (so
// registration adds only [hooks.state] records) with comments around the
// place the records land.
const codexTrustPrior = "# my codex config\nmodel = \"gpt-x\"\napi_key = \"sk-placeholder-not-a-key\"\n\n" +
	"# features block\n[features]\nhooks = true # keep this comment\n"

// TestUnregisterCodexRemovesLastTrustRecords is the 2026-10-21 live proof
// fix (lane HOOKPROOF): when Observer's records are the ONLY [hooks.state]
// tables, unregistering removed all 9 hooks but no trust record, because
// deleting the last child of the implicit hooks.state table was refused as
// a re-serialization and the loop aborted before writing anything. Now
// every record goes, and config.toml returns to its exact prior bytes.
func TestUnregisterCodexRemovesLastTrustRecords(t *testing.T) {
	t.Parallel()
	for _, crlf := range []bool{false, true} {
		home := t.TempDir()
		dir := filepath.Join(home, ".codex")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		prior := codexTrustPrior
		if crlf {
			prior = strings.ReplaceAll(prior, "\n", "\r\n")
		}
		cfgPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(cfgPath, []byte(prior), 0o600); err != nil {
			t.Fatal(err)
		}
		r := newCodexTrustRegistry(t, home)
		if res := r.Register("codex"); res.Error != nil || len(res.TrustRecorded) != len(CodexHookEvents()) {
			t.Fatalf("Register: %v recorded %v", res.Error, res.TrustRecorded)
		}
		un := r.Unregister("codex")
		if un.Error != nil {
			t.Fatalf("Unregister: %v", un.Error)
		}
		want := CodexHookEvents()
		slices.Sort(want)
		if !slices.Equal(un.TrustRemoved, want) || len(un.TrustNotRemoved) != 0 || un.TrustNote != "" {
			t.Errorf("crlf=%v: TrustRemoved %v NotRemoved %v note %q, want every event removed", crlf, un.TrustRemoved, un.TrustNotRemoved, un.TrustNote)
		}
		if got, _ := os.ReadFile(cfgPath); string(got) != prior {
			t.Errorf("crlf=%v: config.toml not restored byte for byte:\n got %q\nwant %q", crlf, got, prior)
		}
	}
}

// TestUnregisterCodexWindowsKeysRemoved: the Windows target's records are
// keyed by the C:\ spelling (escaped backslashes in TOML) and are removed
// just as completely.
func TestUnregisterCodexWindowsKeysRemoved(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, "win", ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(codexTrustPrior), 0o600); err != nil {
		t.Fatal(err)
	}
	winHooks := `C:\Users\op\.codex\hooks.json`
	key := func(string) (string, bool) { return winHooks, true }
	r := newCodexTrustRegistry(t, home)
	target := codexHookTarget{
		tool: "codex-windows", dir: dir, wrapper: "wsl.exe -d Ubuntu-20.04 -- ",
		quote: cmdQuoteIfNeeded, errPrefix: "hook.registerCodexWindows", matchMine: isObserverCodexEntry,
		trustKey: key,
	}
	if res := r.registerCodexAt(target); res.Error != nil || len(res.TrustRecorded) != len(CodexHookEvents()) {
		t.Fatalf("registerCodexAt = %v recorded %v", res.Error, res.TrustRecorded)
	}
	if b, _ := os.ReadFile(cfgPath); !strings.Contains(string(b), `"C:\\Users\\op\\.codex\\hooks.json:`) {
		t.Fatalf("records are not keyed by the Windows spelling:\n%s", b)
	}
	un := r.unregisterCodexAt("codex-windows", dir, "hook.unregisterCodexWindows", key)
	if un.Error != nil || len(un.TrustRemoved) != len(CodexHookEvents()) {
		t.Fatalf("unregisterCodexAt = %v removed %v note %q", un.Error, un.TrustRemoved, un.TrustNote)
	}
	if got, _ := os.ReadFile(cfgPath); string(got) != codexTrustPrior {
		t.Errorf("config.toml not restored:\n got %q\nwant %q", got, codexTrustPrior)
	}
}

// TestUnregisterCodexTrustPerRecord: a record that cannot be removed in
// place (here one the user rewrote as an inline table with an extra key) is
// reported by event and kept, and the others are still removed and written.
func TestUnregisterCodexTrustPerRecord(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(codexTrustPrior), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newCodexTrustRegistry(t, home)
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	// Move the Stop record into an inline table under an explicit
	// [hooks.state] header, with a second key so only its trusted_hash
	// (inside the inline table) would be deleted.
	raw, _ := os.ReadFile(cfgPath)
	stopKey := filepath.Join(dir, "hooks.json") + ":stop:0:0"
	doc, err := cfgfmt.Parse(cfgfmt.FormatTOML, raw)
	if err != nil {
		t.Fatal(err)
	}
	hash, found, err := doc.Get(cfgfmt.Path{"hooks", "state", stopKey, "trusted_hash"})
	if err != nil || !found {
		t.Fatalf("no Stop record after Register: %v %v\n%s", found, err, raw)
	}
	header := "\n[hooks.state." + strconv.Quote(stopKey) + "]\ntrusted_hash = " + strconv.Quote(hash.(string)) + "\n"
	if !strings.Contains(string(raw), header) {
		t.Fatalf("Stop record not in the expected shape:\n%s", raw)
	}
	edited := strings.Replace(string(raw), header, "", 1) +
		"\n[hooks.state]\n" + strconv.Quote(stopKey) + " = { trusted_hash = " + strconv.Quote(hash.(string)) + ", enabled = true }\n"
	if err := os.WriteFile(cfgPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	un := r.Unregister("codex")
	if un.Error != nil {
		t.Fatalf("Unregister: %v", un.Error)
	}
	if !slices.Equal(un.TrustNotRemoved, []string{"Stop"}) || !strings.Contains(un.TrustNote, "Stop") {
		t.Errorf("TrustNotRemoved %v note %q, want Stop reported", un.TrustNotRemoved, un.TrustNote)
	}
	if len(un.TrustRemoved) != len(CodexHookEvents())-1 || slices.Contains(un.TrustRemoved, "Stop") {
		t.Errorf("TrustRemoved = %v, want every event but Stop", un.TrustRemoved)
	}
	got, _ := os.ReadFile(cfgPath)
	if n := strings.Count(string(got), "trusted_hash"); n != 1 || !strings.Contains(string(got), "enabled = true }") {
		t.Errorf("want only the inline Stop record left:\n%s", got)
	}
	if !strings.HasPrefix(string(got), codexTrustPrior) {
		t.Errorf("the operator's lines changed:\n%s", got)
	}
}

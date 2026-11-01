package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// dryRunTwin is r's options in DryRun mode (what `observer doctor --hooks`
// and the node tool-gate reader use to ask "registered and current?").
func dryRunTwin(t *testing.T, r *Registry) *Registry {
	t.Helper()
	opts := r.opts
	opts.DryRun = true
	d, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestClineHookCurrencyNeedsExecutable pins review M2-08 for the Cline
// PreToolUse gate file (FU-154): Cline runs the hook file as a program, so
// the right bytes in a file that is not executable are no hook. A real
// registration repairs the gate file's mode.
func TestClineHookCurrencyNeedsExecutable(t *testing.T) {
	if clineHooksUnsupportedOS(runtime.GOOS) {
		t.Skip("the Cline guard is macOS / Linux only")
	}
	r := toolGateRegistry(t, false, ".cline")
	path := filepath.Join(r.opts.HomeDir, ".cline", "hooks", "PreToolUse")
	if res := r.Register("cline-cli"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if res := dryRunTwin(t, r).Register("cline-cli"); len(res.AlreadySet) != 3 || len(res.HooksAdded) != 0 {
		t.Fatalf("a current guard reads %+v, want AlreadySet beforeModel, beforeTool, PreToolUse", res)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := dryRunTwin(t, r).Register("cline-cli"); len(res.HooksAdded) != 1 || res.HooksAdded[0] != "PreToolUse" {
		t.Fatalf("a non-executable gate file reads %+v, want PreToolUse not current", res)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if res := r.Register("cline-cli"); res.Error != nil {
		t.Fatalf("repair = %+v", res)
	}
	if !clineHookExecutable(path) {
		t.Fatal("repair left the gate file not executable")
	}
}

// TestPluginShimCurrencyIsByteExact pins review M2-07: the marker substring
// only says a shim is Observer's; currency is the exact bytes Observer
// renders today, in dry-run and in a real run alike.
func TestPluginShimCurrencyIsByteExact(t *testing.T) {
	home := t.TempDir()
	r := pluginShimRegistry(t, home, false, nil)
	res := r.Register("opencode")
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	data, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := dryRunTwin(t, r).Register("opencode"); got.Error != nil || len(got.HooksAdded) != 0 || len(got.AlreadySet) == 0 {
		t.Fatalf("a current shim reads %+v, want AlreadySet only", got)
	}
	// Same marker, an older binary path: Observer's file, not today's shim.
	stale := bytes.Replace(data, []byte(`"bin":"/opt/observer/bin/observer"`), []byte(`"bin":"/opt/observer-old/bin/observer"`), 1)
	if bytes.Equal(stale, data) {
		t.Fatal("test setup: the bin field was not found in the shim")
	}
	if err := os.WriteFile(res.ConfigPath, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	got := dryRunTwin(t, r).Register("opencode")
	if got.Error != nil || len(got.AlreadySet) != 0 || len(got.HooksAdded) == 0 {
		t.Fatalf("a stale shim with the marker reads %+v, want it NOT current (HooksAdded)", got)
	}
	// A real run repairs it and reports the events as added, not already set.
	if fix := r.Register("opencode"); fix.Error != nil || len(fix.AlreadySet) != 0 || len(fix.HooksAdded) == 0 {
		t.Fatalf("repair = %+v", fix)
	}
	if now, _ := os.ReadFile(res.ConfigPath); !bytes.Equal(now, data) {
		t.Fatal("repair did not restore today's shim bytes")
	}
}

// TestSkipKindSplit pins review M2-05: a skip that means "nothing can be
// registered here" is never "covered elsewhere", and a skip with no kind is
// read the fail-closed way.
func TestSkipKindSplit(t *testing.T) {
	home := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		SkipEvent:     func(string, string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	res := r.Register("opencode")
	if !res.Skipped || res.SkipKind != SkipNotApplicable || res.CoveredElsewhere() {
		t.Fatalf("every event owing a live test = %+v, want a not-applicable skip", res)
	}
	if (RegistrationResult{Skipped: true}).CoveredElsewhere() {
		t.Error("a skip with no kind read as covered")
	}
	if !(RegistrationResult{Skipped: true, SkipKind: SkipCovered}).CoveredElsewhere() {
		t.Error("a covered skip did not read as covered")
	}
	if !strings.Contains(res.SkipReason, "live test") {
		t.Errorf("reason = %q", res.SkipReason)
	}
}

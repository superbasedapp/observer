//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestParseSandboxCLI: only a launcher verb's own --observer-sandbox (before
// "--") makes a sandboxed launch; the flag is stripped and everything else
// reaches the inner launch. A tool's own --sandbox flag (codex, cursor,
// open-interpreter, gemini and others have one) is never Observer's: it
// passes through untouched, before or after "--" (plans decision log P-017).
func TestParseSandboxCLI(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		ok      bool
		wantErr bool
		profile string
		rest    []string
	}{
		{"not a launcher", []string{"observer", "status", "--observer-sandbox", "bwrap"}, false, false, "", nil},
		{"no flag", []string{"observer", "claude", "--model", "opus"}, false, false, "", nil},
		{"spaced", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--model", "opus"}, true, false, "bwrap", []string{"--model", "opus"}},
		{"equals", []string{"observer", "claude", "--observer-sandbox=auto"}, true, false, "auto", nil},
		{"tool's own flag after --", []string{"observer", "claude", "--", "--observer-sandbox", "x"}, false, false, "", nil},
		{"missing profile", []string{"observer", "claude", "--observer-sandbox"}, true, true, "", nil},
		{"flag-shaped profile", []string{"observer", "claude", "--observer-sandbox", "--model"}, true, true, "", nil},
		{"codex's own --sandbox", []string{"observer", "codex", "--sandbox", "read-only"}, false, false, "", nil},
		{"codex's own --sandbox=", []string{"observer", "codex", "--sandbox=workspace-write"}, false, false, "", nil},
		{"cursor's own --sandbox", []string{"observer", "cursor", "--sandbox", "enabled"}, false, false, "", nil},
		{"bare --sandbox is the tool's", []string{"observer", "claude", "--sandbox"}, false, false, "", nil},
	} {
		got, ok, err := parseSandboxCLI(tc.args)
		if ok != tc.ok || (err != nil) != tc.wantErr {
			t.Errorf("%s: ok %v err %v", tc.name, ok, err)
			continue
		}
		if !ok || err != nil {
			continue
		}
		if got.Profile != tc.profile || !reflect.DeepEqual(got.Rest, tc.rest) || got.Tool != "claude-code" {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

// TestSandboxCLIRefusals: an unknown profile, a run already inside a
// sandbox, and an inactive module each refuse with one line; nothing runs.
func TestSandboxCLIRefusals(t *testing.T) {
	if _, err := sandboxCLIBackend("vmx"); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
	// "auto" names what automatic selection may take on this host (bwrap
	// on Linux, "mxc-process" on Windows, for the refusal's headline); it
	// never forces that row, so a beta row is still never chosen
	// automatically (TestAutoNeverChoosesTheBetaWindowsRow).
	if b, err := sandboxCLIBackend("auto"); err != nil || b != sandboxCLIAutoName(sandboxHostKind()) {
		t.Fatalf("auto: %q %v", b, err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "o.db"))+"\"\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[components]\ndistro = \"developer\"\n")
	var stderr bytes.Buffer
	req := sandboxCLIRequest{Verb: "claude", Tool: "claude-code", Profile: "bwrap", ConfigPath: cfgPath}
	if code := runSandboxCLI(context.Background(), req, &stderr); code != sandboxCLIUnavailable || !strings.Contains(stderr.String(), "not active") {
		t.Fatalf("inactive module: code %d %q", code, stderr.String())
	}
	// Module active, sandboxed terminals off: refused with the switch named.
	write("[components]\ndistro = \"developer\"\nadd = [\"terminals.sandbox\"]\n")
	stderr.Reset()
	if code := runSandboxCLI(context.Background(), req, &stderr); code != sandboxCLIUnavailable || !strings.Contains(stderr.String(), "enabled is false") {
		t.Fatalf("switch off: code %d %q", code, stderr.String())
	}
	old := cliSandboxedEnv
	cliSandboxedEnv = func() bool { return true }
	defer func() { cliSandboxedEnv = old }()
	stderr.Reset()
	if code := runSandboxCLI(context.Background(), req, &stderr); code != sandboxCLIUnavailable || !strings.Contains(stderr.String(), "already inside") {
		t.Fatalf("nested: code %d %q", code, stderr.String())
	}
}

// TestSandboxCLIRefusalNamesTheRequestedRow (Windows 11 Pro live run, B1):
// a launch that names a row is refused with that row and its own reason in
// the headline, before the whole list; every Windows row is a case, and
// auto keeps naming the backend the probe's reason belongs to.
func TestSandboxCLIRefusalNamesTheRequestedRow(t *testing.T) {
	av := dashapi.SandboxAvailability{
		Backend: "hcs", Verdict: "image_missing",
		Reason: "no sandbox backend is available on windows: hcs (image_missing): no utility VM image; mxc-appcontainer (psec_unavailable): base-container tier only; mxc-process (available, not chosen automatically); wslc (backend_missing): WSL is not installed",
		Backends: []dashapi.SandboxBackendAvail{
			{ID: "hcs", Verdict: "image_missing", Reason: "no utility VM image"},
			{ID: "mxc-appcontainer", Verdict: "psec_unavailable", Reason: "base-container tier only"},
			{ID: "mxc-process", Available: true},
			{ID: "wslc", Verdict: "backend_missing", Reason: "WSL is not installed"},
		},
	}
	cases := []struct {
		requested string
		named     bool
		head      string
	}{
		{"hcs", true, "hcs is not available here: no sandbox backend is available on windows: hcs (image_missing)"},
		{"mxc-appcontainer", true, "mxc-appcontainer is not available here (psec_unavailable): base-container tier only. no sandbox backend"},
		{"wslc", true, "wslc is not available here (backend_missing): WSL is not installed. no sandbox backend"},
		{"mxc-process", true, "mxc-process is not available here: it is available, but the launch could not use it. no sandbox backend"},
		{"not-a-row", true, "hcs is not available here: no sandbox backend"},
		{"hcs", false, "hcs is not available here: no sandbox backend"},
		{"auto-name", false, "hcs is not available here: no sandbox backend"},
	}
	for _, c := range cases {
		got := sandboxCLIRefusal(c.requested, c.named, av)
		if !strings.HasPrefix(got, c.head) {
			t.Errorf("%s (named=%v): headline %q, want it to start %q", c.requested, c.named, got, c.head)
		}
		if !strings.Contains(got, "wslc (backend_missing): WSL is not installed") {
			t.Errorf("%s: the list of every row is gone: %q", c.requested, got)
		}
	}
}

// TestSandboxCLIAutoRefusalNamesItsBackend (P-111): with only process_lite
// listed, the legacy bwrap answer gives way to process_lite's own verdict,
// and the CLI refusal names process_lite, the backend the reason belongs
// to, not the auto name.
func TestSandboxCLIAutoRefusalNamesItsBackend(t *testing.T) {
	rows := map[string]dashapi.SandboxBackendAvail{
		sandboxbackend.BackendProcessLite: {ID: sandboxbackend.BackendProcessLite, Verdict: sandbox.VerdictBackendMissing, Reason: "Landlock is not available on this kernel"},
	}
	legacy := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: sandboxbackend.BackendBwrap}
	av := legacyWithinEnabled(legacy, []string{sandboxbackend.BackendProcessLite}, rows)
	if av.Available {
		t.Fatal("process_lite unavailable must refuse")
	}
	if got := sandboxCLIProbedBackend(sandboxbackend.BackendBwrap, av.Backend); got != sandboxbackend.BackendProcessLite {
		t.Fatalf("refusal names %q, want %q (the reason is %q)", got, sandboxbackend.BackendProcessLite, av.Reason)
	}
	if got := sandboxCLIProbedBackend("bwrap", ""); got != "bwrap" {
		t.Fatalf("an answer naming no backend keeps the CLI's choice, got %q", got)
	}
}

// TestAutoNeverChoosesTheBetaWindowsRow: on Windows the launch walk of an
// automatic choice drops mxc-process (beta, ruling P-062) even when it is
// the only enabled and available row, and keeps it for a launch that names
// it (Windows 11 Pro rerun 2026-10-25: TestSandboxCLIRefusals expected the
// Linux auto name; selection itself was not at fault).
func TestAutoNeverChoosesTheBetaWindowsRow(t *testing.T) {
	rows := map[string]dashapi.SandboxBackendAvail{
		sandboxbackend.BackendMXCProcess: {ID: sandboxbackend.BackendMXCProcess, Available: true, Verification: string(vocab.VerifiedDoc)},
	}
	enabled := []string{sandboxbackend.BackendMXCProcess}
	all := func(string) bool { return true }
	if p := sandboxLaunchPick(enabled, rows, true, all); p.chosen != "" || p.skipped == nil || p.drop.Verdict != sandboxselect.VerdictBetaNotChosen {
		t.Fatalf("auto: chosen %q skipped %v drop %+v", p.chosen, p.skipped, p.drop)
	}
	if p := sandboxLaunchPick(enabled, rows, false, all); p.chosen != sandboxbackend.BackendMXCProcess {
		t.Fatalf("named: chosen %q", p.chosen)
	}
	if got := sandboxCLIAutoName(sandboxbackend.HostWindows); got != sandboxbackend.BackendMXCProcess {
		t.Fatalf("the Windows auto name = %q", got)
	}
}

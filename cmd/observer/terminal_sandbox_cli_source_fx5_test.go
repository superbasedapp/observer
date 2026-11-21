//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_cli_source_fx5_test.go pins fold audit M2 (lane FX5):
// a sandboxed CLI launch with no source flag used to send "live" to
// agentlaunch and then prepare the row's own default (clone-local for the
// org-hosted row). The source is now resolved before validation, so the
// source validated is the source launched, on both paths that reach
// runSandboxCLI: `observer <tool> --observer-sandbox <row>` and
// `observer sandbox org-shell resume <run>`.

// fx5SourceCase is one row of the M2 table: a profile, the probe's source
// availability, and either the source the launch must prepare or the
// refusal it must print.
type fx5SourceCase struct {
	name, profile, flag string
	// cloneLocalOff makes the probe refuse clone-local, so a launch that
	// validates clone-local is refused while one that validated live
	// would still pass (the pre-fix behaviour).
	cloneLocalOff bool
	want          workspace.Source
	refusal       string
}

var fx5SourceCases = []fx5SourceCase{
	{name: "a local row keeps live", profile: sandboxbackend.BackendBwrap, want: workspace.SourceLive},
	{name: "the org row validates and launches clone-local", profile: sandboxbackend.BackendOpenShellOrg, want: workspace.SourceCloneLocal},
	{name: "the org row refuses when clone-local is not available", profile: sandboxbackend.BackendOpenShellOrg, cloneLocalOff: true, refusal: "workspace source clone-local is not available"},
	{name: "the flag is validated and launched as given", profile: sandboxbackend.BackendOpenShellOrg, flag: "live", want: workspace.SourceLive},
}

// fx5SourceProbe is the live probe with the org row offered, and
// clone-local refused when off is set.
func fx5SourceProbe(off bool) dashapi.SandboxAvailability {
	p := liveProbe()
	p.Backend = sandboxbackend.BackendBwrap
	p.Backends = append(p.Backends, dashapi.SandboxBackendAvail{ID: sandboxbackend.BackendOpenShellOrg, Maturity: "preview", Available: true, Verification: "doc", Beta: true})
	if off {
		p.Sources = []dashapi.SandboxSourceAvail{{ID: "live", Available: true}, {ID: "clone-local", Reason: "fixture: clone-local is off"}}
	}
	return p
}

// fx5SourceConfig writes a config with sandboxed terminals on and returns
// its directory and path.
func fx5SourceConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".observer", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "o.db")) + "\"\n" +
		"[components]\ndistro = \"developer\"\nadd = [\"terminals.sandbox\"]\n[terminal.sandbox]\nenabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

// fx5RunSourceCases drives every case through run, with only the probe,
// the launch directory and the launch step injected, and checks the source
// the launch step received (or the refusal).
func fx5RunSourceCases(t *testing.T, run func(t *testing.T, tc fx5SourceCase, cfgPath string, stderr *bytes.Buffer) int) {
	oldProbe, oldStart, oldDir := sandboxCLIProbe, sandboxCLIStart, cliLaunchDir
	t.Cleanup(func() { sandboxCLIProbe, sandboxCLIStart, cliLaunchDir = oldProbe, oldStart, oldDir })
	for _, tc := range fx5SourceCases {
		t.Run(tc.name, func(t *testing.T) {
			dir, cfgPath := fx5SourceConfig(t)
			project := filepath.Join(dir, "proj")
			if err := os.Mkdir(project, 0o700); err != nil {
				t.Fatal(err)
			}
			cliLaunchDir = func() (string, error) { return project, nil }
			probe := fx5SourceProbe(tc.cloneLocalOff)
			sandboxCLIProbe = func(context.Context, *sandboxRuntime) dashapi.SandboxAvailability { return probe }
			var launched *sandboxCLILaunch
			sandboxCLIStart = func(_ context.Context, l sandboxCLILaunch) int {
				launched = &l
				return 0
			}
			var stderr bytes.Buffer
			code := run(t, tc, cfgPath, &stderr)
			if tc.refusal != "" {
				if launched != nil || code == 0 || !strings.Contains(stderr.String(), tc.refusal) {
					t.Fatalf("want refusal %q; exit %d launched %v stderr %q", tc.refusal, code, launched != nil, stderr.String())
				}
				return
			}
			if code != 0 || launched == nil {
				t.Fatalf("exit %d, launched %v (stderr %q)", code, launched != nil, stderr.String())
			}
			if launched.source != tc.want {
				t.Fatalf("launched with source %q, want %q", launched.source, tc.want)
			}
			if launched.backend != tc.profile {
				t.Fatalf("launched on %q, want %q", launched.backend, tc.profile)
			}
			if (launched.sourceNote != "") != (tc.flag == "" && tc.want != workspace.SourceLive) {
				t.Fatalf("source note %q for source %q (flag %q)", launched.sourceNote, tc.want, tc.flag)
			}
		})
	}
}

// TestSandboxCLIValidatesTheSourceItLaunches is the foreground path,
// `observer <tool> --observer-sandbox <row>`.
func TestSandboxCLIValidatesTheSourceItLaunches(t *testing.T) {
	fx5RunSourceCases(t, func(_ *testing.T, tc fx5SourceCase, cfgPath string, stderr *bytes.Buffer) int {
		return runSandboxCLI(context.Background(), sandboxCLIRequest{Verb: "claude", Tool: "claude-code", Profile: tc.profile, Source: tc.flag, ConfigPath: cfgPath}, stderr)
	})
}

// TestOrgShellResumeValidatesTheSourceItLaunches is the resume path,
// `observer sandbox org-shell resume <run>`, which names no source flag:
// only its org-row cases apply, read through the user-global config.
func TestOrgShellResumeValidatesTheSourceItLaunches(t *testing.T) {
	fx5RunSourceCases(t, func(t *testing.T, tc fx5SourceCase, cfgPath string, stderr *bytes.Buffer) int {
		if tc.profile != sandboxbackend.BackendOpenShellOrg || tc.flag != "" {
			t.Skip("resume always launches the org row with no source flag")
		}
		home := filepath.Dir(filepath.Dir(cfgPath))
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		cmd := newOrgShellResumeCmd()
		cmd.SetArgs([]string{"run-fx5"})
		cmd.SetOut(stderr)
		cmd.SetErr(stderr)
		cmd.SilenceUsage = true
		if err := cmd.ExecuteContext(context.Background()); err != nil {
			stderr.WriteString(err.Error())
			return 1
		}
		return 0
	})
}

// TestSandboxCLISourceKept is sandboxCLISourceKept's rule, one case per
// row: a flag or an unchanged row keeps the validated source; a different
// chosen row keeps it only when its own default is that source.
func TestSandboxCLISourceKept(t *testing.T) {
	for _, tc := range []struct {
		name, flag, requested, chosen string
		validated                     workspace.Source
		ok                            bool
	}{
		{"a flag is never second-guessed", "live", sandboxbackend.BackendBwrap, sandboxbackend.BackendOpenShellOrg, workspace.SourceLive, true},
		{"the requested row is the chosen row", "", sandboxbackend.BackendOpenShellOrg, sandboxbackend.BackendOpenShellOrg, workspace.SourceCloneLocal, true},
		{"auto chose a row with the same default", "", "bwrap or seatbelt", sandboxbackend.BackendBwrap, workspace.SourceLive, true},
		{"auto chose a row whose default differs", "", sandboxbackend.BackendBwrap, sandboxbackend.BackendOpenShellOrg, workspace.SourceLive, false},
		// Fix round 1 (audit FX5-A5): a chosen row with no flag-free source
		// (its only delivery clones a remote) fails closed.
		{"auto chose a row with no flag-free source", "", sandboxbackend.BackendBwrap, "fx5-remote-clone-only", workspace.SourceLive, false},
	} {
		deliveries := func(id string) []string {
			if id == "fx5-remote-clone-only" {
				return []string{"remote_clone"}
			}
			return sandboxCLIRowDeliveries(id)
		}
		err := sandboxCLISourceKept(tc.flag, tc.validated, tc.requested, tc.chosen, deliveries)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "--observer-sandbox-source") {
			t.Errorf("%s: the refusal does not name the flag: %v", tc.name, err)
		}
	}
}

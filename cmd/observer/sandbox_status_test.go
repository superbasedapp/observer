//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// TestSandboxDoctorCoversEveryOfferedBackend is mutation proof 3: every
// offered registry row gets a `sandbox.<id>` doctor check while the module
// is active, so dropping the check for a row fails here.
func TestSandboxDoctorCoversEveryOfferedBackend(t *testing.T) {
	cfg := config.Default()
	cfg.Terminal.Sandbox.Enabled = true
	selectIfInactive(t, &cfg, sandboxComponent) // the module's doctor, in every edition
	checks := sandboxDoctorChecks(t.Context(), cfg)
	names := map[string]bool{}
	for _, c := range checks {
		names[c.Name] = true
	}
	for _, row := range sandboxbackend.Offered() {
		// A row that never runs on this host is not a doctor check (lane
		// SBX-P5: the macOS rows on Linux); one that does must have one.
		if !row.RunsOn(sandboxHostKind()) {
			if names["sandbox."+row.ID] {
				t.Errorf("doctor checks %s, which never runs on this host", row.ID)
			}
			continue
		}
		if !names["sandbox."+row.ID] {
			t.Errorf("no doctor check for offered backend %s (checks %v)", row.ID, names)
		}
	}
}

func TestSandboxDoctorIsOneLineWhenInactive(t *testing.T) {
	cfg := config.Default()
	cfg.Components = config.ComponentsConfig{Distro: "developer"}
	checks := sandboxDoctorChecks(t.Context(), cfg)
	if len(checks) != 1 || checks[0].Name != "sandbox" || !strings.Contains(checks[0].Message, "not active") {
		t.Fatalf("inactive module: %+v", checks)
	}
}

func TestSandboxDoctorCheckRendering(t *testing.T) {
	st := sandboxStatusReport{Enabled: true, Egress: "internet"}
	ok := sandboxDoctorCheck(st, dashapi.SandboxBackendAvail{ID: "bwrap", Label: "Bubblewrap", Class: "process", Available: true, Beta: true, CaptureByTier: map[string]string{"internet": "full (gateway-guarded)"}})
	if ok.Status != diag.StatusOK || !strings.Contains(ok.Message, "full (gateway-guarded)") || len(ok.Details) != 1 || !strings.Contains(ok.Details[0], "beta") {
		t.Errorf("available beta: %+v", ok)
	}
	bad := sandboxDoctorCheck(st, dashapi.SandboxBackendAvail{ID: "bwrap", Label: "Bubblewrap", Verdict: "userns_denied", Rule: "S4", Reason: "user namespaces are off"})
	if bad.Status != diag.StatusWarn || !strings.Contains(bad.Message, "user namespaces are off") {
		t.Errorf("unavailable: %+v", bad)
	}
	st.Enabled = false
	off := sandboxDoctorCheck(st, dashapi.SandboxBackendAvail{ID: "bwrap", Label: "Bubblewrap", Verdict: "disabled_by_config", Rule: "S2"})
	if off.Status != diag.StatusOK || !strings.Contains(off.Message, "enabled = false") {
		t.Errorf("off: %+v", off)
	}
}

func TestRenderSandboxStatus(t *testing.T) {
	st := sandboxStatusReport{Enabled: true, Egress: "internet", Host: "linux", Backends: []dashapi.SandboxBackendAvail{
		{ID: "bwrap", Class: "process", Location: "local", Maturity: "shipped", Available: true, CaptureByTier: map[string]string{"internet": "full (gateway-guarded)", "host": "proxy_and_transcripts"}},
		{ID: "oci-runc", Class: "container", Location: "local", Maturity: "planned", Phase: "P3", Verdict: "not_in_build"},
	}}
	var buf bytes.Buffer
	if err := renderSandboxStatus(&buf, st); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Sandboxes and VMs on linux: on, network tier internet", "bwrap", "available", "full (gateway-guarded)", "planned (P3)", "host proxy_and_transcripts"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// TestRenderSandboxStatusPrintsTheVerdict (live check macOS 2026-10-22,
// D1): the text output names the overall verdict and its reason, not only
// --json.
func TestRenderSandboxStatusPrintsTheVerdict(t *testing.T) {
	var buf bytes.Buffer
	st := sandboxStatusReport{
		Enabled: true, Egress: "internet", Host: "macos", Verdict: "unsupported_platform",
		Reason: `sandboxing requires a Linux daemon (incl. WSL2); this daemon runs "darwin"`,
	}
	if err := renderSandboxStatus(&buf, st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Overall: unsupported_platform: sandboxing requires a Linux daemon") {
		t.Fatalf("no overall verdict in the text output:\n%s", buf.String())
	}
	buf.Reset()
	st.Verdict, st.Reason = "available", ""
	if err := renderSandboxStatus(&buf, st); err != nil || !strings.Contains(buf.String(), "Overall: available") {
		t.Fatalf("%v\n%s", err, buf.String())
	}
}

// TestSandboxStatusSaysTheRuntimeHint (Linux live check 2026-10-23): a
// driver's note about a known runtime issue reaches the backend list, the
// status text and the doctor check, without making the row unavailable.
func TestSandboxStatusSaysTheRuntimeHint(t *testing.T) {
	hint := "a known issue of this engine that does not make the row unavailable"
	b := dashapi.SandboxBackendAvail{ID: "oci-runc", Label: "OCI (runc)", Class: "container", Location: "local", Maturity: "preview", Available: true, Beta: true, Hint: hint}
	st := sandboxStatusReport{Enabled: true, Egress: "internet", Host: "linux", Backends: []dashapi.SandboxBackendAvail{b}}
	var buf bytes.Buffer
	if err := renderSandboxStatus(&buf, st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "oci-runc: note: "+hint) {
		t.Fatalf("status:\n%s", buf.String())
	}
	c := sandboxDoctorCheck(st, b)
	if c.Status != diag.StatusOK || !strings.Contains(strings.Join(c.Details, "\n"), "note: "+hint) {
		t.Fatalf("doctor %+v", c)
	}
	cfg := config.Default()
	list := sandboxBackendListWith(cfg.Terminal.Sandbox, sandbox.Availability{}, nil, "internet", map[string]sandboxselect.Probe{"oci-runc": {Compiled: true, Verdict: "available", Hint: hint}})
	for _, e := range list {
		if e.ID == "oci-runc" && e.Hint != hint {
			t.Fatalf("the backend list dropped the driver's hint: %+v", e)
		}
	}
}

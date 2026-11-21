//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSandboxBackendList: the probe's per-backend list carries every
// registry row; bwrap follows the shipped probe through the selection
// table, and every planned row is unavailable with its phase.
func TestSandboxBackendList(t *testing.T) {
	cfg := config.TerminalSandboxConfig{Enabled: true}
	ok := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: "bwrap", BackendVersion: "0.9.0"}
	list := sandboxBackendList(cfg, ok, []string{"live"}, vocab.TierInternet)
	if len(list) != len(sandboxbackend.IDs()) {
		t.Fatalf("%d rows, want %d", len(list), len(sandboxbackend.IDs()))
	}
	for _, e := range list {
		if e.Component != sandboxComponent {
			t.Errorf("%s: component %q", e.ID, e.Component)
		}
		row, _ := sandboxbackend.Get(e.ID)
		if !row.Offered() && (e.Available || e.Verdict != sandboxselect.VerdictNotInBuild) {
			t.Errorf("planned row %s offered: %+v", e.ID, e)
		}
		if e.ID != sandboxbackend.BackendBwrap {
			continue
		}
		wantAvail := sandboxHostKind() == sandboxbackend.HostLinux || sandboxHostKind() == sandboxbackend.HostWSL2
		if e.Available != wantAvail {
			t.Errorf("bwrap available %v on %s: %+v", e.Available, sandboxHostKind(), e)
		}
		if e.CaptureByTier["internet"] != "full (gateway-guarded)" || e.CaptureByTier["host"] != "proxy_and_transcripts" {
			t.Errorf("capture by tier %v", e.CaptureByTier)
		}
	}
	// A failing probe passes its own verdict through S4.
	bad := sandbox.Availability{Verdict: sandbox.VerdictUserNSDenied, Reason: "userns off", BackendVersion: "0.9.0"}
	for _, e := range sandboxBackendList(cfg, bad, nil, vocab.TierInternet) {
		if e.ID == sandboxbackend.BackendBwrap && sandboxHostKind() != sandboxbackend.HostMacOS && sandboxHostKind() != sandboxbackend.HostWindows {
			if e.Available || e.Verdict != sandbox.VerdictUserNSDenied || e.Reason != "userns off" {
				t.Errorf("bwrap with a failing probe: %+v", e)
			}
		}
	}
}

// TestSandboxRunCaptureTurnsTheBlockOn: a proxy-routed tool on the
// internet tier gets the provider-host block; a tool that is not
// proxy-routed (its direct calls are its normal path, rule C3) and the
// tiers with no gateway do not.
func TestSandboxRunCaptureTurnsTheBlockOn(t *testing.T) {
	for _, tc := range []struct {
		routed bool
		tier   vocab.Tier
		block  bool
		level  vocab.CaptureLevel
	}{
		{true, vocab.TierInternet, true, vocab.CaptureFull},
		{false, vocab.TierInternet, false, vocab.CaptureTranscriptsOnly},
		{true, vocab.TierProxyOnly, false, vocab.CaptureFull},
		{true, vocab.TierNone, false, vocab.CaptureFull},
		{true, vocab.TierHost, false, vocab.CaptureProxyAndTranscripts},
	} {
		got := sandboxRunCapture(tc.routed, tc.tier, "")
		if got.ProviderBlock != tc.block || got.Level != tc.level {
			t.Errorf("routed %v tier %s: %+v", tc.routed, tc.tier, got)
		}
	}
}

// TestSandboxRunCaptureProviderDirect pins the DEC-9 plumbing (OBS-8a): the
// posture in force reaches the run's capture, so allow turns the one
// provider-host block off and lowers the label, refuse_all turns it on for
// an unrouted internet run too, and the config resolver feeds it (an
// unresolved config reads capture_rule).
func TestSandboxRunCaptureProviderDirect(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inForce string
		routed  bool
		block   bool
		level   vocab.CaptureLevel
	}{
		{"unresolved reads capture_rule", "", true, true, vocab.CaptureFull},
		{"capture_rule", "capture_rule", true, true, vocab.CaptureFull},
		{"allow", "allow", true, false, vocab.CaptureProxyAndTranscripts},
		{"refuse_all on an unrouted tool", "refuse_all", false, true, vocab.CaptureTranscriptsOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default().Terminal.Sandbox
			cfg.ProviderDirectInForce = tc.inForce
			got := sandboxRunCapture(tc.routed, vocab.TierInternet, cfg.EffectiveProviderDirect())
			if got.ProviderBlock != tc.block || got.Level != tc.level {
				t.Fatalf("got %+v", got)
			}
		})
	}
	// A local value alone never reaches a launch (the local file is not read).
	cfg := config.Default().Terminal.Sandbox
	cfg.ProviderDirect = "allow"
	if got := sandboxRunCapture(true, vocab.TierInternet, cfg.EffectiveProviderDirect()); !got.ProviderBlock {
		t.Fatalf("a local provider_direct turned the block off: %+v", got)
	}
}

func TestProxyUpstreamHosts(t *testing.T) {
	got := proxyUpstreamHosts(config.ProxyConfig{
		Upstreams:      map[string]string{"or": "https://OpenRouter.ai/api/v1", "local": "http://127.0.0.1:11434", "lh": "http://localhost:1", "bad": "::"},
		AgentUpstreams: map[string]string{"zen": "https://opencode.ai/zen", "dup": "https://openrouter.ai"},
	})
	if strings.Join(got, ",") != "opencode.ai,openrouter.ai" {
		t.Fatalf("hosts = %v", got)
	}
}

// TestReconcileLegacyProbe pins audit finding P-006 (6): a bwrap below the
// registry's required minimum is refused in backends[] (S2b,
// backend_version_untested) and the legacy top-level fields say the same.
func TestReconcileLegacyProbe(t *testing.T) {
	if h := sandboxHostKind(); h != sandboxbackend.HostLinux && h != sandboxbackend.HostWSL2 {
		t.Skip("bwrap is offered only on Linux and WSL2")
	}
	cfg := config.TerminalSandboxConfig{Enabled: true}
	old := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: "bwrap", BackendVersion: "0.3.3"}
	list := sandboxBackendList(cfg, old, []string{"live"}, vocab.TierInternet)
	got := reconcileLegacyProbe(old, list)
	if got.Available || got.Verdict != sandboxselect.VerdictBackendVersionUntested || got.Reason == "" {
		t.Fatalf("legacy probe for an old bwrap: %+v", got)
	}
	ok := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: "bwrap", BackendVersion: "0.9.0"}
	if got := reconcileLegacyProbe(ok, sandboxBackendList(cfg, ok, []string{"live"}, vocab.TierInternet)); !got.Available {
		t.Fatalf("a supported bwrap lost its availability: %+v", got)
	}
}

// TestSandboxCapabilityFrom: the capability is the available backends only,
// the strongest class among them, full capture on the configured tier and
// beta only when every available backend is beta.
func TestSandboxCapabilityFrom(t *testing.T) {
	av := dashapi.SandboxAvailability{Egress: "internet", Backends: []dashapi.SandboxBackendAvail{
		{ID: "bwrap", Available: true, Class: "process", Beta: true, CaptureByTier: map[string]string{"internet": "full (gateway-guarded)"}},
		{ID: "gvisor", Available: false, Class: "userspace_kernel"},
	}}
	got := sandboxCapabilityFrom(av)
	if strings.Join(got.Backends, ",") != "bwrap" || got.MaxClass != "process" || !got.FullCapture || !got.Beta {
		t.Fatalf("capability %+v", got)
	}
	if none := sandboxCapabilityFrom(dashapi.SandboxAvailability{}); len(none.Backends) != 0 || none.Beta || none.FullCapture {
		t.Fatalf("no backends: %+v", none)
	}
	var st *store.Store
	bindSandboxCapability(context.Background(), st, true, nil) // a nil store is a no-op
}

// TestSandboxLocalFloor: backends wins over backend, a list without bwrap
// refuses, and a min_isolation above bwrap's class refuses; config's class
// list mirrors the vocabulary ladder above none.
func TestSandboxLocalFloor(t *testing.T) {
	on := func(c config.TerminalSandboxConfig) config.TerminalSandboxConfig { c.Enabled = true; return c }
	if got := sandboxEnabledBackends(on(config.TerminalSandboxConfig{Backend: "bwrap", Backends: []string{"oci-runc", "bwrap"}})); strings.Join(got, ",") != "oci-runc,bwrap" {
		t.Fatalf("backends did not win: %v", got)
	}
	for _, tc := range []struct {
		cfg config.TerminalSandboxConfig
		ok  bool
	}{
		{config.TerminalSandboxConfig{}, true},
		{config.TerminalSandboxConfig{MinIsolation: "process"}, true},
		{config.TerminalSandboxConfig{MinIsolation: "container"}, false},
		{config.TerminalSandboxConfig{Backends: []string{"oci-runc"}}, false},
	} {
		if err := sandboxLocalFloor(on(tc.cfg)); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
	}
	var want []string
	for _, c := range vocab.Classes() {
		if c != vocab.ClassNone {
			want = append(want, string(c))
		}
	}
	if got := config.SandboxIsolationClasses(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("config min_isolation classes %v, vocabulary %v", got, want)
	}
}

// TestSandboxNativeVerdict: the boundary reduces the side table to the
// nesting rows: a tool with no native sandbox records not_applicable, a
// default-off one is not judged, and codex's default-on sandbox is kept
// inside bwrap (no known conflict).
func TestSandboxNativeVerdict(t *testing.T) {
	if v, judged := sandboxNativeVerdict("goose", vocab.TierInternet); !judged || sandboxselect.NativeStateFor(v) != vocab.NativeNotApplicable {
		t.Fatalf("goose: %+v %v", v, judged)
	}
	if _, judged := sandboxNativeVerdict("claude-code", vocab.TierInternet); judged {
		t.Fatal("claude-code's opt-in sandbox was judged")
	}
	v, judged := sandboxNativeVerdict("codex", vocab.TierInternet)
	if !judged || v.Outcome != sandboxselect.NativeKept || sandboxNativeRefusal("codex", v) != nil {
		t.Fatalf("codex: %+v %v", v, judged)
	}
	if err := sandboxNativeRefusal("x", sandboxselect.NativeVerdict{Outcome: sandboxselect.NativeDisable, Rule: "N12"}); err == nil ||
		!strings.Contains(err.Error(), "tool_conflict") {
		t.Fatalf("a disable verdict must refuse until switches are applied: %v", err)
	}
}

// TestSandboxBackendListEnabledAndWhenEnabled: each row says whether the
// enabled list names it (the master switch aside), and a row dropped only
// for not being enabled says what selection answers once it is, so the
// Settings editor can tell "enable it and it runs" from "enabling it would
// not help here".
func TestSandboxBackendListEnabledAndWhenEnabled(t *testing.T) {
	ok := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: "bwrap", BackendVersion: "0.9.0"}
	runsHere := sandboxHostKind() == sandboxbackend.HostLinux || sandboxHostKind() == sandboxbackend.HostWSL2
	find := func(list []dashapi.SandboxBackendAvail, id string) dashapi.SandboxBackendAvail {
		t.Helper()
		for _, e := range list {
			if e.ID == id {
				return e
			}
		}
		t.Fatalf("no %s row", id)
		return dashapi.SandboxBackendAvail{}
	}

	// bwrap enabled (the default list): checked, no hypothetical.
	on := find(sandboxBackendList(config.TerminalSandboxConfig{Enabled: true}, ok, []string{"live"}, vocab.TierInternet), sandboxbackend.BackendBwrap)
	if !on.Enabled || on.WhenEnabledAvailable || on.WhenEnabledVerdict != "" {
		t.Errorf("enabled bwrap: %+v", on)
	}

	// The master switch off keeps a listed row checked.
	off := find(sandboxBackendList(config.TerminalSandboxConfig{}, ok, []string{"live"}, vocab.TierInternet), sandboxbackend.BackendBwrap)
	if !off.Enabled || off.Available {
		t.Errorf("bwrap with the master switch off: %+v", off)
	}

	// bwrap left out of the list: dropped at S2, unchecked, and the
	// hypothetical says what enabling it would do on this host.
	cfg := config.TerminalSandboxConfig{Enabled: true, Backends: []string{"not-bwrap"}}
	out := find(sandboxBackendList(cfg, ok, []string{"live"}, vocab.TierInternet), sandboxbackend.BackendBwrap)
	if out.Enabled || out.Available || out.Verdict != sandboxselect.VerdictDisabledByConfig {
		t.Fatalf("bwrap not in the list: %+v", out)
	}
	if runsHere {
		if !out.WhenEnabledAvailable || out.WhenEnabledVerdict != "" {
			t.Errorf("bwrap would run here once enabled: %+v", out)
		}
	} else if out.WhenEnabledAvailable || out.WhenEnabledVerdict != sandboxselect.VerdictUnsupportedPlatform || out.WhenEnabledReason == "" {
		t.Errorf("bwrap cannot run on %s even once enabled: %+v", sandboxHostKind(), out)
	}
}

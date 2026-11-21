//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// pinGuardEnforcing pins this machine's guard enforcement for a test.
func pinGuardEnforcing(t *testing.T, on bool) *int {
	t.Helper()
	calls := 0
	old := hostedGuardEnforcing
	hostedGuardEnforcing = func() bool { calls++; return on }
	t.Cleanup(func() { hostedGuardEnforcing = old })
	return &calls
}

// TestHostedGuardHooksResolution (SBXD-6): the launch's resolution per
// guard_hooks value, guard enforcement and tool coverage (Claude Code is
// covered by its settings-file mechanism; aider has no hook mechanism), and
// enforcement is read only when auto needs it.
func TestHostedGuardHooksResolution(t *testing.T) {
	cases := []struct {
		mode, tool string
		enforcing  bool
		seed       bool
		reason     string
		reads      bool
	}{
		{"", "claude-code", true, true, sandboxremote.GuardHooksReasonEnforcing, true},
		{"auto", "claude-code", false, false, sandboxremote.GuardHooksReasonNotEnforcing, true},
		{"on", "claude-code", false, true, sandboxremote.GuardHooksReasonOn, false},
		{"off", "claude-code", true, false, sandboxremote.GuardHooksReasonOff, false},
		{"auto", "aider", true, false, sandboxremote.GuardHooksReasonNotCovered, false},
		{"on", "aider", true, false, sandboxremote.GuardHooksReasonNotCovered, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%s/%v", c.mode, c.tool, c.enforcing), func(t *testing.T) {
			calls := pinGuardEnforcing(t, c.enforcing)
			r := hostedGuardHooksFor(c.tool, config.TerminalSandboxHostedConfig{GuardHooks: c.mode}, hostedGuardEnforcing)
			if r.Seed != c.seed || r.Reason != c.reason {
				t.Fatalf("got %+v, want seed=%v reason=%s", r, c.seed, c.reason)
			}
			if (*calls > 0) != c.reads {
				t.Fatalf("enforcement read %d times, want read=%v", *calls, c.reads)
			}
		})
	}
}

// TestHostedProbeHookNotices (SBXD-6): a hosted row serves a hook line per
// launchable tool and no longer the row-wide no_hook_gating disclosure; the
// no-hook sentence is said for a tool exactly when gating does not apply;
// a local row gets no hook lines.
func TestHostedProbeHookNotices(t *testing.T) {
	cfg := config.Default().Terminal.Sandbox
	row, _ := sandboxbackend.Get(sandboxremote.VendorDaytona)
	for _, enforcing := range []bool{true, false} {
		pinGuardEnforcing(t, enforcing)
		e := dashapi.SandboxBackendAvail{ID: row.ID, Disclosures: sandboxDisclosuresFor(row, "")}
		hostedFillProbeRow(&e, row, cfg, vocab.TierInternet)
		for _, d := range e.Disclosures {
			if d.ID == string(sandboxbackend.DiscloseNoHookGating) {
				t.Fatalf("enforcing=%v: no_hook_gating is still row-wide", enforcing)
			}
		}
		cc, ok := e.HookNotices["claude-code"]
		if !ok || cc.Gated != enforcing {
			t.Fatalf("enforcing=%v: claude-code notice %+v", enforcing, cc)
		}
		ai, ok := e.HookNotices["aider"]
		if !ok || ai.Gated || ai.Code != sandboxremote.GuardHooksReasonNotCovered {
			t.Fatalf("aider notice %+v", ai)
		}
		for tool, n := range e.HookNotices {
			if strings.Contains(n.Message, sandboxremote.HostedHookNote) == n.Gated {
				t.Errorf("enforcing=%v %s: the no-hook sentence must show exactly when gating does not apply: %+v", enforcing, tool, n)
			}
			if strings.Contains(n.Message, "guard_hooks") || !strings.Contains(n.Technical, n.Code) {
				t.Errorf("%s: internal names belong under Technical details: %+v", tool, n)
			}
		}
	}
	local, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	var l dashapi.SandboxBackendAvail
	hostedFillProbeRow(&l, local, cfg, vocab.TierInternet)
	if l.HookNotices != nil {
		t.Errorf("a local row got hook lines: %+v", l.HookNotices)
	}
	cfg.Hosted.GuardHooks = "off"
	pinGuardEnforcing(t, true)
	var off dashapi.SandboxBackendAvail
	hostedFillProbeRow(&off, row, cfg, vocab.TierInternet)
	if n := off.HookNotices["claude-code"]; n.Gated || n.Code != sandboxremote.GuardHooksReasonOff {
		t.Errorf("guard_hooks off: %+v", n)
	}
}

// TestHostedConsentStatesTheHookRule (SBXD-6): the consent screen's hooks
// line is the rule for the configured value, naming the covered tools.
func TestHostedConsentStatesTheHookRule(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	for _, mode := range []string{"auto", "on", "off"} {
		scr := sandboxremote.BuildConsentScreen(v, sandboxremote.ConsentFacts{Provider: v.ID}, sandboxremote.Manifest{Root: "/w/p"}, v.EstimateCost(60))
		hostedApplyHookConsent(&scr, config.TerminalSandboxHostedConfig{GuardHooks: mode})
		line := ""
		for _, l := range scr.Lines {
			if l.Label == sandboxremote.HooksConsentLabel {
				line = l.Value
			}
		}
		if line != sandboxremote.GuardHooksConsentLine(mode, hostedGuardHooksCoveredNames()) {
			t.Fatalf("%s: line %q", mode, line)
		}
		if mode != "off" && !strings.Contains(line, "Claude Code") {
			t.Fatalf("%s: the covered tools are not named: %q", mode, line)
		}
	}
}

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures/lkgsidecar"
)

// TestTerminalSidecarVerdictRows is one case per row of the CLI path's
// terminals decision (OSH-R-003).
func TestTerminalSidecarVerdictRows(t *testing.T) {
	managed := func(m bool) func() (bool, error) { return func() (bool, error) { return m, nil } }
	noGrant := func() (int64, bool) { return 0, false }
	grant := func() (int64, bool) { return 7, true }
	disabled := &lkgsidecar.TerminalsFile{Schema: 1, Terminals: &lkgsidecar.Terminals{Enabled: false}}
	needBox := &lkgsidecar.TerminalsFile{Schema: 1, Terminals: &lkgsidecar.Terminals{Enabled: true, SandboxRequired: true}}
	cases := []struct {
		name      string
		f         *lkgsidecar.TerminalsFile
		reason    string
		sandboxed bool
		managed   func() (bool, error)
		granted   func() (int64, bool)
		allow     bool
		want      string
	}{
		{"absent sidecar allows on a managed node", nil, lkgsidecar.ReasonAbsent, false, managed(true), noGrant, true, ""},
		{"no terminals rule allows", &lkgsidecar.TerminalsFile{Schema: 1}, "", false, managed(true), noGrant, true, ""},
		{"malformed sidecar refuses on a managed node", nil, lkgsidecar.ReasonMalformed, false, managed(true), noGrant, false, "cannot be read on this managed node"},
		{"unreadable sidecar refuses on a managed node", nil, lkgsidecar.ReasonUnreadable, false, managed(true), noGrant, false, "cannot be read"},
		{"schema too new refuses on a managed node", nil, lkgsidecar.ReasonSchemaTooNew, false, managed(true), noGrant, false, "cannot be read"},
		{"malformed sidecar keeps fail-open on an individual node", nil, lkgsidecar.ReasonMalformed, false, managed(false), noGrant, true, ""},
		{"an enrolment that cannot be read refuses", nil, lkgsidecar.ReasonOversize, false, func() (bool, error) { return false, errors.New("db") }, noGrant, false, "cannot be checked"},
		{"terminals disabled refuses", disabled, "", true, managed(false), noGrant, false, "disabled by organization policy"},
		{"a terminals grant lifts disabled", disabled, "", false, managed(false), grant, true, "org grant #7"},
		{"sandbox required refuses an unsandboxed launch", needBox, "", false, managed(false), grant, false, "requires a sandboxed terminal"},
		{"sandbox required allows a launch in a box", needBox, "", true, managed(false), noGrant, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, why := terminalSidecarVerdict(tc.f, tc.reason, tc.sandboxed, tc.managed, tc.granted)
			if ok != tc.allow || (tc.want != "" && !strings.Contains(why, tc.want)) {
				t.Fatalf("got (%v, %q), want (%v, ...%q...)", ok, why, tc.allow, tc.want)
			}
		})
	}
}

// TestSidecarCarriesTheTerminalsRule: the daemon writes the governed
// terminals rule to the sibling terminals file, a cleared handle writes
// none, and the tools.disallow sidecar keeps the shape an older binary's
// strict decoder reads (audit follow-up F2).
func TestSidecarCarriesTheTerminalsRule(t *testing.T) {
	if sidecarTerminals(nodefeatures.TerminalsRule{}) != nil {
		t.Fatal("an ungoverned terminals rule reached the sidecar")
	}
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	side := config.ResolveFeaturesSidecarPath(cfg, "")
	h := newNodeFeaturesHandle()
	h.SetSidecarWriter(makeFeaturesSidecarWriter(cfg, "v-test", nil))
	spec := nodefeatures.PolicySpec{
		Terminals: nodefeatures.TerminalsRule{FeatureRule: nodefeatures.FeatureRule{Governed: true, Enabled: true}, SandboxRequired: true},
		Tools:     nodefeatures.ToolsRule{Governed: true, Disallow: map[string]bool{"codex": true}},
	}
	h.recordApplied(1, "h", spec)
	f, reason := lkgsidecar.ReadTerminals(lkgsidecar.TerminalsPath(side))
	if f == nil || f.Terminals == nil || !f.Terminals.Enabled || !f.Terminals.SandboxRequired {
		t.Fatalf("terminals file %+v (%s)", f, reason)
	}
	raw, err := os.ReadFile(side)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "terminals") {
		t.Fatalf("the disallow sidecar carries the terminals rule: %s", raw)
	}
	if d, why := lkgsidecar.Read(side, time.Now()); d == nil || !d.Disallowed("codex") {
		t.Fatalf("the disallow sidecar no longer reads: %v %q", d, why)
	}
	h.Clear()
	if f, _ := lkgsidecar.ReadTerminals(lkgsidecar.TerminalsPath(side)); f == nil || f.Terminals != nil {
		t.Fatalf("a cleared handle left a terminals rule: %+v", f)
	}
}

// TestCLILaunchHonoursTheOrgTerminalsRule (OSH-R-003): an `observer <tool>`
// launch, and the inner launcher every dashboard and attach PTY runs, walks
// the terminals row: with the org's terminals disabled it is refused before
// the agent starts; with sandbox_required it is refused outside a box and
// allowed inside one. Before the fix the CLI path never asked.
func TestCLILaunchHonoursTheOrgTerminalsRule(t *testing.T) {
	if processNodeFeatures.Load() != nil {
		t.Skip("a daemon handle is installed in this process")
	}
	for _, tc := range []struct {
		name      string
		rule      lkgsidecar.Terminals
		sandboxed bool
		refused   bool
	}{
		{"disabled", lkgsidecar.Terminals{Enabled: false}, false, true},
		{"sandbox required, no box", lkgsidecar.Terminals{Enabled: true, SandboxRequired: true}, false, true},
		{"sandbox required, in a box", lkgsidecar.Terminals{Enabled: true, SandboxRequired: true}, true, false},
		{"enabled", lkgsidecar.Terminals{Enabled: true}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := writeLaunchGateConfig(t, "off")
			cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
			if err != nil {
				t.Fatal(err)
			}
			rule := tc.rule
			makeFeaturesSidecarWriter(cfg, "v-test", nil)(nil, &rule)
			prevEnv, prevDir := cliSandboxedEnv, cliLaunchDir
			cliSandboxedEnv = func() bool { return tc.sandboxed }
			cliLaunchDir = func() (string, error) { return "", errors.New("no launch directory in this test") }
			defer func() { cliSandboxedEnv, cliLaunchDir = prevEnv, prevDir }()
			err = enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code", budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
			if refused := err != nil && strings.Contains(err.Error(), "organization policy"); refused != tc.refused {
				t.Fatalf("refused=%v, want %v (err %v)", refused, tc.refused, err)
			}
		})
	}
}

// TestDaemonWalkReadsTheLiveHandle: a launch the daemon starts itself (an
// Arena candidate, a benchmark attempt, a GUI launch, a box's host-side
// walk) is judged by the daemon's live handle, with the box answer the
// launch carries.
func TestDaemonWalkReadsTheLiveHandle(t *testing.T) {
	h := newNodeFeaturesHandle()
	h.recordApplied(1, "h", nodefeatures.PolicySpec{Terminals: nodefeatures.TerminalsRule{FeatureRule: nodefeatures.FeatureRule{Governed: true, Enabled: true}, SandboxRequired: true}})
	prev := processNodeFeatures.Swap(h)
	t.Cleanup(func() { processNodeFeatures.Store(prev) })
	for _, boxed := range []bool{false, true} {
		r := daemonLaunchGateRun(context.Background(), "", "claude-code", budgetLaunchEvidence{}, daemonLaunch{dir: t.TempDir(), boxed: boxed})
		s := gateTerminalFeature(r)
		if (s.refuse != nil) == boxed {
			t.Fatalf("boxed=%v: %v", boxed, s.refuse)
		}
	}
}

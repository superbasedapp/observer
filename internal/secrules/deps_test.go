package secrules

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

func depsEngine(t *testing.T, mode policy.Mode) *policy.Engine {
	t.Helper()
	c, err := compose(packTable, func(id string) bool { return id == "security.deps" })
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.New(policy.Config{Mode: mode, Home: "/home/u", ExtraRules: c.Rules})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return eng
}

func depsSec(checks ...policy.InstallCheck) *policy.Security {
	return &policy.Security{Posture: policy.SecurityPostureClean, Packs: []string{"security", "security.deps"}, Installs: checks}
}

// TestInstallGateDecisionTable is one row per rule and mode (section 5.4).
func TestInstallGateDecisionTable(t *testing.T) {
	chk := func(v policy.InstallVerdict) policy.InstallCheck {
		return policy.InstallCheck{Ecosystem: "npm", Name: "pkg", Verdict: v}
	}
	rows := []struct {
		name             string
		kind             policy.EventKind
		sec              *policy.Security
		rule             string
		observe, enforce policy.Decision
	}{
		{"malicious S-741", policy.KindShellExec, depsSec(chk(policy.InstallMalicious)), "S-741", policy.DecisionAsk, policy.DecisionDeny},
		{"near miss S-742", policy.KindShellExec, depsSec(policy.InstallCheck{Ecosystem: "npm", Name: "lodahs", Verdict: policy.InstallNearMiss, NearMiss: "lodash"}), "S-742", policy.DecisionAsk, policy.DecisionAsk},
		{"too new S-743", policy.KindShellExec, depsSec(chk(policy.InstallTooNew)), "S-743", policy.DecisionFlag, policy.DecisionFlag},
		{"unknown S-744", policy.KindShellExec, depsSec(chk(policy.InstallUnknownName)), "S-744", policy.DecisionFlag, policy.DecisionFlag},
		{"online unknown S-748", policy.KindShellExec, depsSec(chk(policy.InstallOnlineUnknown)), "S-748", policy.DecisionFlag, policy.DecisionAsk},
		{"listed version S-749", policy.KindShellExec, depsSec(chk(policy.InstallListedVersion)), "S-749", policy.DecisionFlag, policy.DecisionFlag},
		{"known good", policy.KindShellExec, depsSec(chk(policy.InstallKnownGood)), "", policy.DecisionAllow, policy.DecisionAllow},
		{"not checked", policy.KindShellExec, depsSec(chk(policy.InstallNotChecked)), "", policy.DecisionAllow, policy.DecisionAllow},
		{"custom registry S-745", policy.KindShellExec, func() *policy.Security { s := depsSec(); s.InstallCustomRegistry = true; return s }(), "S-745", policy.DecisionFlag, policy.DecisionFlag},
		{"manifest edit S-747", policy.KindFileAccess, func() *policy.Security {
			s := depsSec(chk(policy.InstallMalicious))
			s.InstallManifest = true
			return s
		}(), "S-747", policy.DecisionFlag, policy.DecisionFlag},
		{"pack off", policy.KindShellExec, &policy.Security{Packs: []string{"security"}, Installs: []policy.InstallCheck{chk(policy.InstallMalicious)}}, "", policy.DecisionAllow, policy.DecisionAllow},
		{"no security facts", policy.KindShellExec, nil, "", policy.DecisionAllow, policy.DecisionAllow},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			for _, m := range []struct {
				mode policy.Mode
				want policy.Decision
			}{{policy.ModeObserve, r.observe}, {policy.ModeEnforce, r.enforce}} {
				ev := policy.Event{
					Security: r.sec, Kind: r.kind, Target: "npm install pkg", ActionType: "run_command",
					Cwd: "/r", ProjectRoot: "/r", Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
				}
				if r.kind == policy.KindFileAccess {
					ev.Target, ev.ActionType = "/r/package.json", "edit_file"
				}
				v := depsEngine(t, m.mode).Evaluate(ev)
				if v.Decision != m.want {
					t.Errorf("%s: decision %s, want %s (%+v)", m.mode, v.Decision, m.want, v)
				}
				if r.rule != "" && v.RuleID != r.rule {
					t.Errorf("%s: rule %q, want %q", m.mode, v.RuleID, r.rule)
				}
			}
		})
	}
}

func TestInstallGateDetailQuotesNames(t *testing.T) {
	ev := policy.Event{
		Security: depsSec(policy.InstallCheck{Ecosystem: "npm", Name: strings.Repeat("a", 120) + "\"", Verdict: policy.InstallMalicious}),
		Kind:     policy.KindShellExec, Target: "npm i x", Cwd: "/r", Caps: policy.Capabilities{PreExecution: true, CanBlock: true}, Now: time.Unix(1, 0),
	}
	v := depsEngine(t, policy.ModeEnforce).Evaluate(ev)
	if !strings.Contains(v.Reason, "npm \""+strings.Repeat("a", 80)+"...\"") {
		t.Errorf("detail %q", v.Reason)
	}
}

// TestNotSetUpNoteWording is lane SEC-D1FIX2 milestone 2d: the
// once-per-session not-set-up note reads as its own message, not as a
// finding about the package, and a manifest edit never reports it as a
// flagged dependency.
func TestNotSetUpNoteWording(t *testing.T) {
	if reasonNotSetUp != secfeed.ReasonNotSetUp {
		t.Fatalf("reasonNotSetUp %q drifted from secfeed.ReasonNotSetUp %q", reasonNotSetUp, secfeed.ReasonNotSetUp)
	}
	if reasonTooMany != secfeed.ReasonTooMany {
		t.Fatalf("reasonTooMany %q drifted from secfeed.ReasonTooMany %q", reasonTooMany, secfeed.ReasonTooMany)
	}
	note := policy.InstallCheck{Ecosystem: "npm", Name: "left-pad", Verdict: policy.InstallUnknownName, Reason: reasonNotSetUp}
	ev := policy.Event{
		Security: depsSec(note), Kind: policy.KindShellExec, Target: "npm i left-pad", Cwd: "/r",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
	}
	v := depsEngine(t, policy.ModeEnforce).Evaluate(ev)
	if v.RuleID != "S-744" || !strings.Contains(v.Reason, "not set up") || strings.Contains(v.Reason, "left-pad") {
		t.Errorf("note %+v", v)
	}
	sec := depsSec(note)
	sec.InstallManifest = true
	mev := policy.Event{Security: sec, Kind: policy.KindFileAccess, Target: "/r/package.json", ActionType: "edit_file", Cwd: "/r", Caps: ev.Caps, Now: ev.Now}
	if v := depsEngine(t, policy.ModeEnforce).Evaluate(mev); v.RuleID == "S-747" {
		t.Errorf("the note flagged a manifest edit: %+v", v)
	}
}

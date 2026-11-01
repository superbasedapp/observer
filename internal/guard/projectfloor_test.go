package guard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

const askFloor = "[project_audience]\nunknown = \"ask\"\n"

// expireMapping moves the fixture's mapping past its offline lifetime and
// stretches root's record to match (the "Offline launch" row).
func (f *orgProjectFixture) expireMapping(root string) {
	f.t.Helper()
	var mf projectmatch.MappingFile
	if err := json.Unmarshal([]byte(f.files[f.layout.MappingPath()]), &mf); err != nil {
		f.t.Fatal(err)
	}
	mf.AcceptedAt = time.Now().Add(-8 * 24 * time.Hour)
	f.put(f.layout.MappingPath(), mf)
	recPath := f.layout.MatchPath(projectmatch.RootHash(root))
	if raw, ok := f.files[recPath]; ok {
		var rec projectmatch.MatchFile
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			f.t.Fatal(err)
		}
		rec.ValidUntil = mf.ValidUntil()
		f.put(recPath, rec)
	}
}

// floorGuard builds an enforce-mode guard over the fixture with the given
// tenancy (nil = unresolved).
func (f *orgProjectFixture) floorGuard(managed *bool) *Guard {
	f.t.Helper()
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Rules.ProjectPolicy = ""
	opts := Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(f.files)}
	if managed != nil {
		m := *managed
		opts.ManagedTenancy = func() bool { return m }
	}
	g, err := New(opts)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func boolp(b bool) *bool { return &b }

func floorEvent(root string, mut func(*policy.Event)) policy.Event {
	ev := policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "make test", SessionID: "s", ProjectRoot: root,
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
	if mut != nil {
		mut(&ev)
	}
	return ev
}

// TestProjectUnknownFloor is milestone 4, one row per cell: the org's
// project_unknown value, the node's tenancy, the root's project layer state
// and the event decide whether the floor raises the verdict (PR14: ask on an
// individual node, deny on a managed node or with tenancy unresolved; never
// weaker than the rules' own verdict).
func TestProjectUnknownFloor(t *testing.T) {
	// A real repository: a directory with no identity (not git) is never
	// unknown (lane sec-p2a audit finding 2).
	root := gitRepo(t, "https://github.com/acme/x.git")
	type setup func(f *orgProjectFixture)
	expired := func(f *orgProjectFixture) { f.match(root, "X"); f.expireMapping(root) }
	missing := func(f *orgProjectFixture) { f.match(root, "X"); delete(f.files, f.layout.EnvelopePath("X")) }
	matched := func(f *orgProjectFixture) { f.match(root, "X") }
	unmatched := func(f *orgProjectFixture) { f.match(root) }
	resolveFailed := func(f *orgProjectFixture) {
		f.put(f.layout.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
			ProjectRootHash: projectmatch.RootHash(root), Epoch: f.epoch, MappingDigest: f.digest,
			Source: projectmatch.SourceResolve, BundleVersion: f.version, Unknown: true, Reason: projectmatch.ReasonResolveFailed,
			MatchedAt: time.Now(), ValidUntil: time.Now().Add(time.Hour),
		})
	}
	rows := []struct {
		name    string
		org     string
		managed *bool
		setup   setup
		event   func(*policy.Event)
		want    policy.Decision
		floor   bool
	}{
		{"none: expired mapping, individual", orgFloor, boolp(false), expired, nil, policy.DecisionAllow, false},
		{"none: expired mapping, managed", orgFloor, boolp(true), expired, nil, policy.DecisionAllow, false},
		{"ask: expired mapping, individual", orgFloor + askFloor, boolp(false), expired, nil, policy.DecisionAsk, true},
		{"ask: expired mapping, managed", orgFloor + askFloor, boolp(true), expired, nil, policy.DecisionDeny, true},
		{"ask: expired mapping, tenancy unresolved", orgFloor + askFloor, nil, expired, nil, policy.DecisionDeny, true},
		{"ask: resolve failed above the cap, individual", orgFloor + askFloor, boolp(false), resolveFailed, nil, policy.DecisionAsk, true},
		{"ask: mapped project with no envelope, managed (P-052)", orgFloor + askFloor, boolp(true), missing, nil, policy.DecisionDeny, true},
		{"ask: mapped project with no envelope, individual", orgFloor + askFloor, boolp(false), missing, nil, policy.DecisionAsk, true},
		{"ask: matched and loaded", orgFloor + askFloor, boolp(true), matched, nil, policy.DecisionAllow, false},
		{"ask: unmatched (known)", orgFloor + askFloor, boolp(true), unmatched, nil, policy.DecisionAllow, false},
		{"ask: a file read is left alone", orgFloor + askFloor, boolp(true), expired, func(e *policy.Event) {
			e.Kind, e.ActionType, e.Target = policy.KindFileAccess, "read_file", root+"/README"
		}, policy.DecisionAllow, false},
		{"ask: a file write is raised", orgFloor + askFloor, boolp(false), expired, func(e *policy.Event) {
			e.Kind, e.ActionType, e.Target = policy.KindFileAccess, "write_file", root+"/main.go"
		}, policy.DecisionAsk, true},
		{"ask: a post-hoc event is left alone", orgFloor + askFloor, boolp(true), expired, func(e *policy.Event) {
			e.Caps = policy.Capabilities{}
		}, policy.DecisionAllow, false},
		{"ask: a rule deny stays the rule's", orgFloor + askFloor, boolp(false), expired, func(e *policy.Event) {
			e.Target = "git push --force origin main"
		}, policy.DecisionDeny, false},
	}
	for _, row := range rows {
		f := newOrgProjectFixture(t, row.org, map[string]string{"X": projX})
		row.setup(f)
		g := f.floorGuard(row.managed)
		av, _ := g.EvaluateHook(floorEvent(root, row.event))
		if av.Verdict.Decision != row.want || (av.Verdict.RuleID == ProjectUnknownRuleID) != row.floor {
			t.Errorf("%s: %s/%s, want %s (floor %v); issues %v", row.name, av.Verdict.RuleID, av.Verdict.Decision, row.want, row.floor, g.LoadIssues())
		}
	}
}

// TestProjectUnknownFloorOnAHostThatCannotAsk is Q27: the floor's ask on a
// host that can block but cannot ask is emitted as a deny, never an allow.
func TestProjectUnknownFloorOnAHostThatCannotAsk(t *testing.T) {
	root := gitRepo(t, "https://github.com/acme/x.git")
	f := newOrgProjectFixture(t, orgFloor+askFloor, map[string]string{"X": projX})
	f.match(root, "X")
	f.expireMapping(root)
	g := f.floorGuard(boolp(false))
	av, _ := g.EvaluateHook(floorEvent(root, func(e *policy.Event) {
		e.Caps = policy.Capabilities{PreExecution: true, CanBlock: true}
	}))
	if av.Verdict.RuleID != ProjectUnknownRuleID || av.Verdict.Decision != policy.DecisionAsk {
		t.Fatalf("verdict %+v", av.Verdict)
	}
	if em := ResolveEmission(av.Verdict, policy.Capabilities{PreExecution: true, CanBlock: true}); em.Permission != "deny" || em.DegradedFrom != "ask" {
		t.Fatalf("emission %+v, want a deny degraded from ask", em)
	}
}

// TestProjectAudienceSettingParse: only the org layer may carry the table; a
// bad value is refused by the authoring gate (Lint) and read as the strictest
// known value by the loader (a newer server's value never relaxes); a project
// section's own table is ignored with an issue.
func TestProjectAudienceSettingParse(t *testing.T) {
	if _, err := parsePolicyFile([]byte(askFloor), layerUser); err == nil {
		t.Fatal("a user policy carrying [project_audience] parsed")
	}
	if probs := Lint([]byte("[project_audience]\nunknown = \"deny\"\n"), layerOrg); len(probs) == 0 {
		t.Fatal("Lint accepted an unknown project_unknown value")
	}
	if probs := Lint([]byte(askFloor), layerOrg); len(probs) != 0 {
		t.Fatalf("Lint refused a valid table: %v", probs)
	}
	pf, err := parsePolicyFile([]byte("[project_audience]\nunknown = \"deny\"\n"), layerOrg)
	if err != nil || pf.projectUnknown != orgcontract.ProjectUnknownAsk || len(pf.notes) == 0 {
		t.Fatalf("loader: %+v %v, want ask with a note", pf, err)
	}
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX + askFloor})
	f.match("/home/u/x", "X")
	f.expireMapping("/home/u/none")
	g := f.floorGuard(boolp(true))
	g.Evaluate(floorEvent("/home/u/x", nil))
	if !strings.Contains(strings.Join(g.LoadIssues(), "\n"), "[project_audience] ignored") {
		t.Fatalf("a project section's table was not reported: %v", g.LoadIssues())
	}
	if es := g.set.Load(); es.orgProjectUnknownDecision() != orgcontract.ProjectUnknownNone {
		t.Fatal("a project section set the org-wide decision")
	}
}

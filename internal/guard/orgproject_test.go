package guard

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// orgProjectFixture writes a v3 composed org bundle, its mapping and the
// given project envelopes into an fsMap, the way the org client caches them.
type orgProjectFixture struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	files   map[string]string
	layout  projectmatch.Layout
	version int64
	epoch   int64
	digest  string
}

func newOrgProjectFixture(t *testing.T, orgTOML string, projects map[string]string) *orgProjectFixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &orgProjectFixture{t: t, priv: priv, files: map[string]string{}, layout: projectmatch.LayoutFor(orgBundlePath), version: 12, epoch: 3}
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	m := orgcontract.ProjectMapping{OrgID: "org", Subject: "u-dana", Epoch: f.epoch, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge}
	for id := range projects {
		m.Projects = append(m.Projects, orgcontract.ProjectMappingEntry{OrgProjectID: id, Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh-" + id}}})
	}
	m = orgcontract.SignProjectMapping(priv, m)
	f.digest = orgcontract.ProjectMappingDigest(m)
	composed := orgcontract.PolicyBundle{
		Version: f.version, BundleTOML: orgTOML, PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", Epoch: f.epoch, MappingDigest: f.digest},
	}
	composed.Signature = orgcontract.SignPolicyBundleEnvelope(priv, composed)
	f.put(orgBundlePath, composed)
	f.put(f.layout.MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: f.version, AcceptedAt: time.Now()})
	for id, body := range projects {
		f.put(f.layout.EnvelopePath(id), f.envelope(id, body, f.epoch))
	}
	return f
}

func (f *orgProjectFixture) envelope(id, body string, epoch int64) orgcontract.PolicyBundle {
	env := orgcontract.PolicyBundle{
		Version: f.version, BundleTOML: body,
		PublicKey:      base64.RawURLEncoding.EncodeToString(f.priv.Public().(ed25519.PublicKey)),
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u-dana", OrgProjectID: id, Epoch: epoch},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(f.priv, env)
	return env
}

func (f *orgProjectFixture) put(path string, v any) {
	f.t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		f.t.Fatal(err)
	}
	f.files[path] = string(raw)
}

// match writes the daemon's match record for root.
func (f *orgProjectFixture) match(root string, ids ...string) {
	f.put(f.layout.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(root), OrgProjectIDs: ids, Epoch: f.epoch, MappingDigest: f.digest, MatchedAt: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	})
}

func (f *orgProjectFixture) guard(inRepoPolicy bool) *Guard {
	f.t.Helper()
	cfg := guardCfgOrg()
	if !inRepoPolicy {
		cfg.Rules.ProjectPolicy = ""
	}
	g, err := New(Options{Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/x", "/home/u/y", "/home/u/xy", "/home/u/none"}, ReadFile: fsMap(f.files)})
	if err != nil {
		f.t.Fatalf("guard.New: %v", err)
	}
	return g
}

const (
	orgFloor = "[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\nenforce = true\n"
	projX    = `
[[rule]]
id = "PRJ-X1"
category = "exfil"
severity = "high"
decision = "deny"
applies_to = ["shell_exec"]
match.command_regex = '(?i)\bcurl\b.*\bbilling\.internal\b'
enforce = true

[[override]]
rule = "R-110"
decision = "deny"
enforce = true

[[override]]
rule = "R-153"
decision = "ask"
`
	projY = `
[[rule]]
id = "PRJ-Y1"
category = "exfil"
severity = "high"
decision = "ask"
applies_to = ["shell_exec"]
match.command_regex = '(?i)\bcurl\b.*\bbilling\.internal\b'
enforce = true
`
)

func shell(root, cmd string) policy.Event {
	return policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: cmd, ProjectRoot: root}
}

// TestOrgProjectLayer is milestone 4c: a matched project root gets its
// project's envelope as an org-signed layer (strictest wins, a relaxing
// override dropped); an unmatched root gets the org, team and member layers
// only; several matched projects give the strictest of all; a stale or
// expired mapping leaves the project layer unknown.
func TestOrgProjectLayer(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY})
	f.match("/home/u/x", "X")
	f.match("/home/u/y", "Y")
	f.match("/home/u/xy", "X", "Y")
	f.match("/home/u/none")

	for _, inRepo := range []bool{true, false} {
		g := f.guard(inRepo)
		if v, _ := g.Evaluate(shell("/home/u/x", "curl https://billing.internal/x")); v.RuleID != "PRJ-X1" || v.Decision != policy.DecisionDeny {
			t.Fatalf("inRepo=%v matched X: project rule verdict = %+v", inRepo, v)
		}
		if v, _ := g.Evaluate(shell("/home/u/x", "git push --force origin main")); v.RuleID != "R-110" || v.Decision != policy.DecisionDeny {
			t.Fatalf("inRepo=%v matched X: R-110 = %+v, want deny", inRepo, v)
		}
		if v, _ := g.Evaluate(shell("/home/u/none", "curl https://billing.internal/x")); v.RuleID == "PRJ-X1" {
			t.Fatalf("inRepo=%v an unmatched root got project X's rule", inRepo)
		}
		if v, _ := g.Evaluate(shell("/home/u/none", "git push --force origin main")); v.Decision == policy.DecisionDeny && v.RuleID == "R-110" {
			t.Fatalf("inRepo=%v an unmatched root got project X's R-110 deny: %+v", inRepo, v)
		}
		// Y alone asks for the billing call; X and Y together give the
		// strictest of both (X's deny).
		if v, _ := g.Evaluate(shell("/home/u/y", "curl https://billing.internal/x")); v.RuleID != "PRJ-Y1" || v.Decision != policy.DecisionAsk {
			t.Fatalf("inRepo=%v matched Y: %+v, want PRJ-Y1 ask; issues %v", inRepo, v, g.LoadIssues())
		}
		if v, _ := g.Evaluate(shell("/home/u/xy", "curl https://billing.internal/x")); v.RuleID != "PRJ-X1" || v.Decision != policy.DecisionDeny {
			t.Fatalf("inRepo=%v matched X and Y: %+v, want the strictest (PRJ-X1 deny)", inRepo, v)
		}
	}
	g := f.guard(false)
	g.Evaluate(shell("/home/u/x", "true"))
	var dropped bool
	for _, is := range g.LoadIssues() {
		if strings.Contains(is, "R-153") && strings.Contains(is, "relax") {
			dropped = true
		}
	}
	if !dropped {
		t.Fatalf("project X's relaxing R-153 override was not reported as dropped: %v", g.LoadIssues())
	}
	var loaded bool
	for _, st := range g.PolicyStates() {
		if st.Layer == layerOrgProject && st.Version == "12" {
			loaded = true
		}
	}
	if !loaded {
		t.Fatalf("no org_project state: %+v", g.PolicyStates())
	}
}

func TestOrgProjectLayerUnknownAndRejected(t *testing.T) {
	// An expired mapping: the project layer is unknown, X's rule does not
	// load, and an issue says so. A real repository: a directory with no
	// identity is never unknown (lane sec-p2a audit finding 2).
	root := gitRepo(t, "https://github.com/acme/x.git")
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match(root, "X")
	var mf projectmatch.MappingFile
	if err := json.Unmarshal([]byte(f.files[f.layout.MappingPath()]), &mf); err != nil {
		t.Fatal(err)
	}
	mf.AcceptedAt = time.Now().Add(-8 * 24 * time.Hour)
	f.put(f.layout.MappingPath(), mf)
	var rec projectmatch.MatchFile
	recPath := f.layout.MatchPath(projectmatch.RootHash(root))
	if err := json.Unmarshal([]byte(f.files[recPath]), &rec); err != nil {
		t.Fatal(err)
	}
	rec.ValidUntil = mf.ValidUntil()
	f.put(recPath, rec)
	g := f.guard(false)
	if v, _ := g.Evaluate(shell(root, "curl https://billing.internal/x")); v.RuleID == "PRJ-X1" {
		t.Fatal("an expired mapping still loaded the project layer")
	}
	if !orgProjectIssue(g, "is unknown") {
		t.Fatalf("no unknown-layer issue: %v", g.LoadIssues())
	}

	// An envelope of an older epoch is refused, never loaded.
	f2 := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f2.match("/home/u/x", "X")
	f2.put(f2.layout.EnvelopePath("X"), f2.envelope("X", projX, 2))
	g2 := f2.guard(false)
	if v, _ := g2.Evaluate(shell("/home/u/x", "curl https://billing.internal/x")); v.RuleID == "PRJ-X1" {
		t.Fatal("an envelope of another epoch was loaded")
	}
	if !orgProjectIssue(g2, "rejected") {
		t.Fatalf("no rejected-envelope issue: %v", g2.LoadIssues())
	}

	// A plain v2 org bundle: no project file is ever read.
	env, _ := signedEnvelope(t, 4, orgFloor)
	reads := map[string]int{}
	files := map[string]string{orgBundlePath: env}
	cfg := guardCfgOrg()
	cfg.Rules.ProjectPolicy = ""
	g3, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: func(p string) ([]byte, error) {
		reads[p]++
		return fsMap(files)(p)
	}})
	if err != nil {
		t.Fatal(err)
	}
	g3.Evaluate(shell("/home/u/x", "true"))
	for p := range reads {
		if strings.Contains(p, projectmatch.DirName) {
			t.Fatalf("a node without the project audience read %s", p)
		}
	}
}

func orgProjectIssue(g *Guard, sub string) bool {
	for _, is := range g.LoadIssues() {
		if strings.Contains(is, sub) {
			return true
		}
	}
	return false
}

// TestOrgProjectRulesAreOrgLockedOnAnIndividualNode is audit finding 3: on an
// individual node a rule only a project section names (R-110 in project X;
// the org floor names R-153 only) is org-locked inside a root that matches X,
// so a local approval cannot pass the project deny there. In an unmatched
// root the org does not name R-110 and the lock does not reach it.
func TestOrgProjectRulesAreOrgLockedOnAnIndividualNode(t *testing.T) {
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX})
	f.match("/home/u/x", "X")
	f.match("/home/u/none")
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Rules.ProjectPolicy = ""
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/x", "/home/u/none"},
		ReadFile: fsMap(f.files), ManagedTenancy: func() bool { return false },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
	hook := func(root string) ActionVerdict {
		av, _ := g.EvaluateHook(policy.Event{
			Kind: policy.KindShellExec, ActionType: "run_command", Target: "git push --force origin main",
			SessionID: "sA", ProjectRoot: root,
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
		})
		return av
	}
	in := hook("/home/u/x")
	if in.Verdict.RuleID != "R-110" || in.Verdict.Decision != policy.DecisionDeny || in.DegradedFrom == "approved" || !in.OrgLocked {
		t.Fatalf("matched X: %+v (degraded %q, locked %v), want an org-locked R-110 deny the approval cannot pass; issues %v",
			in.Verdict, in.DegradedFrom, in.OrgLocked, g.LoadIssues())
	}
	if !strings.Contains(in.Verdict.Reason, "org_locked") {
		t.Fatalf("the refused local approval is not recorded on the verdict: %q", in.Verdict.Reason)
	}
	if out := hook("/home/u/none"); out.OrgLocked || out.Verdict.Decision >= policy.DecisionDeny {
		t.Fatalf("unmatched root: %+v (locked %v), the project section must not lock R-110 outside X", out.Verdict, out.OrgLocked)
	}
}

// TestOrgProjectMissingEnvelopeIsReported is audit finding 4 on the node: a
// project the signed mapping lists with no envelope file is reported (a load
// issue on the hook path, and OrgProjectCacheIssues for guard status), and a
// root matching it and another project still loads the other one.
func TestOrgProjectMissingEnvelopeIsReported(t *testing.T) {
	if issues := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX}).guard(false).OrgProjectCacheIssues(); len(issues) != 0 {
		t.Fatalf("a complete cache reported %v", issues)
	}
	f := newOrgProjectFixture(t, orgFloor, map[string]string{"X": projX, "Y": projY})
	f.match("/home/u/xy", "X", "Y")
	delete(f.files, f.layout.EnvelopePath("X"))
	g := f.guard(false)
	if issues := g.OrgProjectCacheIssues(); len(issues) != 1 || !strings.Contains(issues[0], "envelope for X is missing") {
		t.Fatalf("OrgProjectCacheIssues = %v, want X reported missing", issues)
	}
	if v, _ := g.Evaluate(shell("/home/u/xy", "curl https://billing.internal/x")); v.RuleID != "PRJ-Y1" {
		t.Fatalf("Y must still load beside the missing X: %+v", v)
	}
	var reported bool
	for _, is := range g.LoadIssues() {
		if strings.Contains(is, "envelope for X is missing") {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("the hook path did not record the missing envelope: %v", g.LoadIssues())
	}
}

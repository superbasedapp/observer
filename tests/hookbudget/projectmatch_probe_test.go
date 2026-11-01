package hookbudget

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/hookbudget"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// projectMatchFixture is a home holding a composed org bundle of ten
// org-wide overrides, and, for the v3 case, a 50-project mapping, the match
// record of the timed root and that project's envelope of five rules: the
// files a hook in a matched project reads (security plan 6.4 project row).
type projectMatchFixture struct {
	cfgV2, cfgV3 config.GuardConfig
	home, root   string
}

func newProjectMatchFixture(t testing.TB) projectMatchFixture {
	t.Helper()
	base := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	var org strings.Builder
	for _, id := range []string{"R-110", "R-111", "R-112", "R-113", "R-114", "R-120", "R-130", "R-140", "R-141", "R-153"} {
		fmt.Fprintf(&org, "[[override]]\nrule = %q\nenforce = true\n\n", id)
	}
	var proj strings.Builder
	for i := 0; i < 5; i++ {
		fmt.Fprintf(&proj, "[[rule]]\nid = \"PRJ-%d\"\ncategory = \"exfil\"\nseverity = \"high\"\ndecision = \"deny\"\napplies_to = [\"shell_exec\"]\nmatch.command_regex = '(?i)\\bcurl\\b.*\\bsecret%d\\.internal\\b'\nenforce = true\n\n", i, i)
	}
	write := func(path string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := orgcontract.ProjectMapping{OrgID: "org", Subject: "u", Epoch: 3, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge}
	for i := 0; i < 50; i++ {
		m.Projects = append(m.Projects, orgcontract.ProjectMappingEntry{
			OrgProjectID: fmt.Sprintf("p%02d", i),
			Repos:        []orgcontract.ProjectRepoHashes{{RemoteHash: projectmatch.Hash(fmt.Sprint("r", i)), RootCommitHash: projectmatch.Hash(fmt.Sprint("c", i))}},
		})
	}
	m = orgcontract.SignProjectMapping(priv, m)
	digest := orgcontract.ProjectMappingDigest(m)

	v2 := orgcontract.PolicyBundle{Version: 9, BundleTOML: org.String(), PublicKey: pub, Binding: &orgcontract.PolicyBinding{OrgID: "org", Subject: "u"}}
	v2.Signature = orgcontract.SignPolicyBundleEnvelope(priv, v2)
	v2Path := filepath.Join(base, "v2", "org-policy-bundle.json")
	write(v2Path, v2)

	v3 := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: org.String(), PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", Epoch: 3, MappingDigest: digest},
	}
	v3.Signature = orgcontract.SignPolicyBundleEnvelope(priv, v3)
	v3Path := filepath.Join(base, "v3", "org-policy-bundle.json")
	write(v3Path, v3)
	l := projectmatch.LayoutFor(v3Path)
	write(l.MappingPath(), projectmatch.MappingFile{Mapping: m, BundleVersion: 9, AcceptedAt: time.Now()})
	env := orgcontract.PolicyBundle{
		Version: 9, BundleTOML: proj.String(), PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org", Subject: "u", OrgProjectID: "p07", Epoch: 3},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	write(l.EnvelopePath("p07"), env)
	root := filepath.Join(base, "work", "billing")
	write(l.MatchPath(projectmatch.RootHash(root)), projectmatch.MatchFile{
		ProjectRootHash: projectmatch.RootHash(root), OrgProjectIDs: []string{"p07"}, Epoch: 3, MappingDigest: digest, MatchedAt: time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	})
	cfg := func(bundle string) config.GuardConfig {
		return config.GuardConfig{Enabled: true, Mode: "enforce", Rules: config.GuardRulesConfig{OrgBundle: bundle}}
	}
	return projectMatchFixture{cfgV2: cfg(v2Path), cfgV3: cfg(v3Path), home: base, root: root}
}

// hookOnce is the guard work one hook process does: construct, evaluate.
func (f projectMatchFixture) hookOnce(t testing.TB, cfg config.GuardConfig) (time.Duration, policy.Verdict) {
	t.Helper()
	start := hookbudget.Now()
	g, err := guard.New(guard.Options{Config: cfg, Home: f.home})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := g.Evaluate(policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "curl https://secret3.internal/x", ProjectRoot: f.root})
	return hookbudget.Since(start), v
}

// projectMatchSamples times n paired runs and returns the per-pair added
// work (a matched v3 hook minus the same hook on the plain bundle).
func projectMatchSamples(t testing.TB, n int) []time.Duration {
	t.Helper()
	f := newProjectMatchFixture(t)
	if _, v := f.hookOnce(t, f.cfgV3); v.RuleID != "PRJ-3" {
		g, _ := guard.New(guard.Options{Config: f.cfgV3, Home: f.home})
		t.Fatalf("the matched project's section did not apply: %+v (issues %v)", v, g.LoadIssues())
	}
	if _, v := f.hookOnce(t, f.cfgV2); v.RuleID == "PRJ-3" {
		t.Fatal("the plain bundle applied a project section")
	}
	for range 20 {
		f.hookOnce(t, f.cfgV2)
		f.hookOnce(t, f.cfgV3)
	}
	out := make([]time.Duration, 0, n)
	for range n {
		base, _ := f.hookOnce(t, f.cfgV2)
		with, _ := f.hookOnce(t, f.cfgV3)
		out = append(out, max(with-base, 0))
	}
	return out
}

// TestProjectMatchProbe keeps the probe working in every test run (a short
// run, no timing asserted) and, with SBO_HOOK_BUDGET=1, logs the added work.
func TestProjectMatchProbe(t *testing.T) {
	if got := len(projectMatchSamples(t, 10)); got != 10 {
		t.Fatalf("%d samples", got)
	}
	if os.Getenv(envEnable) != "1" {
		return
	}
	s := hookbudget.Summarize(projectMatchSamples(t, 2000))
	t.Logf("project match and section load, added work: p50 %s p95 %s p99 %s (n=%d, budget 2ms)", s.P50, s.P95, s.P99, s.N)
}

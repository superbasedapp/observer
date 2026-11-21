//go:build !sbo_omit_security

package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// facetSeed is one finding of the shared fixture.
type facetSeed struct {
	key, root, rule, driver, rel, evidence, message string
	cat                                             secfinding.Category
	sev                                             secfinding.Severity
	base                                            secfinding.Baseline
	status                                          secfinding.Status
}

// secretEvidence is the secret's redacted excerpt: it holds a package-like
// token on purpose, so a read that leaked a secret's evidence into a
// search, a facet or a group would show.
const secretEvidence = "AKIA****lodash@4.17.20****"

var facetSeeds = []facetSeed{
	{
		key: "s1", root: "p1", rule: "S-721", driver: "native", rel: "a.go", evidence: secretEvidence, message: "secret in code",
		cat: policy.FindingSecret, sev: policy.FindingSeverityHigh, base: policy.FindingBaselineNew,
	},
	{
		key: "d1", root: "p1", rule: "GHSA-1", driver: "scalibr", rel: "package-lock.json", evidence: "npm lodash@4.17.20", message: "Known vulnerability in a npm dependency (GHSA-1).",
		cat: policy.FindingVulnerableDependency, sev: policy.FindingSeverityCritical, base: policy.FindingBaselinePreExisting,
	},
	{
		key: "d2", root: "p2", rule: "GHSA-1", driver: "osv", rel: "package-lock.json", evidence: "npm lodash@4.17.20", message: "Known vulnerability in a npm dependency (GHSA-1).",
		cat: policy.FindingVulnerableDependency, sev: policy.FindingSeverityCritical, base: policy.FindingBaselineNew,
	},
	{
		key: "d3", root: "p1", rule: "GHSA-2", driver: "scalibr", rel: ".github/workflows/ci.yml", evidence: "GitHub Actions tj-actions/changed-files@v45.0.0", message: "Known vulnerability in a GitHub Actions action (GHSA-2).",
		cat: policy.FindingVulnerableDependency, sev: policy.FindingSeverityHigh, base: policy.FindingBaselineNew,
	},
	{
		key: "d4", root: "p2", rule: "GO-1", driver: "scalibr", rel: "go.mod", evidence: "Go golang.org/x/text@v0.3.5", message: "Known vulnerability in a Go dependency (GO-1).",
		cat: policy.FindingVulnerableDependency, sev: policy.FindingSeverityMedium, base: policy.FindingBaselineNew,
	},
	{
		key: "c1", root: "p2", rule: "OG-1", driver: "opengrep", rel: "web/App.tsx", message: "Unsafe 50%_done",
		cat: policy.FindingCodeVuln, sev: policy.FindingSeverityLow, base: policy.FindingBaselineNew,
	},
	{
		key: "c2", root: "p1", rule: "KICS-1", driver: "kics", rel: "infra/Dockerfile", message: "Container runs as root",
		cat: policy.FindingIaC, sev: policy.FindingSeverityMedium, base: policy.FindingBaselineNew,
	},
	{
		key: "c3", root: "p2", rule: "S-721", driver: "native", rel: `deploy\prod.env`, evidence: "ghp_****", message: "secret in config",
		cat: policy.FindingSecret, sev: policy.FindingSeverityHigh, base: policy.FindingBaselineNew, status: policy.FindingStatusFixedVerified,
	},
}

// seedFacetStore writes facetSeeds, one minute apart in order (s1 the
// oldest).
func seedFacetStore(t *testing.T) *Store {
	t.Helper()
	s, _ := newTestStore(t)
	t0 := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	for i, x := range facetSeeds {
		f := secfinding.Normalize(secfinding.Finding{
			LocalKey: x.key, Rule: secfinding.Rule{ID: x.rule}, Engine: secfinding.Engine{Driver: x.driver},
			Category: x.cat, Severity: x.sev, Confidence: policy.FindingConfidenceHigh, Baseline: x.base, Status: x.status,
			Project: secfinding.Project{RootHash: x.root}, Location: secfinding.Location{RelPath: x.rel},
			EvidenceRedacted: x.evidence, Message: x.message,
		})
		if _, _, err := s.UpsertSecFinding(context.Background(), f, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// secKeys lists what a filter selects, sorted.
func secKeys(t *testing.T, s *Store, f SecFindingFilter) []string {
	t.Helper()
	got, err := s.ListSecFindings(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range got {
		out = append(out, x.LocalKey)
	}
	sort.Strings(out)
	n, err := s.CountSecFindings(context.Background(), f)
	if err != nil || n != len(out) {
		t.Fatalf("count %d (%v) disagrees with the list %v", n, err, out)
	}
	return out
}

// TestSecFindingFilterRows is one case per filter row: each list and
// exact filter, the dependency-only ecosystem and package, the
// non-dependency language, the free-text search (and its privacy rule: a
// secret's evidence is never matched), the cap and the AND across filters.
func TestSecFindingFilterRows(t *testing.T) {
	t.Parallel()
	s := seedFacetStore(t)
	junk := make([]string, SecFilterMaxValues)
	for i := range junk {
		junk[i] = fmt.Sprintf("junk-%d", i)
	}
	all := []string{"c1", "c2", "c3", "d1", "d2", "d3", "d4", "s1"}
	cases := []struct {
		name string
		f    SecFindingFilter
		want []string
	}{
		{"no filter", SecFindingFilter{}, all},
		{"severity", SecFindingFilter{Severities: []string{"critical"}}, []string{"d1", "d2"}},
		{"severities OR", SecFindingFilter{Severities: []string{"high", "critical"}}, []string{"c3", "d1", "d2", "d3", "s1"}},
		{"category", SecFindingFilter{Categories: []string{"vulnerable_dependency"}}, []string{"d1", "d2", "d3", "d4"}},
		{"driver", SecFindingFilter{Drivers: []string{"scalibr", "osv"}}, []string{"d1", "d2", "d3", "d4"}},
		{"project list", SecFindingFilter{ProjectRootHashes: []string{"p2"}}, []string{"c1", "c3", "d2", "d4"}},
		{"project list of two", SecFindingFilter{ProjectRootHashes: []string{"p1", "p2"}}, all},
		{"project hash and list AND", SecFindingFilter{ProjectRootHash: "p1", ProjectRootHashes: []string{"p2"}}, nil},
		{"baseline", SecFindingFilter{Baselines: []string{"pre_existing"}}, []string{"d1"}},
		{"status", SecFindingFilter{Status: policy.FindingStatusFixedVerified}, []string{"c3"}},
		{"ecosystem", SecFindingFilter{Ecosystems: []string{"npm"}}, []string{"d1", "d2"}},
		{"ecosystem with a space", SecFindingFilter{Ecosystems: []string{"GitHub Actions"}}, []string{"d3"}},
		{"ecosystem is the whole prefix, not its first word", SecFindingFilter{Ecosystems: []string{"GitHub"}}, nil},
		{"ecosystem never reads a secret's evidence", SecFindingFilter{Ecosystems: []string{"AKIA****lodash@4.17.20****", ""}}, nil},
		{"language by suffix", SecFindingFilter{Languages: []string{"go"}}, []string{"s1"}},
		{"language skips dependency rows", SecFindingFilter{Languages: []string{"yaml"}}, nil},
		{"language by name", SecFindingFilter{Languages: []string{"dockerfile"}}, []string{"c2"}},
		{"language on a backslash path", SecFindingFilter{Languages: []string{"dotenv"}}, []string{"c3"}},
		{"languages OR", SecFindingFilter{Languages: []string{"typescript", "go"}}, []string{"c1", "s1"}},
		{"unknown language matches nothing", SecFindingFilter{Languages: []string{"cobol"}}, nil},
		{"rule", SecFindingFilter{RuleID: "GHSA-1"}, []string{"d1", "d2"}},
		{"path", SecFindingFilter{RelPath: "package-lock.json"}, []string{"d1", "d2"}},
		{"package", SecFindingFilter{Package: "lodash@4.17.20"}, []string{"d1", "d2"}},
		{"package with a slash", SecFindingFilter{Package: "tj-actions/changed-files@v45.0.0"}, []string{"d3"}},
		{"package is exact", SecFindingFilter{Package: "changed-files@v45.0.0"}, nil},
		{"q over a dependency's package", SecFindingFilter{Query: "LODASH"}, []string{"d1", "d2"}},
		{"q never matches a secret's evidence", SecFindingFilter{Query: "akia"}, nil},
		{"q over the message, case-insensitive", SecFindingFilter{Query: "Secret IN"}, []string{"c3", "s1"}},
		{"q over the path", SecFindingFilter{Query: "app.tsx"}, []string{"c1"}},
		{"q over the rule id", SecFindingFilter{Query: "ghsa-2"}, []string{"d3"}},
		{"q escapes %", SecFindingFilter{Query: "%"}, []string{"c1"}},
		{"q escapes _", SecFindingFilter{Query: "50%_d"}, []string{"c1"}},
		{"q blank is no filter", SecFindingFilter{Query: "   "}, all},
		{"filters AND", SecFindingFilter{Categories: []string{"vulnerable_dependency"}, ProjectRootHashes: []string{"p1"}}, []string{"d1", "d3"}},
		{"empty values are dropped", SecFindingFilter{Severities: []string{""}}, all},
		{"a list is capped", SecFindingFilter{Severities: append(append([]string(nil), junk...), "critical")}, nil},
	}
	for _, c := range cases {
		if got := secKeys(t, s, c.f); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSecFindingFacets: each facet counts every filter but its own, the
// severity facet runs critical first, the others by count then value,
// every facet is present, and no facet reads a secret's evidence.
func TestSecFindingFacets(t *testing.T) {
	t.Parallel()
	s := seedFacetStore(t)
	ctx := context.Background()
	render := func(vals []SecFacetValue) string {
		var parts []string
		for _, v := range vals {
			parts = append(parts, fmt.Sprintf("%s=%d", v.Value, v.Count))
		}
		return strings.Join(parts, ",")
	}
	cases := []struct {
		name string
		f    SecFindingFilter
		want map[string]string
	}{
		{"no filter", SecFindingFilter{}, map[string]string{
			SecFacetSeverity:  "critical=2,high=3,medium=2,low=1",
			SecFacetCategory:  "vulnerable_dependency=4,secret=2,code_vuln=1,iac=1",
			SecFacetDriver:    "scalibr=3,native=2,kics=1,opengrep=1,osv=1",
			SecFacetEcosystem: "npm=2,GitHub Actions=1,Go=1",
			SecFacetLanguage:  "dockerfile=1,dotenv=1,go=1,typescript=1",
			SecFacetProject:   "p1=4,p2=4",
			SecFacetStatus:    "open=7,fixed_verified=1",
			SecFacetBaseline:  "new=7,pre_existing=1",
		}},
		{"each facet ignores its own filter", SecFindingFilter{Severities: []string{"critical"}, Categories: []string{"vulnerable_dependency"}}, map[string]string{
			SecFacetSeverity:  "critical=2,high=1,medium=1",
			SecFacetCategory:  "vulnerable_dependency=2",
			SecFacetDriver:    "osv=1,scalibr=1",
			SecFacetEcosystem: "npm=2",
			SecFacetLanguage:  "",
			SecFacetProject:   "p1=1,p2=1",
			SecFacetStatus:    "open=2",
			SecFacetBaseline:  "new=1,pre_existing=1",
		}},
		{"status and project filters", SecFindingFilter{Status: policy.FindingStatusOpen, ProjectRootHashes: []string{"p2"}}, map[string]string{
			SecFacetSeverity:  "critical=1,medium=1,low=1",
			SecFacetCategory:  "vulnerable_dependency=2,code_vuln=1",
			SecFacetDriver:    "opengrep=1,osv=1,scalibr=1",
			SecFacetEcosystem: "Go=1,npm=1",
			SecFacetLanguage:  "typescript=1",
			SecFacetProject:   "p1=4,p2=3",
			SecFacetStatus:    "open=3,fixed_verified=1",
			SecFacetBaseline:  "new=3",
		}},
	}
	for _, c := range cases {
		got, err := s.SecFindingFacets(ctx, c.f)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(SecFacetNames()) {
			t.Fatalf("%s: facets %v, want every one of %v", c.name, got, SecFacetNames())
		}
		for _, name := range SecFacetNames() {
			vals, ok := got[name]
			if !ok || vals == nil {
				t.Errorf("%s: facet %s missing or nil", c.name, name)
			}
			if r := render(vals); r != c.want[name] {
				t.Errorf("%s: facet %s = %q, want %q", c.name, name, r, c.want[name])
			}
			for _, v := range vals {
				if strings.Contains(v.Value, "AKIA") || strings.Contains(v.Value, "ghp_") {
					t.Fatalf("%s: facet %s shows a secret's evidence: %q", c.name, name, v.Value)
				}
			}
		}
	}
}

// TestSecFindingGroups: each grouping's keys, counts, projects and worst
// severity; the default severity order and the count and last_seen sorts;
// paging; by severity over every group, not the page; the filter applied;
// an unknown grouping refused; and no group carries a secret's evidence.
func TestSecFindingGroups(t *testing.T) {
	t.Parallel()
	s := seedFacetStore(t)
	ctx := context.Background()
	keyOf := func(g SecFindingGroup) string {
		switch {
		case g.ProjectRootHash != "":
			return g.ProjectRootHash
		case g.Dependency:
			return g.RuleID + "|" + g.Evidence
		default:
			return g.RuleID + "|" + g.RelPath
		}
	}
	render := func(p SecFindingGroupsPage) string {
		var parts []string
		for _, g := range p.Groups {
			parts = append(parts, fmt.Sprintf("%s:%d/%d/%s", keyOf(g), g.Count, g.Projects, g.MaxSeverity))
		}
		return strings.Join(parts, " ")
	}
	cases := []struct {
		name  string
		f     SecFindingFilter
		q     SecGroupQuery
		want  string
		total int
		bySev map[string]int
	}{
		{
			"issue, worst severity first",
			SecFindingFilter{},
			SecGroupQuery{By: SecGroupIssue, Desc: true},
			"GHSA-1|npm lodash@4.17.20:2/2/critical GHSA-2|GitHub Actions tj-actions/changed-files@v45.0.0:1/1/high S-721|a.go:1/1/high S-721|deploy\\prod.env:1/1/high " +
				"GO-1|Go golang.org/x/text@v0.3.5:1/1/medium KICS-1|infra/Dockerfile:1/1/medium OG-1|web/App.tsx:1/1/low",
			7,
			map[string]int{"critical": 1, "high": 3, "medium": 2, "low": 1},
		},
		{
			"package, dependency rows only",
			SecFindingFilter{},
			SecGroupQuery{By: SecGroupPackage, Desc: true},
			"|npm lodash@4.17.20:2/2/critical |GitHub Actions tj-actions/changed-files@v45.0.0:1/1/high |Go golang.org/x/text@v0.3.5:1/1/medium",
			3,
			map[string]int{"critical": 1, "high": 1, "medium": 1},
		},
		{
			"rule by count",
			SecFindingFilter{},
			SecGroupQuery{By: SecGroupRule, Sort: SecGroupSortCount, Desc: true},
			"GHSA-1|:2/2/critical S-721|:2/2/high GHSA-2|:1/1/high GO-1|:1/1/medium KICS-1|:1/1/medium OG-1|:1/1/low",
			6,
			map[string]int{"critical": 1, "high": 2, "medium": 2, "low": 1},
		},
		{
			"project",
			SecFindingFilter{},
			SecGroupQuery{By: SecGroupProject, Desc: true},
			"p1:4/1/critical p2:4/1/critical", 2,
			map[string]int{"critical": 2},
		},
		{
			"issue, oldest last seen first",
			SecFindingFilter{Categories: []string{"vulnerable_dependency"}},
			SecGroupQuery{By: SecGroupIssue, Sort: SecGroupSortLastSeen},
			"GHSA-1|npm lodash@4.17.20:2/2/critical GHSA-2|GitHub Actions tj-actions/changed-files@v45.0.0:1/1/high GO-1|Go golang.org/x/text@v0.3.5:1/1/medium",
			3,
			map[string]int{"critical": 1, "high": 1, "medium": 1},
		},
		{
			"a page of the issue groups",
			SecFindingFilter{},
			SecGroupQuery{By: SecGroupIssue, Desc: true, Limit: 2, Offset: 2},
			"S-721|a.go:1/1/high S-721|deploy\\prod.env:1/1/high",
			7,
			map[string]int{"critical": 1, "high": 3, "medium": 2, "low": 1},
		},
		{
			"the filter applies",
			SecFindingFilter{Query: "lodash"},
			SecGroupQuery{By: SecGroupIssue, Desc: true},
			"GHSA-1|npm lodash@4.17.20:2/2/critical", 1,
			map[string]int{"critical": 1},
		},
	}
	for _, c := range cases {
		p, err := s.SecFindingGroups(ctx, c.f, c.q)
		if err != nil {
			t.Fatal(err)
		}
		if r := render(p); r != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, r, c.want)
		}
		if p.Total != c.total || fmt.Sprint(p.BySeverity) != fmt.Sprint(c.bySev) {
			t.Errorf("%s: total %d by severity %v, want %d %v", c.name, p.Total, p.BySeverity, c.total, c.bySev)
		}
		for _, g := range p.Groups {
			if strings.Contains(g.Evidence, "AKIA") || strings.Contains(g.Evidence, "ghp_") || (!g.Dependency && g.Evidence != "") {
				t.Fatalf("%s: a group carries a secret's evidence: %+v", c.name, g)
			}
			if g.FirstSeen.IsZero() || g.LastSeen.Before(g.FirstSeen) {
				t.Fatalf("%s: seen times %+v", c.name, g)
			}
		}
	}
	// The worst severity's representative message is deterministic.
	p, _ := s.SecFindingGroups(ctx, SecFindingFilter{}, SecGroupQuery{By: SecGroupRule, Desc: true})
	if p.Groups[0].RuleID != "GHSA-1" || p.Groups[0].Message != "Known vulnerability in a npm dependency (GHSA-1)." || p.Groups[0].Category != "vulnerable_dependency" {
		t.Fatalf("rule group: %+v", p.Groups[0])
	}
	if _, err := s.SecFindingGroups(ctx, SecFindingFilter{}, SecGroupQuery{By: "none"}); !errors.Is(err, ErrSecGroupBy) {
		t.Fatalf("unknown grouping: %v", err)
	}
	if empty, err := s.SecFindingGroups(ctx, SecFindingFilter{RuleID: "nope"}, SecGroupQuery{By: SecGroupIssue}); err != nil || empty.Groups == nil || len(empty.Groups) != 0 || empty.Total != 0 {
		t.Fatalf("no groups: %+v %v", empty, err)
	}
}

// TestSecLatestCoverageRuns: the newest run per project and named driver,
// a run that never executed skipped, other drivers left out, the coverage
// decoded with the skipped parts capped, and a row whose coverage is not
// JSON read with its outcome alone.
func TestSecLatestCoverageRuns(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
	skip := func(path, reason string) map[string]string { return map[string]string{"Path": path, "Reason": reason} }
	runs := []SecScanRun{
		{ProjectRootHash: "p1", Driver: "scalibr", Outcome: "clean", Coverage: map[string]any{"Outcome": "clean", "Scanned": []string{"npm"}}},
		{ProjectRootHash: "p1", Driver: "scalibr", Outcome: "unknown", Coverage: map[string]any{
			"Outcome": "unknown", "Reason": "partial_coverage", "FilesScanned": 4, "Scanned": []string{"Go", "npm"},
			"Skipped": []map[string]string{skip("a/requirements.txt", "unpinned_version"), skip("b/pyproject.toml", "no_lockfile"), skip("ecosystem:PyPI", "database_missing")},
		}},
		{ProjectRootHash: "p1", Driver: "osv", Outcome: "failed", Coverage: map[string]any{"Outcome": "failed", "Reason": "not_installed"}},
		{ProjectRootHash: "p1", Driver: "osv", Outcome: "not_scanned", Coverage: map[string]any{"reason": SecRunReasonNotRun}},
		{ProjectRootHash: "p1", Driver: SecBaselineDriverPrefix + "scalibr", Outcome: "clean"},
		{ProjectRootHash: "p1", Driver: "opengrep", Outcome: "clean"},
		{ProjectRootHash: "p2", Driver: "scalibr", Outcome: "failed", Coverage: map[string]any{"Outcome": "failed", "Reason": "isolation_refused"}},
	}
	for i, r := range runs {
		r.Scope = policy.FindingScopeScheduled
		r.StartedAt = t0.Add(time.Duration(i) * time.Minute)
		if err := s.InsertSecScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sec_scan_runs (project_root_hash, driver, scope, coverage_json, outcome, findings, started_at, duration_ms)
		VALUES ('p3', 'osv', 'scheduled', 'not json', 'unknown', 0, ?, 0)`, t0.Format(secTime)); err != nil {
		t.Fatal(err)
	}
	got, err := s.SecLatestCoverageRuns(ctx, []string{"scalibr", "osv"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range got {
		var sk []string
		for _, x := range r.Skipped {
			sk = append(sk, x.Path+"="+x.Reason)
		}
		lines = append(lines, fmt.Sprintf("%s/%s %s %q files=%d scanned=%v skipped=%v of %d", r.ProjectRootHash, r.Driver, r.Outcome, r.Reason,
			r.FilesScanned, r.Scanned, sk, r.SkippedTotal))
	}
	want := []string{
		`p1/osv failed "not_installed" files=0 scanned=[] skipped=[] of 0`,
		`p1/scalibr unknown "partial_coverage" files=4 scanned=[Go npm] skipped=[a/requirements.txt=unpinned_version b/pyproject.toml=no_lockfile] of 3`,
		`p2/scalibr failed "isolation_refused" files=0 scanned=[] skipped=[] of 0`,
		`p3/osv unknown "" files=0 scanned=[] skipped=[] of 0`,
	}
	if !slices.Equal(lines, want) {
		t.Fatalf("coverage runs:\n got  %s\n want %s", strings.Join(lines, "\n      "), strings.Join(want, "\n      "))
	}
	if !got[1].StartedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("started at %v", got[1].StartedAt)
	}
	if none, err := s.SecLatestCoverageRuns(ctx, nil, 50); err != nil || none != nil {
		t.Fatalf("no drivers: %v %v", none, err)
	}
	if capped, _ := s.SecLatestCoverageRuns(ctx, []string{"scalibr"}, 0); len(capped) != 2 || capped[0].Skipped != nil || capped[0].SkippedTotal != 3 {
		t.Fatalf("a zero cap keeps no skipped part but counts them: %+v", capped)
	}
}

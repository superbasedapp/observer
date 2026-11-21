//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// facetRowSecretEvidence is the secret's redacted excerpt in the facet
// fixture: it holds a package-like token on purpose, so a route that let a
// secret's evidence reach a search, a facet or a group would show.
const facetRowSecretEvidence = "AKIA****lodash@4.17.20****"

// seedFacetRows stores the routes' fixture (one secret, two dependency
// findings, one IaC finding in the test project; one secret in a project
// no projects row names) and returns the ids by key.
func seedFacetRows(t *testing.T, s *Server, hash, orphan string) map[string]string {
	t.Helper()
	st := store.New(s.db())
	rows := []struct {
		key, root, rule, driver, rel, evidence, msg string
		cat                                         policy.FindingCategory
		sev                                         policy.FindingSeverity
	}{
		{"s1", hash, "S-721", "native", "cmd/main.go", facetRowSecretEvidence, "A secret in a file.", policy.FindingSecret, policy.FindingSeverityHigh},
		{"d1", hash, "GHSA-1", "scalibr", "package-lock.json", "npm lodash@4.17.20", "Known vulnerability in a npm dependency (GHSA-1).", policy.FindingVulnerableDependency, policy.FindingSeverityCritical},
		{"d2", hash, "GHSA-2", "scalibr", ".github/workflows/ci.yml", "GitHub Actions tj-actions/changed-files@v45.0.0", "Known vulnerability in a GitHub Actions action (GHSA-2).", policy.FindingVulnerableDependency, policy.FindingSeverityHigh},
		{"c1", hash, "KICS-1", "kics", "infra/Dockerfile", "", "Container runs as root.", policy.FindingIaC, policy.FindingSeverityMedium},
		{"o1", orphan, "S-721", "native", "config/prod.env", "ghp_****", "A secret in a file.", policy.FindingSecret, policy.FindingSeverityHigh},
	}
	ids := map[string]string{}
	t0 := time.Now().Add(-time.Hour)
	for i, x := range rows {
		id, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
			LocalKey: x.key, Rule: secfinding.Rule{ID: x.rule}, Engine: secfinding.Engine{Driver: x.driver},
			Category: x.cat, Severity: x.sev, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Project: secfinding.Project{RootHash: x.root}, Location: secfinding.Location{RelPath: x.rel},
			EvidenceRedacted: x.evidence, Message: x.msg, Status: policy.FindingStatusOpen,
		}), t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		ids[x.key] = id
	}
	return ids
}

// getSecurityJSON GETs a route through its handler and decodes the body
// into v, returning the raw body too.
func getSecurityJSON(t *testing.T, h http.HandlerFunc, target string, v any) string {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", target, w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatal(err)
	}
	return w.Body.String()
}

// TestSecurityFindingsFilterParams: every filter parameter reaches the
// store (comma lists, the one-value project, the dependency-only
// ecosystem and package, the non-dependency language, the exact rule and
// path, q), each non-dependency row names its language, and q never
// matches a secret's evidence.
func TestSecurityFindingsFilterParams(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	orphan := secposture.ProjectRootHash("/gone/project")
	ids := seedFacetRows(t, s, hash, orphan)
	keys := map[string]string{}
	for k, id := range ids {
		keys[id] = k
	}
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"c1", "d1", "d2", "o1", "s1"}},
		{"project=" + hash, []string{"c1", "d1", "d2", "s1"}},
		{"project=" + orphan + "," + hash, []string{"c1", "d1", "d2", "o1", "s1"}},
		{"severity=critical,%20high", []string{"d1", "d2", "o1", "s1"}},
		{"category=secret,iac", []string{"c1", "o1", "s1"}},
		{"driver=kics", []string{"c1"}},
		{"baseline=pre_existing", nil},
		{"ecosystem=" + url.QueryEscape("GitHub Actions"), []string{"d2"}},
		{"ecosystem=GitHub", nil},
		{"language=go", []string{"s1"}},
		{"language=dockerfile,dotenv", []string{"c1", "o1"}},
		{"language=yaml", nil},
		{"package=lodash@4.17.20&ecosystem=npm", []string{"d1"}},
		{"rule=S-721", []string{"o1", "s1"}},
		{"path=infra/Dockerfile", []string{"c1"}},
		{"q=LODASH", []string{"d1"}},
		{"q=akia", nil},
		{"q=ghp_", nil},
		{"status=fixed_verified", nil},
		{"category=vulnerable_dependency&project=" + hash, []string{"d1", "d2"}},
	}
	for _, c := range cases {
		var p securityFindingsPage
		getSecurityJSON(t, s.handleSecurityFindings, "/api/security/findings?"+c.query, &p)
		var got []string
		for _, f := range p.Findings {
			got = append(got, keys[f.ID])
		}
		sort.Strings(got)
		if !slices.Equal(got, c.want) || p.Total != len(c.want) {
			t.Errorf("%q: %v (total %d), want %v", c.query, got, p.Total, c.want)
		}
	}
	var all securityFindingsPage
	getSecurityJSON(t, s.handleSecurityFindings, "/api/security/findings", &all)
	for _, f := range all.Findings {
		want := map[string]string{"s1": "go", "c1": "dockerfile", "o1": "dotenv", "d1": "", "d2": ""}[keys[f.ID]]
		if f.Language != want {
			t.Errorf("%s: language %q, want %q", keys[f.ID], f.Language, want)
		}
	}
}

// TestSecurityFindingsFacetsRoute: the facets read answers the filtered
// total and every facet, each counting all filters but its own, an empty
// facet as [] (never null), and no value from a secret's evidence.
func TestSecurityFindingsFacetsRoute(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	orphan := secposture.ProjectRootHash("/gone/project")
	seedFacetRows(t, s, hash, orphan)
	var resp securityFindingsFacetsJS
	raw := getSecurityJSON(t, s.handleSecurityFindingsFacets, "/api/security/findings/facets?category=vulnerable_dependency&project="+hash, &resp)
	if resp.Total != 2 {
		t.Fatalf("total %d, want 2", resp.Total)
	}
	for _, name := range store.SecFacetNames() {
		if _, ok := resp.Facets[name]; !ok {
			t.Fatalf("facet %s missing: %s", name, raw)
		}
	}
	if !strings.Contains(raw, `"language":[]`) || strings.Contains(raw, "null") {
		t.Fatalf("an empty facet is [] and nothing is null: %s", raw)
	}
	render := func(name string) string {
		var parts []string
		for _, v := range resp.Facets[name] {
			parts = append(parts, v.Value+"="+strconv.Itoa(v.Count))
		}
		return strings.Join(parts, ",")
	}
	want := map[string]string{
		"category":  "vulnerable_dependency=2,iac=1,secret=1",
		"ecosystem": "GitHub Actions=1,npm=1",
		"severity":  "critical=1,high=1",
		"driver":    "scalibr=2",
		"project":   hash + "=2",
		"status":    "open=2",
		"baseline":  "new=2",
		"language":  "",
	}
	for name, w := range want {
		if got := render(name); got != w {
			t.Errorf("facet %s = %q, want %q", name, got, w)
		}
	}
	if strings.Contains(raw, "AKIA") || strings.Contains(raw, "ghp_") {
		t.Fatalf("a facet shows a secret's evidence: %s", raw)
	}
}

// TestSecurityFindingsGroupsRoute: each grouping's keys and fields (a
// package group's ecosystem and package parsed from its evidence), the
// count of all groups and their worst severities beside one page, the
// limit cap, an unknown grouping refused, every group's drill-down
// listing exactly its findings, and no secret's evidence anywhere.
func TestSecurityFindingsGroupsRoute(t *testing.T) {
	s, root := newTestServer(t)
	hash := secposture.ProjectRootHash(root)
	orphan := secposture.ProjectRootHash("/gone/project")
	seedFacetRows(t, s, hash, orphan)
	get := func(query string) (securityFindingGroupsJS, string) {
		t.Helper()
		var resp securityFindingGroupsJS
		raw := getSecurityJSON(t, s.handleSecurityFindingsGroups, "/api/security/findings/groups?"+query, &resp)
		if strings.Contains(raw, "AKIA") || strings.Contains(raw, "ghp_") {
			t.Fatalf("%s: a group shows a secret's evidence: %s", query, raw)
		}
		return resp, raw
	}

	pkgs, _ := get("by=package")
	if pkgs.By != "package" || pkgs.Total != 2 || len(pkgs.Groups) != 2 {
		t.Fatalf("package groups: %+v", pkgs)
	}
	if g := pkgs.Groups[0]; g.Ecosystem != "npm" || g.Package != "lodash@4.17.20" || g.Key != "npm lodash@4.17.20" || g.RuleID != "" || g.MaxSeverity != "critical" {
		t.Fatalf("first package group: %+v", g)
	}
	if g := pkgs.Groups[1]; g.Ecosystem != "GitHub Actions" || g.Package != "tj-actions/changed-files@v45.0.0" {
		t.Fatalf("second package group: %+v", g)
	}

	issues, raw := get("")
	if issues.By != "issue" || issues.Total != 5 || issues.Page != 1 || issues.Limit != 50 {
		t.Fatalf("issue groups (the default): %+v", issues)
	}
	if !strings.Contains(raw, `"by_severity":{`) || strings.Contains(raw, "null") {
		t.Fatalf("no null in the groups read: %s", raw)
	}
	for _, g := range issues.Groups {
		// The drill-down (web/src/lib/codeSecurityApi.ts groupDrillDown)
		// lists exactly the group's findings.
		q := url.Values{"rule": {g.RuleID}}
		if g.Package != "" {
			q.Set("package", g.Package)
			q.Set("ecosystem", g.Ecosystem)
			if g.RelPath != "" {
				t.Fatalf("a dependency issue group carries a path: %+v", g)
			}
		} else {
			q.Set("path", g.RelPath)
			if g.Ecosystem != "" || g.Package != "" || !strings.HasSuffix(g.Key, "|path|"+g.RelPath) {
				t.Fatalf("a non-dependency issue group: %+v", g)
			}
		}
		var p securityFindingsPage
		getSecurityJSON(t, s.handleSecurityFindings, "/api/security/findings?"+q.Encode(), &p)
		if p.Total != g.Count {
			t.Errorf("issue %s: drill-down lists %d, the group counts %d", g.Key, p.Total, g.Count)
		}
	}

	one, _ := get("by=issue&limit=1&sort=count")
	if len(one.Groups) != 1 || one.Total != 5 || one.Limit != 1 {
		t.Fatalf("one page: %+v", one)
	}
	if one.BySeverity["critical"] != 1 || one.BySeverity["high"] != 3 || one.BySeverity["medium"] != 1 {
		t.Fatalf("by severity counts every group, not the page: %v", one.BySeverity)
	}
	if capped, _ := get("by=rule&limit=5000"); capped.Limit != store.SecGroupMaxLimit || capped.Total != 4 {
		t.Fatalf("limit cap: %+v", capped)
	}
	projects, _ := get("by=project")
	for _, g := range projects.Groups {
		if g.ProjectRootHash == "" || g.Key != g.ProjectRootHash || g.Message != "" || g.Category != "" {
			t.Fatalf("project group: %+v", g)
		}
	}
	for _, by := range []string{"none", "bogus"} {
		w := httptest.NewRecorder()
		s.handleSecurityFindingsGroups(w, httptest.NewRequest(http.MethodGet, "/api/security/findings/groups?by="+by, nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("by=%s: %d, want 400", by, w.Code)
		}
	}
}

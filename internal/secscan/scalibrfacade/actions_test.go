//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// actions_test.go: the GitHub Actions extractor (secciwf.ActionRefs over
// the workflow files the walker visits) and the facade's own matcher for
// the ecosystem (SCALIBR's comparator, the OSV range walk), with minimal
// records shaped like the real export's.

const (
	sha1 = "b4ffde65f46336ab88eb53be808477a3936bae11"
	sha2 = "0ad4b8fadaa221de15dcec353f45205ec38ea70b"
)

const ciWorkflow = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: tj-actions/changed-files@v45.0.0
      - uses: actions/checkout@` + sha1 + ` # v4.1.0
      - uses: actions/cache@` + sha2 + `
      - uses: Azure/setup-kubectl@v2
      - uses: actions/labeler@main
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - uses: tj-actions/changed-files@v45.0.0
  reuse:
    uses: octo-org/shared/.github/workflows/ci.yml@v1.2.3
`

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func actionsProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, ".github/workflows/ci.yml", ciWorkflow)
	writeFile(t, root, "sub/.github/workflows/lint.yaml", "on: push\njobs:\n  l:\n    runs-on: x\n    steps:\n      - uses: reviewdog/action-setup@v1\n")
	writeFile(t, root, "node_modules/pkg/.github/workflows/x.yml", "jobs:\n  a:\n    steps:\n      - uses: evil/action@v1.0.0\n")
	writeFile(t, root, ".github/workflows/README.md", "uses: not/a-workflow@v1.0.0\n")
	writeFile(t, root, ".github/actions/setup/action.yml", "runs:\n  using: composite\n")
	return root
}

func TestActionsExtract(t *testing.T) {
	root := actionsProject(t)
	writeFile(t, root, ".github/workflows/broken.yml", "jobs: [unclosed\n")
	writeFile(t, root, ".github/workflows/huge.yaml", "jobs: {}\n"+strings.Repeat("# pad\n", 100_000))
	inv, err := Extract(context.Background(), root, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range inv.Packages {
		if p.Ecosystem != "GitHub Actions" {
			t.Fatalf("unexpected package %+v", p)
		}
		if _, dup := got[p.Name+"@"+p.Version]; dup {
			t.Fatalf("%s listed twice in one file", p.Name)
		}
		got[p.Name+"@"+p.Version] = p
	}
	want := map[string]func(Package) bool{
		"tj-actions/changed-files@v45.0.0": func(p Package) bool {
			return p.Path == ".github/workflows/ci.yml" && p.Line == 7 && !p.MovingTag && !p.VersionFromComment
		},
		"actions/checkout@v4.1.0":   func(p Package) bool { return p.VersionFromComment && !p.MovingTag && p.Line == 8 },
		"actions/cache@":            func(p Package) bool { return p.PinnedBySHA },
		"azure/setup-kubectl@v2":    func(p Package) bool { return p.MovingTag },
		"actions/labeler@main":      func(p Package) bool { return p.NotAVersion },
		"octo-org/shared@v1.2.3":    func(p Package) bool { return p.Line == 16 },
		"reviewdog/action-setup@v1": func(p Package) bool { return p.Path == "sub/.github/workflows/lint.yaml" && p.MovingTag },
	}
	if len(got) != len(want) {
		t.Fatalf("packages %v, want %d", got, len(want))
	}
	for k, ok := range want {
		p, has := got[k]
		if !has || !ok(p) {
			t.Errorf("%s: %+v (present %v)", k, p, has)
		}
	}
	var st *Status
	for i := range inv.Statuses {
		if inv.Statuses[i].Extractor == actionsExtractorName {
			st = &inv.Statuses[i]
		}
	}
	if st == nil || st.OK || strings.Join(st.Files, ",") != ".github/workflows/broken.yml,.github/workflows/huge.yaml" {
		t.Fatalf("the unparsable and the over-cap workflow must fail the extractor on those files: %+v", st)
	}
	infos, err := Extractors()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, i := range infos {
		if i.Name == actionsExtractorName {
			found = i.Ecosystem == "GitHub Actions" && i.RequiresOS == "any"
		}
	}
	if !found {
		t.Fatal("the actions extractor is not in the table with its ecosystem")
	}
}

// Records shaped like the real GitHub Actions export (2026-11-04).
const (
	ghaChangedFiles = `{"id":"GHSA-mrrh-fwg8-r2c3","aliases":["CVE-2025-30066"],"affected":[{"package":{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"46.0.1"}]}]}],"database_specific":{"severity":"HIGH"}}`
	ghaKubectl = `{"id":"GHSA-p756-rfxh-x63h","affected":[{"package":{"name":"Azure/setup-kubectl","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3"}]}]}],"database_specific":{"severity":"MODERATE"}}`
	ghaReviewdog = `{"id":"GHSA-qmg3-hpqr-gqvc","affected":[{"package":{"name":"reviewdog/action-setup","ecosystem":"GitHub Actions"},"versions":["1"]}]}`
	ghaCheckout  = `{"id":"GHSA-0000-0000-0001","affected":[{"package":{"name":"actions/checkout","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.0.0"},{"last_affected":"4.1.0"}]}]}]}`
	ghaWithdrawn = `{"id":"GHSA-0000-0000-0002","withdrawn":"2026-09-24T20:05:24Z","affected":[{"package":{"name":"octo-org/shared","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`
	ghaOtherEco = `{"id":"GHSA-0000-0000-0003","affected":[{"package":{"name":"octo-org/shared","ecosystem":"npm"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`
	ghaGitOnly = `{"id":"GHSA-0000-0000-0004","affected":[{"package":{"name":"octo-org/shared","ecosystem":"GitHub Actions"},
"ranges":[{"type":"GIT","repo":"https://github.com/octo-org/shared","events":[{"introduced":"0"},{"fixed":"` + sha1 + `"}]}]}]}`
	ghaMalformed = `{"id":"GHSA-0000-0000-0005","affected":[{"package":{"name":"octo-org/shared","ecosystem":"GitHub Actions"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":0}]}]}]}`
	ghaBadEvent  = `{"id":"GHSA-0000-0000-0006","affected":[{"package":{"name":"octo-org/shared","ecosystem":"GitHub Actions"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{}]}]}]}`
)

func TestActionsMatch(t *testing.T) {
	inv, err := Extract(context.Background(), actionsProject(t), ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	db := t.TempDir()
	var idx []int
	for i := range inv.Packages {
		idx = append(idx, i)
	}
	req := MatchRequest{Ecosystem: "GitHub Actions", Indices: idx, Canary: &Canary{Name: "tj-actions/changed-files", Version: "v45.0.0"}}
	if _, err := Match(context.Background(), inv, req, MatchOptions{DBDir: db}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("no export must answer ErrNoDatabase, got %v", err)
	}
	writeDB(t, db, "GitHub Actions", map[string]string{
		"a.json": ghaChangedFiles, "b.json": ghaKubectl, "c.json": ghaReviewdog, "d.json": ghaCheckout,
		"e.json": ghaWithdrawn, "f.json": ghaOtherEco, "g.json": ghaGitOnly, "h.json": ghaMalformed, "i.json": ghaBadEvent,
		"not-json.txt": "x", "j.json": "{not json",
	})
	res, err := Match(context.Background(), inv, req, MatchOptions{DBDir: db})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CanaryHit || res.Matcher != "observer/osvranges" {
		t.Fatalf("canary %v matcher %q", res.CanaryHit, res.Matcher)
	}
	byName := map[string][]string{}
	for _, v := range res.Vulns {
		byName[inv.Packages[v.Index].Name] = append(byName[inv.Packages[v.Index].Name], v.ID)
	}
	want := map[string]string{
		"tj-actions/changed-files": "GHSA-mrrh-fwg8-r2c3",
		"azure/setup-kubectl":      "GHSA-p756-rfxh-x63h",
		"reviewdog/action-setup":   "GHSA-qmg3-hpqr-gqvc",
		"actions/checkout":         "GHSA-0000-0000-0001",
	}
	if len(byName) != len(want) {
		t.Fatalf("vulns %v, want %v", byName, want)
	}
	for name, id := range want {
		if strings.Join(byName[name], ",") != id {
			t.Errorf("%s: %v, want %s", name, byName[name], id)
		}
	}
	for _, v := range res.Vulns {
		if v.ID == "GHSA-mrrh-fwg8-r2c3" && (v.Severity != "HIGH" || len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2025-30066") {
			t.Fatalf("advisory fields %+v", v)
		}
	}
	// A database that does not flag its canary: the self-test fails.
	db2 := t.TempDir()
	writeDB(t, db2, "GitHub Actions", map[string]string{"b.json": ghaKubectl})
	if res, err := Match(context.Background(), inv, req, MatchOptions{DBDir: db2}); err != nil || res.CanaryHit {
		t.Fatalf("a database without the canary's advisory: %+v %v", res, err)
	}
	// Online matching is never this matcher's.
	if _, err := Match(context.Background(), inv, req, MatchOptions{Online: true}); err == nil {
		t.Fatal("online matching of GitHub Actions must be refused")
	}
	// A rebuilt inventory (the online path's NewInventory) still matches by
	// the plain rows, never handing the ecosystem to osvlocal.
	if res, err := Match(context.Background(), NewInventory(inv.Packages), req, MatchOptions{DBDir: db}); err != nil || len(res.Vulns) != len(want) {
		t.Fatalf("rebuilt inventory: %+v %v", res, err)
	}
}

// TestSemverCompare pins SCALIBR's comparator on tag shapes: a leading v
// either case, a moving tag reads as its lowest member.
func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v45.0.0", "46.0.1", -1},
		{"V46.0.1", "46.0.1", 0},
		{"v4", "4.0.0", 0},
		{"v4.1", "4.0.9", 1},
		{"v2", "3", -1},
		{"v1.0.0a0", "1.0.0", -1},
		{"main", "0.0.1", -1},
	}
	for _, c := range cases {
		got := semverCompare(c.a, c.b)
		if (got < 0 && c.want >= 0) || (got > 0 && c.want <= 0) || (got == 0 && c.want != 0) {
			t.Errorf("compare(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

// TestRangeAffects walks the OSV range algorithm, one case per event shape.
func TestRangeAffects(t *testing.T) {
	ev := func(kv ...string) []osvEvent {
		var out []osvEvent
		for i := 0; i+1 < len(kv); i += 2 {
			var e osvEvent
			switch kv[i] {
			case "i":
				e.Introduced = kv[i+1]
			case "f":
				e.Fixed = kv[i+1]
			case "l":
				e.LastAffected = kv[i+1]
			case "x":
				e.Limit = kv[i+1]
			}
			out = append(out, e)
		}
		return out
	}
	cases := []struct {
		name   string
		events []osvEvent
		v      string
		want   bool
	}{
		{"introduced 0 fixed: below", ev("i", "0", "f", "46.0.1"), "v45.0.0", true},
		{"introduced 0 fixed: at the fix", ev("i", "0", "f", "46.0.1"), "v46.0.1", false},
		{"introduced above", ev("i", "1.13.2", "f", "1.13.6"), "v1.13.0", false},
		{"inside", ev("i", "1.13.2", "f", "1.13.6"), "v1.13.5", true},
		{"last_affected inclusive", ev("i", "0", "l", "3.0.0"), "v3.0.0", true},
		{"past last_affected", ev("i", "0", "l", "3.0.0"), "v3.0.1", false},
		{"two ranges in one, unsorted", ev("f", "6", "i", "4", "f", "3", "i", "0"), "v5", true},
		{"between two ranges", ev("i", "0", "f", "3", "i", "4", "f", "6"), "v3.5", false},
		{"limit", ev("i", "0", "x", "2.0.0"), "v2.1.0", false},
		{"under the limit", ev("i", "0", "x", "2.0.0"), "v1.9.0", true},
		{"open range", ev("i", "4.0.0"), "v9", true},
		{"no events", nil, "v1", false},
		{"an empty event refuses the range", []osvEvent{{Introduced: "0"}, {}}, "v1", false},
		{"a version with a space refuses the range", ev("i", "0", "f", "1 2"), "v1", false},
	}
	for _, c := range cases {
		if got := rangeAffects(semverCompare, c.events, c.v); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	if !exactVersion([]string{"v1.14.2", "1"}, "v1") || !exactVersion([]string{"v1.14.2"}, "1.14.2") || exactVersion([]string{"1.14"}, "v1.14.2") {
		t.Fatal("exact versions match with a leading v tolerated, nothing else")
	}
}

// TestRecordAffectsNeverPanics: a comparator that panics answers "not
// affected" for that record; the scan goes on.
func TestRecordAffectsNeverPanics(t *testing.T) {
	m := ownMatcher{name: "t", compare: func(string, string) int { panic("boom") }}
	rec := osvRecord{ID: "X", Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "1"}}}}}}}
	rec.Affected[0].Package.Ecosystem, rec.Affected[0].Package.Name = "GitHub Actions", "a/b"
	if recordAffects(m, rec, "GitHub Actions", ownTarget{name: "a/b", version: "v2"}) {
		t.Fatal("a panicking evaluation must answer not affected")
	}
}

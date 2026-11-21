//go:build !sbo_omit_security && !sbo_omit_security_deps

package dashboard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityExtractorPatterns is one case per shape of the facade
// table's Files words: a plain list, a parenthetical (with a comma inside
// it), a bare "*.ext" read in the directory before it, prose and directory
// names dropped.
func TestSecurityExtractorPatterns(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"package-lock.json, npm-shrinkwrap.json", []string{"package-lock.json", "npm-shrinkwrap.json"}},
		{"go.mod (with go.sum)", []string{"go.mod"}},
		{"obj/project.assets.json (the packages NuGet restored, transitive ones included)", []string{"obj/project.assets.json"}},
		{"*.csproj, *.fsproj, *.vbproj (a PackageReference with no version takes it from the nearest Directory.Packages.props)", []string{"*.csproj", "*.fsproj", "*.vbproj"}},
		{".github/workflows/*.yml, *.yaml", []string{".github/workflows/*.yml", ".github/workflows/*.yaml"}},
		{"libs.versions.toml, gradle/*.versions.toml (declared versions)", []string{"libs.versions.toml", "gradle/*.versions.toml"}},
		{"*.jar, *.war, *.ear and other Java archives", []string{"*.jar", "*.war", "*.ear"}},
		{"*.whl, *.egg, *.dist-info/METADATA, *.egg-info/PKG-INFO", []string{"*.whl", "*.egg", "*.dist-info/METADATA", "*.egg-info/PKG-INFO"}},
		{"executables under bin/, dist/, target/release/ and --artifacts directories (Go build info)", nil},
		{"", nil},
	}
	for _, c := range cases {
		if got := securityExtractorPatterns(c.text); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.text, got, c.want)
		}
	}
}

// coverageTestServer is a test server whose config lives in a fresh home
// (no database installed), with the given extractor seam.
func coverageTestServer(t *testing.T, extractors func() []dashapi.SecurityExtractor) (*Server, string) {
	t.Helper()
	s, root := newTestServer(t)
	cfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.opts.ConfigPath = cfg
	if extractors != nil {
		s.opts.SecurityScanNow = &dashapi.SecurityScanNow{Extractors: extractors}
	}
	return s, root
}

// TestSecurityCoverageSupported: every ecosystem the drivers scan, in the
// extractor table's order, then every one Observer finds but cannot check,
// each with its files, the drivers this build carries, its advisory source
// and an honest note; nothing installed on a fresh home.
func TestSecurityCoverageSupported(t *testing.T) {
	s, _ := coverageTestServer(t, func() []dashapi.SecurityExtractor {
		return []dashapi.SecurityExtractor{
			{Kind: "lockfile", Ecosystem: "npm", Files: "package-lock.json, npm-shrinkwrap.json"},
			{Kind: "manifest", Ecosystem: "GitHub Actions", Files: ".github/workflows/*.yml, *.yaml"},
			{Kind: "lockfile", Ecosystem: "Go", Files: "go.mod (with go.sum)"},
			{Kind: depscan.ArtifactKind, Ecosystem: "Go", Files: "executables under bin/, dist/, target/release/ and --artifacts directories (Go build info)"},
		}
	})
	var resp securityCoverageResponse
	raw := getSecurityJSON(t, s.handleSecurityCoverage, "/api/security/coverage", &resp)
	if strings.Contains(raw, "null") {
		t.Fatalf("no array is null: %s", raw)
	}
	var ecos []string
	by := map[string]securityCoverageSupportedJS{}
	for _, r := range resp.Supported {
		ecos = append(ecos, r.Ecosystem)
		by[r.Ecosystem] = r
		if r.DatabaseInstalled {
			t.Errorf("%s reads installed on a fresh home", r.Ecosystem)
		}
	}
	wantOrder := []string{"npm", "GitHub Actions", "Go"}
	for _, eco := range depscan.Ecosystems() {
		if !slices.Contains(wantOrder, eco) {
			wantOrder = append(wantOrder, eco)
		}
	}
	wantOrder = append(wantOrder, "CocoaPods", "opam", "GIT", "ConanCenter", "vcpkg")
	if !slices.Equal(ecos, wantOrder) {
		t.Fatalf("supported order:\n got  %v\n want %v", ecos, wantOrder)
	}
	drivers := func(eco string) []string {
		out := []string{}
		if scalibrDriverCompiled {
			out = append(out, depscan.ScalibrID)
		}
		if osvDriverCompiled && depscan.OSVScannerReads(eco) {
			out = append(out, depscan.OSVID)
		}
		return out
	}
	for _, eco := range depscan.Ecosystems() {
		r := by[eco]
		if r.AdvisorySource != "OSV "+eco || r.OnlineOnly || !slices.Equal(r.Drivers, drivers(eco)) || len(r.Files)+len(r.UnreadFiles) == 0 {
			t.Errorf("%s: %+v", eco, r)
		}
	}
	npm := by["npm"]
	if !slices.Equal(npm.Files[:2], []string{"package-lock.json", "npm-shrinkwrap.json"}) {
		t.Fatalf("npm files lead with the extractor's own: %v", npm.Files)
	}
	// A manifest checked only through its lockfile, and a file no extractor
	// reads, are found but never listed as read.
	for _, f := range []string{"package.json", "bun.lockb"} {
		if slices.Contains(npm.Files, f) || !slices.Contains(npm.UnreadFiles, f) {
			t.Errorf("npm %s: files %v, unread %v", f, npm.Files, npm.UnreadFiles)
		}
	}
	if !slices.Equal(by["GitHub Actions"].Files, []string{".github/workflows/*.yml", ".github/workflows/*.yaml"}) {
		t.Fatalf("GitHub Actions files: %v", by["GitHub Actions"].Files)
	}
	if !slices.Equal(by["Go"].Files, []string{"go.mod"}) {
		t.Fatalf("Go files (the artifact row's words name no file): %v", by["Go"].Files)
	}
	for _, c := range []struct {
		eco, source, note string
		online            bool
		file              string
	}{
		{"ConanCenter", "", depscan.ReasonWords(depscan.ReasonNoAdvisoryData), false, "conanfile.txt"},
		{"vcpkg", "", depscan.ReasonWords(depscan.ReasonNoAdvisoryData), false, "vcpkg.json"},
		{"GIT", "OSV GIT", depscan.ReasonWords(depscan.ReasonNeedsOnline), true, ".gitmodules"},
		{"CocoaPods", "", depscan.ReasonWords(depscan.ReasonNoAdvisoryData), false, "Podfile.lock"},
		{"opam", "", advisoriesPublishedWords, false, "*.opam"},
	} {
		r := by[c.eco]
		if r.AdvisorySource != c.source || r.Note != c.note || r.OnlineOnly != c.online || r.DatabaseInstalled {
			t.Errorf("%s: %+v", c.eco, r)
		}
		// The online lookup reads its own file; every other row's files are
		// found but not read.
		if c.online && !slices.Contains(r.Files, c.file) || !c.online && (len(r.Files) != 0 || !slices.Contains(r.UnreadFiles, c.file)) {
			t.Errorf("%s: %+v", c.eco, r)
		}
		if !c.online && len(r.Drivers) != 0 {
			t.Errorf("%s: no driver checks it, yet drivers %v", c.eco, r.Drivers)
		}
	}

	// Without the seam the list is the same ecosystems, sorted, each still
	// with the manifest and dependency-file tables' files.
	bare, _ := coverageTestServer(t, nil)
	var plain securityCoverageResponse
	getSecurityJSON(t, bare.handleSecurityCoverage, "/api/security/coverage", &plain)
	if len(plain.Supported) != len(resp.Supported) || plain.Supported[0].Ecosystem != depscan.Ecosystems()[0] {
		t.Fatalf("supported without the seam: %+v", plain.Supported)
	}
	for _, r := range plain.Supported {
		if len(r.UnreadFiles) != 0 {
			t.Errorf("without the seam nothing says what the drivers read, so %s lists no unread file: %+v", r.Ecosystem, r)
		}
	}
}

// TestSecurityCoverageProjects: the newest scalibr and osv run per project
// (other drivers left out), skipped parts capped at 50 with the total, an
// active project listed with no runs yet, a hash no project names listed
// unnamed and idle, and the reasons' words (the legend's and every named
// reason that has words).
func TestSecurityCoverageProjects(t *testing.T) {
	s, root := coverageTestServer(t, nil)
	st := store.New(s.db())
	ctx := context.Background()
	hash := secposture.ProjectRootHash(root)
	orphan := secposture.ProjectRootHash("/gone/project")
	var skipped []map[string]string
	for i := 0; i < 60; i++ {
		skipped = append(skipped, map[string]string{"Path": fmt.Sprintf("svc%02d/requirements.txt", i), "Reason": depscan.ReasonUnpinned})
	}
	t0 := time.Now().Add(-time.Hour).UTC()
	for i, r := range []store.SecScanRun{
		{ProjectRootHash: hash, Driver: depscan.ScalibrID, Outcome: "clean", Coverage: map[string]any{"Outcome": "clean", "Scanned": []string{"npm"}}},
		{ProjectRootHash: hash, Driver: depscan.ScalibrID, Outcome: "unknown", Coverage: map[string]any{
			"Outcome": "unknown", "Reason": "partial_coverage", "FilesScanned": 61, "Scanned": []string{"Go", "npm"}, "Skipped": skipped,
		}},
		{ProjectRootHash: hash, Driver: "opengrep", Outcome: "clean"},
		{ProjectRootHash: orphan, Driver: depscan.OSVID, Outcome: "not_scanned", Coverage: map[string]any{"Outcome": "not_scanned", "Reason": depscan.ReasonNotInstalled}},
	} {
		r.Scope, r.StartedAt = policy.FindingScopeScheduled, t0.Add(time.Duration(i)*time.Minute)
		if err := st.InsertSecScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	var resp securityCoverageResponse
	raw := getSecurityJSON(t, s.handleSecurityCoverage, "/api/security/coverage", &resp)
	if strings.Contains(raw, "null") {
		t.Fatalf("no array is null: %s", raw)
	}
	by := map[string]securityCoverageProjectJS{}
	for _, p := range resp.Projects {
		by[p.ProjectRootHash] = p
	}
	p, ok := by[hash]
	if !ok || !p.Active || p.Name != filepath.Base(root) || p.ProjectID == 0 || len(p.Runs) != 1 {
		t.Fatalf("project: %+v", p)
	}
	run := p.Runs[0]
	if run.Driver != depscan.ScalibrID || run.Outcome != "unknown" || run.Reason != "partial_coverage" || run.FilesScanned != 61 ||
		!slices.Equal(run.Scanned, []string{"Go", "npm"}) || len(run.Skipped) != securityCoverageMaxSkipped || run.SkippedTotal != 60 ||
		run.Skipped[0].Path != "svc00/requirements.txt" || run.Skipped[0].Reason != depscan.ReasonUnpinned {
		t.Fatalf("run: %+v", run)
	}
	if _, err := time.Parse(time.RFC3339, run.StartedAt); err != nil {
		t.Fatalf("started_at %q: %v", run.StartedAt, err)
	}
	o, ok := by[orphan]
	if !ok || o.Active || o.Name != "" || o.ProjectID != 0 || len(o.Runs) != 1 || o.Runs[0].Driver != depscan.OSVID || o.Runs[0].Reason != depscan.ReasonNotInstalled {
		t.Fatalf("orphan: %+v", o)
	}
	for _, reason := range append(append([]string(nil), securityCoverageLegend...), depscan.ReasonNotInstalled) {
		if resp.Reasons[reason] != depscan.ReasonWords(reason) || resp.Reasons[reason] == reason {
			t.Errorf("reason %s: %q", reason, resp.Reasons[reason])
		}
	}
	if _, ok := resp.Reasons["partial_coverage"]; ok {
		t.Errorf("a reason depscan has no words for is left out: %v", resp.Reasons)
	}

	// An active project with no dependency run yet is listed, runs [].
	fresh, freshRoot := coverageTestServer(t, nil)
	var none securityCoverageResponse
	getSecurityJSON(t, fresh.handleSecurityCoverage, "/api/security/coverage", &none)
	if len(none.Projects) != 1 || none.Projects[0].ProjectRootHash != secposture.ProjectRootHash(freshRoot) || !none.Projects[0].Active || len(none.Projects[0].Runs) != 0 {
		t.Fatalf("a project with no run: %+v", none.Projects)
	}
}

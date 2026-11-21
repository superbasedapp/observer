//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

func writeDB(t *testing.T, dir, eco string, entries map[string]string) {
	t.Helper()
	p := filepath.Join(dir, "osv-scalibr", eco, "all.zip")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// The fixture database flags the npm canary (lodash 4.17.20) and the
// hoisted workspace dependency @babel/core 7.29.0.
const lodash = `{"id":"GHSA-35jh-r3h4-6jhm","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],
"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
"database_specific":{"severity":"HIGH"}}`

const babel = `{"id":"GHSA-4x5r-pxfx-6jf8","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"npm","name":"@babel/core"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"7.29.6"}]}]}]}`

// A PyPI database that does NOT flag the canary: a stale or broken export.
const unrelated = `{"id":"PYSEC-0000-1","modified":"2024-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"PyPI","name":"nothing-here"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`

func fixtureRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "scalibrfacade", "testdata", "project"))
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestRunPerEcosystem(t *testing.T) {
	db := t.TempDir()
	writeDB(t, db, "npm", map[string]string{"a.json": lodash, "b.json": babel})
	writeDB(t, db, "PyPI", map[string]string{"c.json": unrelated})
	resp := Run(context.Background(), depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Root: fixtureRoot(t), DBDir: db,
		Epochs: map[string]string{"npm": "npm-epoch", "PyPI": "pypi-epoch"}, GOOS: "linux",
	}, nil)
	if resp.Error != "" || !resp.Compiled {
		t.Fatalf("resp %+v", resp)
	}
	got := map[string]depscan.EcoResult{}
	for _, e := range resp.Ecosystems {
		got[e.Ecosystem] = e
	}
	if e := got["npm"]; e.Outcome != depscan.EcoScanned || e.Epoch != "npm-epoch" || len(e.Advisories) != 2 {
		t.Fatalf("npm %+v: scanned with two advisories (lodash and the restored @babel/core)", e)
	}
	if e := got["PyPI"]; e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonSelfTestFailed {
		t.Fatalf("PyPI %+v: a database that misses its canary is not scanned", e)
	}
	if e := got["Go"]; e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonNoDatabase {
		t.Fatalf("Go %+v: no database is not scanned for Go only", e)
	}
	if resp.Dropped["empty_version"] != 1 || resp.Dropped["root_project"] == 0 {
		t.Fatalf("dropped %v: flask (no pin) and the workspace's own package.json", resp.Dropped)
	}
	for _, x := range resp.Extractors {
		if x.Ecosystem == "" {
			t.Fatalf("extractor %+v carries no ecosystem", x)
		}
	}
	cov := depscan.Coverage(depscan.RunFacts{Ecosystems: resp.Ecosystems, Findings: 2})
	if cov.Outcome != secscan.OutcomeFindings || cov.Reason != "partial_coverage" {
		t.Fatalf("coverage %+v", cov)
	}
}

func TestRunRefusesOtherProtocol(t *testing.T) {
	if r := Run(context.Background(), depscan.ChildRequest{Version: 99}, nil); r.Error == "" {
		t.Fatal("a request with another protocol version must be refused")
	}
}

// The GitHub Actions export's canary record and one other, shaped like the
// real export (OSV ecosystem "GitHub Actions", ECOSYSTEM ranges).
const (
	ghaCanary = `{"id":"GHSA-mrrh-fwg8-r2c3","aliases":["CVE-2025-30066"],"affected":[{"package":{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"46.0.1"}]}]}],"database_specific":{"severity":"HIGH"}}`
	ghaKubectl = `{"id":"GHSA-p756-rfxh-x63h","affected":[{"package":{"name":"Azure/setup-kubectl","ecosystem":"GitHub Actions"},
"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3"}]}]}],"database_specific":{"severity":"MODERATE"}}`
)

// TestRunGitHubActions: the actions a workflow uses are one more ecosystem
// of the child's inventory, matched by the facade's own matcher, with the
// self-test, the SHA gap and a missing database exactly like any other.
func TestRunGitHubActions(t *testing.T) {
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(wf), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n" +
		"      - uses: azure/setup-kubectl@v2\n" +
		"      - uses: actions/cache@0ad4b8fadaa221de15dcec353f45205ec38ea70b\n"
	if err := os.WriteFile(wf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(db string, epochs map[string]string) (depscan.ChildResponse, depscan.EcoResult) {
		resp := Run(context.Background(), depscan.ChildRequest{Version: depscan.ProtocolVersion, Root: root, DBDir: db, Epochs: epochs, GOOS: "linux"}, nil)
		if resp.Error != "" {
			t.Fatalf("resp %+v", resp)
		}
		for _, e := range resp.Ecosystems {
			if e.Ecosystem == "GitHub Actions" {
				return resp, e
			}
		}
		t.Fatalf("no GitHub Actions row: %+v", resp.Ecosystems)
		return resp, depscan.EcoResult{}
	}
	db := t.TempDir()
	writeDB(t, db, "GitHub Actions", map[string]string{"a.json": ghaCanary, "b.json": ghaKubectl})
	resp, e := run(db, map[string]string{"GitHub Actions": "gha-epoch"})
	if e.Outcome != depscan.EcoScanned || e.Epoch != "gha-epoch" || len(e.Advisories) != 1 || e.Advisories[0].ID != "GHSA-p756-rfxh-x63h" {
		t.Fatalf("GitHub Actions %+v", e)
	}
	if p := resp.Packages[e.Advisories[0].Index]; p.Name != "azure/setup-kubectl" || !p.MovingTag || p.Line != 6 || p.Path != ".github/workflows/ci.yml" {
		t.Fatalf("matched package %+v", p)
	}
	if resp.Dropped["sha_no_version"] != 1 {
		t.Fatalf("dropped %v: the SHA pin with no comment is a gap", resp.Dropped)
	}
	final, gaps := depscan.Finalize(resp)
	if len(gaps) != 1 || gaps[0].Reason != depscan.ReasonPinnedBySHA || gaps[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("gaps %+v", gaps)
	}
	if cov := depscan.Coverage(depscan.RunFacts{Ecosystems: final.Ecosystems, Gaps: gaps, Findings: 1}); cov.Outcome != secscan.OutcomeFindings || len(cov.Scanned) != 0 {
		t.Fatalf("coverage %+v: a gap keeps the ecosystem out of Scanned", cov)
	}
	// A database that misses the canary did not load: not scanned.
	db2 := t.TempDir()
	writeDB(t, db2, "GitHub Actions", map[string]string{"b.json": ghaKubectl})
	if _, e := run(db2, map[string]string{"GitHub Actions": "x"}); e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonSelfTestFailed {
		t.Fatalf("no canary hit: %+v", e)
	}
	// No database installed: not scanned for GitHub Actions only.
	if _, e := run(db2, map[string]string{}); e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonNoDatabase {
		t.Fatalf("no database: %+v", e)
	}
}

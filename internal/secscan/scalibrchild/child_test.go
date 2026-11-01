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

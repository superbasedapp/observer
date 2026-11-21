//go:build !sbo_omit_security_scan_scalibr

package scalibrchild

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// TestRunSBOM (security coverage gaps plan item 2): an SBOM request
// matches only its own rows, through the same per-ecosystem table and
// canary as a project scan, and extracts nothing.
func TestRunSBOM(t *testing.T) {
	db := t.TempDir()
	writeDB(t, db, "npm", map[string]string{"a.json": lodash, "b.json": babel})
	resp := Run(context.Background(), depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Kind: depscan.KindSBOM, DBDir: db,
		Epochs: map[string]string{"npm": "npm-epoch"}, GOOS: "linux",
		Packages: []depscan.Package{
			{Ecosystem: "npm", Name: "@babel/core", Version: "7.29.0", Path: "bom.json", Extractor: "sbom:cyclonedx"},
			{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "bom.json", Extractor: "sbom:cyclonedx"},
			{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0", Path: "bom.json", Extractor: "sbom:cyclonedx"},
		},
	}, nil)
	if resp.Error != "" || resp.Kind != depscan.KindSBOM || len(resp.Extractors) != 0 {
		t.Fatalf("resp %+v", resp)
	}
	if len(resp.Packages) != 3 {
		t.Fatalf("packages %v", resp.Packages)
	}
	got := map[string]depscan.EcoResult{}
	for _, e := range resp.Ecosystems {
		got[e.Ecosystem] = e
	}
	if e := got["npm"]; e.Outcome != depscan.EcoScanned || len(e.Advisories) != 1 || e.Packages != 2 {
		t.Fatalf("npm %+v: one advisory, for @babel/core only", e)
	}
	if e := got["PyPI"]; e.Outcome != depscan.EcoNotScanned || e.Reason != depscan.ReasonNoDatabase {
		t.Fatalf("PyPI %+v", e)
	}
}

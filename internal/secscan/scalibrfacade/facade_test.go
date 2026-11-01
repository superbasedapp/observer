//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"archive/zip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeDB writes one ecosystem's database zip in the layout osvlocal reads
// (<dir>/osv-scalibr/<Ecosystem>/all.zip).
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
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

const npmAdvisories = `{"id":"GHSA-35jh-r3h4-6jhm","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],
"affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}],
"database_specific":{"severity":"HIGH"}}`

const npmBabel = `{"id":"GHSA-4x5r-pxfx-6jf8","modified":"2026-01-01T00:00:00Z",
"affected":[{"package":{"ecosystem":"npm","name":"@babel/core"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"7.29.6"}]}]}],
"database_specific":{"severity":"MODERATE"}}`

func extractFixture(t *testing.T) *Inventory {
	t.Helper()
	inv, err := Extract(context.Background(), filepath.Join("testdata", "project"), ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func find(inv *Inventory, eco, name string) (int, bool) {
	for i, p := range inv.Packages {
		if p.Ecosystem == eco && p.Name == name {
			return i, true
		}
	}
	return -1, false
}

func TestExtractorsTableIsClosedAndOSIndependent(t *testing.T) {
	rows, err := Extractors()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(extractorTable) || len(rows) != 20 {
		t.Fatalf("got %d rows, want the 20-row table", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Name == "" || r.Ecosystem == "" || (r.Kind != "lockfile" && r.Kind != "manifest") {
			t.Errorf("malformed row %+v", r)
		}
		if seen[r.Name] {
			t.Errorf("duplicate extractor %s", r.Name)
		}
		seen[r.Name] = true
		if r.RequiresOS != "any" {
			t.Errorf("%s declares OS %q; the Platforms row assumes every extractor is OS-independent", r.Name, r.RequiresOS)
		}
		if _, ok := purlTypes[r.Ecosystem]; !ok {
			t.Errorf("%s feeds %q, which has no canary PURL type", r.Name, r.Ecosystem)
		}
	}
}

func TestExtractFixture(t *testing.T) {
	inv := extractFixture(t)
	for _, want := range []struct{ eco, name, version string }{
		{"npm", "lodash", "4.17.20"},
		{"npm", "@babel/core", "7.29.0"},
		{"PyPI", "requests", "2.19.0"},
		{"Go", "golang.org/x/text", "v0.3.5"},
	} {
		i, ok := find(inv, want.eco, want.name)
		if !ok {
			t.Errorf("%s %s not extracted: %+v", want.eco, want.name, inv.Packages)
			continue
		}
		p := inv.Packages[i]
		if p.Version != want.version && "v"+p.Version != want.version {
			t.Errorf("%s version %q, want %q", want.name, p.Version, want.version)
		}
		if filepath.IsAbs(p.Path) {
			t.Errorf("%s path %q is absolute; paths must be relative to the root", want.name, p.Path)
		}
	}
	for _, s := range inv.Statuses {
		if !s.OK {
			t.Errorf("extractor %s failed: %s", s.Extractor, s.Detail)
		}
	}
}

// TestNPMLockRule is the fixture test of the LOCAL false negative, with
// entries taken from this repository's root package-lock.json (hoisted
// workspace dependencies written with no "resolved").
func TestNPMLockRule(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "project", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := RegistryEntries(b)
	for _, id := range []string{"@babel/core@7.29.0", "esbuild@0.21.5", "vite@5.4.21"} {
		if !reg[id] {
			t.Errorf("%s: a hoisted workspace dependency with no resolved field must be a registry package", id)
		}
	}
	for _, id := range []string{"fixture-web@0.1.0", "localdep@2.0.0", "lodash@4.17.20", "fixture-root@1.0.0"} {
		if reg[id] {
			t.Errorf("%s: a workspace member, file dependency or already resolved entry must not be restored", id)
		}
	}
	inv := extractFixture(t)
	i, ok := find(inv, "npm", "@babel/core")
	if !ok || !inv.Packages[i].Restored || inv.Packages[i].Local {
		t.Fatalf("@babel/core not restored: %+v", inv.Packages[i])
	}
	if i, ok := find(inv, "npm", "lodash"); !ok || inv.Packages[i].Restored {
		t.Fatalf("lodash came with its registry source and needs no rule")
	}
}

func indices(inv *Inventory, eco string) []int {
	var out []int
	for i, p := range inv.Packages {
		if p.Ecosystem == eco {
			out = append(out, i)
		}
	}
	return out
}

func TestMatchLocalOffline(t *testing.T) {
	inv := extractFixture(t)
	db := t.TempDir()
	writeDB(t, db, "npm", map[string]string{"GHSA-35jh-r3h4-6jhm.json": npmAdvisories, "GHSA-4x5r-pxfx-6jf8.json": npmBabel})
	res, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "npm", Indices: indices(inv, "npm"), Canary: &Canary{Name: "lodash", Version: "4.17.20"}}, MatchOptions{DBDir: db})
	if err != nil {
		t.Fatal(err)
	}
	if !res.CanaryHit {
		t.Error("the canary must match the planted advisory")
	}
	var names []string
	for _, v := range res.Vulns {
		p := inv.Packages[v.Index]
		names = append(names, p.Name+"="+v.ID)
		if v.ID == "GHSA-35jh-r3h4-6jhm" && (v.Severity != "HIGH" || !slices.Contains(v.Aliases, "CVE-2021-23337")) {
			t.Errorf("lodash advisory lost its severity or aliases: %+v", v)
		}
	}
	slices.Sort(names)
	want := []string{"@babel/core=GHSA-4x5r-pxfx-6jf8", "lodash=GHSA-35jh-r3h4-6jhm"}
	if !slices.Equal(names, want) {
		t.Fatalf("matches %v, want %v (the restored @babel/core must match)", names, want)
	}
}

func TestMatchMissingDatabaseIsPerEcosystem(t *testing.T) {
	inv := extractFixture(t)
	db := t.TempDir()
	writeDB(t, db, "npm", map[string]string{"a.json": npmAdvisories})
	if _, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "PyPI", Indices: indices(inv, "PyPI")}, MatchOptions{DBDir: db}); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("missing PyPI database: err=%v, want ErrNoDatabase", err)
	}
	if _, err := Match(context.Background(), inv, MatchRequest{Ecosystem: "npm", Indices: indices(inv, "npm")}, MatchOptions{DBDir: db}); err != nil {
		t.Fatalf("npm must still match while PyPI is missing: %v", err)
	}
}

func TestMatchLocalNeverDials(t *testing.T) {
	_, err := refuseTransport{}.RoundTrip(nil)
	if err == nil {
		t.Fatal("the local path's placeholder client must refuse every request")
	}
	if _, err := newEnricher(MatchOptions{Online: true}); err == nil {
		t.Fatal("online matching without the lane's client must be refused")
	}
}

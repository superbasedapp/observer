//go:build !sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func extractTree(t *testing.T, root string) *Inventory {
	t.Helper()
	inv, err := Extract(context.Background(), root, ExtractOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// TestUnpinnedRequirements: a range is not a version; only == and === pin.
func TestUnpinnedRequirements(t *testing.T) {
	inv := extractTree(t, writeTree(t, map[string]string{
		"requirements.txt": "requests>=2.0\nflask==1.0\nurllib3~=1.26\nidna===3.4\n",
	}))
	got := map[string]bool{}
	for _, p := range inv.Packages {
		got[p.Name] = p.Unpinned
	}
	want := map[string]bool{"requests": true, "flask": false, "urllib3": true, "idna": false}
	for k, v := range want {
		if u, ok := got[k]; !ok || u != v {
			t.Errorf("%s unpinned=%v (present %v), want %v", k, u, ok, v)
		}
	}
}

// TestOversizeLockfileMarksLocalEntries: past the rule's cap, a LOCAL entry
// may be a hoisted registry package, so it is marked unchecked.
func TestOversizeLockfileMarksLocalEntries(t *testing.T) {
	saved := maxNPMLockBytes
	maxNPMLockBytes = 64
	t.Cleanup(func() { maxNPMLockBytes = saved })
	inv := extractFixture(t)
	i, ok := find(inv, "npm", "@babel/core")
	if !ok {
		t.Fatal("@babel/core missing from the inventory")
	}
	if p := inv.Packages[i]; !p.Local || p.Restored || !p.LockfileTooLarge {
		t.Fatalf("@babel/core %+v: over the cap it stays LOCAL and is marked unchecked", p)
	}
	if i, ok := find(inv, "npm", "lodash"); !ok || inv.Packages[i].LockfileTooLarge {
		t.Fatalf("lodash (a resolved registry entry) must not be marked: %+v", inv.Packages)
	}
}

// TestUnlockedManifests: a Cargo.toml or pyproject.toml that declares
// dependencies with no lockfile beside or above it is reported.
func TestUnlockedManifests(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lone/Cargo.toml":               "[package]\nname = \"lone\"\n[dependencies]\nserde = \"1\"\n",
		"ws/Cargo.lock":                 "version = 3\n",
		"ws/member/Cargo.toml":          "[package]\nname = \"member\"\n[dependencies]\nserde = \"1\"\n",
		"nodeps/Cargo.toml":             "[package]\nname = \"nodeps\"\n",
		"py/pyproject.toml":             "[project]\nname = \"p\"\ndependencies = [\"requests>=2\"]\n",
		"pyok/pyproject.toml":           "[project]\nname = \"q\"\ndependencies = [\"requests>=2\"]\n",
		"pyok/uv.lock":                  "version = 1\n",
		"tools/pyproject.toml":          "[tool.ruff]\nline-length = 100\n",
		"node_modules/x/pyproject.toml": "[project]\nname = \"x\"\ndependencies = [\"a\"]\n",
		"pyreq/pyproject.toml":          "[project]\nname = \"r\"\ndependencies = [\"requests\"]\n",
		"pyreq/requirements-lock.txt":   "requests==2.31.0\n",
	})
	inv := extractTree(t, root)
	var got []string
	for _, m := range inv.Unlocked {
		got = append(got, m.Ecosystem+" "+m.Path)
	}
	want := []string{"crates.io lone/Cargo.toml", "PyPI py/pyproject.toml"}
	if !slices.Equal(got, want) {
		t.Fatalf("unlocked %v, want %v", got, want)
	}
	for _, s := range inv.Statuses {
		if s.Extractor == (&manifestProbe{}).Name() {
			t.Fatal("the probe is not one of SCALIBR's extractors and has no status row")
		}
	}
}

// TestFailedFileIsNamed: a lockfile caught mid-write fails its extractor,
// and the status names the file, so the run can report it not scanned.
func TestFailedFileIsNamed(t *testing.T) {
	inv := extractTree(t, writeTree(t, map[string]string{
		"package-lock.json": "{\"name\":\"x\",\"lockfileVersion\":3,\"packages\":{\"node_modules/a\":{\"vers",
	}))
	for _, s := range inv.Statuses {
		if s.OK {
			continue
		}
		if !slices.Equal(s.Files, []string{"package-lock.json"}) {
			t.Fatalf("status %+v: the failed file is named", s)
		}
		return
	}
	t.Fatalf("statuses %+v: a truncated lockfile must fail its extractor", inv.Statuses)
}

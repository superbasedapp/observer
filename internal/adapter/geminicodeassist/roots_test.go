package geminicodeassist

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/vscodehost"
)

// linuxHome builds a fake Linux home root so the per-OS globalStorage
// ladder resolves to `<home>/.config/<Product>/User/globalStorage`
// regardless of the host this test runs on (Windows dev box, Linux CI).
func linuxHome(path string) crossmount.HomeRoot {
	return crossmount.HomeRoot{Path: path, OS: crossmount.OSLinux, Origin: "native"}
}

func TestRootsForHomesCoversEveryProduct(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	roots := rootsForHomes([]crossmount.HomeRoot{linuxHome(home)})

	got := map[string]bool{}
	for _, r := range roots {
		got[filepath.ToSlash(r)] = true
	}

	for _, p := range vscodehost.Products() {
		userDir := vscodehost.UserDir(linuxHome(home), p)
		if userDir == "" {
			t.Fatalf("vscodehost.UserDir returned empty for product %q on a linux home", p.Host)
		}
		gs := filepath.Join(userDir, "globalStorage")
		extDir := filepath.Join(gs, extensionDirName)

		for _, want := range []string{
			filepath.Join(extDir, metricsSpoolDirName),
			filepath.Join(extDir, checkpointsDirName),
		} {
			if !got[filepath.ToSlash(want)] {
				t.Errorf("product %q: missing root %s", p.Host, filepath.ToSlash(want))
			}
		}

		stateDB := filepath.ToSlash(filepath.Join(gs, stateDBFileName))
		if ownsStateDB(p) {
			if !got[stateDB] {
				t.Errorf("product %q: missing state.vscdb file root %s", p.Host, stateDB)
			}
		} else if got[stateDB] {
			t.Errorf("product %q: declared state.vscdb root %s that %s owns",
				p.Host, stateDB, stateDBOwnedElsewhere[strings.ToLower(p.Host)])
		}
	}
}

// TestRootsForHomesRespectsStateDBOwnership pins the ownership decision
// documented on rootsForHomes: internal/adapter/cursor and
// internal/adapter/windsurf already declare their own product's
// state.vscdb, so this package must not. Registering two adapters on the
// same file root would fail internal/adapter/defaults'
// TestRegistryRootsNonOverlapping (an identical file root is a prefix of
// itself).
func TestRootsForHomesRespectsStateDBOwnership(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	roots := rootsForHomes([]crossmount.HomeRoot{linuxHome(home)})

	got := map[string]bool{}
	for _, r := range roots {
		got[filepath.ToSlash(r)] = true
	}

	desktopStateDB := func(product string) string {
		return filepath.ToSlash(filepath.Join(
			home, ".config", product, "User", "globalStorage", stateDBFileName))
	}

	for _, tc := range []struct {
		name  string
		path  string
		want  bool
		owner string
	}{
		{name: "cursor", path: desktopStateDB("Cursor"), want: false, owner: "internal/adapter/cursor"},
		{name: "windsurf", path: desktopStateDB("Windsurf"), want: false, owner: "internal/adapter/windsurf"},
		{name: "vscode", path: desktopStateDB("Code"), want: true},
		{name: "vscodium", path: desktopStateDB("VSCodium"), want: true},
		{
			name: "cursor-remote",
			path: filepath.ToSlash(filepath.Join(
				home, ".cursor-server", "data", "User", "globalStorage", stateDBFileName)),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got[tc.path] == tc.want {
				return
			}
			if tc.want {
				t.Errorf("state.vscdb root %s should be declared: no adapter owns it today", tc.path)
			} else {
				t.Errorf("state.vscdb root %s must not be declared here (owned by %s)", tc.path, tc.owner)
			}
		})
	}
}

func TestRootsForHomesDeduplicatesAcrossHomes(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	// The same home listed twice (crossmount can legitimately surface
	// overlapping roots) must not double the output.
	once := rootsForHomes([]crossmount.HomeRoot{linuxHome(home)})
	twice := rootsForHomes([]crossmount.HomeRoot{linuxHome(home), linuxHome(home)})
	if len(once) != len(twice) {
		t.Errorf("duplicate homes changed root count: %d vs %d", len(once), len(twice))
	}
}

func TestRootsForHomesSkipsUnknownOS(t *testing.T) {
	roots := rootsForHomes([]crossmount.HomeRoot{{Path: "/nowhere", OS: "plan9", Origin: "native"}})
	if len(roots) != 0 {
		t.Errorf("unknown home OS produced %d roots, want 0: %v", len(roots), roots)
	}
}

func TestRootsForHomesEmpty(t *testing.T) {
	if roots := rootsForHomes(nil); len(roots) != 0 {
		t.Errorf("no homes produced %d roots, want 0", len(roots))
	}
}

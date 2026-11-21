package osvdb

import (
	"strings"
	"testing"
)

// osvEcosystemNames are the 48 ecosystem names of osv-schema's Go bindings
// at the version this module pins (osvconstants, 2026-04-24), copied so the
// test needs no new module dependency.
var osvEcosystemNames = []string{
	"AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers",
	"Bioconductor", "Bitnami", "Chainguard", "CleanStart", "ConanCenter", "CRAN", "crates.io",
	"Debian", "Docker Hardened Images", "Echo", "FreeBSD", "GHC", "GitHub Actions", "Go",
	"Hackage", "Hex", "Julia", "Kubernetes", "Linux", "Mageia", "Maven", "MinimOS", "npm",
	"NuGet", "opam", "openEuler", "openSUSE", "OSS-Fuzz", "Packagist", "Photon OS", "Pub",
	"PyPI", "Red Hat", "Rocky Linux", "Root", "RubyGems", "SUSE", "SwiftURL", "TuxCare",
	"Ubuntu", "VSCode", "Wolfi",
}

// TestArtifactBaseInjective: every OSV ecosystem name maps to a plain
// artifact name the feed host serves, and no two map to the same one.
func TestArtifactBaseInjective(t *testing.T) {
	if len(osvEcosystemNames) != 48 {
		t.Fatalf("%d names, want the 48 of osv-schema", len(osvEcosystemNames))
	}
	seen := map[string]string{}
	for _, eco := range osvEcosystemNames {
		b, ok := ArtifactBase(eco)
		if !ok {
			t.Fatalf("%q has no artifact name", eco)
		}
		for _, r := range b {
			if !(r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				t.Fatalf("%q -> %q carries %q, which the feed host does not serve", eco, b, r)
			}
		}
		if prev, dup := seen[strings.ToLower(b)]; dup {
			t.Fatalf("%q and %q both map to %q (case-folded)", prev, eco, b)
		}
		seen[strings.ToLower(b)] = eco
	}
}

func TestArtifactNames(t *testing.T) {
	cases := []struct{ eco, base, delta string }{
		{"npm", "npm.zip", "npm.delta.zip"},
		{"crates.io", "crates.io.zip", "crates.io.delta.zip"},
		{"GitHub Actions", "GitHub-Actions.zip", "GitHub-Actions.delta.zip"},
		{"OSS-Fuzz", "OSS-Fuzz.zip", "OSS-Fuzz.delta.zip"},
		{"", "", ""},
		{"../npm", "", ""},
		{"a/b", "", ""},
		{"Debian:12", "", ""},
		{" npm", "", ""},
		{"GitHub  Actions", "", ""},
	}
	for _, c := range cases {
		if got := ExportArtifact(c.eco); got != c.base {
			t.Errorf("ExportArtifact(%q) = %q, want %q", c.eco, got, c.base)
		}
		if got := DeltaArtifact(c.eco); got != c.delta {
			t.Errorf("DeltaArtifact(%q) = %q, want %q", c.eco, got, c.delta)
		}
	}
}

func TestValidEcosystem(t *testing.T) {
	for _, ok := range []string{"npm", "GitHub Actions", "crates.io", "Debian:12", "OSS-Fuzz"} {
		if !ValidEcosystem(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "a/b", `a\b`, " npm", "npm ", "a  b", "a\tb", strings.Repeat("a", 65)} {
		if ValidEcosystem(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestTakeServed: a source takes what it holds and lets the rest fall
// through; the last source of the order takes what is left; nil holds all.
func TestTakeServed(t *testing.T) {
	eight := []string{"Go", "GitHub Actions", "npm"}
	oldFeed := func(eco string) bool { return eco != "GitHub Actions" }
	cases := []struct {
		name       string
		serves     func(string) bool
		last       bool
		take, rest string
	}{
		{"an old feed passes the new ecosystem on", oldFeed, false, "Go,npm", "GitHub Actions"},
		{"the last source takes everything left", oldFeed, true, "Go,GitHub Actions,npm", ""},
		{"a remote that names no set holds every ecosystem", nil, false, "Go,GitHub Actions,npm", ""},
		{"a set holding nothing passes everything on", func(string) bool { return false }, false, "", "Go,GitHub Actions,npm"},
	}
	for _, c := range cases {
		take, rest := TakeServed(eight, c.serves, c.last)
		if strings.Join(take, ",") != c.take || strings.Join(rest, ",") != c.rest {
			t.Errorf("%s: take %v rest %v, want %q %q", c.name, take, rest, c.take, c.rest)
		}
	}
}

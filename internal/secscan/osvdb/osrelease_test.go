package osvdb

import (
	"regexp"
	"testing"
)

// TestOSReleaseTableWellFormed: artifact names are plain, unique and never
// collide with a language ecosystem's artifact; every row maps back.
func TestOSReleaseTableWellFormed(t *testing.T) {
	plain := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	seen := map[string]bool{}
	for _, r := range OSReleases {
		if !plain.MatchString(r.Artifact) || seen[r.Artifact] {
			t.Fatalf("artifact %q not plain or duplicate", r.Artifact)
		}
		seen[r.Artifact] = true
		if _, ok := ArtifactBase(r.Base); !ok {
			t.Fatalf("base %q refused", r.Base)
		}
		if got, ok := ReleaseByArtifact(r.Artifact); !ok || got.Ecosystem != r.Ecosystem {
			t.Fatalf("ReleaseByArtifact(%q)", r.Artifact)
		}
		if !r.Keep(r.Ecosystem) && !r.KeepPrefix {
			t.Fatalf("%s does not keep its own ecosystem", r.Artifact)
		}
	}
	for _, eco := range []string{"npm", "PyPI", "Go", "crates.io", "RubyGems", "Packagist", "NuGet", "Maven", "GitHub Actions"} {
		b, _ := ArtifactBase(eco)
		if seen[b] {
			t.Fatalf("release artifact collides with %s", eco)
		}
	}
}

// TestReleaseFor is one case per mapping row.
func TestReleaseFor(t *testing.T) {
	cases := []struct {
		id, ver, want string
		ok            bool
	}{
		{"debian", "12", "Debian-12", true},
		{"debian", `"12"`, "Debian-12", true},
		{"ubuntu", "24.04", "Ubuntu-24.04-LTS", true},
		{"ubuntu", "25.10", "", false},
		{"alpine", "3.20.3", "Alpine-v3.20", true},
		{"rhel", "9.3", "Red-Hat-EL9", true},
		{"rocky", "9.3", "Rocky-Linux-9", true},
		{"centos", "7", "", false},
		{"debian", "9", "", false},
	}
	for _, c := range cases {
		r, ok := ReleaseFor(c.id, c.ver)
		if ok != c.ok || r.Artifact != c.want {
			t.Errorf("ReleaseFor(%q,%q) = %q,%v want %q,%v", c.id, c.ver, r.Artifact, ok, c.want, c.ok)
		}
	}
}

// TestKeep: Red Hat keeps every stream of its major only; others keep the
// exact ecosystem.
func TestKeep(t *testing.T) {
	el9, _ := ReleaseFor("rhel", "9")
	el10, _ := ReleaseFor("rhel", "10")
	deb, _ := ReleaseFor("debian", "12")
	cases := []struct {
		r    OSRelease
		eco  string
		want bool
	}{
		{el9, "Red Hat:enterprise_linux:9::baseos", true},
		{el9, "Red Hat:enterprise_linux:9::appstream", true},
		{el9, "Red Hat:enterprise_linux:10::baseos", false},
		{el9, "Red Hat:hummingbird:1", false},
		{el10, "Red Hat:enterprise_linux:10.1", true},
		{el10, "Red Hat:enterprise_linux:10::baseos", true},
		{el10, "Red Hat:enterprise_linux:100", false},
		{deb, "Debian:12", true},
		{deb, "Debian:11", false},
	}
	for _, c := range cases {
		if got := c.r.Keep(c.eco); got != c.want {
			t.Errorf("%s.Keep(%q) = %v", c.r.Artifact, c.eco, got)
		}
	}
}

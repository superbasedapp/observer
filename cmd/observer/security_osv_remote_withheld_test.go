//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

// TestRemoteSendableWithholdsUnprovableNames pins the remote lookup's
// privacy rule (plan section 13.4, "withheld names stay withheld") for every
// ecosystem the security.deps classifier cannot prove public offline: Maven
// (the reactor and the local repository resolve before any remote, so a
// coordinate is not provably Central's), GitHub Actions (a private or
// internal repository on github.com has the same owner/repo shape), the six
// ecosystems mirrored since 2026-11-06 (their extractors emit git, path and
// private-registry packages under plain names, and no configuration says
// which), and RubyGems and Packagist (install-gate rows, no classifier). A
// name there is never hashed into a request unless the developer sends
// private names too (remote_private = send, its own consent); a public
// looking name is withheld as surely as a private looking one. npm on its
// public default registry is the control.
func TestRemoteSendableWithholdsUnprovableNames(t *testing.T) {
	depsScopeHome(t)
	root := t.TempDir()
	for _, f := range []string{
		"package-lock.json", "pom.xml", ".github/workflows/ci.yml", "pubspec.lock", "Package.resolved",
		"mix.lock", "cabal.project.freeze", "Manifest.toml", "renv.lock", "Gemfile.lock", "composer.lock",
	} {
		writeFile(t, filepath.Join(root, filepath.FromSlash(f)), "{}")
	}
	public := newDepsLockfileClassifiers(root, depsOnlineScanClassifier)
	cases := []struct {
		name string
		pkg  depscan.Package
		sent bool // sent while private names are withheld
	}{
		{"npm on the public default registry (the control)", depscan.Package{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", Path: "package-lock.json"}, true},
		{"a private-looking Maven group", depscan.Package{Ecosystem: "Maven", Name: "com.corp.internal:billing-core", Version: "1.4.0", Path: "pom.xml"}, false},
		{"a Maven Central coordinate is not provable either", depscan.Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Path: "pom.xml"}, false},
		{"a private org's action", depscan.Package{Ecosystem: "GitHub Actions", Name: "corp-internal/deploy-action", Version: "v2.1.0", Path: ".github/workflows/ci.yml"}, false},
		{"a public-looking action is not provable either", depscan.Package{Ecosystem: "GitHub Actions", Name: "actions/checkout", Version: "v4.1.0", Path: ".github/workflows/ci.yml"}, false},
		{"Pub", depscan.Package{Ecosystem: "Pub", Name: "dio", Version: "5.0.0", Path: "pubspec.lock"}, false},
		{"SwiftURL", depscan.Package{Ecosystem: "SwiftURL", Name: "github.com/apple/swift-nio", Version: "2.40.0", Path: "Package.resolved"}, false},
		{"Hex", depscan.Package{Ecosystem: "Hex", Name: "plug", Version: "1.14.0", Path: "mix.lock"}, false},
		{"Hackage", depscan.Package{Ecosystem: "Hackage", Name: "aeson", Version: "2.1.0.0", Path: "cabal.project.freeze"}, false},
		{"Julia", depscan.Package{Ecosystem: "Julia", Name: "HTTP", Version: "1.9.0", Path: "Manifest.toml"}, false},
		{"CRAN", depscan.Package{Ecosystem: "CRAN", Name: "readxl", Version: "1.4.0", Path: "renv.lock"}, false},
		{"RubyGems", depscan.Package{Ecosystem: "RubyGems", Name: "rails", Version: "7.0.0", Path: "Gemfile.lock"}, false},
		{"Packagist", depscan.Package{Ecosystem: "Packagist", Name: "symfony/http-kernel", Version: "4.0.0", Path: "composer.lock"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgs := []depscan.Package{c.pkg}
			if got := remoteSendable(c.pkg.Ecosystem, pkgs, []int{0}, public, false); (len(got) == 1) != c.sent {
				t.Errorf("sent %v with private names withheld, want %v", got, c.sent)
			}
			// remote_private = send (with its own consent) sends every name.
			if got := remoteSendable(c.pkg.Ecosystem, pkgs, []int{0}, public, true); len(got) != 1 {
				t.Errorf("sent %v with private names sent, want the one name", got)
			}
		})
	}
}

//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// TestOnlineMatcherClassifiesPerLockfile is lane SEC-DEPS3 item 2
// (P-029/P-030): the online matcher classifies each package with its own
// lockfile's directory chain, so a sub-package's .npmrc scope keeps its
// names private; a path leaving the root withholds; the process
// environment only restricts.
func TestOnlineMatcherClassifiesPerLockfile(t *testing.T) {
	depsScopeHome(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "frontend", ".npmrc"), "@corp:registry=https://npm.corp.example/\n")
	writeFile(t, filepath.Join(root, "frontend", "package-lock.json"), "{}")
	writeFile(t, filepath.Join(root, "package-lock.json"), "{}")
	corp := secfeed.ParseSpec(secfeed.EcoNpm, "@corp/x@1.0.0")
	pad := secfeed.ParseSpec(secfeed.EcoNpm, "left-pad@1.3.0")
	builds := 0
	c := newDepsLockfileClassifiers(root, func(s secfeed.Scope) secfeed.Classifier {
		builds++
		return depsOnlineScanClassifier(s)
	})
	for _, tc := range []struct {
		name, path string
		spec       secfeed.InstallSpec
		public     bool
	}{
		{"root lockfile, scoped name", "package-lock.json", corp, true},
		{"sub-package lockfile, its own scope", "frontend/package-lock.json", corp, false},
		{"deeper lockfile under the scoped dir", "frontend/apps/web/package-lock.json", corp, false},
		{"sub-package lockfile, public name", "frontend/package-lock.json", pad, true},
		{"leaves the root", "../other/package-lock.json", pad, false},
		{"absolute", "/etc/package-lock.json", pad, false},
		{"empty path", "", pad, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.public(tc.path, tc.spec); got != tc.public {
				t.Errorf("public=%v want %v", got, tc.public)
			}
		})
	}
	before := builds
	c.public("frontend/package-lock.json", pad)
	if builds != before {
		t.Error("one classifier per directory must be cached")
	}
	// An unknown root withholds everything.
	if newDepsLockfileClassifiers("", depsOnlineScanClassifier).public("package-lock.json", pad) {
		t.Error("no root must withhold")
	}
	// A lockfile directory that is a symlink out of the root withholds.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err == nil {
		if c.public("linked/package-lock.json", pad) {
			t.Error("a lockfile directory resolving outside the root must withhold")
		}
	}
	// The process environment only restricts: a registry it names makes
	// a root name private, and a user config it points at cannot make a
	// name public that the default files keep private.
	t.Setenv("NPM_CONFIG_REGISTRY", "https://npm.corp.example/")
	c2 := newDepsLockfileClassifiers(root, depsOnlineScanClassifier)
	if c2.public("package-lock.json", pad) {
		t.Error("the process's registry variable must withhold")
	}
}

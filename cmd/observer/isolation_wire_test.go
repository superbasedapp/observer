//go:build !sbo_omit_isolation

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/isolation"
)

// TestIsolationFactoryFollowsTheComponent: a consumer gets the one-shot
// factory only while the isolation component is active (and only on
// Linux); an inactive component hands out nil, so nothing can be isolated
// and a run that requires isolation is refused by the runner.
func TestIsolationFactoryFollowsTheComponent(t *testing.T) {
	if bad := componentstate.UnknownNodeIDs(isolationComponent); len(bad) > 0 {
		t.Fatalf("isolation component id unknown: %v", bad)
	}
	off := componentstate.Resolve(config.ComponentsConfig{Distro: "developer"}, nil)
	if off.ModuleActive(isolationComponent) {
		t.Fatal("isolation active by default in the developer distro; the catalog says off")
	}
	if f := isolationFactoryFor(off, "/home/u/.observer", nil); f != nil {
		t.Fatal("inactive isolation handed out a factory")
	}
	on := componentstate.Resolve(config.ComponentsConfig{Distro: "developer", Add: []string{isolationComponent}}, nil)
	f := isolationFactoryFor(on, "/home/u/.observer", nil)
	if runtime.GOOS != "linux" {
		if f != nil {
			t.Fatal("a factory outside Linux")
		}
		return
	}
	if f == nil {
		t.Fatal("active isolation handed out no factory")
	}
	// Turning the sandbox module on activates the engine it Requires.
	sbx := componentstate.Resolve(config.ComponentsConfig{Distro: "developer", Add: []string{"terminals.sandbox"}}, nil)
	if !sbx.ModuleActive(isolationComponent) {
		t.Fatal("terminals.sandbox active without the isolation engine it requires")
	}
}

// TestResolvedOneShotComparesResolvedPaths pins audit finding P-006 (5):
// the home and ~/.observer are resolved through symlinks so the real
// observer directory is the one hidden, and a project that is a symlink
// into ~/.observer is refused because the overlap check sees the resolved
// path.
func TestResolvedOneShotComparesResolvedPaths(t *testing.T) {
	skipOnWindows(t, "the bwrap one-shot isolation is Linux-only")
	root := t.TempDir()
	realHome := filepath.Join(root, "real-home")
	disk := filepath.Join(root, "disk")
	for _, d := range []string{realHome, filepath.Join(disk, "observer", "posture"), filepath.Join(root, "src", "proj"), filepath.Join(root, "out")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(root, "home")
	if err := testSymlink(t, realHome, home); err != nil {
		t.Fatal(err)
	}
	obs := filepath.Join(realHome, ".observer")
	if err := testSymlink(t, filepath.Join(disk, "observer"), obs); err != nil {
		t.Fatal(err)
	}
	host := isolation.Host{Bwrap: "/usr/bin/bwrap", Home: home, ObserverDir: filepath.Join(home, ".observer")}
	dirs := extrun.OneShotDirs{Project: filepath.Join(root, "src", "proj"), Output: filepath.Join(root, "out", "run-1"), Cache: filepath.Join(root, "cache")}
	p, err := newResolvedOneShot(host, dirs)
	if err != nil {
		t.Fatalf("an ordinary run was refused: %v", err)
	}
	plan, err := p.Wrap(context.Background(), extrun.Plan{Path: "/usr/bin/true", Dir: dirs.Project})
	if err != nil {
		t.Fatalf("Wrap with the caller's own project path: %v", err)
	}
	realObs := filepath.Join(disk, "observer")
	hidden := false
	for i, a := range plan.Args {
		if a == "--tmpfs" && i+1 < len(plan.Args) && plan.Args[i+1] == realObs {
			hidden = true
		}
	}
	if !hidden {
		t.Fatalf("the real observer dir %s is not hidden: %v", realObs, plan.Args)
	}

	// A project that is a link into the observer dir.
	sneaky := filepath.Join(root, "sneaky")
	if err := testSymlink(t, filepath.Join(disk, "observer", "posture"), sneaky); err != nil {
		t.Fatal(err)
	}
	bad := dirs
	bad.Project = sneaky
	if _, err := newResolvedOneShot(host, bad); err == nil {
		t.Fatal("a project linked into ~/.observer was accepted")
	}
	// An output dir reached through the linked home is still inside it.
	bad = dirs
	bad.Output = filepath.Join(home, ".observer", "out")
	if _, err := newResolvedOneShot(host, bad); err == nil {
		t.Fatal("an output dir under the linked ~/.observer was accepted")
	}
}

// TestResolvedOneShotKeepsArgv0 (P-017 (h)): a program reached through a
// link keeps its own name as argv0 (a multi-call binary picks its applet
// from it), and the link's target directory is bound so the link resolves
// inside the run.
func TestResolvedOneShotKeepsArgv0(t *testing.T) {
	skipOnWindows(t, "the bwrap one-shot isolation is Linux-only")
	root := t.TempDir()
	for _, d := range []string{filepath.Join(root, "home"), filepath.Join(root, "proj"), filepath.Join(root, "out"), filepath.Join(root, "bin"), filepath.Join(root, "toolbox")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	multi := filepath.Join(root, "toolbox", "busybox")
	if err := os.WriteFile(multi, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	applet := filepath.Join(root, "bin", "ls")
	if err := testSymlink(t, multi, applet); err != nil {
		t.Fatal(err)
	}
	host := isolation.Host{Bwrap: "/usr/bin/bwrap", Home: filepath.Join(root, "home"), ObserverDir: filepath.Join(root, "home", ".observer")}
	dirs := extrun.OneShotDirs{Project: filepath.Join(root, "proj"), Output: filepath.Join(root, "out", "r"), Cache: filepath.Join(root, "cache")}
	p, err := newResolvedOneShot(host, dirs)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := p.Wrap(context.Background(), extrun.Plan{Path: applet, Dir: dirs.Project})
	if err != nil {
		t.Fatal(err)
	}
	sep := -1
	for i, a := range plan.Args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 || sep+1 >= len(plan.Args) {
		t.Fatalf("no command after --: %v", plan.Args)
	}
	if got := plan.Args[sep+1]; filepath.Base(got) != "ls" {
		t.Fatalf("argv0 %q, want the link's own name", got)
	}
	bound := false
	target := filepath.Join(root, "toolbox")
	if real, err := filepath.EvalSymlinks(target); err == nil {
		target = real
	}
	for i, a := range plan.Args[:sep] {
		if (a == "--ro-bind" || a == "--ro-bind-try") && i+1 < sep && plan.Args[i+1] == target {
			bound = true
		}
	}
	if !bound {
		t.Fatalf("the link target's directory %s is not bound: %v", target, plan.Args)
	}
}

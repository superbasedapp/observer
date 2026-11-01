//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_merge_test.go pins the SEC-G1 merge fixes on the cmd
// side: the worktree roots (audit finding 2), the engine manifest's
// revocations (finding 5) and R-165's per-build base check (P-045).

// TestKnownProjectRootInLinkedWorktree (audit finding 2): inside a linked
// worktree the project is the main repository (the known project, which
// keys the findings) and the checkout is the worktree (what a scan reads).
func TestKnownProjectRootInLinkedWorktree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	ctx := context.Background()
	main := filepath.Join(t.TempDir(), "main")
	if err := os.MkdirAll(main, 0o700); err != nil {
		t.Fatal(err)
	}
	gitInitMain(t, main)
	if err := os.WriteFile(filepath.Join(main, "README"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, main, "add", "README")
	gitRun(t, main, "commit", "-q", "-m", "first")
	wt := filepath.Join(t.TempDir(), "wt")
	gitRun(t, main, "worktree", "add", "-q", wt)
	wantMain, _ := filepath.EvalSymlinks(main)
	wantWT, _ := filepath.EvalSymlinks(wt)
	st, _ := openTestStore(t)
	if _, _, err := knownProjectRoot(ctx, st, wt); err == nil {
		t.Fatal("a project the store does not know was accepted")
	}
	if _, err := st.UpsertProject(ctx, wantMain, ""); err != nil {
		t.Fatal(err)
	}
	root, checkout, err := knownProjectRoot(ctx, st, wt)
	if err != nil || root != wantMain || checkout != wantWT {
		t.Fatalf("worktree: root %q checkout %q (%v), want %q and %q", root, checkout, err, wantMain, wantWT)
	}
	root, checkout, err = knownProjectRoot(ctx, st, main)
	if err != nil || root != wantMain || checkout != wantMain {
		t.Fatalf("main checkout: root %q checkout %q (%v)", root, checkout, err)
	}
}

// TestEngineManifestKeepsRevocations (audit finding 5): a manifest past its
// age floor, or one whose entries are refused, loses its pins but keeps its
// revocations, so a revoked compiled pin is refused whatever the manifest's
// state.
func TestEngineManifestKeepsRevocations(t *testing.T) {
	pin, _ := secengine.CompiledPin("linux", "amd64")
	revoked := []content.Revocation{{SHA256: strings.ToUpper(pin.SHA256), Reason: "test"}}
	badEntry := []content.Entry{{Name: "opengrep_manylinux_x86", Version: secengine.TestedVersion, OS: "linux", Arch: "amd64", SHA256: pin.SHA256}}
	cases := []struct {
		name    string
		l       contentchan.Loaded
		err     error
		refused bool
		pins    bool
	}{
		{"fresh", contentchan.Loaded{Manifest: content.Manifest{Kind: content.Engine, Revoked: revoked}, Freshness: content.Fresh}, nil, true, false},
		{"past its age floor", contentchan.Loaded{Manifest: content.Manifest{Kind: content.Engine, Revoked: revoked}, Freshness: content.Unknown}, nil, true, false},
		{"stale", contentchan.Loaded{Manifest: content.Manifest{Kind: content.Engine, Revoked: revoked}, Freshness: content.Stale}, nil, true, false},
		{"an entry FromManifest refuses", contentchan.Loaded{Manifest: content.Manifest{Kind: content.Engine, Entries: badEntry, Revoked: revoked}, Freshness: content.Fresh}, nil, true, false},
		{"past its floor with nothing revoked", contentchan.Loaded{Manifest: content.Manifest{Kind: content.Engine}, Freshness: content.Unknown}, nil, false, false},
		{"unreadable", contentchan.Loaded{}, errors.New("signature does not verify"), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mp := engineManifestPins(c.l, c.err)
			if mp != nil && len(mp.Pins) > 0 != c.pins {
				t.Errorf("pins %+v", mp.Pins)
			}
			d := secengine.Decide(secengine.Input{GOOS: "linux", GOARCH: "amd64", Digest: pin.SHA256, Manifest: mp, Tree: secengine.TreeNone})
			if got := d.Status == secengine.StatusRefused && d.Detail == secengine.DetailRevoked; got != c.refused {
				t.Fatalf("decision %+v, want refused as revoked = %v", d, c.refused)
			}
		})
	}
}

// TestSecurityKeepingBasesForBuilds (plans decision log P-045): the list
// this binary injects into R-165 is computed from the build's compiled set
// and what it runs. In a developer build (security.scan.scalibr not
// compiled in) selecting developer drops nothing and passes; in a full
// build, which compiles and runs that scanner, it is denied. minimal and
// managed are never in either list.
func TestSecurityKeepingBasesForBuilds(t *testing.T) {
	t.Cleanup(func() { policy.SetSecurityKeepingBases(thisBuildKeepingBases) })
	dev := components.InDistro(components.DistroDeveloper)
	full := components.InDistro(components.DistroFull)
	if slices.Contains(dev, "security.scan.scalibr") || !slices.Contains(full, "security.scan.scalibr") {
		t.Fatalf("the catalog changed: developer %v, full %v", dev, full)
	}
	devList := securityKeepingBasesFor(dev, componentstate.Resolve(config.ComponentsConfig{Distro: string(components.DistroDeveloper)}, dev))
	fullList := securityKeepingBasesFor(full, componentstate.Resolve(config.ComponentsConfig{Distro: string(components.DistroFull)}, full))
	if !slices.Contains(devList, "developer") || slices.Contains(fullList, "developer") || !slices.Contains(fullList, "full") {
		t.Fatalf("developer build %v, full build %v", devList, fullList)
	}
	t.Logf("keeping bases: developer build %v, full build %v, this build %v", devList, fullList, thisBuildKeepingBases())
	for _, l := range [][]string{devList, fullList} {
		if slices.Contains(l, "minimal") || slices.Contains(l, "managed") {
			t.Fatalf("a list keeps minimal or managed: %v", l)
		}
	}
	// This build's own list: where no security component runs by default
	// (the managed edition, inert with no block) no base drops anything
	// that runs, so every base keeps; elsewhere minimal and managed drop a
	// running component and never keep.
	this := thisBuildKeepingBases()
	if securityInertByDefault() {
		for _, d := range components.Distros() {
			if !slices.Contains(this, string(d)) {
				t.Fatalf("this build runs no security component by default, yet %s is not a keeping base: %v", d, this)
			}
		}
	} else if slices.Contains(this, "minimal") || slices.Contains(this, "managed") {
		t.Fatalf("this build's list keeps minimal or managed: %v", this)
	}
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	denied := func(line string) bool {
		v := e.Evaluate(policy.Event{Kind: policy.KindShellExec, Target: line, Cwd: "/home/u/p", ProjectRoot: "/home/u/p"})
		return v.RuleID == "R-165" && v.Decision == policy.DecisionDeny
	}
	for _, c := range []struct {
		name string
		list []string
		want bool
	}{{"developer build", devList, false}, {"full build", fullList, true}} {
		list := c.list
		policy.SetSecurityKeepingBases(func() []string { return list })
		if got := denied("observer components select developer --yes"); got != c.want {
			t.Errorf("%s: select developer denied = %v, want %v", c.name, got, c.want)
		}
		for _, base := range []string{"minimal", "managed", "nonesuch"} {
			if !denied("observer components select " + base + " --yes") {
				t.Errorf("%s: select %s passed", c.name, base)
			}
		}
	}
}

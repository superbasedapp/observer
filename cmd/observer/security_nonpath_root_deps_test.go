//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/xcodehost"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Audit finding 1 on the w14 hand-back (completes w14's row 7): the
// scheduled dependency scan and the manifest prefetch never resolve the
// stored non-path "Xcode (project unknown)" root against the daemon's
// working directory. Each test plants, at a temporary working directory, a
// folder of that name holding a manifest that a relative resolution would
// find, and stores the root through the Xcode autosave path (FU-193).

// nonPathRootStore is a store holding the non-path root and one real
// project with a package.json; it returns the real project's stored root.
func nonPathRootStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	ctx := context.Background()
	st := store.New(openDeliveryTestDB(t))
	id, err := st.UpsertProject(ctx, "/Users/lume/Library/Autosave Information", "")
	if err != nil {
		t.Fatal(err)
	}
	if root, _ := st.ProjectRootByID(ctx, id); root != xcodehost.ProjectUnknown {
		t.Fatalf("stored root = %q, want %q", root, xcodehost.ProjectUnknown)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"dependencies":{"left-pad":"1.3.0"}}`)
	rid, err := st.UpsertProject(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	real, err := st.ProjectRootByID(ctx, rid)
	if err != nil || real == "" {
		t.Fatalf("real project root: %q %v", real, err)
	}
	return st, real
}

// TestDepsScheduleNeverStatsANonPathRoot: the schedule's tick stats and
// scans the real project only. The non-path root is also handed to the
// tick directly, so its own check holds without the store's filter.
func TestDepsScheduleNeverStatsANonPathRoot(t *testing.T) {
	st, real := nonPathRootStore(t)
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, xcodehost.ProjectUnknown, "package.json"), `{"dependencies":{"xcode-only":"1.0.0"}}`)
	roots, err := st.SecActiveProjectRoots(context.Background(), time.Now().Add(-depsScanActive))
	if err != nil {
		t.Fatal(err)
	}
	var statted, scanned []string
	// stat resolves a relative name against the planted working directory,
	// as os.Stat would against the daemon's.
	stat := func(p string) (os.FileInfo, error) {
		statted = append(statted, p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		return os.Stat(p)
	}
	scan := func(root string) (secscan.Result, error) {
		scanned = append(scanned, root)
		return secscan.Result{}, nil
	}
	e := &depsScanEnv{dir: t.TempDir(), logger: newLogger("error")}
	e.scheduledScans(context.Background(), depscan.ScalibrComponent, depscan.ScalibrID, "npm=a",
		append([]string{xcodehost.ProjectUnknown}, roots...), stat, scan)
	if slices.Contains(statted, xcodehost.ProjectUnknown) || slices.Contains(scanned, xcodehost.ProjectUnknown) {
		t.Errorf("the non-path root was read: statted %q, scanned %q", statted, scanned)
	}
	if !slices.Equal(scanned, []string{real}) {
		t.Errorf("scanned %q, want the real project %q", scanned, real)
	}
}

// TestDepsPrefetchNeverReadsANonPathRoot: a name confirmed public for the
// non-path root is never looked up from the working directory's manifest;
// the real project's confirmed name still is. The manifest read has no
// seam, so the test changes the working directory (restored by t.Chdir).
func TestDepsPrefetchNeverReadsANonPathRoot(t *testing.T) {
	depsScopeHome(t)
	st, real := nonPathRootStore(t)
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, xcodehost.ProjectUnknown, "package.json"), `{"dependencies":{"xcode-only":"1.0.0"}}`)
	t.Chdir(cwd)
	c := &depsConfirmed{}
	c.add(secfeed.Scope{ProjectRoot: xcodehost.ProjectUnknown}, []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "xcode-only@1.0.0")})
	c.add(secfeed.Scope{ProjectRoot: real}, []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad@1.0.0")})
	var sent []string
	env := &depsEnv{
		cfg: config.Config{Security: config.DefaultSecurityConfig()}, st: st, logger: newLogger("error"),
		disclose: secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true},
		lookup: func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			var out []secfeed.OnlineAnswer
			for _, s := range specs {
				sent = append(sent, s.Name)
				out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version, Status: secfeed.OnlineNotFound})
			}
			return out
		},
	}
	rt := &depsRuntime{confirmed: c}
	rt.prefetch(context.Background(), env)
	if slices.Contains(sent, "xcode-only") {
		t.Errorf("the prefetch read the working directory's manifest for the non-path root: sent %q", sent)
	}
	if !slices.Contains(sent, "left-pad") {
		t.Errorf("the real project's confirmed name was not prefetched: sent %q", sent)
	}
}

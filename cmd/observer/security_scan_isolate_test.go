//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_isolation

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/isolation"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// TestScalibrIsolateResolvesSymlinks pins lane SEC-DEPS3 items 3 and 5: on
// a symlinked project root and a symlinked user cache, the child request
// carries the resolved root and database directory (the only paths the
// provider binds); a host with no bwrap yields no provider and no error
// (the driver then runs unisolated, labelled), any other factory error is
// returned so the driver refuses the scan.
func TestScalibrIsolateResolvesSymlinks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the isolation engine and XDG_CACHE_HOME are Linux-only")
	}
	realCache, realProject, links := t.TempDir(), t.TempDir(), t.TempDir()
	cacheLink, projectLink := filepath.Join(links, "cache"), filepath.Join(links, "project")
	for _, l := range [][2]string{{realCache, cacheLink}, {realProject, projectLink}} {
		if err := testSymlink(t, l[0], l[1]); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_CACHE_HOME", cacheLink)
	setTestHome(t, t.TempDir())
	obs := t.TempDir()
	db := osvdb.Open(filepath.Join(obs, "security", "osv"))
	zip := filepath.Join(db.Dir(), "osv-scalibr", "npm", "all.zip")
	if err := os.MkdirAll(filepath.Dir(zip), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zip, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &depsScanEnv{dir: filepath.Join(obs, "security"), db: db}
	resolvedProject, err := filepath.EvalSymlinks(realProject)
	if err != nil {
		t.Fatal(err)
	}
	resolvedCache, err := filepath.EvalSymlinks(realCache)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		err      error
		provider bool
		wantErr  bool
	}{
		{name: "provider built", provider: true},
		{name: "no bwrap on this host", err: isolation.ErrNoBwrap},
		{name: "provider refused (overlap with ~/.observer)", err: errors.New("isolation: project overlaps the observer directory"), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forceScanIsolation(t, true)
			factory := func(extrun.OneShotDirs) (extrun.IsolationProvider, error) {
				if c.err != nil {
					return nil, c.err
				}
				return fakeScanIsolation{}, nil
			}
			iso, err := e.scalibrIsolate(factory, map[string]string{"npm": "e1"})(projectLink)
			if iso.Cleanup != nil {
				defer iso.Cleanup()
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("err %v, want error %v", err, c.wantErr)
			}
			if (iso.Provider != nil) != c.provider {
				t.Fatalf("provider %v, want %v", iso.Provider, c.provider)
			}
			if !c.provider {
				return
			}
			if iso.Root != resolvedProject {
				t.Fatalf("child root %q, want the resolved %q", iso.Root, resolvedProject)
			}
			if !strings.HasPrefix(iso.DBDir, resolvedCache+string(filepath.Separator)) {
				t.Fatalf("child db dir %q is not under the resolved cache %q", iso.DBDir, resolvedCache)
			}
		})
	}
}

// TestScalibrIsolateNoProviderSkipsPreparation pins audit finding 2 of
// lane sec-deps3b: on a host with no isolation provider, a preparation
// that would fail (the run directory cannot be made under the user cache,
// or the root cannot be resolved) yields no provider and no error, so the
// driver runs the child unisolated with its fixed note; the same failure
// on a host with a provider refuses the scan.
func TestScalibrIsolateNoProviderSkipsPreparation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the isolation engine and XDG_CACHE_HOME are Linux-only")
	}
	notADir := filepath.Join(t.TempDir(), "cache-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CACHE_HOME", notADir)
	setTestHome(t, t.TempDir())
	obs := t.TempDir()
	e := &depsScanEnv{dir: filepath.Join(obs, "security"), db: osvdb.Open(filepath.Join(obs, "security", "osv"))}
	called := false
	factory := func(extrun.OneShotDirs) (extrun.IsolationProvider, error) {
		called = true
		return nil, isolation.ErrNoBwrap
	}
	cases := []struct {
		name      string
		available bool
		root      string
		wantErr   bool
	}{
		{name: "no provider, run directory cannot be made", root: t.TempDir()},
		{name: "no provider, root cannot be resolved", root: filepath.Join(obs, "missing")},
		{name: "provider, run directory cannot be made", available: true, root: t.TempDir(), wantErr: true},
		{name: "provider, root cannot be resolved", available: true, root: filepath.Join(obs, "missing"), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			forceScanIsolation(t, c.available)
			called = false
			iso, err := e.scalibrIsolate(factory, map[string]string{"npm": "e1"})(c.root)
			if iso.Cleanup != nil {
				defer iso.Cleanup()
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("err %v, want error %v", err, c.wantErr)
			}
			if iso.Provider != nil || called {
				t.Fatalf("provider %v, factory called %v: nothing may be built", iso.Provider, called)
			}
		})
	}
}

// fakeScanIsolation is a provider that wraps nothing.
type fakeScanIsolation struct{}

func (fakeScanIsolation) Name() string { return "test.isolation" }

func (fakeScanIsolation) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) { return p, nil }

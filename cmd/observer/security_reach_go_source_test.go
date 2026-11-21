//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_reach_go && !sbo_omit_security_scan_osv

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// reachSourceRecord is a GO- record that lists one symbol.
const reachSourceRecord = `{"id":"GO-2020-0017","aliases":["CVE-2020-26160"],"affected":[{"package":{"ecosystem":"Go","name":"example.com/jwt"},
 "ecosystem_specific":{"imports":[{"path":"example.com/jwt","symbols":["MapClaims.VerifyAudience"]}]}}]}`

// reachSourceCalled is one go.mod run's osv-scanner output: the record
// called.
const reachSourceCalled = `{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[
 {"package":{"name":"example.com/jwt","version":"1.0.0","ecosystem":"Go"},
  "groups":[{"ids":["GO-2020-0017"],"aliases":["CVE-2020-26160","GO-2020-0017"],"experimental_analysis":{"GO-2020-0017":{"called":true}}}]}]}]}`

type fakeReachIsolation struct{}

func (fakeReachIsolation) Name() string { return "isolation.fake" }
func (fakeReachIsolation) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	return p, nil
}

type reachSourceFixture struct {
	e       *depsScanEnv
	root    string
	ex      *extruntest.Executor
	noGo    bool
	iso     bool
	isoDirs extrun.OneShotDirs
	// stdout answers a run by its go.mod (relative), stderr and exit too.
	answer func(gomod string) (stdout, stderr string, code int)
}

func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func newReachSourceFixture(t *testing.T) *reachSourceFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fixture uses POSIX paths")
	}
	setTestHome(t, t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	obs := t.TempDir()
	dir := filepath.Join(obs, "security")
	db := osvdb.Open(filepath.Join(dir, "osv"))
	entries := map[string]string{osvdb.EntryName("GO-2020-0017"): reachSourceRecord}
	writeZip(t, filepath.Join(db.Dir(), "osv-scalibr", "Go", "all.zip"), entries)
	writeZip(t, filepath.Join(db.Dir(), "osv-scanner", "Go", "all.zip"), entries)
	eps, _ := json.Marshal([]osvdb.Epoch{{Ecosystem: "Go", CRC32C: "c", Size: 1, FetchedAt: time.Now()}})
	if err := os.WriteFile(filepath.Join(db.Dir(), "epochs.json"), eps, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Components.Add = []string{"security", "security.deps", reachGoComponent}
	root := t.TempDir()
	for _, p := range []string{"go.mod", "tools/go.mod"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), []byte("module example.com/app\n\ngo 1.27.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fx := &reachSourceFixture{e: &depsScanEnv{cfg: cfg, dir: dir, db: db}, root: root}
	fx.answer = func(string) (string, string, int) { return reachSourceCalled, "", 1 }
	fx.ex = &extruntest.Executor{Facts: func(p extrun.Plan) extrun.ExecFacts {
		if slices.Contains(p.Args, "--version") {
			return extrun.ExecFacts{Stdout: []byte("osv-scanner version: 2.6.0\n"), PeakChildren: -1}
		}
		i := slices.Index(p.Args, "-L")
		rel, _ := filepath.Rel(root, p.Args[i+1])
		out, errOut, code := fx.answer(filepath.ToSlash(rel))
		return extrun.ExecFacts{Stdout: []byte(out), Stderr: []byte(errOut), ExitCode: code, PeakChildren: -1}
	}}
	saved := reachSourceHooks
	t.Cleanup(func() { reachSourceHooks = saved })
	files := extruntest.Files{"/opt/osv/osv-scanner": {}, "/opt/go/bin/go": {}}
	reachSourceHooks.newRunner = func(p extrun.IsolationProvider) *extrun.Runner {
		r := extruntest.NewRunner("linux", files, fx.ex, nil)
		r.Isolation = p
		r.Resolve = func(spec integration.BinaryResolveSpec) toolresolve.Resolution {
			switch {
			case slices.Contains(spec.Names.Unix, "osv-scanner"):
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/opt/osv/osv-scanner"}
			case slices.Contains(spec.Names.Unix, "go") && !fx.noGo:
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/opt/go/bin/go"}
			}
			return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
		}
		return r
	}
	reachSourceHooks.isolation = func(*depsScanEnv) (extrun.IsolationFactory, bool) {
		if !fx.iso {
			return nil, false
		}
		return func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
			fx.isoDirs = d
			return fakeReachIsolation{}, nil
		}, true
	}
	reachSourceHooks.goRoot = func(string) (string, string, bool) { return "/opt/go", "go1.27.3", true }
	reachSourceHooks.modCache = func() string { return "/opt/gomod" }
	return fx
}

func (fx *reachSourceFixture) optIn(t *testing.T, allowUnisolated bool) {
	t.Helper()
	key, err := depsRecordSigningKey(fx.e.dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secreachsvc.RecordSourceOptIn(fx.e.dir, secposture.ProjectRootHash(fx.root), "cli", "", allowUnisolated, time.Now(), key); err != nil {
		t.Fatal(err)
	}
}

func (fx *reachSourceFixture) run(opts reachSourceOptions) (reachSourceReport, error) {
	opts.Root = fx.root
	return fx.e.runReachSource(context.Background(), opts)
}

func TestReachSourceRefusals(t *testing.T) {
	fx := newReachSourceFixture(t)
	if _, err := fx.run(reachSourceOptions{}); !errors.Is(err, errReachSourceNotOptedIn) {
		t.Fatalf("not opted in: %v", err)
	}
	fx.optIn(t, false)
	_, err := fx.run(reachSourceOptions{})
	if err == nil || !strings.Contains(err.Error(), "isolation") {
		t.Fatalf("no isolation, no override: %v", err)
	}
	if n := len(fx.ex.Calls()); n != 0 {
		t.Fatalf("a refused check started %d processes", n)
	}
	fx.e.cfg.Components.Add = []string{"security", "security.deps"}
	if _, err := fx.run(reachSourceOptions{AllowUnisolated: true}); !errors.Is(err, errReachSourceNotSelected) {
		t.Fatalf("component off: %v", err)
	}
}

func TestReachSourceRunsEachGoModAndStores(t *testing.T) {
	fx := newReachSourceFixture(t)
	fx.optIn(t, true) // the stored override
	fx.answer = func(gomod string) (string, string, int) {
		if gomod == "tools/go.mod" {
			return "", "fatal error: runtime: out of memory\n", 2
		}
		return reachSourceCalled, "", 1
	}
	rep, err := fx.run(reachSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Isolation != "not isolated" || rep.Toolchain != "go1.27.3" || rep.Engine != "2.6.0" {
		t.Errorf("report %+v", rep)
	}
	if len(rep.Runs) != 2 || rep.Runs[0].Target != "go.mod" || rep.Runs[1].Reason != secreach.ReasonOutOfMemory {
		t.Fatalf("runs %+v", rep.Runs)
	}
	called := false
	for _, r := range rep.Runs[0].Records {
		called = called || (r.ID == "GO-2020-0017" && r.Verdict == secreach.VerdictCalled)
	}
	if !called {
		t.Errorf("go.mod records %+v", rep.Runs[0].Records)
	}
	stored := secreachsvc.LoadSymbolRuns(fx.e.dir, secposture.ProjectRootHash(fx.root))
	if len(stored) != 2 || stored[0].Source != secreach.SourceGovulncheckSource {
		t.Errorf("stored %+v", stored)
	}
	var runs []extrun.Plan
	for _, p := range fx.ex.Calls() {
		if slices.Contains(p.Args, "-L") {
			runs = append(runs, p)
		}
	}
	if len(runs) != 2 {
		t.Fatalf("%d go.mod processes, want one per go.mod", len(runs))
	}
	env := strings.Join(runs[0].Env, "\n") + "\n"
	for _, want := range []string{"GOTOOLCHAIN=local\n", "GOPROXY=off\n", "GOFLAGS=-mod=readonly\n", "GOWORK=off\n", "GOMEMLIMIT=11059MiB\n", "GOMODCACHE=/opt/gomod\n"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q", want)
		}
	}
	if slices.Contains(runs[0].Args, "-r") || !slices.Contains(runs[0].Args, "--call-analysis=go") {
		t.Errorf("args %v", runs[0].Args)
	}
	if runs[0].Limits.MemoryBytes != 12288<<20 {
		t.Errorf("memory cap %d", runs[0].Limits.MemoryBytes)
	}
}

func TestReachSourceIsolatedRunBindsToolchainAndCache(t *testing.T) {
	fx := newReachSourceFixture(t)
	fx.optIn(t, false)
	fx.iso = true
	rep, err := fx.run(reachSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Isolation != "isolation.fake" {
		t.Errorf("isolation %q", rep.Isolation)
	}
	if !slices.Contains(fx.isoDirs.ProgramDirs, "/opt/go") || !slices.Contains(fx.isoDirs.ProgramDirs, "/opt/gomod") || fx.isoDirs.Project == "" {
		t.Errorf("one-shot dirs %+v", fx.isoDirs)
	}
}

func TestReachSourceNoToolchainAndModuleCap(t *testing.T) {
	fx := newReachSourceFixture(t)
	fx.optIn(t, true)
	fx.noGo = true
	rep, err := fx.run(reachSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep.Runs {
		if r.Reason != secreach.ReasonNoToolchain {
			t.Errorf("no toolchain: %+v", r)
		}
	}
	fx.noGo = false
	fx.e.cfg.Security.Reach.Go.SourceMaxModules = 1
	rep, err = fx.run(reachSourceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Runs) != 2 || rep.Runs[0].Reason != "" || rep.Runs[1].Reason != secreach.ReasonModuleCap {
		t.Errorf("module cap: %+v", rep.Runs)
	}
}

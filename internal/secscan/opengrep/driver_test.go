package opengrep

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const (
	root     = "/home/u/src/p"
	packDir  = "/home/u/.cache/sbo/scanners/opengrep/pack"
	cacheDir = "/home/u/.cache/sbo/scanners/opengrep/engine"
	outDir   = "/home/u/.cache/sbo/scanners/opengrep/runs/r1"
	bin      = "/usr/local/bin/opengrep"
	treeDir  = cacheDir + "/xdg-cache/opengrep/v1.30.1"
)

var canaryPath = packDir + "/canary/observer_code_canary.py"

// memState is an in-memory StateStore.
type memState struct {
	mu    sync.Mutex
	s     State
	saves int
}

func (m *memState) Load() (State, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.s, nil }
func (m *memState) Save(s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s = s
	m.saves++
	return nil
}

// sarifDoc builds Opengrep-shaped SARIF: severity on the rule, a
// matchBasedId fingerprint, repository-relative URIs.
func sarifDoc(results ...[3]string) string {
	var rs []string
	for i, r := range results {
		rs = append(rs, fmt.Sprintf(`{"ruleId":%q,"fingerprints":{"matchBasedId/v1":"fp%d"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q,"uriBaseId":"%%SRCROOT%%"},"region":{"startLine":%s,"endLine":%s}}}],"message":{"text":"engine text with a secret"},"properties":{}}`, r[0], i, r[1], r[2], r[2]))
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Opengrep OSS","rules":[` +
		`{"id":"python.sql-string-concat","defaultConfiguration":{"level":"error"}},` +
		`{"id":"observer-code.canary","defaultConfiguration":{"level":"note"}}]}},` +
		`"invocations":[{"executionSuccessful":true}],"results":[` + strings.Join(rs, ",") + `]}]}`
}

// fake is the scripted engine: what each run prints and writes.
type fake struct {
	t        *testing.T
	files    extruntest.Files
	tree     secengine.TreeListing
	written  map[string][]byte
	version  string
	exit     int
	kill     extrun.KillReason
	results  [][3]string
	noCanary bool
	scanned  []string
	errors   []string
	// gitConfig is what `git config --get-regexp ^filter.` prints (the
	// filter-driver check); empty prints nothing and exits 1. gitExit, when
	// set, is its exit status.
	gitConfig string
	gitExit   int
}

func newFake(t *testing.T) *fake {
	pin, _ := secengine.CompiledPin("linux", "amd64")
	return &fake{
		t: t, version: secengine.TestedVersion, written: map[string][]byte{},
		files: extruntest.Files{
			bin:                         {Digest: pin.SHA256},
			"/usr/bin/git":              {},
			treeDir + "/opengrep.bin":   {Digest: strings.Repeat("1", 64)},
			treeDir + "/lib/_opcode.so": {Digest: strings.Repeat("2", 64)},
		},
		tree:    secengine.TreeListing{Files: []string{"lib/_opcode.so", "opengrep.bin"}},
		results: [][3]string{{"python.sql-string-concat", "b.py", "7"}},
		scanned: []string{"a.py", "b.py"},
	}
}

func (f *fake) facts(p extrun.Plan) extrun.ExecFacts {
	if p.Path == "/usr/bin/git" {
		code := f.gitExit
		if code == 0 && f.gitConfig == "" {
			code = 1
		}
		return extrun.ExecFacts{Stdout: []byte(f.gitConfig), ExitCode: code, PeakChildren: -1}
	}
	if slices.Contains(p.Args, "--version") {
		return extrun.ExecFacts{Stdout: []byte(f.version + "\n"), PeakChildren: -1}
	}
	if f.kill != extrun.KillNone {
		return extrun.ExecFacts{KillReason: f.kill, Signaled: true, PeakChildren: -1}
	}
	if f.exit != 0 {
		return extrun.ExecFacts{ExitCode: f.exit, PeakChildren: -1}
	}
	withCanary := slices.Contains(p.Args, canaryPath) && !f.noCanary
	selfTest := withCanary && !slices.Contains(p.Args, ".") && !slices.ContainsFunc(p.Args, func(a string) bool { return strings.HasPrefix(a, "./") })
	var results [][3]string
	scanned := []string{}
	if !selfTest {
		results = append(results, f.results...)
		for _, s := range f.scanned {
			scanned = append(scanned, fmt.Sprintf("%q", s))
		}
	}
	if withCanary {
		results = append(results, [3]string{"observer-code.canary", canaryPath, "5"})
		scanned = append(scanned, fmt.Sprintf("%q", canaryPath))
	}
	var errs []string
	for _, e := range f.errors {
		errs = append(errs, fmt.Sprintf(`{"path":%q}`, e))
	}
	for _, a := range p.Args {
		if out, ok := strings.CutPrefix(a, "--json-output="); ok {
			f.written[out] = []byte(`{"version":"1.30.1","results":[],"errors":[` + strings.Join(errs, ",") + `],"paths":{"scanned":[` + strings.Join(scanned, ",") + `]}}`)
		}
	}
	return extrun.ExecFacts{Stdout: []byte(sarifDoc(results...)), PeakChildren: -1}
}

func (f *fake) env(ex *extruntest.Executor, st StateStore) Env {
	r := extruntest.NewRunner("linux", f.files, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		switch {
		case slices.Contains(s.Names.Unix, "opengrep"):
			if _, ok := f.files[bin]; ok {
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: bin}
			}
		case slices.Contains(s.Names.Unix, "git"):
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: "/usr/bin/git"}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
	}
	ex.Facts = f.facts
	pack, err := secrulepack.Floor()
	if err != nil {
		f.t.Fatal(err)
	}
	return Env{
		Runner: r, Pack: pack, PackDir: packDir, CacheDir: cacheDir, OutDir: outDir, State: st,
		ListTree: func(dir string) secengine.TreeListing {
			if dir != treeDir {
				return secengine.TreeListing{Missing: true}
			}
			return f.tree
		},
		ReadFile: func(p string, _ int64) ([]byte, error) {
			b, ok := f.written[p]
			if !ok {
				return nil, errors.New("no such file")
			}
			return b, nil
		},
		GOOS: "linux", GOARCH: "amd64", Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) },
	}
}

func full() secscan.Target {
	return secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeManual}
}

func hasNote(notes []string, prefix string) bool {
	for _, n := range notes {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

func TestFullScanVerified(t *testing.T) {
	f := newFake(t)
	ex := &extruntest.Executor{}
	st := &memState{}
	res, scanned, err := New(f.env(ex, st)).ScanFiles(context.Background(), full())
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 1 {
		t.Fatalf("coverage %+v findings %d", res.Coverage, len(res.Findings))
	}
	fd := res.Findings[0]
	if fd.Rule.ID != "python.sql-string-concat" || fd.Rule.Pack != secrulepack.PackID || fd.Rule.PackVersion != floorVersion(t) ||
		fd.Severity != policy.FindingSeverityHigh || fd.Confidence != policy.FindingConfidenceMedium || fd.Location.RelPath != "b.py" {
		t.Errorf("finding %+v", fd)
	}
	if strings.Contains(fd.Message, "secret") {
		t.Errorf("engine text reached the finding: %q", fd.Message)
	}
	if !hasNote(res.Coverage.Notes, NotIsolatedPrefix) || hasNote(res.Coverage.Notes, UnverifiedPrefix) || hasNote(res.Coverage.Notes, UntestedPrefix) {
		t.Errorf("notes %v", res.Coverage.Notes)
	}
	if strings.Join(scanned.Files, ",") != "a.py,b.py" || !scanned.Canary {
		t.Errorf("scanned %+v", scanned)
	}
	if res.Engine.Version != "1.30.1" || res.Engine.RulePackVersion != floorVersion(t) || res.Engine.Digest == "" {
		t.Errorf("engine %+v", res.Engine)
	}
	// The tree and the self-test were recorded after this first verified run.
	s, _ := st.Load()
	if s.Tree == nil || len(s.Tree.Files) != 2 || s.SelfTest == nil {
		t.Fatalf("state %+v", s)
	}
	calls := ex.Calls()
	if len(calls) != 2 {
		t.Fatalf("%d runs, want the version probe and the scan", len(calls))
	}
	p := calls[1]
	for _, flag := range FlagsAlways {
		if !slices.Contains(p.Args, flag) {
			t.Errorf("flag %s missing from %v", flag, p.Args)
		}
	}
	joined := strings.Join(p.Args, " ")
	for _, never := range FlagsNever {
		if strings.Contains(joined, never) {
			t.Errorf("refused flag %q passed", never)
		}
	}
	for _, want := range []string{"--config " + packDir + "/rules", "--no-git-ignore", "--json-output=" + outDir + "/opengrep.json", ". " + canaryPath, "-j 4"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args lack %q: %s", want, joined)
		}
	}
	if p.Component != ComponentID || p.Dir != root || p.Limits.Wall != 600*time.Second || p.Limits.MemoryBytes != 2<<30 || p.Limits.Children != 64 || p.Limits.StdoutBytes != 32<<20 {
		t.Errorf("plan %+v", p)
	}
}

// TestRequestEnv pins the environment the runner hands Opengrep: the
// locale, its own HOME and XDG_CACHE_HOME where the driver looks for the
// tree, the git hardening, and a PATH holding git's directory only.
func TestRequestEnv(t *testing.T) {
	f := newFake(t)
	ex := &extruntest.Executor{}
	if _, err := New(f.env(ex, &memState{})).Scan(context.Background(), full()); err != nil {
		t.Fatal(err)
	}
	env := ex.Calls()[1].Env
	want := []string{
		"LC_ALL=C.UTF-8", "HOME=" + cacheDir + "/home", "XDG_CACHE_HOME=" + cacheDir + "/xdg-cache",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_LFS_SKIP_SMUDGE=1", "PATH=/usr/bin",
	}
	for _, w := range want {
		if !slices.Contains(env, w) {
			t.Errorf("env lacks %s: %v", w, env)
		}
	}
	for _, e := range env {
		if strings.HasPrefix(e, "GIT_CONFIG_PARAMETERS=") && !strings.Contains(e, "core.fsmonitor=false") {
			t.Errorf("fsmonitor not disabled: %s", e)
		}
	}
}

func TestScanRefusals(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(f *fake, e *Env)
		target  secscan.Target
		outcome secscan.Outcome
		reason  string
		runs    int
	}{
		{"not installed starts nothing", func(f *fake, _ *Env) { delete(f.files, bin) }, full(), secscan.OutcomeNotScanned, ReasonNotInstalled, 0},
		{"a pin-owed platform is refused", func(_ *fake, e *Env) { e.GOOS = "windows" }, full(), secscan.OutcomeFailed, secengine.ReasonUnverified, 0},
		{"an unpinned binary on a managed node is refused", func(f *fake, e *Env) {
			f.files[bin] = extruntest.File{Digest: strings.Repeat("9", 64)}
			e.Managed = true
		}, full(), secscan.OutcomeFailed, secengine.ReasonUnverified, 0},
		{"an old version is refused", func(f *fake, _ *Env) {
			f.files[bin] = extruntest.File{Digest: strings.Repeat("9", 64)}
			f.version = "1.29.0"
		}, full(), secscan.OutcomeFailed, secengine.ReasonUnverified, 1},
		{"a crash", func(f *fake, _ *Env) { f.exit = 2 }, full(), secscan.OutcomeFailed, ReasonCrashed, 2},
		{"an invalid rule file", func(f *fake, _ *Env) { f.exit = 7 }, full(), secscan.OutcomeFailed, ReasonConfig, 2},
		{"the wall cap", func(f *fake, _ *Env) { f.kill = extrun.KillTimeout }, full(), secscan.OutcomeFailed, ReasonBudget, 2},
		{"exit 0 with no canary is unknown, never clean", func(f *fake, _ *Env) { f.noCanary, f.results = true, nil }, full(), secscan.OutcomeUnknown, "canary_not_reported", 2},
		{"a diff base that is not a commit id", nil, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeDiff, BaseRev: "--upload-pack=x"}, secscan.OutcomeFailed, ReasonBadBase, 0},
		{"an isolation provider that refuses", func(_ *fake, e *Env) {
			e.Isolate = func(extrun.OneShotDirs) (extrun.IsolationProvider, error) { return nil, errors.New("bwrap refused") }
			e.IsolatedRunner = func(extrun.IsolationProvider) *extrun.Runner { return e.Runner }
		}, full(), secscan.OutcomeFailed, ReasonIsolation, 0},
		{"no pack", func(_ *fake, e *Env) { e.Pack = nil }, full(), secscan.OutcomeNotScanned, ReasonNoPack, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			ex := &extruntest.Executor{}
			e := f.env(ex, &memState{})
			if c.prepare != nil {
				c.prepare(f, &e)
			}
			res, scanned, err := New(e).ScanFiles(context.Background(), c.target)
			if err != nil {
				t.Fatal(err)
			}
			if res.Coverage.Outcome != c.outcome || res.Coverage.Reason != c.reason {
				t.Fatalf("coverage %+v, want %s %s", res.Coverage, c.outcome, c.reason)
			}
			if c.outcome != secscan.OutcomeFindings && len(res.Findings) != 0 || len(scanned.Files) != 0 {
				t.Errorf("a run that did not scan returned findings or closable files (%v)", scanned.Files)
			}
			if got := len(ex.Calls()); got != c.runs {
				t.Errorf("%d processes started, want %d", got, c.runs)
			}
		})
	}
}

func TestUnverifiedOnIndividualNodeIsLabelled(t *testing.T) {
	f := newFake(t)
	f.files[bin] = extruntest.File{Digest: strings.Repeat("9", 64)}
	f.version = "1.31.0"
	st := &memState{}
	res, _, _ := New(f.env(&extruntest.Executor{}, st)).ScanFiles(context.Background(), full())
	if res.Coverage.Outcome != secscan.OutcomeFindings || !hasNote(res.Coverage.Notes, UnverifiedPrefix) || !hasNote(res.Coverage.Notes, UntestedPrefix) {
		t.Fatalf("coverage %+v", res.Coverage)
	}
	if s, _ := st.Load(); s.Tree != nil || s.SelfTest != nil {
		t.Errorf("an unverified run recorded state: %+v", s)
	}
}

// TestCompanionTreeX9: after the first verified run, a changed file of the
// unpacked tree refuses the run (the runner compares the recorded digest);
// an added file labels it on an individual node and refuses it on a
// managed one; a removed tree is unpacked and recorded again.
func TestCompanionTreeX9(t *testing.T) {
	f := newFake(t)
	st := &memState{}
	ctx := context.Background()
	if res, _, _ := New(f.env(&extruntest.Executor{}, st)).ScanFiles(ctx, full()); res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Fatalf("first run %+v", res.Coverage)
	}
	// Second run: the recorded digests reach the runner.
	ex := &extruntest.Executor{}
	if res, _, _ := New(f.env(ex, st)).ScanFiles(ctx, full()); res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Fatalf("second run %+v", res.Coverage)
	}
	if !slices.Contains(ex.Calls()[0].Args, "--version") {
		t.Fatal("expected the version probe first")
	}
	// One byte of _opcode.so changed: the runner refuses before anything starts.
	f.files[treeDir+"/lib/_opcode.so"] = extruntest.File{Digest: strings.Repeat("3", 64)}
	ex = &extruntest.Executor{}
	res, _, _ := New(f.env(ex, st)).ScanFiles(ctx, full())
	if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
		t.Fatalf("a changed tree file: %+v, %d processes", res.Coverage, len(ex.Calls()))
	}
	f.files[treeDir+"/lib/_opcode.so"] = extruntest.File{Digest: strings.Repeat("2", 64)}
	// An added file: labelled on an individual node.
	f.tree.Files = append(f.tree.Files, "lib/planted.so")
	f.files[treeDir+"/lib/planted.so"] = extruntest.File{}
	res, _, _ = New(f.env(&extruntest.Executor{}, st)).ScanFiles(ctx, full())
	if !hasNote(res.Coverage.Notes, UnverifiedPrefix) || res.Coverage.Outcome == secscan.OutcomeFailed {
		t.Fatalf("an added file, individual: %+v", res.Coverage)
	}
	e := f.env(&extruntest.Executor{}, st)
	e.Managed = true
	res, _, _ = New(e).ScanFiles(ctx, full())
	if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != secengine.ReasonUnverified {
		t.Fatalf("an added file, managed: %+v", res.Coverage)
	}
	// The tree removed: unpacked and recorded again by the next verified run.
	f.tree = secengine.TreeListing{Missing: true}
	e = f.env(&extruntest.Executor{}, st)
	e.ListTree = func(string) secengine.TreeListing { return f.tree }
	res, _, _ = New(e).ScanFiles(ctx, full())
	if res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Fatalf("a removed tree: %+v", res.Coverage)
	}
}

func TestDiffScope(t *testing.T) {
	f := newFake(t)
	st := &memState{}
	ex := &extruntest.Executor{}
	tgt := secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeDiff, BaseRev: "c3fef7c"}
	res, scanned, err := New(f.env(ex, st)).ScanFiles(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	calls := ex.Calls()
	if len(calls) != 4 {
		t.Fatalf("%d runs, want the filter-driver check, the probe, the self-test and the diff scan", len(calls))
	}
	if calls[0].Path != "/usr/bin/git" || !slices.Equal(calls[0].Args, GitFilterArgs) {
		t.Errorf("first run %s %v, want the filter-driver check", calls[0].Path, calls[0].Args)
	}
	calls = calls[1:]
	selfTest, diff := strings.Join(calls[1].Args, " "), strings.Join(calls[2].Args, " ")
	if !strings.HasSuffix(selfTest, canaryPath) || strings.Contains(selfTest, "--baseline-commit") {
		t.Errorf("self-test args %s", selfTest)
	}
	if !strings.Contains(diff, "--baseline-commit c3fef7c .") || strings.Contains(diff, canaryPath) || strings.Contains(diff, "--no-git-ignore") {
		t.Errorf("diff args %s", diff)
	}
	if calls[2].Limits.Wall != 60*time.Second {
		t.Errorf("diff wall %s", calls[2].Limits.Wall)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(scanned.Files) != 0 {
		t.Fatalf("diff result %+v, closable %v (a diff scope closes nothing)", res.Coverage, scanned.Files)
	}
	// The next diff relies on the recorded self-test: no canary run.
	ex = &extruntest.Executor{}
	f.results = nil
	res, _, _ = New(f.env(ex, st)).ScanFiles(context.Background(), tgt)
	if len(ex.Calls()) != 3 || res.Coverage.Outcome != secscan.OutcomeClean {
		t.Fatalf("second diff: %d runs, %+v", len(ex.Calls()), res.Coverage)
	}
}

func TestCanaryOnlyCountsInTheCanaryFile(t *testing.T) {
	f := newFake(t)
	f.noCanary = true
	f.results = [][3]string{{"observer-code.canary", "fake_canary.py", "1"}}
	res, _, _ := New(f.env(&extruntest.Executor{}, &memState{})).ScanFiles(context.Background(), full())
	if res.Coverage.Outcome != secscan.OutcomeUnknown || len(res.Findings) != 0 {
		t.Fatalf("a project file calling the canary marker: %+v, %d findings", res.Coverage, len(res.Findings))
	}
}

func TestPartiallyParsedFilesNeverClose(t *testing.T) {
	f := newFake(t)
	f.errors = []string{"a.py"}
	res, scanned, _ := New(f.env(&extruntest.Executor{}, &memState{})).ScanFiles(context.Background(), full())
	if slices.Contains(scanned.Files, "a.py") || len(scanned.Partial) != 1 {
		t.Fatalf("scanned %+v", scanned)
	}
	if len(res.Coverage.Skipped) != 1 || res.Coverage.Skipped[0].Reason != "partially_parsed" {
		t.Errorf("skipped %+v", res.Coverage.Skipped)
	}
}

func TestIsolatedRun(t *testing.T) {
	f := newFake(t)
	ex := &extruntest.Executor{}
	e := f.env(ex, &memState{})
	var dirs extrun.OneShotDirs
	e.Isolate = func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) { dirs = d; return wrapper{}, nil }
	base := e.Runner
	e.IsolatedRunner = func(p extrun.IsolationProvider) *extrun.Runner {
		return &extrun.Runner{GOOS: base.GOOS, Resolve: base.Resolve, Inspect: base.Inspect, Hash: base.Hash, Getenv: base.Getenv, Exec: base.Exec, Isolation: p}
	}
	res, _, _ := New(e).ScanFiles(context.Background(), full())
	if hasNote(res.Coverage.Notes, NotIsolatedPrefix) || res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Fatalf("isolated: %+v", res.Coverage)
	}
	if dirs.Project != root || dirs.Output != outDir || dirs.Cache != cacheDir || !slices.Contains(dirs.ProgramDirs, packDir) {
		t.Errorf("one-shot dirs %+v", dirs)
	}
	if ex.Calls()[1].Path != "/usr/bin/bwrap" {
		t.Errorf("the scan was not wrapped: %s", ex.Calls()[1].Path)
	}
}

// wrapper is a stand-in isolation provider.
type wrapper struct{}

func (wrapper) Name() string { return "test-wrapper" }
func (wrapper) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	p.Args = append([]string{p.Path}, p.Args...)
	p.Path = "/usr/bin/bwrap"
	return p, nil
}

func TestRowRegisters(t *testing.T) {
	if _, err := secscan.NewRegistry(New(Env{})); err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	r := Row()
	if r.Kind != secscan.KindProcess || !r.DiffAware || !r.Offline.NoNetwork || len(r.Egress) != 0 || r.SemanticAdapter != "opengrep" {
		t.Errorf("row %+v", r)
	}
}

func TestJobsScaleTheChildrenCap(t *testing.T) {
	if LimitsFor(ModeFull, 8).Children != 128 || LimitsFor(ModeFull, 2).Children != 64 || LimitsFor(ModeDiff, 0).Children != 64 {
		t.Error("children cap does not scale with -j")
	}
	if ClampJobs(100) != MaxJobs || ClampJobs(-1) != DefaultJobs {
		t.Error("jobs not clamped")
	}
}

// TestInspectDoesNotHashTheTree (lane SEC-G1 audit finding 6): status and
// doctor report the recorded tree and its age; they hash the binary only,
// never the unpacked tree, and write nothing. The next scan's runner is
// what compares the tree's digests.
func TestInspectDoesNotHashTheTree(t *testing.T) {
	f := newFake(t)
	st := &memState{}
	_, _, _ = New(f.env(&extruntest.Executor{}, st)).ScanFiles(context.Background(), full())
	saves := st.saves
	f.files[treeDir+"/opengrep.bin"] = extruntest.File{Digest: strings.Repeat("7", 64)}
	ex := &extruntest.Executor{}
	e := f.env(ex, st)
	var hashed []string
	inner := e.Runner.Hash
	e.Runner.Hash = func(p string) (string, error) { hashed = append(hashed, p); return inner(p) }
	in := New(e).Inspect()
	if in.Tree != secengine.TreeSame || in.Decision.Status != secengine.StatusVerified || in.TreeRecordedAt.IsZero() || in.SelfTestAt.IsZero() {
		t.Fatalf("after the first run: %+v", in)
	}
	if !slices.Equal(hashed, []string{bin}) {
		t.Errorf("Inspect hashed %v, want the binary only", hashed)
	}
	if st.saves != saves || len(ex.Calls()) != 0 {
		t.Errorf("Inspect wrote the state (%d saves) or started %d processes", st.saves-saves, len(ex.Calls()))
	}
	// The changed file is caught by the next scan, before Opengrep starts.
	ex = &extruntest.Executor{}
	if res, _, _ := New(f.env(ex, st)).ScanFiles(context.Background(), full()); res.Coverage.Reason != secengine.ReasonUnverified || len(ex.Calls()) != 0 {
		t.Fatalf("the scan after a changed tree file: %+v, %d processes", res.Coverage, len(ex.Calls()))
	}
}

// floorVersion is the embedded pack's version (lane SEC-G3 raises it).
func floorVersion(t *testing.T) string {
	t.Helper()
	p, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	return p.Version()
}

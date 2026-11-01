package seciac

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

const (
	dRoot    = "/work/project"
	dCache   = "/c/engine"
	dOut     = "/c/runs/r1"
	dCanary  = "/c/canary"
	dTrivy   = "/usr/local/bin/trivy"
	dKICS    = "/opt/kics/kics"
	dQueries = "/opt/kics/assets/queries"
)

type memState struct {
	mu sync.Mutex
	s  State
}

func (m *memState) Load() (State, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.s, nil }
func (m *memState) Save(s State) error   { m.mu.Lock(); defer m.mu.Unlock(); m.s = s; return nil }

// engineFake scripts one engine: what --version, --help and a scan print
// and write.
type engineFake struct {
	t        *testing.T
	id       EngineID
	files    extruntest.Files
	written  map[string][]byte
	version  string
	help     []byte
	sarif    []byte
	noCanary bool
	exit     int
}

func newEngineFake(t *testing.T, id EngineID) *engineFake {
	t.Helper()
	f := &engineFake{t: t, id: id, written: map[string][]byte{}, files: extruntest.Files{}}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	switch id {
	case Trivy:
		f.files[dTrivy] = extruntest.File{Digest: hexd('b')}
		f.version, f.help, f.sarif = "Version: 0.75.0\n", read("trivy-0.75.0-config-help.txt"), read("trivy-0.75.0-config.sarif")
	case KICS:
		f.files[dKICS] = extruntest.File{Digest: hexd('7')}
		f.files[dQueries] = extruntest.File{Dir: true}
		f.files[dQueries+"/a/query.rego"] = extruntest.File{Digest: hexd('1')}
		f.version, f.help, f.sarif = "Keeping Infrastructure as Code Secure v2.2.0\n", read("kics-2.2.0-scan-help.txt"), read("kics-2.2.0-scan.sarif")
	}
	return f
}

func (f *engineFake) facts(p extrun.Plan) extrun.ExecFacts {
	switch {
	case slices.Contains(p.Args, "--version") || slices.Equal(p.Args, []string{"version"}):
		return extrun.ExecFacts{Stdout: []byte(f.version), PeakChildren: -1}
	case slices.Contains(p.Args, "--help"):
		return extrun.ExecFacts{Stdout: f.help, PeakChildren: -1}
	}
	if f.exit != 0 {
		return extrun.ExecFacts{ExitCode: f.exit, PeakChildren: -1}
	}
	out := ""
	for i, a := range p.Args {
		if a == "--output" || a == "--output-path" {
			out = p.Args[i+1]
		}
	}
	canary := slices.Contains(p.Args, dCanary)
	if f.id == Trivy {
		out = strings.TrimSuffix(out, "/trivy.sarif")
	}
	switch {
	case canary && f.noCanary:
		f.written[SARIFPath(f.id, RunPaths{Out: out})] = []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`)
	case canary:
		f.written[SARIFPath(f.id, RunPaths{Out: out})] = []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"DS-0002"}]}},"results":[{"ruleId":"DS-0002","locations":[{"physicalLocation":{"artifactLocation":{"uri":"Dockerfile"},"region":{"startLine":1}}}],"message":{"text":"m"}}]}]}`)
	default:
		f.written[SARIFPath(f.id, RunPaths{Out: out})] = f.sarif
	}
	return extrun.ExecFacts{PeakChildren: -1}
}

type fakeProvider struct{}

func (fakeProvider) Name() string { return "test-no-network" }
func (fakeProvider) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	p.Path = "/isolate"
	return p, nil
}

func (f *engineFake) env(ex *extruntest.Executor, st StateStore, isolated bool) Env {
	r := extruntest.NewRunner("linux", f.files, ex, nil)
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		for _, p := range []string{dTrivy, dKICS} {
			if _, ok := f.files[p]; ok && slices.Contains(s.Names.Unix, filepath.Base(p)) {
				return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: p}
			}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
	}
	ex.Facts = f.facts
	e := Env{
		Engine: f.id, Runner: r, CacheDir: dCache, OutDir: dOut, CanaryDir: dCanary, State: st, Compiled: pinned(),
		TopNames: func(string) []string { return []string{".trivyignore", "kics.config"} },
		ListTree: func(dir string) secengine.TreeListing {
			if dir != dQueries {
				return secengine.TreeListing{Missing: true}
			}
			return secengine.TreeListing{Files: []string{"a/query.rego"}}
		},
		ReadFile: func(p string, _ int64) ([]byte, error) {
			b, ok := f.written[p]
			if !ok {
				return nil, errors.New("no such file " + p)
			}
			return b, nil
		},
		RootHash: func(string) string { return "h" },
		GOOS:     "linux", GOARCH: "amd64", Now: func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) },
	}
	if isolated {
		e.Isolate = func(extrun.OneShotDirs) (extrun.IsolationProvider, error) { return fakeProvider{}, nil }
		e.IsolatedRunner = func(p extrun.IsolationProvider) *extrun.Runner {
			r2 := extruntest.NewRunner("linux", f.files, ex, nil)
			r2.Resolve, r2.Isolation = r.Resolve, p
			return r2
		}
	}
	return e
}

func target() secscan.Target {
	return secscan.Target{ProjectRoot: dRoot, Scope: policy.FindingScopeManual}
}

func scanArgs(ex *extruntest.Executor) [][]string {
	var out [][]string
	for _, p := range ex.Calls() {
		out = append(out, p.Args)
	}
	return out
}

func TestDriverTrivyVerifiedRun(t *testing.T) {
	f := newEngineFake(t, Trivy)
	ex := &extruntest.Executor{}
	st := &memState{}
	res, err := NewDriver(f.env(ex, st, true)).Scan(context.Background(), target())
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 30 || res.Engine.Version != "0.75.0" {
		t.Fatalf("%+v", res.Coverage)
	}
	notes := strings.Join(res.Coverage.Notes, "\n")
	if strings.Contains(notes, NotIsolatedPrefix) || !strings.Contains(notes, RepoConfigPrefix+": .trivyignore") {
		t.Errorf("notes %s", notes)
	}
	for _, p := range ex.Calls() {
		if p.Path != "/isolate" {
			t.Fatalf("a Trivy call ran unisolated: %v", p.Args)
		}
	}
	if strings.Contains(notes, UnverifiedPrefix) {
		t.Errorf("a pinned binary was labelled unverified: %s", notes)
	}
	// version, help, canary, scan; the scan carries every offline flag.
	calls := scanArgs(ex)
	if len(calls) != 4 {
		t.Fatalf("calls %v", calls)
	}
	scan := calls[3]
	for _, flag := range []string{"--skip-check-update", "--skip-version-check", "--disable-telemetry", "--ignorefile", "--config"} {
		if !slices.Contains(scan, flag) {
			t.Errorf("scan lacks %s: %v", flag, scan)
		}
	}
	if s, _ := st.Load(); s.FlagsOK != hexd('b') || s.SelfTest != hexd('b') {
		t.Errorf("state %+v", s)
	}
	// A second run skips the help and the canary.
	ex2 := &extruntest.Executor{}
	if _, err := NewDriver(f.env(ex2, st, true)).Scan(context.Background(), target()); err != nil {
		t.Fatal(err)
	}
	if n := len(ex2.Calls()); n != 1 { // the version answer is cached per runner; a new runner asks again
		if n != 2 {
			t.Errorf("second run made %d calls", n)
		}
	}
}

func TestDriverRefusalsStartNothing(t *testing.T) {
	cases := []struct {
		name    string
		mod     func(*engineFake, *Env)
		outcome secscan.Outcome
		reason  string
		calls   int
	}{
		{"not installed", func(f *engineFake, _ *Env) { delete(f.files, dTrivy) }, secscan.OutcomeNotScanned, ReasonNotInstalled, 0},
		{"managed refuses an unpinned binary", func(f *engineFake, e *Env) {
			f.files[dTrivy] = extruntest.File{Digest: hexd('c')}
			e.Managed = true
		}, secscan.OutcomeFailed, ReasonUnverified, 0},
		{"managed refuses a pin-owed platform", func(_ *engineFake, e *Env) { e.Managed, e.Compiled = true, CompiledPins(Trivy) }, secscan.OutcomeFailed, ReasonUnverified, 0},
		{"an individual node refuses an unpinned binary by default", func(f *engineFake, _ *Env) { f.files[dTrivy] = extruntest.File{Digest: hexd('c')} }, secscan.OutcomeFailed, ReasonUnverified, 0},
		{"managed refuses an unpinned binary whatever allow_unpinned says", func(f *engineFake, e *Env) {
			f.files[dTrivy] = extruntest.File{Digest: hexd('c')}
			e.Managed, e.AllowUnpinned = true, true
		}, secscan.OutcomeFailed, ReasonUnverified, 0},
		{"no isolation refuses Trivy by name", func(f *engineFake, e *Env) { e.Isolate, e.IsolatedRunner = nil, nil }, secscan.OutcomeNotScanned, ReasonIsolationRequired, 0},
		{"an old version is refused", func(f *engineFake, _ *Env) { f.version = "Version: 0.70.0\n" }, secscan.OutcomeFailed, ReasonUnverified, 1},
		{"a help without a required flag is refused", func(f *engineFake, _ *Env) {
			f.help = []byte(strings.ReplaceAll(string(f.help), "--skip-check-update", ""))
		}, secscan.OutcomeFailed, ReasonFlagsMissing, 2},
		{"a canary miss is never clean", func(f *engineFake, _ *Env) { f.noCanary = true }, secscan.OutcomeFailed, ReasonSelfTestFailed, 3},
		{"a crash", func(f *engineFake, _ *Env) { f.exit = 1 }, secscan.OutcomeFailed, ReasonCrashed, 3},
	}
	for _, c := range cases {
		f := newEngineFake(t, Trivy)
		ex := &extruntest.Executor{}
		e := f.env(ex, &memState{}, true)
		c.mod(f, &e)
		res, _ := NewDriver(e).Scan(context.Background(), target())
		if res.Coverage.Outcome != c.outcome || res.Coverage.Reason != c.reason || len(ex.Calls()) != c.calls {
			t.Errorf("%s: %s %s, %d calls; want %s %s, %d", c.name, res.Coverage.Outcome, res.Coverage.Reason, len(ex.Calls()), c.outcome, c.reason, c.calls)
		}
		if EngineRan(res.Coverage) && c.calls < 3 {
			t.Errorf("%s: a run that never scanned reads as a scan", c.name)
		}
	}
}

// TestDriverIndividualUnverifiedLabelledAndFirstUse (ruling P-143): an
// unpinned binary on an individual node is refused by default, naming the
// key; with allow_unpinned it runs labelled and its digest is recorded at
// first use.
func TestDriverIndividualUnverifiedLabelledAndFirstUse(t *testing.T) {
	f := newEngineFake(t, Trivy)
	f.files[dTrivy] = extruntest.File{Digest: hexd('c')}
	st := &memState{}
	refused, _ := NewDriver(f.env(&extruntest.Executor{}, st, true)).Scan(context.Background(), target())
	if refused.Coverage.Outcome != secscan.OutcomeFailed || !strings.Contains(strings.Join(refused.Coverage.Notes, " "), "[security.scan.trivy].allow_unpinned = true") {
		t.Fatalf("default: %+v", refused.Coverage)
	}
	if s, _ := st.Load(); s.FirstUse != "" {
		t.Fatalf("a refused binary recorded its first use: %+v", s)
	}
	e := f.env(&extruntest.Executor{}, st, true)
	e.AllowUnpinned = true
	res, _ := NewDriver(e).Scan(context.Background(), target())
	if res.Coverage.Outcome != secscan.OutcomeFindings || !strings.Contains(strings.Join(res.Coverage.Notes, " "), UnverifiedPrefix) ||
		!strings.Contains(strings.Join(res.Coverage.Notes, " "), "allow_unpinned is on") {
		t.Fatalf("%+v", res.Coverage)
	}
	if s, _ := st.Load(); s.FirstUse != hexd('c') || s.SelfTest != hexd('c') {
		t.Fatalf("state %+v (the canary passed for this digest)", s)
	}
	// The canary runs once per binary (audit finding F5): a second scan of
	// the same labelled binary skips it, a changed binary runs it again.
	canaries := func(ex *extruntest.Executor) int {
		n := 0
		for _, p := range ex.Calls() {
			if slices.ContainsFunc(p.Args, func(a string) bool { return strings.Contains(a, dCanary) }) {
				n++
			}
		}
		return n
	}
	ex2 := &extruntest.Executor{}
	e2 := f.env(ex2, st, true)
	e2.AllowUnpinned = true
	if _, err := NewDriver(e2).Scan(context.Background(), target()); err != nil || canaries(ex2) != 0 {
		t.Fatalf("the canary ran again for an unchanged binary: %d (%v)", canaries(ex2), err)
	}
	f.files[dTrivy] = extruntest.File{Digest: hexd('9')}
	ex3 := &extruntest.Executor{}
	e3 := f.env(ex3, st, true)
	e3.AllowUnpinned = true
	if _, err := NewDriver(e3).Scan(context.Background(), target()); err != nil || canaries(ex3) != 1 {
		t.Fatalf("a changed binary skipped the canary: %d (%v)", canaries(ex3), err)
	}
}

// TestDriverKICSNeedsIsolation: KICS has a network call no flag turns off,
// so without the isolation one-shot nothing starts; isolated, it runs and
// records its queries tree after the first verified run.
func TestDriverKICSNeedsIsolation(t *testing.T) {
	f := newEngineFake(t, KICS)
	ex := &extruntest.Executor{}
	unisolated := f.env(ex, &memState{}, false)
	unisolated.AllowUnpinned = true
	res, _ := NewDriver(unisolated).Scan(context.Background(), target())
	if res.Coverage.Outcome != secscan.OutcomeNotScanned || res.Coverage.Reason != ReasonIsolationRequired || len(ex.Calls()) != 0 {
		t.Fatalf("unisolated KICS: %+v, %d calls", res.Coverage, len(ex.Calls()))
	}
	if p := NewDriver(f.env(ex, &memState{}, false)).Probe(context.Background()); p.Reason != ReasonIsolationRequired {
		t.Fatalf("probe %+v", p)
	}
	// Pinned through a test table, isolated: a verified run.
	st := &memState{}
	ex2 := &extruntest.Executor{}
	e := f.env(ex2, st, true)
	e.Compiled = []Pin{{Engine: KICS, Version: "2.2.0", OS: "linux", Arch: "amd64", AssetSHA256: hexd('6'), BinarySHA256: hexd('7'), Status: PinPinned, Source: "compiled", DigestOnly: true}}
	res, _ = NewDriver(e).Scan(context.Background(), target())
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 32 {
		t.Fatalf("isolated KICS: %+v", res.Coverage)
	}
	for _, p := range ex2.Calls() {
		if p.Path != "/isolate" {
			t.Fatalf("a KICS call ran unisolated: %v", p.Args)
		}
	}
	if !strings.Contains(strings.Join(res.Coverage.Notes, " "), DigestOnlyPrefix) {
		t.Errorf("a digest-only pin is not labelled: %v", res.Coverage.Notes)
	}
	s, _ := st.Load()
	if s.Tree == nil || s.Tree.Files["a/query.rego"] != hexd('1') {
		t.Fatalf("queries tree not recorded: %+v", s.Tree)
	}
	// The next run hands every recorded query file to the runner with its
	// digest, so a changed one refuses the run before KICS starts.
	ex3 := &extruntest.Executor{}
	e3 := f.env(ex3, st, true)
	e3.Compiled = e.Compiled
	f.files[dQueries+"/a/query.rego"] = extruntest.File{Digest: hexd('2')}
	res, _ = NewDriver(e3).Scan(context.Background(), target())
	if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != ReasonUnverified {
		t.Fatalf("a changed query file: %+v", res.Coverage)
	}
}

// TestDriverProbeHashUsedForResolve (audit finding F5): the resolve step
// hashes through Env.ProbeHash when set (the daemon's cache), never through
// the runner's own hasher, which stays for the exec-time check.
func TestDriverProbeHashUsedForResolve(t *testing.T) {
	f := newEngineFake(t, Trivy)
	e := f.env(&extruntest.Executor{}, &memState{}, true)
	probes := 0
	e.ProbeHash = func(string) (string, error) { probes++; return hexd('b'), nil }
	for i := 0; i < 3; i++ {
		if p := NewDriver(e).Probe(context.Background()); !p.Installed || !p.Verified {
			t.Fatalf("probe %+v", p)
		}
	}
	if probes != 3 {
		t.Fatalf("ProbeHash called %d times for 3 probes", probes)
	}
}

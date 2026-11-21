package depdriver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/extrun/extruntest"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
)

const exe = "/opt/observer/bin/observer"

func childAnswer(resp depscan.ChildResponse) func(extrun.Plan) extrun.ExecFacts {
	b, _ := json.Marshal(resp)
	return func(extrun.Plan) extrun.ExecFacts { return extrun.ExecFacts{Stdout: b, PeakChildren: -1} }
}

func newEnv(ex *extruntest.Executor, compiled bool) Env {
	r := extruntest.NewRunner("linux", extruntest.Files{exe: {}}, ex, map[string]string{"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "x"})
	return Env{
		Runner: r, Executable: exe, Compiled: compiled, DBDir: "/home/u/.observer/security/osv",
		Epochs: map[string]string{"npm": "e1"}, GOOS: "linux", GOARCH: "amd64",
	}
}

func TestScalibrRunsAsChildUnderCaps(t *testing.T) {
	ex := &extruntest.Executor{Facts: childAnswer(depscan.ChildResponse{
		Version: depscan.ProtocolVersion, Compiled: true,
		Packages: []depscan.Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: "package-lock.json"}},
		Ecosystems: []depscan.EcoResult{{
			Ecosystem: "npm", Outcome: depscan.EcoScanned, Epoch: "e1", Packages: 1,
			Advisories: []depscan.Advisory{{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Severity: "HIGH"}},
		}},
		Extractors: []depscan.ExtractorStatus{{Extractor: "javascript/packagelockjson", OK: true}},
	})}
	res, err := NewScalibr(newEnv(ex, true)).Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p", Scope: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	calls := ex.Calls()
	if len(calls) != 1 {
		t.Fatalf("want one child process, got %d", len(calls))
	}
	p := calls[0]
	switch {
	case p.Component != depscan.ScalibrComponent || p.Path != exe:
		t.Fatalf("plan %+v", p)
	case !slices.Equal(p.Args, ScalibrChildArgs):
		t.Fatalf("args %v", p.Args)
	case p.Dir != "/home/u/src/p":
		t.Fatalf("dir %q", p.Dir)
	case p.Limits.MemoryBytes != ScalibrLimits.MemoryBytes || p.Limits.Wall != ScalibrLimits.Wall:
		t.Fatalf("limits %+v", p.Limits)
	}
	for _, e := range p.Env {
		if strings.HasPrefix(e, "PATH=") || strings.HasPrefix(e, "ANTHROPIC_") {
			t.Fatalf("the child must see no PATH and no inherited secret: %v", p.Env)
		}
	}
	var req depscan.ChildRequest
	if err := json.Unmarshal(p.Stdin, &req); err != nil || req.Root != "/home/u/src/p" || req.Epochs["npm"] != "e1" {
		t.Fatalf("stdin %s %v", p.Stdin, err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 1 || res.Findings[0].Rule.ID != "CVE-2021-23337" {
		t.Fatalf("result %+v", res)
	}
	if res.Engine.DatabaseEpoch != "npm=e1" || res.Findings[0].Engine.DatabaseEpoch != "e1" {
		t.Fatalf("epochs %q / %q", res.Engine.DatabaseEpoch, res.Findings[0].Engine.DatabaseEpoch)
	}
}

func TestScalibrNotCompiledStartsNothing(t *testing.T) {
	ex := &extruntest.Executor{}
	res, err := NewScalibr(newEnv(ex, false)).Scan(context.Background(), secscan.Target{ProjectRoot: "/p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Calls()) != 0 {
		t.Fatal("a build without SCALIBR must start no process")
	}
	if res.Coverage.Outcome != secscan.OutcomeNotScanned || res.Coverage.Reason != depscan.ReasonNotCompiled {
		t.Fatalf("coverage %+v", res.Coverage)
	}
}

func TestScalibrChildFailureIsNeverClean(t *testing.T) {
	for name, facts := range map[string]extrun.ExecFacts{
		"timeout":     {KillReason: extrun.KillTimeout, PeakChildren: -1},
		"crash":       {ExitCode: 2, PeakChildren: -1},
		"bad answer":  {Stdout: []byte("{"), PeakChildren: -1},
		"old version": {Stdout: []byte(`{"version":0}`), PeakChildren: -1},
	} {
		t.Run(name, func(t *testing.T) {
			ex := &extruntest.Executor{Facts: func(extrun.Plan) extrun.ExecFacts { return facts }}
			res, _ := NewScalibr(newEnv(ex, true)).Scan(context.Background(), secscan.Target{ProjectRoot: "/p"})
			if res.Coverage.Outcome != secscan.OutcomeFailed {
				t.Fatalf("coverage %+v", res.Coverage)
			}
		})
	}
}

func TestProbeLabelsWindowsBeta(t *testing.T) {
	env := newEnv(&extruntest.Executor{}, true)
	env.GOOS = "windows"
	p := NewScalibr(env).Probe(context.Background())
	if !p.Beta || p.Platform != secscan.SupportUntested {
		t.Fatalf("probe %+v: Windows is beta and untested (D-764 Q25)", p)
	}
}

func TestApplyOnlineFillsOnlyMissingDatabases(t *testing.T) {
	resp := depscan.ChildResponse{
		Version: depscan.ProtocolVersion, Compiled: true,
		Packages: []depscan.Package{{Ecosystem: "npm", Name: "a", Version: "1"}, {Ecosystem: "PyPI", Name: "b", Version: "2"}, {Ecosystem: "Go", Name: "c", Version: "v3"}},
		Ecosystems: []depscan.EcoResult{
			{Ecosystem: "Go", Outcome: depscan.EcoNotScanned, Reason: depscan.ReasonSelfTestFailed},
			{Ecosystem: "PyPI", Outcome: depscan.EcoNotScanned, Reason: depscan.ReasonNoDatabase},
			{Ecosystem: "npm", Outcome: depscan.EcoScanned, Epoch: "local"},
		},
	}
	var asked []string
	out := ApplyOnline(context.Background(), resp, func(_ context.Context, eco string, _ []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		asked = append(asked, eco)
		if len(idx) != 1 || idx[0] != 1 {
			t.Fatalf("indices %v", idx)
		}
		return depscan.EcoResult{Ecosystem: eco, Outcome: depscan.EcoScanned, Epoch: "online"}, true
	})
	if !slices.Equal(asked, []string{"PyPI"}) {
		t.Fatalf("asked %v: only a missing database goes online", asked)
	}
	if out.Ecosystems[1].Epoch != "online" || resp.Ecosystems[1].Epoch != "" {
		t.Fatal("the answer must replace the copy, not the input")
	}
}

// TestResultReportsGaps: the shared result path turns the child's raw
// facts into gaps. An unlocked manifest or an unpinned line makes a run
// partial, never clean; a failed extractor leaves nothing scanned in full.
func TestResultReportsGaps(t *testing.T) {
	npm := depscan.EcoResult{Ecosystem: "npm", Outcome: depscan.EcoScanned, Epoch: "e1", Packages: 1}
	lock := depscan.Package{Ecosystem: "npm", Name: "a", Version: "1.0.0", Path: "package-lock.json"}
	cases := []struct {
		name    string
		resp    depscan.ChildResponse
		outcome secscan.Outcome
		scanned []string
		skip    string
	}{
		{"clean", depscan.ChildResponse{Packages: []depscan.Package{lock}, Ecosystems: []depscan.EcoResult{npm}}, secscan.OutcomeClean, []string{"npm"}, ""},
		{"no lockfile", depscan.ChildResponse{
			Packages: []depscan.Package{lock}, Ecosystems: []depscan.EcoResult{npm},
			Unlocked: []depscan.Manifest{{Ecosystem: "crates.io", Path: "Cargo.toml"}},
		}, secscan.OutcomeUnknown, []string{"npm"}, "Cargo.toml"},
		{"unpinned line", depscan.ChildResponse{
			Packages:   []depscan.Package{lock, {Ecosystem: "PyPI", Name: "requests", Version: "2.0", Unpinned: true, Path: "requirements.txt"}},
			Ecosystems: []depscan.EcoResult{npm},
		}, secscan.OutcomeUnknown, []string{"npm"}, "requirements.txt"},
		{"extractor failed", depscan.ChildResponse{
			Packages: []depscan.Package{lock}, Ecosystems: []depscan.EcoResult{npm},
			Extractors: []depscan.ExtractorStatus{{Extractor: "javascript/yarnlock", Ecosystem: "npm", Files: []string{"yarn.lock"}}},
		}, secscan.OutcomeUnknown, nil, "yarn.lock"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.resp.Version, c.resp.Compiled = depscan.ProtocolVersion, true
			res := Result(Input{DriverID: depscan.ScalibrID, Target: secscan.Target{ProjectRoot: "/p"}, Response: c.resp})
			if res.Coverage.Outcome != c.outcome || !slices.Equal(res.Coverage.Scanned, c.scanned) {
				t.Fatalf("coverage %+v, want %s scanned %v", res.Coverage, c.outcome, c.scanned)
			}
			if c.skip == "" {
				return
			}
			for _, s := range res.Coverage.Skipped {
				if s.Path == c.skip {
					return
				}
			}
			t.Fatalf("skipped %+v, want %s", res.Coverage.Skipped, c.skip)
		})
	}
}

// fakeIsolation wraps a plan in a launcher, like the bwrap one-shot does.
type fakeIsolation struct{ fail bool }

func (fakeIsolation) Name() string { return "test.isolation" }

func (f fakeIsolation) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	if f.fail {
		return extrun.Plan{}, errors.New("the program directory reaches ~/.observer")
	}
	p.Args = append([]string{p.Path}, p.Args...)
	p.Path = "/usr/bin/bwrap"
	return p, nil
}

// TestScalibrIsolation pins milestone 2d of lane SEC-D2B and lane SEC-DEPS3
// items 3, 5 and 6: the scan child runs through the isolation provider when
// one is available and reads the root and database the provider binds
// (resolved paths); with no provider on the host it runs unisolated, with a
// fixed note; a provider that exists but cannot be prepared, or that the
// runner refuses to apply, refuses the scan with a fixed reason and starts
// no child.
func TestScalibrIsolation(t *testing.T) {
	answer := depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: true}
	const secret = "/home/u/.observer/secret-path"
	cases := []struct {
		name      string
		isolate   func(root string) (Isolated, error)
		isolated  bool
		refused   bool
		noteHas   string
		wantRoot  string
		wantDBDir string
	}{
		{name: "no provider on this host", noteHas: "no isolation provider", wantRoot: "/home/u/src/p", wantDBDir: "/home/u/.observer/security/osv"},
		{name: "a provider factory with no provider on the host", isolate: func(string) (Isolated, error) {
			return Isolated{}, nil
		}, noteHas: "no isolation provider", wantRoot: "/home/u/src/p", wantDBDir: "/home/u/.observer/security/osv"},
		{name: "isolated", isolate: func(string) (Isolated, error) {
			return Isolated{Provider: fakeIsolation{}, DBDir: "/home/u/.cache/runs/x/db"}, nil
		}, isolated: true, wantRoot: "/home/u/src/p", wantDBDir: "/home/u/.cache/runs/x/db"},
		{name: "isolated on a symlinked root", isolate: func(string) (Isolated, error) {
			return Isolated{Provider: fakeIsolation{}, Root: "/data/src/p", DBDir: "/data/cache/runs/x/db"}, nil
		}, isolated: true, wantRoot: "/data/src/p", wantDBDir: "/data/cache/runs/x/db"},
		{name: "could not prepare", isolate: func(string) (Isolated, error) {
			return Isolated{}, errors.New("the database could not be linked under " + secret)
		}, refused: true},
		{name: "provider refuses the plan", isolate: func(string) (Isolated, error) {
			return Isolated{Provider: fakeIsolation{fail: true}, DBDir: "/x"}, nil
		}, refused: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex := &extruntest.Executor{Facts: childAnswer(answer)}
			env := newEnv(ex, true)
			cleaned := false
			if c.isolate != nil {
				env.Isolate = func(root string) (Isolated, error) {
					iso, err := c.isolate(root)
					iso.Cleanup = func() { cleaned = true }
					return iso, err
				}
				env.IsolatedRunner = func(p extrun.IsolationProvider) *extrun.Runner {
					r := extruntest.NewRunner("linux", extruntest.Files{exe: {}, "/usr/bin/bwrap": {}}, ex, nil)
					r.Isolation = p
					return r
				}
			}
			res, err := NewScalibr(env).Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p"})
			if err != nil {
				t.Fatal(err)
			}
			if c.isolate != nil && !cleaned {
				t.Fatal("the prepared run directory must be cleaned up")
			}
			calls := ex.Calls()
			if c.refused {
				if len(calls) != 0 {
					t.Fatalf("a refused isolation starts no child, got %d", len(calls))
				}
				if res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != depscan.ReasonIsolationRefused {
					t.Fatalf("coverage %+v, want failed %s", res.Coverage, depscan.ReasonIsolationRefused)
				}
				if len(res.Coverage.Notes) != 0 || strings.Contains(fmt.Sprint(res.Coverage), secret) {
					t.Fatalf("a refusal carries a fixed reason only: %+v", res.Coverage)
				}
				return
			}
			if len(calls) != 1 {
				t.Fatalf("want one child process, got %d", len(calls))
			}
			if got := calls[0].Path == "/usr/bin/bwrap"; got != c.isolated {
				t.Fatalf("launcher %q, isolated=%v", calls[0].Path, c.isolated)
			}
			var req depscan.ChildRequest
			if err := json.Unmarshal(calls[0].Stdin, &req); err != nil || req.DBDir != c.wantDBDir || req.Root != c.wantRoot {
				t.Fatalf("child request root %q db_dir %q (err %v), want %q %q", req.Root, req.DBDir, err, c.wantRoot, c.wantDBDir)
			}
			notes := strings.Join(res.Coverage.Notes, " ")
			switch {
			case c.noteHas == "" && notes != "":
				t.Fatalf("an isolated run carries no note: %q", notes)
			case c.noteHas != "" && (!strings.HasPrefix(notes, depscan.NotIsolatedPrefix) || !strings.Contains(notes, c.noteHas)):
				t.Fatalf("notes %q, want %q", notes, c.noteHas)
			}
		})
	}
}

// TestApplyOnlineTurnsLookupGapsIntoGaps (lane RM-2): packages a remote
// lookup could not match (a shard that failed) become remote_lookup_failed
// gaps, so the ecosystem is partial and its run never reads clean.
func TestApplyOnlineTurnsLookupGapsIntoGaps(t *testing.T) {
	resp := depscan.ChildResponse{
		Packages:   []depscan.Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0", Path: "package-lock.json"}, {Ecosystem: "npm", Name: "b", Version: "1.0.0", Path: "package-lock.json"}},
		Ecosystems: []depscan.EcoResult{{Ecosystem: "npm", Outcome: depscan.EcoNotScanned, Reason: depscan.ReasonNoDatabase, Packages: 2}},
	}
	m := func(_ context.Context, eco string, _ []depscan.Package, idx []int) (depscan.EcoResult, bool) {
		return depscan.EcoResult{Ecosystem: eco, Outcome: depscan.EcoScanned, Packages: len(idx) - 1, LookupGaps: 1, Epoch: "remote:x npm@1"}, true
	}
	out := ApplyOnline(context.Background(), resp, m)
	if len(out.Gaps) != 1 || out.Gaps[0].Reason != depscan.ReasonRemoteLookupFailed || out.Gaps[0].Packages != 1 || len(resp.Gaps) != 0 {
		t.Fatalf("gaps %+v (input %+v)", out.Gaps, resp.Gaps)
	}
	res := Result(Input{DriverID: depscan.ScalibrID, Target: secscan.Target{ProjectRoot: t.TempDir()}, Response: out})
	if res.Coverage.Outcome == secscan.OutcomeClean || len(res.Coverage.Scanned) != 0 {
		t.Fatalf("a run with a failed shard read %s, scanned %v", res.Coverage.Outcome, res.Coverage.Scanned)
	}
}

// TestScalibrReachGoPlumbing: the symbol check is asked for only while
// Env.ReachGo is set, an unisolated child gets the prepared scratch
// directory, and the child's runs reach the sink unchanged, findings
// untouched.
func TestScalibrReachGoPlumbing(t *testing.T) {
	runs := []secreach.SymbolRun{{Source: secreach.SourceGovulncheckBinary, Target: "bin/app", Reason: secreach.ReasonStripped}}
	for _, on := range []bool{false, true} {
		ex := &extruntest.Executor{Facts: childAnswer(depscan.ChildResponse{
			Version: depscan.ProtocolVersion, Compiled: true, Reach: runs, ReachRan: on,
		})}
		env := newEnv(ex, true)
		env.ReachGo = on
		cleaned := false
		env.ReachScratch = func() (string, func(), error) { return "/tmp/reach-1", func() { cleaned = true }, nil }
		var gotRoot string
		var gotRuns []secreach.SymbolRun
		var gotRan bool
		env.ReachSink = func(root string, r []secreach.SymbolRun, ran bool) { gotRoot, gotRuns, gotRan = root, r, ran }
		res, err := NewScalibr(env).Scan(context.Background(), secscan.Target{ProjectRoot: "/home/u/src/p", Scope: "manual"})
		if err != nil {
			t.Fatal(err)
		}
		var req depscan.ChildRequest
		if err := json.Unmarshal(ex.Calls()[0].Stdin, &req); err != nil {
			t.Fatal(err)
		}
		if req.ReachGo != on || (on && req.ScratchDir != "/tmp/reach-1") || (!on && req.ScratchDir != "") || cleaned != on {
			t.Fatalf("on=%v: request %+v, cleaned %v", on, req, cleaned)
		}
		if gotRoot != "/home/u/src/p" || gotRan != on || len(gotRuns) != 1 {
			t.Fatalf("on=%v: sink %q %+v %v", on, gotRoot, gotRuns, gotRan)
		}
		if len(res.Findings) != 0 {
			t.Fatalf("findings %+v", res.Findings)
		}
	}
}

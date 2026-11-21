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
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// taintrun_test.go drives the intrafile taint pass through the driver with
// a scripted engine: tiny synthetic file lists, no real Opengrep.

// taintScript is what the taint pass's batches print and write.
type taintScript struct {
	mu sync.Mutex
	// results are each file's taint-pass results (rule, line).
	results map[string][][2]string
	// kill, exit and noCanary script a batch by its index.
	kill     map[int]extrun.KillReason
	exit     map[int]int
	noCanary map[int]bool
	// partial files are reported in the JSON copy's errors.
	partial []string
	// calls are the taint batches' argument lists, in order.
	calls [][]string
}

func isTaintBatch(args []string) bool { return slices.Contains(args, secrulepack.FlagTaintIntrafile) }

func (s *taintScript) facts(f *fake, p extrun.Plan) extrun.ExecFacts {
	s.mu.Lock()
	i := len(s.calls)
	s.calls = append(s.calls, slices.Clone(p.Args))
	s.mu.Unlock()
	if k := s.kill[i]; k != extrun.KillNone {
		return extrun.ExecFacts{KillReason: k, Signaled: true, PeakChildren: -1}
	}
	if c := s.exit[i]; c != 0 {
		return extrun.ExecFacts{ExitCode: c, PeakChildren: -1}
	}
	var results [][3]string
	scanned := []string{}
	for _, a := range p.Args {
		rel, ok := strings.CutPrefix(a, "./")
		if !ok {
			continue
		}
		for _, r := range s.results[rel] {
			results = append(results, [3]string{r[0], rel, r[1]})
		}
		if !slices.Contains(s.partial, rel) {
			scanned = append(scanned, fmt.Sprintf("%q", rel))
		}
	}
	if !s.noCanary[i] {
		results = append(results, [3]string{"observer-code.canary", canaryPath, "5"})
		scanned = append(scanned, fmt.Sprintf("%q", canaryPath))
	}
	var errs []string
	for _, e := range s.partial {
		errs = append(errs, fmt.Sprintf(`{"path":%q}`, e))
	}
	for _, a := range p.Args {
		if out, ok := strings.CutPrefix(a, "--json-output="); ok {
			f.written[out] = []byte(`{"results":[],"errors":[` + strings.Join(errs, ",") + `],"paths":{"scanned":[` + strings.Join(scanned, ",") + `]}}`)
		}
	}
	return extrun.ExecFacts{Stdout: []byte(sarifDoc(results...)), PeakChildren: -1}
}

// memTaintCache is an in-memory TaintCacheStore.
type memTaintCache struct {
	c     TaintCache
	saves int
}

func (m *memTaintCache) Load() (TaintCache, error) { return m.c, nil }
func (m *memTaintCache) Save(c TaintCache) error   { m.c = c; m.saves++; return nil }

// taintFixture is a fake engine whose core pass reports a taint-rule
// result in b.py and a search-rule result in a.py, over the given files.
func taintFixture(t *testing.T, files ...string) (*fake, *taintScript, *extruntest.Executor, Env) {
	f := newFake(t)
	if len(files) == 0 {
		files = []string{"a.py", "b.py"}
	}
	f.scanned = files
	f.results = [][3]string{{"python.sql-string-concat", "b.py", "7"}, {"python.weak-cipher", "a.py", "3"}}
	s := &taintScript{results: map[string][][2]string{"b.py": {{"python.sql-string-concat", "12"}}}}
	ex := &extruntest.Executor{}
	env := f.env(ex, &memState{})
	ex.Facts = func(p extrun.Plan) extrun.ExecFacts {
		if isTaintBatch(p.Args) {
			return s.facts(f, p)
		}
		return f.facts(p)
	}
	sizes := map[string]int64{}
	for _, rel := range files {
		sizes[root+"/"+rel] = 1000
	}
	env.Stat = func(p string) (int64, bool, error) {
		if n, ok := sizes[p]; ok {
			return n, true, nil
		}
		return 0, false, errors.New("no such file")
	}
	return f, s, ex, env
}

func findingSet(res secscan.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, fmt.Sprintf("%s %s:%d", f.Rule.ID, f.Location.RelPath, f.Location.StartLine))
	}
	slices.Sort(out)
	return out
}

func scanTaint(t *testing.T, env Env, target secscan.Target) (secscan.Result, Scanned, secscan.PassStatus) {
	t.Helper()
	res, scanned, err := New(env).ScanFiles(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := TaintPassOf(res.Coverage)
	return res, scanned, p
}

var coreFindings = []string{"python.sql-string-concat b.py:7", "python.weak-cipher a.py:3"}

// TestTaintPassReplacesCoveredFiles: a completed batch's taint results
// replace the core pass's taint results in the files it read; a search
// rule's result is never touched; the core pass never ran the flag.
func TestTaintPassReplacesCoveredFiles(t *testing.T) {
	_, s, ex, env := taintFixture(t)
	res, scanned, p := scanTaint(t, env, full())
	if got, want := findingSet(res), []string{"python.sql-string-concat b.py:12", "python.weak-cipher a.py:3"}; !slices.Equal(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	if p.Status != TaintCompleted || p.Batches != 1 || p.Merged != 1 || p.Covered != 2 || p.Targets != 2 || p.BudgetMS != 60000 {
		t.Fatalf("pass %+v", p)
	}
	if len(scanned.TaintHold) != 0 || !slices.Equal(scanned.Files, []string{"a.py", "b.py"}) {
		t.Fatalf("scanned %+v", scanned)
	}
	core := 0
	for _, c := range ex.Calls() {
		if slices.Contains(c.Args, ".") {
			core++
			if isTaintBatch(c.Args) {
				t.Fatalf("the core pass ran with the flag: %v", c.Args)
			}
		}
	}
	if core != 1 || len(s.calls) != 1 {
		t.Fatalf("%d core runs, %d taint batches", core, len(s.calls))
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Fatalf("coverage %+v", res.Coverage)
	}
}

// TestTaintPassFailureLeavesTheCore: whatever stops a batch, the core
// pass's findings come back exactly, the pass records why, and the files
// it did not answer are held from closing taint-rule findings.
func TestTaintPassFailureLeavesTheCore(t *testing.T) {
	cases := []struct {
		name           string
		script         func(*taintScript)
		status, reason string
	}{
		{"a timeout", func(s *taintScript) { s.kill = map[int]extrun.KillReason{0: extrun.KillTimeout} }, TaintTimedOut, TaintBatchTimedOut},
		{"an output cap", func(s *taintScript) { s.kill = map[int]extrun.KillReason{0: extrun.KillOutputCap} }, TaintFailed, ReasonBudget},
		{"a crash", func(s *taintScript) { s.exit = map[int]int{0: 2} }, TaintFailed, ReasonCrashed},
		{"no canary", func(s *taintScript) { s.noCanary = map[int]bool{0: true} }, TaintFailed, TaintCanaryMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, s, _, env := taintFixture(t)
			c.script(s)
			res, scanned, p := scanTaint(t, env, full())
			if got := findingSet(res); !slices.Equal(got, coreFindings) {
				t.Fatalf("findings %v, want the core's %v", got, coreFindings)
			}
			if p.Status != c.status || p.Reason != c.reason || p.Merged != 0 || p.Covered != 0 {
				t.Fatalf("pass %+v, want %s (%s)", p, c.status, c.reason)
			}
			if !slices.Equal(scanned.TaintHold, []string{"a.py", "b.py"}) || len(scanned.TaintHoldRules) == 0 {
				t.Fatalf("hold %v rules %d", scanned.TaintHold, len(scanned.TaintHoldRules))
			}
			for _, id := range scanned.TaintHoldRules {
				if id == "python.sql-string-concat" {
					t.Fatal("a held file closes a taint rule's findings")
				}
			}
			if res.Coverage.Outcome != secscan.OutcomeFindings || !slices.Equal(scanned.Files, []string{"a.py", "b.py"}) {
				t.Fatalf("the core's coverage changed: %+v %v", res.Coverage, scanned.Files)
			}
		})
	}
}

// TestTaintPassFinishedBatchesSurvive: a kill of a later batch loses only
// that batch; the batches before and after it are merged.
func TestTaintPassFinishedBatchesSurvive(t *testing.T) {
	var files []string
	for i := 0; i < 250; i++ {
		files = append(files, fmt.Sprintf("f%03d.py", i))
	}
	files = append(files, "b.py")
	_, s, _, env := taintFixture(t, files...)
	// Sorted: b.py first, so batch 0 holds b.py and f000..f098; batch 1 is
	// killed.
	s.kill = map[int]extrun.KillReason{1: extrun.KillTimeout}
	s.results["f150.py"] = [][2]string{{"python.sql-string-concat", "4"}}
	s.results["f220.py"] = [][2]string{{"python.sql-string-concat", "9"}}
	res, scanned, p := scanTaint(t, env, full())
	if p.Status != TaintTimedOut || p.Batches != 3 || p.Merged != 2 || p.Covered != 151 || p.Targets != 251 {
		t.Fatalf("pass %+v", p)
	}
	got := findingSet(res)
	for _, want := range []string{"python.sql-string-concat b.py:12", "python.sql-string-concat f220.py:9"} {
		if !slices.Contains(got, want) {
			t.Errorf("finished batch result %s missing from %v", want, got)
		}
	}
	if slices.Contains(got, "python.sql-string-concat f150.py:4") || slices.Contains(got, "python.sql-string-concat b.py:7") {
		t.Errorf("findings %v", got)
	}
	if len(scanned.TaintHold) != 100 || scanned.TaintHold[0] != "f099.py" {
		t.Fatalf("hold %d first %v", len(scanned.TaintHold), scanned.TaintHold[:1])
	}
}

// TestTaintPassPartialFileKeepsBoth: a file a completed batch read only in
// part keeps the core pass's taint results and adds the pass's.
func TestTaintPassPartialFileKeepsBoth(t *testing.T) {
	_, s, _, env := taintFixture(t)
	s.partial = []string{"b.py"}
	res, scanned, p := scanTaint(t, env, full())
	want := []string{"python.sql-string-concat b.py:12", "python.sql-string-concat b.py:7", "python.weak-cipher a.py:3"}
	if got := findingSet(res); !slices.Equal(got, want) {
		t.Fatalf("findings %v, want %v", got, want)
	}
	if p.Status != TaintCompleted || p.Partial != 1 || p.Covered != 1 || !slices.Equal(scanned.TaintHold, []string{"b.py"}) {
		t.Fatalf("pass %+v hold %v", p, scanned.TaintHold)
	}
}

// TestTaintPassCache: a second scan of unchanged files runs no batch and
// gives the same findings; a changed file alone re-runs.
func TestTaintPassCache(t *testing.T) {
	f, s, _, env := taintFixture(t)
	cache := &memTaintCache{}
	env.TaintCache = cache
	first, _, p := scanTaint(t, env, full())
	if p.Cached != 0 || cache.saves != 1 || len(cache.c.Entries) != 2 {
		t.Fatalf("first pass %+v, cache %d saves %d entries", p, cache.saves, len(cache.c.Entries))
	}
	for _, e := range cache.c.Entries {
		for _, r := range e.Results {
			if r.Message != "" || strings.HasPrefix(r.Locations[0].URI, "/") {
				t.Fatalf("a cached result keeps engine text or an absolute path: %+v", r)
			}
		}
	}
	second, _, p := scanTaint(t, env, full())
	if len(s.calls) != 1 || p.Status != TaintCompleted || p.Cached != 2 || p.Batches != 0 {
		t.Fatalf("second pass %+v after %d batches", p, len(s.calls))
	}
	if !slices.Equal(findingSet(first), findingSet(second)) {
		t.Fatalf("cached findings %v, first %v", findingSet(second), findingSet(first))
	}
	f.files[root+"/b.py"] = extruntest.File{Digest: strings.Repeat("9", 64)}
	_, _, p = scanTaint(t, env, full())
	if len(s.calls) != 2 || p.Cached != 1 || p.Batches != 1 {
		t.Fatalf("third pass %+v after %d batches", p, len(s.calls))
	}
	if last := s.calls[1]; !slices.Contains(last, "./b.py") || slices.Contains(last, "./a.py") {
		t.Fatalf("the changed file alone should re-run: %v", last)
	}
}

// TestTaintPassSkips: off, and every scan that is not full, leave the core
// alone; off is recorded on a full scan, a diff scan records no pass.
func TestTaintPassSkips(t *testing.T) {
	_, s, _, env := taintFixture(t)
	env.Taint.Mode = "off"
	res, scanned, p := scanTaint(t, env, full())
	if p.Status != TaintSkipped || p.Reason != TaintSkipOff || len(scanned.TaintHold) != 0 || !slices.Equal(findingSet(res), coreFindings) {
		t.Fatalf("off: pass %+v hold %v findings %v", p, scanned.TaintHold, findingSet(res))
	}
	env.Taint.Mode = ""
	env.Stat = nil
	if _, _, p := scanTaint(t, env, full()); p.Status != TaintSkipped || p.Reason != TaintSkipNoFileAccess {
		t.Fatalf("no stat: %+v", p)
	}
	_, _, _, env = taintFixture(t)
	res, _, err := New(env).ScanFiles(context.Background(), secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeDiff, BaseRev: "abcdef1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Coverage.Passes) != 0 {
		t.Fatalf("a diff scan recorded a pass: %+v", res.Coverage.Passes)
	}
	_, _, _, env = taintFixture(t, "README.md", "web/app.min.js")
	if _, _, p := scanTaint(t, env, full()); p.Status != TaintSkipped || p.Reason != TaintSkipNoTargets {
		t.Fatalf("no targets: %+v", p)
	}
	if len(s.calls) != 0 {
		t.Fatalf("%d taint batches ran", len(s.calls))
	}
}

// TestTaintPassCoreIncomplete: a core pass without its canary skips the
// pass (the core run is unknown and closes nothing anyway).
func TestTaintPassCoreIncomplete(t *testing.T) {
	f, s, _, env := taintFixture(t)
	f.noCanary = true
	_, _, p := scanTaint(t, env, full())
	if p.Status != TaintSkipped || p.Reason != TaintSkipCoreIncomplete || len(s.calls) != 0 {
		t.Fatalf("pass %+v after %d batches", p, len(s.calls))
	}
}

// TestTaintPassLimits: a batch runs under its own -j, memory, CPU and wall,
// with the taint rules and the canary rule as its only configs.
func TestTaintPassLimits(t *testing.T) {
	_, _, ex, env := taintFixture(t)
	env.Taint = TaintConfig{Jobs: 3, MemoryMiB: 1024, BudgetSeconds: 120}
	_, _, p := scanTaint(t, env, full())
	if p.BudgetMS != 120000 {
		t.Fatalf("pass %+v", p)
	}
	var batch *extrun.Plan
	for _, c := range ex.Calls() {
		if isTaintBatch(c.Args) {
			c := c
			batch = &c
		}
	}
	if batch == nil {
		t.Fatal("no taint batch ran")
	}
	joined := strings.Join(batch.Args, " ")
	if !strings.Contains(joined, "-j 3") || !strings.Contains(joined, "--max-target-bytes 250000") || !strings.Contains(joined, "--exclude *.min.js") {
		t.Fatalf("args %s", joined)
	}
	configs := 0
	for i, a := range batch.Args {
		if a == "--config" {
			configs++
			if next := batch.Args[i+1]; !strings.HasPrefix(next, packDir+"/rules/") {
				t.Fatalf("config %s outside the pack", next)
			}
		}
	}
	pack, _ := secrulepack.Floor()
	if configs != len(pack.TaintRules())+1 {
		t.Fatalf("%d configs, want the %d taint rules and the canary", configs, len(pack.TaintRules()))
	}
	l := batch.Limits
	if l.MemoryBytes != 1024<<20 || l.Wall != 120*time.Second || l.CPU != 360*time.Second {
		t.Fatalf("limits %+v", l)
	}
}

// TestTaintPassBudgetExhausted: a batch the budget cannot start is not
// run, and the pass reads timed out with the finished batches merged.
func TestTaintPassBudgetExhausted(t *testing.T) {
	var files []string
	for i := 0; i < 300; i++ {
		files = append(files, fmt.Sprintf("f%03d.py", i))
	}
	_, s, _, env := taintFixture(t, files...)
	clock := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	ticks := 0
	env.Now = func() time.Time {
		ticks++
		return clock.Add(time.Duration(ticks) * 25 * time.Second)
	}
	_, _, p := scanTaint(t, env, full())
	if p.Status != TaintTimedOut || p.Reason != TaintBudgetExhausted || p.Merged == 0 || p.Merged >= p.Batches || len(s.calls) != p.Merged {
		t.Fatalf("pass %+v after %d batches", p, len(s.calls))
	}
}

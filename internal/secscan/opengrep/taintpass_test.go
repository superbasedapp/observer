package opengrep

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// taintpass_test.go pins the pure rules of the intrafile taint pass, one
// case per table row.

func TestTaintSkipReason(t *testing.T) {
	ok := TaintGate{ConfigMode: TaintModeAuto, Mode: ModeFull, TaintRules: 3, CorePassed: true, FileAccess: true}
	cases := []struct {
		name string
		mut  func(*TaintGate)
		want string
	}{
		{"off", func(g *TaintGate) { g.ConfigMode = TaintModeOff }, TaintSkipOff},
		{"a diff scan stays plain", func(g *TaintGate) { g.Mode = ModeDiff }, TaintSkipNotFull},
		{"a files scan stays plain", func(g *TaintGate) { g.Mode = ModeFiles }, TaintSkipNotFull},
		{"no taint rule", func(g *TaintGate) { g.TaintRules = 0 }, TaintSkipNoTaintRules},
		{"the pack already runs the flag", func(g *TaintGate) { g.PackIntrafile = true }, TaintSkipPackIntrafile},
		{"the core pass did not pass its canary", func(g *TaintGate) { g.CorePassed = false }, TaintSkipCoreIncomplete},
		{"no file access", func(g *TaintGate) { g.FileAccess = false }, TaintSkipNoFileAccess},
		{"auto runs", func(*TaintGate) {}, ""},
		{"empty reads as auto", func(g *TaintGate) { g.ConfigMode = "" }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := ok
			c.mut(&g)
			if got := TaintSkipReason(g); got != c.want {
				t.Fatalf("TaintSkipReason = %q, want %q", got, c.want)
			}
		})
	}
}

func TestTaintBudget(t *testing.T) {
	cases := []struct {
		name       string
		files      int
		bytes      int64
		configured int
		want       time.Duration
	}{
		{"floor", 10, 1 << 20, 0, 60 * time.Second},
		{"small", 3000, 20 << 20, 0, 150 * time.Second},
		{"this repository's size is the 300 s reference", 16435, 142 << 20, 0, 300 * time.Second},
		{"large", 40000, 400 << 20, 0, 600 * time.Second},
		{"ceiling", 100000, 2 << 30, 0, 900 * time.Second},
		{"bytes alone move the row", 10, 100 << 20, 0, 300 * time.Second},
		{"configured", 10, 1, 120, 120 * time.Second},
		{"configured under the floor", 10, 1, 5, TaintMinBudget},
		{"configured over the ceiling", 10, 1, 99999, TaintMaxBudget},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TaintBudget(c.files, c.bytes, c.configured); got != c.want {
				t.Fatalf("TaintBudget = %v, want %v", got, c.want)
			}
		})
	}
}

func targets(n int, size int64) []TaintTarget {
	out := make([]TaintTarget, n)
	for i := range out {
		out[i] = TaintTarget{Rel: fmt.Sprintf("src/f%05d.py", i), Size: size, SHA256: "x"}
	}
	return out
}

func TestPlanTaintBatches(t *testing.T) {
	cases := []struct {
		name    string
		targets []TaintTarget
		argv    int
		want    []int
	}{
		{"none", nil, TaintArgvCap, nil},
		{"a few files are one batch", targets(50, 100), TaintArgvCap, []int{50}},
		{"the minimum batch size", targets(250, 100), TaintArgvCap, []int{100, 100, 50}},
		{"an eighth of the targets", targets(1600, 100), TaintArgvCap, []int{200, 200, 200, 200, 200, 200, 200, 200}},
		{"the maximum batch size", targets(20000, 10), TaintArgvCap, []int{2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000}},
		{"the byte cap", targets(4, 12<<20), TaintArgvCap, []int{2, 2}},
		{"the Windows argument cap", targets(1000, 10), TaintArgvCapWindows, []int{125, 125, 125, 125, 125, 125, 125, 125}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []int
			for _, b := range PlanTaintBatches(c.targets, c.argv) {
				got = append(got, len(b.Targets))
			}
			if !slices.Equal(got, c.want) {
				t.Fatalf("batch sizes %v, want %v", got, c.want)
			}
		})
	}
	// Sorted, and every target in exactly one batch.
	in := []TaintTarget{{Rel: "b.go", Size: 1}, {Rel: "a.go", Size: 2}}
	bs := PlanTaintBatches(in, TaintArgvCap)
	if len(bs) != 1 || bs[0].Targets[0].Rel != "a.go" || bs[0].Bytes != 3 {
		t.Fatalf("plan %+v", bs)
	}
}

func TestTaintBatchWall(t *testing.T) {
	cases := []struct {
		name               string
		remaining          time.Duration
		batch, remainBytes int64
		want               time.Duration
	}{
		{"too little left to start", 9 * time.Second, 1, 10, 0},
		{"twice the byte share", 300 * time.Second, 10, 80, 75 * time.Second},
		{"at least the minimum", 300 * time.Second, 1, 1000, TaintMinBatchWall},
		{"never more than is left", 20 * time.Second, 1, 1000, 20 * time.Second},
		{"the last batch gets what is left", 100 * time.Second, 10, 10, 100 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TaintBatchWall(c.remaining, c.batch, c.remainBytes); got != c.want {
				t.Fatalf("TaintBatchWall = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBatchStatusFor(t *testing.T) {
	cases := []struct {
		name                       string
		classified                 string
		timedOut, canceled, canary bool
		status, reason             string
	}{
		{"a cancel", "", true, true, true, BatchFailed, ReasonCanceled},
		{"a timeout", ReasonBudget, true, false, false, BatchTimedOut, TaintBatchTimedOut},
		{"a crash", ReasonCrashed, false, false, false, BatchFailed, ReasonCrashed},
		{"a memory or output cap", ReasonBudget, false, false, false, BatchFailed, ReasonBudget},
		{"no canary", "", false, false, false, BatchFailed, TaintCanaryMissing},
		{"completed", "", false, false, true, BatchCompleted, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := BatchStatusFor(c.classified, c.timedOut, c.canceled, c.canary)
			if s != c.status || r != c.reason {
				t.Fatalf("BatchStatusFor = %s %s, want %s %s", s, r, c.status, c.reason)
			}
		})
	}
}

func TestTaintPassStatus(t *testing.T) {
	done := TaintBatchOutcome{Status: BatchCompleted}
	cases := []struct {
		name           string
		bs             []TaintBatchOutcome
		status, reason string
	}{
		{"a cancel fails the pass", []TaintBatchOutcome{done, {Status: BatchFailed, Reason: ReasonCanceled}, {Status: BatchTimedOut, Reason: TaintBatchTimedOut}}, TaintFailed, ReasonCanceled},
		{"every batch completed", []TaintBatchOutcome{done, done}, TaintCompleted, ""},
		{"no batch (all from the cache)", nil, TaintCompleted, ""},
		{"the budget ran out", []TaintBatchOutcome{done, {Status: BatchTimedOut}, {Status: BatchNotRun, Reason: TaintBudgetExhausted}}, TaintTimedOut, TaintBudgetExhausted},
		{"a batch timed out", []TaintBatchOutcome{{Status: BatchFailed, Reason: ReasonCrashed}, {Status: BatchTimedOut}}, TaintTimedOut, TaintBatchTimedOut},
		{"a failure", []TaintBatchOutcome{done, {Status: BatchFailed, Reason: TaintCanaryMissing}, {Status: BatchFailed, Reason: ReasonCrashed}}, TaintFailed, TaintCanaryMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, r := TaintPassStatus(c.bs)
			if s != c.status || r != c.reason {
				t.Fatalf("TaintPassStatus = %s %s, want %s %s", s, r, c.status, c.reason)
			}
		})
	}
}

func res(rule, uri string, line int) sarif.Result {
	return sarif.Result{RuleID: rule, RuleIndex: -1, Locations: []sarif.Location{{URI: uri, StartLine: line, EndLine: line}}}
}

func resultSet(run sarif.Run) []string {
	var out []string
	for _, r := range run.Results {
		out = append(out, fmt.Sprintf("%s %s:%d", r.RuleID, r.Locations[0].URI, r.Locations[0].StartLine))
	}
	slices.Sort(out)
	return out
}

func TestMergeTaint(t *testing.T) {
	isTaint := func(id string) bool { return strings.HasPrefix(id, "t.") }
	core := sarif.Run{Results: []sarif.Result{
		res("t.sql", "covered.py", 3),
		res("s.cipher", "covered.py", 9),
		res("t.sql", "partial.py", 4),
		res("t.sql", "untouched.py", 5),
	}}
	m := TaintMerge{
		Covered: map[string]bool{"covered.py": true, "clean.py": true},
		Partial: map[string]bool{"partial.py": true},
		Results: map[string][]sarif.Result{
			"covered.py":   {res("t.sql", "covered.py", 11)},
			"partial.py":   {res("t.sql", "partial.py", 4), res("t.ssrf", "partial.py", 8)},
			"unread.py":    {res("t.sql", "unread.py", 1)},
			"untouched.py": nil,
		},
	}
	got := resultSet(MergeTaint(core, isTaint, "", "/r", m))
	want := []string{
		"s.cipher covered.py:9", // a search rule is never replaced
		"t.sql covered.py:11",   // the covered file's taint results are the pass's
		"t.sql partial.py:4",    // a partial file keeps the core's, once
		"t.sql untouched.py:5",  // a file the pass did not read keeps the core's
		"t.ssrf partial.py:8",   // and adds the pass's
	}
	if !slices.Equal(got, want) {
		t.Fatalf("merged %v\nwant %v", got, want)
	}
	// Nothing covered: the core run comes back as it was.
	if got := resultSet(MergeTaint(core, isTaint, "", "/r", TaintMerge{})); !slices.Equal(got, resultSet(core)) {
		t.Fatalf("an empty merge changed the core run: %v", got)
	}
}

func TestTaintResultsByFile(t *testing.T) {
	run := sarif.Run{
		Tool: sarif.Tool{Rules: []sarif.Rule{{ID: "t.sql"}}},
		Results: []sarif.Result{
			{RuleIndex: 0, Message: "engine text", Locations: []sarif.Location{{URI: "./a.py", StartLine: 2}}},
			res("s.cipher", "a.py", 3),
			res("t.sql", "../outside.py", 3),
		},
	}
	got := TaintResultsByFile(run, func(id string) bool { return id == "t.sql" }, "", "/r")
	if len(got) != 1 || len(got["a.py"]) != 1 {
		t.Fatalf("by file %+v", got)
	}
	r := got["a.py"][0]
	if r.RuleID != "t.sql" || r.RuleIndex != -1 || r.Message != "" || r.Locations[0].URI != "a.py" {
		t.Fatalf("result %+v: id resolved, message dropped, location relative", r)
	}
}

func TestTaintCandidate(t *testing.T) {
	exts := TaintExtensions([]secrulepack.Rule{{Languages: []string{"javascript", "typescript"}}, {Languages: []string{"go"}}})
	cases := []struct {
		rel  string
		want bool
	}{
		{"web/app.js", true},
		{"web/app.TSX", true},
		{"cmd/main.go", true},
		{"web/vendor/jquery.min.js", false},
		{"a.py", false},
		{"README.md", false},
		{"Makefile", false},
	}
	for _, c := range cases {
		if got := TaintCandidate(c.rel, exts); got != c.want {
			t.Errorf("TaintCandidate(%q) = %v", c.rel, got)
		}
	}
	for _, c := range []struct {
		size int64
		want bool
	}{{0, false}, {1, true}, {TaintMaxTargetBytes, true}, {TaintMaxTargetBytes + 1, false}} {
		if got := TaintSizeOK(c.size); got != c.want {
			t.Errorf("TaintSizeOK(%d) = %v", c.size, got)
		}
	}
}

func TestTaintLimits(t *testing.T) {
	l := TaintLimits(100*time.Second, 0, 0)
	if l.Wall != 100*time.Second || l.CPU != 200*time.Second || l.MemoryBytes != 2048<<20 || l.Children != 64 {
		t.Fatalf("default limits %+v", l)
	}
	l = TaintLimits(10*time.Second, 99, 99999)
	if l.CPU != 80*time.Second || l.MemoryBytes != int64(TaintMaxMemoryMiB)<<20 || l.Children != 128 {
		t.Fatalf("clamped limits %+v", l)
	}
	if ClampTaintMemoryMiB(1) != TaintMinMemoryMiB || ClampTaintJobs(-1) != TaintDefaultJobs || ClampTaintJobs(3) != 3 {
		t.Fatal("clamps")
	}
}

func TestArgsForTaintBatch(t *testing.T) {
	args := ArgsForTaintBatch([]string{"/p/rules/a.yaml", "/p/rules/canary.yaml"}, "/p/canary/c.py", "/o/taint-0.json", []string{"a.py", "b/c.py"}, 0)
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--taint-intrafile", "--max-target-bytes 250000", "-j 2", "--config /p/rules/a.yaml", "--config /p/rules/canary.yaml",
		"--json-output=/o/taint-0.json", "--no-git-ignore", "--exclude *.min.js", "--exclude node_modules", "./a.py ./b/c.py /p/canary/c.py",
		"--disable-nosem", "--x-ignore-semgrepignore-files", "--no-rewrite-rule-ids", "--sarif",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args lack %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "1000000") || slices.Contains(args, ".") || slices.Contains(args, "--baseline-commit") {
		t.Errorf("args %s", joined)
	}
	if args[len(args)-1] != "/p/canary/c.py" {
		t.Errorf("the canary is not the last target: %s", joined)
	}
	for _, never := range FlagsNever {
		if strings.Contains(joined, never) {
			t.Errorf("args carry the refused flag %q", never)
		}
	}
}

func TestTaintCacheKey(t *testing.T) {
	base := TaintCacheKey("a.py", "s1", "p1", "1.30.1")
	if base != TaintCacheKey("a.py", "s1", "p1", "1.30.1") || len(base) != 64 {
		t.Fatal("the key is not a stable sha256")
	}
	for _, other := range []string{
		TaintCacheKey("b.py", "s1", "p1", "1.30.1"),
		TaintCacheKey("a.py", "s2", "p1", "1.30.1"),
		TaintCacheKey("a.py", "s1", "p2", "1.30.1"),
		TaintCacheKey("a.py", "s1", "p1", "1.31.0"),
		TaintCacheKey("a.pys1", "", "p1", "1.30.1"),
	} {
		if other == base {
			t.Fatal("a key ignores one of its parts")
		}
	}
}

func TestPruneTaintCache(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	c := TaintCache{Version: TaintCacheVersion, Entries: map[string]TaintCacheEntry{
		"fresh": {Used: now.Unix()},
		"old":   {Used: now.Add(-TaintCacheMaxAge - time.Hour).Unix()},
	}}
	got := PruneTaintCache(c, now)
	if _, ok := got.Entries["fresh"]; !ok || len(got.Entries) != 1 {
		t.Fatalf("pruned %v", got.Entries)
	}
	if got := PruneTaintCache(TaintCache{Version: "other", Entries: c.Entries}, now); len(got.Entries) != 0 || got.Version != TaintCacheVersion {
		t.Fatalf("another version kept %v", got)
	}
	big := TaintCache{Version: TaintCacheVersion, Entries: map[string]TaintCacheEntry{}}
	for i := 0; i < TaintCacheMaxEntries+10; i++ {
		big.Entries[fmt.Sprintf("k%06d", i)] = TaintCacheEntry{Used: now.Unix() - int64(i)}
	}
	got = PruneTaintCache(big, now)
	if len(got.Entries) != TaintCacheMaxEntries {
		t.Fatalf("%d entries kept", len(got.Entries))
	}
	if _, ok := got.Entries[fmt.Sprintf("k%06d", TaintCacheMaxEntries+5)]; ok {
		t.Fatal("the oldest entry was kept over the cap")
	}
}

func TestTaintCacheResultsRelocate(t *testing.T) {
	e := TaintCacheEntry{Results: []sarif.Result{res("t.sql", "a.py", 3)}}
	got := TaintCacheResults(e, "b/a.py")
	if got[0].Locations[0].URI != "b/a.py" || e.Results[0].Locations[0].URI != "a.py" {
		t.Fatalf("relocated %+v, entry %+v", got, e)
	}
}

func TestHeldCloseRules(t *testing.T) {
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	rules, ok := HeldCloseRules(pack)
	if !ok || len(rules) == 0 {
		t.Fatalf("the floor pack's held-file rules: %v %v", rules, ok)
	}
	for _, id := range rules {
		if pack.IsTaintRule(id) {
			t.Errorf("%s is a taint rule", id)
		}
	}
	if len(rules)+len(pack.TaintRules()) != len(pack.Manifest.Rules) {
		t.Errorf("%d + %d rules of %d", len(rules), len(pack.TaintRules()), len(pack.Manifest.Rules))
	}
	if _, ok := HeldCloseRules(nil); ok {
		t.Fatal("no pack closes something")
	}
}

func TestTaintStatusWords(t *testing.T) {
	cases := []struct {
		p    secscan.PassStatus
		want string
	}{
		{secscan.PassStatus{Status: TaintSkipped, Reason: TaintSkipOff}, "skipped (off): the core pass's taint-rule results stand"},
		{secscan.PassStatus{Status: TaintCompleted, Covered: 10, Cached: 4}, "completed: 10 files (4 from the cache)"},
		{
			secscan.PassStatus{Status: TaintTimedOut, Reason: TaintBudgetExhausted, Batches: 8, Merged: 6, Targets: 100, Covered: 70, Cached: 5, Partial: 1},
			"timed_out (budget_exhausted): 6 of 8 batches merged, 70 of 100 files (5 from the cache), 1 read in part; the core pass's taint-rule results stand for the rest",
		},
	}
	for _, c := range cases {
		if got := TaintStatusWords(c.p); got != c.want {
			t.Errorf("TaintStatusWords = %q\nwant %q", got, c.want)
		}
	}
}

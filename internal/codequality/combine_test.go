package codequality

import (
	"strings"
	"testing"
	"time"
)

func rep(f Format, files ...FileCoverage) Report {
	r := Report{Format: f, Files: files}
	for _, fc := range files {
		r.Lines += fc.Lines
		r.Covered += fc.Covered
	}
	return r
}

func fc(path string, lines, covered int) FileCoverage {
	return FileCoverage{Path: path, Lines: lines, Covered: covered}
}

func TestCombineSameRunRule(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	jsLCOV := Found{RelPath: "coverage/lcov.info", ModTime: t0, Report: rep(FormatLCOV, fc("src/a.ts", 10, 5), fc("src/b.ts", 10, 10))}
	jsCob := Found{RelPath: "coverage/cobertura-coverage.xml", ModTime: t0, Report: rep(FormatCobertura, fc("a.ts", 10, 5), fc("b.ts", 10, 10))}
	goProf := Found{RelPath: "coverage.out", ModTime: t0.Add(time.Hour), Report: rep(FormatGoCover, fc("example.com/x/a.go", 20, 10))}
	rootLCOV := Found{RelPath: "lcov.info", ModTime: t0, Report: rep(FormatLCOV, fc("web/x.ts", 20, 20))}
	totals := Found{RelPath: "coverage.xml", ModTime: t0, Report: Report{Format: FormatCobertura, Lines: 40, Covered: 4, TotalsOnly: true}}
	webLCOV := Found{RelPath: "web/coverage/lcov.info", ModTime: t0, Report: rep(FormatLCOV, fc("src/a.ts", 30, 3))}

	cases := []struct {
		name    string
		in      []Found
		lines   int
		covered int
		sameRun map[string]string // path -> same_run_as
	}{
		{name: "one report", in: []Found{jsLCOV}, lines: 20, covered: 15},
		{name: "two formats of one run count once, lcov kept", in: []Found{jsCob, jsLCOV}, lines: 20, covered: 15,
			sameRun: map[string]string{"coverage/cobertura-coverage.xml": "coverage/lcov.info"}},
		{name: "different languages in one directory are both counted", in: []Found{goProf, rootLCOV}, lines: 40, covered: 30},
		{name: "a totals-only report beside another is the same run", in: []Found{rootLCOV, totals}, lines: 20, covered: 20,
			sameRun: map[string]string{"coverage.xml": "lcov.info"}},
		{name: "different directories are summed", in: []Found{jsLCOV, webLCOV}, lines: 50, covered: 18},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fig := Combine(c.in)
			if fig.Lines != c.lines || fig.Covered != c.covered {
				t.Fatalf("lines/covered = %d/%d, want %d/%d", fig.Lines, fig.Covered, c.lines, c.covered)
			}
			for _, r := range fig.Reports {
				want, dup := c.sameRun[r.RelPath]
				if dup != (r.Use == UseSameRun) || r.SameRunAs != want {
					t.Fatalf("report %s: use=%s same_run_as=%q", r.RelPath, r.Use, r.SameRunAs)
				}
			}
		})
	}
}

func TestCombineLeastCoveredAndTimes(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	a := Found{RelPath: "a/lcov.info", ModTime: t0, Report: rep(FormatLCOV, fc("x.ts", 10, 9), fc("y.ts", 50, 5), fc("tiny.ts", 3, 0))}
	b := Found{RelPath: "b/lcov.info", ModTime: t0.Add(2 * time.Hour), Report: rep(FormatLCOV, fc("z.ts", 20, 2))}
	fig := Combine([]Found{a, b})
	if len(fig.LeastCovered) != 3 {
		t.Fatalf("least covered = %+v (tiny.ts is under the line floor)", fig.LeastCovered)
	}
	// y.ts and z.ts are both 10%; the larger file first.
	if fig.LeastCovered[0].Path != "y.ts" || fig.LeastCovered[1].Path != "z.ts" || fig.LeastCovered[2].Path != "x.ts" {
		t.Fatalf("order = %+v", fig.LeastCovered)
	}
	if !fig.NewestReport.Equal(t0.Add(2*time.Hour)) || !fig.OldestReport.Equal(t0) {
		t.Fatalf("times = %v / %v", fig.NewestReport, fig.OldestReport)
	}
	if fig.Percent == nil || *fig.Percent < 19.27 || *fig.Percent > 19.28 { // 16/83
		t.Fatalf("percent = %v", fig.Percent)
	}
}

func TestPlanProbes(t *testing.T) {
	kids := []string{"web", ".git", "node_modules", "api", "vendor", "", ".github"}
	got := PlanProbes(kids)
	want := len(ReportLocations) * 3 // root, api, web
	if len(got) != want {
		t.Fatalf("len = %d, want %d", len(got), want)
	}
	if got[0] != ReportLocations[0].RelPath {
		t.Fatalf("root probes first: %q", got[0])
	}
	if !strings.HasPrefix(got[len(ReportLocations)], "api/") || !strings.HasPrefix(got[2*len(ReportLocations)], "web/") {
		t.Fatalf("children sorted: %q, %q", got[len(ReportLocations)], got[2*len(ReportLocations)])
	}
	// A child named "coverage" re-yields coverage/lcov.info: probed once.
	seen := map[string]int{}
	for _, p := range PlanProbes([]string{"coverage"}) {
		seen[p]++
		if seen[p] > 1 {
			t.Fatalf("%s probed twice", p)
		}
	}
	many := make([]string, 0, MaxChildDirs+10)
	for i := 0; i < MaxChildDirs+10; i++ {
		many = append(many, "d"+strings.Repeat("x", i+1))
	}
	if n := len(PlanProbes(many)); n != len(ReportLocations)*(1+MaxChildDirs) {
		t.Fatalf("child cap: %d probes", n)
	}
}

func TestProbeChild(t *testing.T) {
	for name, want := range map[string]bool{
		"web": true, "services": true, ".venv": false, "node_modules": false,
		"target": false, "": false, "vendor": false,
	} {
		if got := ProbeChild(name); got != want {
			t.Errorf("ProbeChild(%q) = %v", name, got)
		}
	}
}

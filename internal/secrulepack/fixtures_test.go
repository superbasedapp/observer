package secrulepack

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// fixtures_test.go holds the recall half of the precision method (JSP-8
// step 5): every rule has a positive fixture (lines annotated
// `ruleid: <id>`, the next line must be reported) and a near-miss (lines
// annotated `ok: <id>`, the next line must not be). The fixtures live in
// testdata/fixtures, never in the embedded floor.
//
// testdata/fixtures-intrafile holds the cross-function half (lane M3L-1a):
// for every taint-mode rule one positive where the tainted value crosses a
// function boundary in the same file (a helper that holds the sink, a helper
// that returns the source) and one near-miss where a sanitizer sits in the
// helper, or, for a rule with no sanitizer, a helper that ignores its
// input. They are found, or cleared, only with --taint-intrafile, so they
// are checked only when the pack declares taint_intrafile
// (Pack.EngineFlags), and TestIntrafileFixturesNeedTheFlag proves the
// contrast against the pinned engine.
//
// TestFixturesAgainstOpengrep runs the pack with a real Opengrep when
// OBSERVER_OPENGREP_BIN names one (a live check: the pinned v1.30.1
// passed it on 2026-10-22 with pack 1.2.0, 61 rules in five languages, 166
// of 166 positives and none of 177 near-misses reported, the near-misses
// holding the false-positive shapes the SEC-G3 reviewers named for the 22
// rewritten rules; on 2026-10-23, lane SEC-G5, with pack 1.3.0 (the SEC-G4
// merge's TLS and randomness fixes and the narrowed SQL rules), 172 of 172
// positives and none of 185 near-misses; on 2026-10-24, lane LEFT-SEC, with
// pack 1.3.1 (the three Java and C# rules rewritten), 177 of 177 positives
// and none of 197 near-misses; on 2026-11-04, lane M3L-2 1b, with pack 1.4.0
// (80 rules: 19 new rows and three rules rewritten as taint), 243 of 243
// positives and none of 292 near-misses, and with --taint-intrafile 86 of
// 86 cross-function positives and none of 43 near-misses; on 2026-11-04,
// lane M3L-2 1c, with pack 1.5.0 (107 rules: 27 new Ruby, PHP and Kotlin
// rows), 376 of 376 positives and none of 429 near-misses, and with
// --taint-intrafile 132 of 132 cross-function positives and none of 66
// near-misses); without it the test skips and
// TestEveryRuleHasFixtures still checks coverage.

// The two fixture directories under testdata.
const (
	fixturesDir          = "fixtures"
	fixturesIntrafileDir = "fixtures-intrafile"
)

var annotation = regexp.MustCompile(`(?:#|//) (ruleid|ok): ([a-z0-9.\-]+)\s*$`)

type mark struct {
	rule, file string
	line       int
}

// fixtureMarks reads every annotation of the main fixtures: the marked line
// is the next one.
func fixtureMarks(t *testing.T) (positives, nearMisses map[mark]bool) {
	t.Helper()
	return fixtureMarksIn(t, fixturesDir)
}

// fixtureMarksIn is fixtureMarks for one directory under testdata.
func fixtureMarksIn(t *testing.T, dir string) (positives, nearMisses map[mark]bool) {
	t.Helper()
	positives, nearMisses = map[mark]bool{}, map[mark]bool{}
	entries, err := os.ReadDir(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("testdata", dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(b), "\n") {
			m := annotation.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			k := mark{rule: m[2], file: e.Name(), line: i + 2}
			if m[1] == "ruleid" {
				positives[k] = true
			} else {
				nearMisses[k] = true
			}
		}
	}
	return positives, nearMisses
}

func TestEveryRuleHasFixtures(t *testing.T) {
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	pos, near := fixtureMarks(t)
	count := func(set map[mark]bool, id string) int {
		n := 0
		for k := range set {
			if k.rule == id {
				n++
			}
		}
		return n
	}
	for _, r := range p.Manifest.Rules {
		if count(pos, r.ID) == 0 || count(near, r.ID) == 0 {
			t.Errorf("rule %s: %d positive and %d near-miss fixture lines (want at least one of each)", r.ID, count(pos, r.ID), count(near, r.ID))
		}
	}
	for k := range pos {
		if _, ok := p.Rule(k.rule); !ok {
			t.Errorf("fixture %s names unknown rule %s", k.file, k.rule)
		}
	}
	canary := string(p.files[p.Manifest.Canary.Target])
	if !strings.Contains(canary, "observer_code_canary_7f3a9c(") {
		t.Error("the canary target does not call the canary marker")
	}
}

// countMarks counts the marks of one rule.
func countMarks(set map[mark]bool, id string) int {
	n := 0
	for k := range set {
		if k.rule == id {
			n++
		}
	}
	return n
}

// TestEveryTaintRuleHasIntrafileFixtures: every taint-mode rule has a
// cross-function positive and a near-miss in testdata/fixtures-intrafile,
// and nothing else is annotated there.
func TestEveryTaintRuleHasIntrafileFixtures(t *testing.T) {
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	pos, near := fixtureMarksIn(t, fixturesIntrafileDir)
	taint := 0
	for _, r := range p.Manifest.Rules {
		isTaint := bytes.Contains(p.files[r.File], []byte("mode: taint"))
		got := countMarks(pos, r.ID) + countMarks(near, r.ID)
		switch {
		case !isTaint && got > 0:
			t.Errorf("rule %s is not a taint rule but has %d intrafile fixture lines", r.ID, got)
		case isTaint:
			taint++
			if countMarks(pos, r.ID) == 0 || countMarks(near, r.ID) == 0 {
				t.Errorf("taint rule %s: %d cross-function positive and %d near-miss lines (want at least one of each)", r.ID, countMarks(pos, r.ID), countMarks(near, r.ID))
			}
		}
	}
	if taint == 0 {
		t.Fatal("the floor has no taint rule")
	}
}

// opengrepRun is what one live scan reported.
type opengrepRun struct {
	got    map[mark]bool
	canary bool
}

// runOpengrep scans targets (absolute paths) with the floor written to a
// scratch directory, the way the driver does but with a fixed flag set:
// extra are the engine flags beyond the driver's fixed ones.
func runOpengrep(t *testing.T, bin string, p *Pack, extra []string, targets ...string) opengrepRun {
	t.Helper()
	dir := t.TempDir()
	for name, b := range p.Files() {
		dst := filepath.Join(dir, "pack", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(dir, "home")
	args := []string{
		"scan", "--disable-version-check", "--sarif", "--no-rewrite-rule-ids", "--disable-nosem",
		"--x-ignore-semgrepignore-files", "--no-git-ignore",
	}
	args = append(args, extra...)
	args = append(args, "-j", "2", "--config", filepath.Join(dir, "pack", RulesDir))
	args = append(args, targets...)
	args = append(args, filepath.Join(dir, "pack", CanaryDir))
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"HOME=" + home, "XDG_CACHE_HOME=" + filepath.Join(dir, "cache"), "LC_ALL=C.UTF-8", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("opengrep: %v", err)
	}
	var sarif struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical struct {
						Artifact struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out, &sarif); err != nil || len(sarif.Runs) != 1 {
		t.Fatalf("SARIF: %v", err)
	}
	run := opengrepRun{got: map[mark]bool{}}
	for _, r := range sarif.Runs[0].Results {
		l := r.Locations[0].Physical
		if r.RuleID == p.Manifest.Canary.Rule {
			run.canary = run.canary || strings.HasSuffix(l.Artifact.URI, filepath.Base(p.Manifest.Canary.Target))
			continue
		}
		run.got[mark{rule: r.RuleID, file: filepath.Base(l.Artifact.URI), line: l.Region.StartLine}] = true
	}
	return run
}

// mergeMarks unions mark sets.
func mergeMarks(sets ...map[mark]bool) map[mark]bool {
	out := map[mark]bool{}
	for _, s := range sets {
		for k := range s {
			out[k] = true
		}
	}
	return out
}

// compareRun lists the differences between a run and the annotated marks:
// a missed positive, a reported near-miss, an unannotated result and (when
// wantCanary) a canary that did not report.
func compareRun(run opengrepRun, pos, near map[mark]bool, wantCanary bool) []string {
	var problems []string
	for k := range pos {
		if !run.got[k] {
			problems = append(problems, "missed "+k.rule+" at "+k.file)
		}
	}
	for k := range run.got {
		switch {
		case near[k]:
			problems = append(problems, "near miss reported: "+k.rule+" at "+k.file)
		case !pos[k]:
			problems = append(problems, "unannotated result: "+k.rule+" at "+k.file)
		}
	}
	if wantCanary && !run.canary {
		problems = append(problems, "the canary was not reported")
	}
	sort.Strings(problems)
	return problems
}

// engineBin returns the pinned engine the live checks need, or skips.
func engineBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("OBSERVER_OPENGREP_BIN")
	if bin == "" {
		t.Skip("set OBSERVER_OPENGREP_BIN to a pinned Opengrep to run the pack against its fixtures")
	}
	return bin
}

func TestFixturesAgainstOpengrep(t *testing.T) {
	bin := engineBin(t)
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	fx, _ := filepath.Abs(filepath.Join("testdata", fixturesDir))
	targets := []string{fx}
	pos, near := fixtureMarks(t)
	if p.Manifest.TaintIntrafile {
		// The pack is measured with --taint-intrafile, so the
		// cross-function fixtures must hold with the pack's own flags.
		fi, _ := filepath.Abs(filepath.Join("testdata", fixturesIntrafileDir))
		targets = append(targets, fi)
		ip, in := fixtureMarksIn(t, fixturesIntrafileDir)
		pos, near = mergeMarks(pos, ip), mergeMarks(near, in)
	}
	// The pack's own engine flags, as the driver passes them: the fixtures
	// are checked the way the pack was measured.
	run := runOpengrep(t, bin, p, p.EngineFlags(), targets...)
	for _, problem := range compareRun(run, pos, near, true) {
		t.Error(problem)
	}
}

// TestIntrafileFixturesNeedTheFlag is the contrast: with --taint-intrafile
// every cross-function positive is reported and no near-miss is; without
// it every positive is missed and every near-miss is reported (the engine's
// default propagation treats a call as carrying its argument's taint, and
// sees no taint a helper returns from its own source). It runs whatever the
// pack declares, so the fixtures are shown to exercise the flag before the
// pack turns it on.
func TestIntrafileFixturesNeedTheFlag(t *testing.T) {
	bin := engineBin(t)
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := filepath.Abs(filepath.Join("testdata", fixturesIntrafileDir))
	pos, near := fixtureMarksIn(t, fixturesIntrafileDir)

	with := runOpengrep(t, bin, p, []string{FlagTaintIntrafile}, fi)
	for _, problem := range compareRun(with, pos, near, true) {
		t.Errorf("with %s: %s", FlagTaintIntrafile, problem)
	}

	without := runOpengrep(t, bin, p, nil, fi)
	for k := range pos {
		if without.got[k] {
			t.Errorf("without the flag a cross-function positive is already reported: %s at %s (it does not exercise the flag)", k.rule, k.file)
		}
	}
	for k := range near {
		if !without.got[k] {
			t.Errorf("without the flag a near-miss is already clear: %s at %s (it does not exercise the flag)", k.rule, k.file)
		}
	}
}

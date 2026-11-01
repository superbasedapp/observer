package secrulepack

import (
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
// TestFixturesAgainstOpengrep runs the pack with a real Opengrep when
// OBSERVER_OPENGREP_BIN names one (a live check: the pinned v1.30.1
// passed it on 2026-10-22 with pack 1.2.0, 61 rules in five languages, 166
// of 166 positives and none of 177 near-misses reported, the near-misses
// holding the false-positive shapes the SEC-G3 reviewers named for the 22
// rewritten rules; on 2026-10-23, lane SEC-G5, with pack 1.3.0 (the SEC-G4
// merge's TLS and randomness fixes and the narrowed SQL rules), 172 of 172
// positives and none of 185 near-misses; on 2026-10-24, lane LEFT-SEC, with
// pack 1.3.1 (the three Java and C# rules rewritten), 177 of 177 positives
// and none of 197 near-misses); without it the test skips and
// TestEveryRuleHasFixtures still checks coverage.

var annotation = regexp.MustCompile(`(?:#|//) (ruleid|ok): ([a-z0-9.\-]+)\s*$`)

type mark struct {
	rule, file string
	line       int
}

// fixtureMarks reads every annotation: the marked line is the next one.
func fixtureMarks(t *testing.T) (positives, nearMisses map[mark]bool) {
	t.Helper()
	positives, nearMisses = map[mark]bool{}, map[mark]bool{}
	entries, err := os.ReadDir(filepath.Join("testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("testdata", "fixtures", e.Name()))
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

func TestFixturesAgainstOpengrep(t *testing.T) {
	bin := os.Getenv("OBSERVER_OPENGREP_BIN")
	if bin == "" {
		t.Skip("set OBSERVER_OPENGREP_BIN to a pinned Opengrep to run the pack against its fixtures")
	}
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
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
	fx, _ := filepath.Abs(filepath.Join("testdata", "fixtures"))
	home := filepath.Join(dir, "home")
	cmd := exec.Command(bin, "scan", "--disable-version-check", "--sarif", "--no-rewrite-rule-ids", "--disable-nosem",
		"--x-ignore-semgrepignore-files", "--no-git-ignore", "-j", "2", "--config", filepath.Join(dir, "pack", RulesDir),
		fx, filepath.Join(dir, "pack", CanaryDir))
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
	got := map[mark]bool{}
	canary := false
	for _, r := range sarif.Runs[0].Results {
		l := r.Locations[0].Physical
		if r.RuleID == p.Manifest.Canary.Rule {
			canary = canary || strings.HasSuffix(l.Artifact.URI, filepath.Base(p.Manifest.Canary.Target))
			continue
		}
		got[mark{rule: r.RuleID, file: filepath.Base(l.Artifact.URI), line: l.Region.StartLine}] = true
	}
	pos, near := fixtureMarks(t)
	var problems []string
	for k := range pos {
		if !got[k] {
			problems = append(problems, "missed "+k.rule+" at "+k.file)
		}
	}
	for k := range got {
		switch {
		case near[k]:
			problems = append(problems, "near miss reported: "+k.rule+" at "+k.file)
		case !pos[k]:
			problems = append(problems, "unannotated result: "+k.rule+" at "+k.file)
		}
	}
	if !canary {
		problems = append(problems, "the canary was not reported")
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

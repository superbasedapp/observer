package seccustom

import (
	"slices"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// SelfTestResult is what one self-test run showed.
type SelfTestResult struct {
	Passed  bool
	Missing []string
	// Verdict is the run's own verdict (a self-test that could not run
	// is never a pass).
	Verdict Verdict
}

// CheckSelfTest passes a self-test run only when the run completed with
// findings and every expected rule appears among them (one planted finding
// per enabled rule family: gosec built with Go 1.26 against Go 1.27 drops
// G703, and gosec with no go companion reports nothing, so either fails
// here and the driver's runs stay unknown).
func CheckSelfTest(st *SelfTest, v Verdict, findings []secfinding.Finding) SelfTestResult {
	out := SelfTestResult{Verdict: v}
	if st == nil {
		return out
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.Rule.ID] = true
	}
	for _, r := range st.ExpectRules {
		if !seen[r] {
			out.Missing = append(out.Missing, r)
		}
	}
	sort.Strings(out.Missing)
	out.Passed = len(out.Missing) == 0 && v.Outcome == "findings"
	return out
}

// SelfTestTargets returns the fixture's file paths under root, sorted, as
// the self-test run's targets.
func SelfTestTargets(goos, root string, files Fixture) []string {
	out := make([]string, 0, len(files))
	for p := range files {
		if goos == "windows" {
			p = slashToBack(p)
		}
		out = append(out, join(goos, root, p))
	}
	slices.Sort(out)
	return out
}

func slashToBack(p string) string {
	b := []byte(p)
	for i, c := range b {
		if c == '/' {
			b[i] = '\\'
		}
	}
	return string(b)
}

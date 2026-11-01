package opengrep

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestEngineRan: one row per notRunReasons entry and per outcome (lane
// SEC-G2 audit finding 4).
func TestEngineRan(t *testing.T) {
	t.Parallel()
	failedWith := func(r string) secscan.Coverage { return secscan.Coverage{Outcome: secscan.OutcomeFailed, Reason: r} }
	cases := []struct {
		name string
		c    secscan.Coverage
		want bool
	}{
		{"clean", secscan.Coverage{Outcome: secscan.OutcomeClean}, true},
		{"findings", secscan.Coverage{Outcome: secscan.OutcomeFindings}, true},
		{"unknown", secscan.Coverage{Outcome: secscan.OutcomeUnknown}, true},
		{"not scanned", secscan.Coverage{Outcome: secscan.OutcomeNotScanned, Reason: ReasonNotInstalled}, false},
		{"not installed", failedWith(ReasonNotInstalled), false},
		{"no git", failedWith(ReasonNoGit), false},
		{"no pack", failedWith(ReasonNoPack), false},
		{"bad base", failedWith(ReasonBadBase), false},
		{"bad paths", failedWith(ReasonBadPaths), false},
		{"isolation refused", failedWith(ReasonIsolation), false},
		{"runner refused", failedWith(ReasonRunner), false},
		{"git filter driver", failedWith(ReasonGitFilter), false},
		{"git config unreadable", failedWith(ReasonGitConfig), false},
		{"unverified", failedWith(secengine.ReasonUnverified), false},
		{"crashed", failedWith(ReasonCrashed), true},
		{"budget", failedWith(ReasonBudget), true},
		{"rule config", failedWith(ReasonConfig), true},
		{"output unreadable", failedWith(ReasonOutput), true},
		{"canceled", failedWith(ReasonCanceled), true},
	}
	for _, c := range cases {
		if got := EngineRan(c.c); got != c.want {
			t.Errorf("%s: EngineRan %v, want %v", c.name, got, c.want)
		}
	}
	if len(notRunReasons) != 10 {
		t.Fatalf("notRunReasons has %d rows; add a case for each", len(notRunReasons))
	}
}

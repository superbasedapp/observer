package guard

import (
	"strings"
	"testing"
	"time"
)

// TestEvasionTracker: the tracker counts other shapes of the same rule in
// the same session within the window; an identical repeat, another rule,
// another session and an aged entry do not count, and a zero window is off.
func TestEvasionTracker(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	const w = 5 * time.Minute
	var tr evasionTracker
	steps := []struct {
		session, rule, key string
		at                 time.Duration
		window             time.Duration
		want               int
	}{
		{"s1", "R-112", "git commit -n", 0, w, 0},
		{"s1", "R-112", "git commit -n", time.Second, w, 0},
		{"s1", "R-112", "git commit --no-verify", 2 * time.Second, w, 1},
		{"s1", "R-113", "HUSKY=0 git commit", 3 * time.Second, w, 0},
		{"s2", "R-112", "git -c core.hooksPath=/dev/null commit", 4 * time.Second, w, 0},
		{"s1", "R-112", "git -c core.hooksPath=/dev/null commit", 5 * time.Second, w, 2},
		{"s1", "R-112", "git ci", 20 * time.Minute, w, 0},
		{"s3", "R-112", "a", 0, 0, 0},
		{"s3", "R-112", "b", time.Second, 0, 0},
	}
	for i, s := range steps {
		if got := tr.Observe(s.session, s.rule, s.key, now.Add(s.at), s.window); got != s.want {
			t.Fatalf("step %d (%s %s %q): %d other shapes, want %d", i, s.session, s.rule, s.key, got, s.want)
		}
	}
}

// TestA613OnTheIngestPath: with the window set and the guard enforcing, a
// reworded retry of a denied commit adds an A-613 flag beside the R-112
// deny; with the window at its default of zero, nothing is added.
func TestA613OnTheIngestPath(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	count := func(window int, mode string) (a613 int, reason string) {
		cfg := guardCfg()
		cfg.Mode = mode
		cfg.Rules.EvasionWindowSeconds = window
		g := newTestGuard(t, cfg, nil)
		for i, cmd := range []string{"git commit -n -m x", "git commit --no-verify -m x", "git commit -m x -n"} {
			for _, v := range g.EvaluateActions([]ActionInput{budgetIn("s1", cmd, now.Add(time.Duration(i)*time.Second))}) {
				if v.Verdict.RuleID == "A-613" {
					a613++
					reason = v.Verdict.Reason
				}
			}
		}
		return a613, reason
	}
	if n, _ := count(0, "enforce"); n != 0 {
		t.Fatalf("A-613 with the window off: %d, want 0", n)
	}
	n, reason := count(300, "enforce")
	if n != 2 || !strings.Contains(reason, "R-112") {
		t.Fatalf("A-613 with the window on: %d (%q), want 2 naming R-112", n, reason)
	}
	// Observe mode only flags, so the refusal it tracks is a flag from a
	// rule whose enforce decision is deny (plans decision log P-004).
	n, reason = count(300, "observe")
	if n != 2 || !strings.Contains(reason, "R-112") {
		t.Fatalf("A-613 in observe mode: %d (%q), want 2 naming R-112", n, reason)
	}
}

// TestR166ClassesAreFiltered: an unknown protected path class is dropped
// with an issue, a known one reaches the engine.
func TestR166ClassesAreFiltered(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Boundary.ProtectedPathClasses = []string{"ci", "fixtures"}
	g := newTestGuard(t, cfg, nil)
	found := false
	for _, is := range g.issues {
		found = found || strings.Contains(is, `"fixtures"`)
	}
	if !found {
		t.Errorf("no issue for the unknown class: %v", g.issues)
	}
	in := budgetIn("s1", "echo x > .github/workflows/release.yml", time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	out := g.EvaluateActions([]ActionInput{in})
	if len(out) == 0 || out[0].Verdict.RuleID != "R-166" {
		t.Fatalf("workflow write: %+v, want R-166", out)
	}
}

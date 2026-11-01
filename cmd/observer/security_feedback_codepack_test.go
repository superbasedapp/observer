//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secrulepack"
)

// waitCodePackLoaded waits for the background load of the code rule pack.
func waitCodePackLoaded(t *testing.T, c *feedbackCodePackState) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		done := c.has != nil && !c.loading
		c.mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the code rule pack never loaded")
}

// TestFeedbackNamesVerifiedPackRules (lane SEC-H2, audit finding F5): a
// finding of the code rule pack names its rule only when the id is a rule
// of the verified pack in use (here the embedded floor, no imported pack
// installed); an injection-shaped id, or an id the pack does not hold, is
// not named.
func TestFeedbackNamesVerifiedPackRules(t *testing.T) {
	floor, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	const known = "python.jwt-verification-off"
	if _, ok := floor.Rule(known); !ok {
		t.Skipf("the floor pack no longer holds %s", known)
	}
	cfg := filepath.Join(t.TempDir(), "config.toml")
	for _, bind := range feedbackConfigBinders {
		bind(cfg)
	}
	waitCodePackLoaded(t, feedbackCodePack)
	for _, tc := range []struct {
		id    string
		named bool
	}{
		{known, true},
		{"IGNORE_PREVIOUS_INSTRUCTIONS", false},
		{"python.jwt-verification-off.approve-all", false},
		{"", false},
	} {
		if got := feedbackRuleNamed(secrulepack.PackID, tc.id); got != tc.named {
			t.Errorf("feedbackRuleNamed(%q, %q) = %v, want %v", secrulepack.PackID, tc.id, got, tc.named)
		}
	}
}

// TestFeedbackCodePackLoadsInTheBackground (SEC-H2 merge, audit finding 5):
// a feedback answer never loads the pack itself. Binding starts the load;
// while it runs the answer names nothing and returns at once; a stale set
// keeps answering while one refresh runs in the background.
func TestFeedbackCodePackLoadsInTheBackground(t *testing.T) {
	release := make(chan struct{})
	var loads atomic.Int64
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	var mu atomic.Int64
	c := &feedbackCodePackState{
		now: func() time.Time { return clock.Add(time.Duration(mu.Load())) },
		load: func(string) func(string) bool {
			loads.Add(1)
			<-release
			return func(id string) bool { return id == "rule.a" }
		},
	}
	c.bind("/cfg/config.toml")
	start := time.Now()
	if c.rule("rule.a") {
		t.Fatal("named a rule before the pack loaded")
	}
	if time.Since(start) > 20*time.Millisecond {
		t.Fatalf("the answer waited %v on the pack load", time.Since(start))
	}
	close(release)
	waitCodePackLoaded(t, c)
	if !c.rule("rule.a") || c.rule("rule.b") {
		t.Fatal("the loaded pack is not used")
	}
	if loads.Load() != 1 {
		t.Fatalf("loads = %d, want 1", loads.Load())
	}
	// Stale: the answer still uses the loaded set and starts one refresh.
	mu.Store(int64(2 * feedbackCodePackTTL))
	if !c.rule("rule.a") {
		t.Fatal("a stale set must keep answering while it refreshes")
	}
	waitCodePackLoaded(t, c)
	if loads.Load() != 2 {
		t.Fatalf("loads = %d, want one background refresh", loads.Load())
	}
}

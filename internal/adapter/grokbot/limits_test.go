package grokbot

import "testing"

// TestNoLimitSourceIsGrounded is a trivial guard against the const going
// stale silently: it must stay non-empty and keep naming the actual
// structural reason (remote-sandbox execution), not degrade into a vague
// placeholder over time.
func TestNoLimitSourceIsGrounded(t *testing.T) {
	if NoLimitSource == "" {
		t.Fatal("NoLimitSource is empty")
	}
	const mustMention = "remote sandbox"
	found := false
	for i := 0; i+len(mustMention) <= len(NoLimitSource); i++ {
		if NoLimitSource[i:i+len(mustMention)] == mustMention {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("NoLimitSource = %q, want it to mention %q", NoLimitSource, mustMention)
	}
}

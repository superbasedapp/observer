package openshellorg

import (
	"strings"
	"testing"
)

// TestHomeRelayRefusalNamesOnlyWhatServesIt (FX4 item 5, F-P6-1): the R2
// home_relay refusal lists what serves home_relay (credential injection,
// the org AI gateway route) and says a routing key pool does not; it never
// offers the pool as a way to serve it (FX3 item 5: the pool only rotates
// keys a request already carries).
func TestHomeRelayRefusalNamesOnlyWhatServesIt(t *testing.T) {
	for _, r := range ProbeLadder {
		if r.Verdict != VerdictHomeRelayMissing {
			continue
		}
		if !strings.Contains(r.Why, "credentials add") || !strings.Contains(r.Why, "org AI gateway route") ||
			!strings.Contains(r.Why, "a routing key pool does not serve home_relay") {
			t.Errorf("R2 says: %s", r.Why)
		}
		return
	}
	t.Fatal("no home_relay row")
}

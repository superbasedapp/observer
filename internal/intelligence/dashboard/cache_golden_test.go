package dashboard

import (
	"encoding/json"
	"testing"
)

// TestSessionCacheResponse_JSONShapeUnchanged pins the exact wire shape of
// GET /api/session/<id>/cache after the timeline builder (buildCacheTimeline
// / buildCacheEfficiency / collapseTier / isFlaggedCause)
// moved to internal/cachetrack (timeline.go) and the dashboard types became
// aliases of the cachetrack types. This is a behaviour-preservation gate:
// the SessionCacheResponse struct is assembled the same way
// handleSessionCache does it, from a fixed event list, and compared to a
// literal JSON document. Any accidental field rename, tag change, or
// omitempty drift breaks this test.
func TestSessionCacheResponse_JSONShapeUnchanged(t *testing.T) {
	t.Parallel()

	events := []SessionCacheEvent{
		ev("hit", "suffix_growth", 10000, 0, "2026-06-09T00:00:00Z"),
		ev("write", "suffix_growth", 9000, 200, "2026-06-09T00:00:10Z"),
		ev("invalidation_rewrite", "tools_changed", 39056, 5400, "2026-06-09T00:00:20Z"),
		{
			Timestamp: "2026-06-09T00:00:30Z", Tier: "proxy", Model: "claude-opus-4-8",
			Kind: "mispredict", Cause: "unknown", TokensRead: 0, TokensWritten: 0, ZeroUsage: true,
		},
	}

	resp := SessionCacheResponse{
		Tier:       collapseTier(events),
		Entries:    []SessionCacheEntry{},
		Events:     events,
		Efficiency: buildCacheEfficiency(events),
		Timeline:   buildCacheTimeline(events),
	}

	got, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const want = `{"tier":"proxy","entries":[],"events":[` +
		`{"timestamp":"2026-06-09T00:00:00Z","tier":"proxy","model":"claude-opus-4-8","kind":"hit","cause":"suffix_growth","tokens_read":10000,"tokens_written":0},` +
		`{"timestamp":"2026-06-09T00:00:10Z","tier":"proxy","model":"claude-opus-4-8","kind":"write","cause":"suffix_growth","tokens_read":9000,"tokens_written":200},` +
		`{"timestamp":"2026-06-09T00:00:20Z","tier":"proxy","model":"claude-opus-4-8","kind":"invalidation_rewrite","cause":"tools_changed","tokens_read":39056,"tokens_written":5400},` +
		`{"timestamp":"2026-06-09T00:00:30Z","tier":"proxy","model":"claude-opus-4-8","kind":"mispredict","cause":"unknown","tokens_read":0,"tokens_written":0,"zero_usage":true}` +
		`],"efficiency":{"read_tokens":58056,"written_tokens":5600,"ratio":10.367142857142857,"avoidable_usd":0},"timeline":[` +
		`{"kind":"baseline","count":2,"baseline_read_sum":19000,"baseline_write_sum":200,"first_at":"2026-06-09T00:00:00Z","last_at":"2026-06-09T00:00:10Z"},` +
		`{"kind":"anomaly","event":{"timestamp":"2026-06-09T00:00:20Z","tier":"proxy","model":"claude-opus-4-8","kind":"invalidation_rewrite","cause":"tools_changed","tokens_read":39056,"tokens_written":5400},"flagged":true},` +
		`{"kind":"anomaly","event":{"timestamp":"2026-06-09T00:00:30Z","tier":"proxy","model":"claude-opus-4-8","kind":"mispredict","cause":"unknown","tokens_read":0,"tokens_written":0,"zero_usage":true}}` +
		`]}`

	if string(got) != want {
		t.Errorf("SessionCacheResponse JSON shape changed:\n got:  %s\n want: %s", got, want)
	}
}

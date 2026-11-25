package adapter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func pendingResult() ParseResult {
	return ParseResult{
		ToolEvents:        make([]models.ToolEvent, 5),
		TokenEvents:       make([]models.TokenEvent, 4),
		CacheObservations: make([]models.CacheTurnObservation, 3),
		NewOffset:         1000,
	}
}

func TestDeferUnpairedTail(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.jsonl")
	if err := os.WriteFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "stale.jsonl")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * PendingResultGrace)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	// Two calls pending: the earlier record (offset 600) wins.
	pending := map[string]PendingMark{
		"late":  {ToolIdx: 4, LineStart: 800, ToolLen: 4, TokenLen: 3, CacheLen: 2},
		"early": {ToolIdx: 2, LineStart: 600, ToolLen: 2, TokenLen: 1, CacheLen: 1},
	}
	type want struct {
		offset                int64
		tools, tokens, caches int
		retry                 bool
	}
	cases := []struct {
		name        string
		path        string
		pending     map[string]PendingMark
		newOffset   int64
		rewindCache bool
		want        want
	}{
		{"nothing pending", fresh, nil, 1000, false, want{1000, 5, 4, 3, false}},
		{"rewinds to the earliest record", fresh, pending, 1000, false, want{600, 2, 1, 3, true}},
		{"rewinds cache observations when asked", fresh, pending, 1000, true, want{600, 2, 1, 1, true}},
		{"tail too far behind the parsed end", fresh, pending, 600 + MaxDeferTailBytes + 1, false, want{600 + MaxDeferTailBytes + 1, 5, 4, 3, false}},
		{"transcript stale past the grace", stale, pending, 1000, true, want{1000, 5, 4, 3, false}},
		{"transcript missing", filepath.Join(dir, "gone.jsonl"), pending, 1000, true, want{1000, 5, 4, 3, false}},
	}
	for _, tc := range cases {
		res := pendingResult()
		res.NewOffset = tc.newOffset
		DeferUnpairedTail(&res, tc.path, tc.pending, tc.rewindCache)
		got := want{res.NewOffset, len(res.ToolEvents), len(res.TokenEvents), len(res.CacheObservations), res.RetrySuggested}
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

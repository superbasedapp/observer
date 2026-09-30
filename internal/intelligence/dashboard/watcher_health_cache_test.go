package dashboard

import (
	"testing"
	"time"
)

// TestWatcherHealthCacheSWR pins finding N5 of the 2026-09-27 optimization
// review: with Options.ReadCaches the payload is served fresh for
// watcherHealthFreshTTL, then stale-while-revalidate (the stale answer
// immediately, one background recompute), and recomputed synchronously once
// older than watcherHealthStaleServeMax. Without ReadCaches every request
// recomputes — the pre-change behaviour every other test relies on.
func TestWatcherHealthCacheSWR(t *testing.T) {
	s, root := newTestServer(t)
	s.opts.RecognizesSessionFile = func(string) bool { return true }
	s.opts.CursorSemanticsFor = nil
	advance := pinClock(s)
	fetch := func() watcherHealthPayload {
		t.Helper()
		got := fetchWatcherHealth(t, s)
		s.watcherHealth.bg.Wait()
		return got
	}

	// Off: every request sees the database as it is now.
	seedCursor(t, s, root, "a.jsonl", 4096, 0)
	if got := fetch(); got.TotalFiles != 1 {
		t.Fatalf("uncached total_files = %d, want 1", got.TotalFiles)
	}
	seedCursor(t, s, root, "b.jsonl", 4096, 0)
	if got := fetch(); got.TotalFiles != 2 {
		t.Fatalf("uncached total_files = %d, want 2", got.TotalFiles)
	}

	s.opts.ReadCaches = true
	if got := fetch(); got.TotalFiles != 2 {
		t.Fatalf("first cached total_files = %d, want 2", got.TotalFiles)
	}
	seedCursor(t, s, root, "c.jsonl", 4096, 0)
	if got := fetch(); got.TotalFiles != 2 {
		t.Fatalf("within fresh TTL total_files = %d, want the memoized 2", got.TotalFiles)
	}
	// Stale: the old answer is served, and ONE background recompute runs.
	advance(watcherHealthFreshTTL + time.Second)
	if got := fetchWatcherHealth(t, s); got.TotalFiles != 2 {
		t.Fatalf("stale hit total_files = %d, want the stale 2 served immediately", got.TotalFiles)
	}
	s.watcherHealth.bg.Wait()
	if got := fetch(); got.TotalFiles != 3 {
		t.Fatalf("after background refresh total_files = %d, want 3", got.TotalFiles)
	}
	// Too old to present as current: synchronous recompute.
	seedCursor(t, s, root, "d.jsonl", 4096, 0)
	advance(watcherHealthStaleServeMax + time.Second)
	if got := fetch(); got.TotalFiles != 4 {
		t.Fatalf("past stale max total_files = %d, want a synchronous 4", got.TotalFiles)
	}
}

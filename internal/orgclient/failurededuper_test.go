package orgclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFailureDeduper_Observe drives one failureDeduper through a fixed
// sequence of cycle outcomes and pins the exact isRepeat/repeats it
// reports at each step: the first sighting of a failure kind is NOT a
// repeat, an identical kind immediately after IS a repeat with a growing
// counter, a CHANGED kind is fresh again, and a success ("") clears the
// tracker so the SAME kind returning afterward is treated as fresh too
// (a "recovery" re-arms the WARN). This is the exact behavior
// internal/orgclient's runLoop/PushLoop rely on to log a wedged remote's
// failure ONCE at WARN instead of once per retry forever (2026-09-07: 316
// WARN lines/hour against a dead org server).
func TestFailureDeduper_Observe(t *testing.T) {
	type step struct {
		name        string
		kind        string
		wantRepeat  bool
		wantRepeats int
	}
	steps := []step{
		{"first failure of kind A", "errA", false, 1},
		{"second identical A — repeat", "errA", true, 2},
		{"third identical A — repeat, counter grows", "errA", true, 3},
		{"kind changes to B — fresh, not a repeat", "errB", false, 1},
		{"second identical B — repeat", "errB", true, 2},
		{"success clears the tracker", "", false, 0},
		{"same kind B after recovery — fresh again", "errB", false, 1},
		{"identical B again — repeat", "errB", true, 2},
	}

	var d failureDeduper
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			gotRepeat, gotRepeats := d.observe(s.kind)
			if gotRepeat != s.wantRepeat {
				t.Errorf("observe(%q) isRepeat = %v, want %v", s.kind, gotRepeat, s.wantRepeat)
			}
			if gotRepeats != s.wantRepeats {
				t.Errorf("observe(%q) repeats = %d, want %d", s.kind, gotRepeats, s.wantRepeats)
			}
		})
	}
}

// TestWarnOnce_LogsWarnThenDebug pins warnOnce's log-level policy: the
// first occurrence of an error logs at WARN, an identical repeat logs at
// DEBUG (not WARN — that's the whole point), a changed error re-WARNs,
// and clearing the deduper (a recovery) makes even the SAME error WARN
// again.
func TestWarnOnce_LogsWarnThenDebug(t *testing.T) {
	// This test is about the KIND-based dedup, not the time backstop (see
	// TestWarnOnce_TimeBackstop for that) — advance the fake clock well
	// past warnBackstopInterval between every call so the backstop never
	// fires here and every "fresh kind" case gets its expected WARN.
	fake := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	restore := stubClockNow(func() time.Time {
		now := fake
		fake = fake.Add(warnBackstopInterval + time.Minute)
		return now
	})
	defer restore()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var d failureDeduper
	errA := errors.New("boom")
	errB := errors.New("kaboom")

	warnOnce(logger, &d, errA, "op failed") // 1: WARN (fresh)
	warnOnce(logger, &d, errA, "op failed") // 2: DEBUG (repeat)
	warnOnce(logger, &d, errA, "op failed") // 3: DEBUG (repeat)
	warnOnce(logger, &d, errB, "op failed") // 4: WARN (changed kind)
	d.observe("")                           // recovery
	warnOnce(logger, &d, errA, "op failed") // 5: WARN (fresh after recovery, even though errA repeats history)

	var levels []string
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.Contains(line, "level=WARN"):
			levels = append(levels, "WARN")
		case strings.Contains(line, "level=DEBUG"):
			levels = append(levels, "DEBUG")
		default:
			t.Fatalf("log line has neither level=WARN nor level=DEBUG: %q", line)
		}
	}

	want := []string{"WARN", "DEBUG", "DEBUG", "WARN", "WARN"}
	if len(levels) != len(want) {
		t.Fatalf("levels = %v, want %d entries (log:\n%s)", levels, len(want), buf.String())
	}
	for i, lvl := range want {
		if levels[i] != lvl {
			t.Errorf("levels[%d] = %q, want %q (full sequence: %v)", i, levels[i], lvl, levels)
		}
	}
}

// stubClockNow overrides the package-level clockNow for the duration of a
// test and returns a func that restores it — callers defer the result.
func stubClockNow(fn func() time.Time) (restore func()) {
	orig := clockNow
	clockNow = fn
	return func() { clockNow = orig }
}

// TestNormalizeFailureKey pins the three tiers a code review asked for
// after warnOnce's original err.Error()-keyed dedup was found to re-arm a
// WARN every cycle a variable-payload error (a server-echoed request id,
// an OS-specific network-error rendering) merely reworded itself without
// the underlying failure actually changing class.
func TestNormalizeFailureKey(t *testing.T) {
	t.Run("body-echoed request id normalizes to the same key", func(t *testing.T) {
		// Same status, different echoed body (a fresh request id/timestamp
		// each cycle) — must collapse to one key via the httpStatusError
		// tier, not the raw message text.
		e1 := &httpStatusError{op: "orgclient.PushOnce", status: 503, body: "request-id=a1b2c3d4e5, retry later"}
		e2 := &httpStatusError{op: "orgclient.PushOnce", status: 503, body: "request-id=z9y8x7w6v5, retry later"}
		k1, k2 := normalizeFailureKey(e1), normalizeFailureKey(e2)
		if k1 != k2 {
			t.Errorf("keys differ for the same status with only the echoed body varying: %q vs %q", k1, k2)
		}
	})

	t.Run("connection refused vs timeout yield different keys", func(t *testing.T) {
		refused := &url.Error{Op: "Post", URL: "https://org.example/api/v1/push", Err: syscall.ECONNREFUSED}
		timeout := &url.Error{Op: "Post", URL: "https://org.example/api/v1/push", Err: context.DeadlineExceeded}
		k1, k2 := normalizeFailureKey(refused), normalizeFailureKey(timeout)
		if k1 == k2 {
			t.Errorf("connection-refused and timeout must classify differently, both got %q", k1)
		}
	})

	t.Run("status change 500 to 503 yields different keys", func(t *testing.T) {
		e500 := &httpStatusError{op: "orgclient.PushOnce", status: 500, body: "internal error"}
		e503 := &httpStatusError{op: "orgclient.PushOnce", status: 503, body: "internal error"}
		k1, k2 := normalizeFailureKey(e500), normalizeFailureKey(e503)
		if k1 == k2 {
			t.Errorf("a genuine status change (500 -> 503) must yield a different key, both got %q", k1)
		}
	})

	t.Run("fallback tier collapses long digit runs but keeps short ones", func(t *testing.T) {
		// A decode-error-style message carrying a variable byte offset
		// (long digit run) must normalize the same across occurrences...
		e1 := fmt.Errorf("orgclient.FetchOrgAnnouncement: decode: invalid character at offset 8213947")
		e2 := fmt.Errorf("orgclient.FetchOrgAnnouncement: decode: invalid character at offset 55201")
		if normalizeFailureKey(e1) != normalizeFailureKey(e2) {
			t.Errorf("long digit runs (byte offsets) should collapse to the same key: %q vs %q", normalizeFailureKey(e1), normalizeFailureKey(e2))
		}
		// ...while a short digit run (an HTTP status embedded in prose,
		// not routed through httpStatusError) still distinguishes.
		e3 := fmt.Errorf("orgclient.FetchRoutingPolicy: server returned 500")
		e4 := fmt.Errorf("orgclient.FetchRoutingPolicy: server returned 503")
		if normalizeFailureKey(e3) == normalizeFailureKey(e4) {
			t.Errorf("a short (3-digit) status embedded in a fallback-tier message must still distinguish: both got %q", normalizeFailureKey(e3))
		}
	})

	t.Run("wrapped httpStatusError is still found via errors.As", func(t *testing.T) {
		wrapped := fmt.Errorf("orgclient.PushOnce: %w", &httpStatusError{op: "orgclient.PushOnce", status: 500, body: "req=1"})
		bare := &httpStatusError{op: "orgclient.PushOnce", status: 500, body: "req=2"}
		if normalizeFailureKey(wrapped) != normalizeFailureKey(bare) {
			t.Errorf("a %%w-wrapped httpStatusError should key identically to the bare error: %q vs %q", normalizeFailureKey(wrapped), normalizeFailureKey(bare))
		}
	})
}

// TestWarnOnce_TimeBackstop pins the safety net for a normalization gap:
// even when the dedup key changes on every single cycle (as it would for
// a class of failure normalizeFailureKey hasn't learned to collapse),
// warnOnce must not emit more than one WARN per warnBackstopInterval —
// degrading gracefully to DEBUG instead of regressing to the original
// one-WARN-per-retry complaint.
func TestWarnOnce_TimeBackstop(t *testing.T) {
	fake := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	restore := stubClockNow(func() time.Time { return fake })
	defer restore()

	buf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var d failureDeduper
	warnOnce(logger, &d, errors.New("flavor alpha"), "op failed") // t=0:    WARN (first ever)
	fake = fake.Add(2 * time.Minute)
	warnOnce(logger, &d, errors.New("flavor beta"), "op failed") // t=2m:   changed kind, but within 10m of the last WARN -> DEBUG
	fake = fake.Add(3 * time.Minute)
	warnOnce(logger, &d, errors.New("flavor gamma"), "op failed") // t=5m:   still within the window -> DEBUG
	fake = fake.Add(6 * time.Minute)
	warnOnce(logger, &d, errors.New("flavor delta"), "op failed") // t=11m:  past warnBackstopInterval since the last WARN -> WARN

	var levels []string
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		switch {
		case strings.Contains(line, "level=WARN"):
			levels = append(levels, "WARN")
		case strings.Contains(line, "level=DEBUG"):
			levels = append(levels, "DEBUG")
		default:
			t.Fatalf("log line has neither level=WARN nor level=DEBUG: %q", line)
		}
	}

	want := []string{"WARN", "DEBUG", "DEBUG", "WARN"}
	if len(levels) != len(want) {
		t.Fatalf("levels = %v, want %d entries (log:\n%s)", levels, len(want), buf.String())
	}
	for i, lvl := range want {
		if levels[i] != lvl {
			t.Errorf("levels[%d] = %q, want %q (full sequence: %v)", i, levels[i], lvl, levels)
		}
	}
}

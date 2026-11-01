package hookspool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSpoolCapRule pins, per kind, whether a record is skipped once the live
// spool is past MaxActivitySpoolBytes (R-188 F5): only the activity kind is
// capped, an action (tool-event) or compaction record still lands on a full
// spool, and each skip is counted.
func TestSpoolCapRule(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		rec    Record
		capped bool
	}{
		{"activity", Record{Tool: "claude-code", Kind: KindActivity, HookEvent: "PreToolUse", Timestamp: now}, true},
		{"action (tool-event row)", Record{Tool: "claude-code", SessionID: "s1", ActionType: "session_end", Timestamp: now}, false},
		{"compaction", Record{Tool: "claude-code", Kind: KindCompaction, SessionID: "s1", Phase: "pre", Timestamp: now}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := capsAtSpoolLimit(tc.rec.Kind); got != tc.capped {
				t.Fatalf("capsAtSpoolLimit(%q) = %v, want %v", tc.rec.Kind, got, tc.capped)
			}
			for _, full := range []bool{false, true} {
				p := filepath.Join(t.TempDir(), Filename)
				if full {
					fillSpool(t, p, MaxActivitySpoolBytes)
				}
				before := fileSize(t, p)
				err := Append(p, tc.rec)
				skipped, serr := SkippedActivity(p)
				if serr != nil {
					t.Fatal(serr)
				}
				wantSkip := full && tc.capped
				switch {
				case wantSkip && !errors.Is(err, ErrActivitySkipped):
					t.Fatalf("full=%v: err %v, want ErrActivitySkipped", full, err)
				case !wantSkip && err != nil:
					t.Fatalf("full=%v: err %v, want the record appended", full, err)
				}
				grew := fileSize(t, p) > before
				if grew == wantSkip {
					t.Fatalf("full=%v: spool grew=%v, want grew=%v", full, grew, !wantSkip)
				}
				if want := map[bool]int64{true: 1, false: 0}[wantSkip]; skipped != want {
					t.Fatalf("full=%v: skipped %d, want %d", full, skipped, want)
				}
			}
		})
	}
}

// TestSpoolCapBoundary: an activity record lands while the spool is below the
// cap, is skipped at the cap, and the counter is taken (read and cleared)
// once by the drainer.
func TestSpoolCapBoundary(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), Filename)
	rec := Record{Tool: "codex", Kind: KindActivity, HookEvent: "Stop"}
	fillSpool(t, p, MaxActivitySpoolBytes-1)
	if err := Append(p, rec); err != nil {
		t.Fatalf("below the cap: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := Append(p, rec); !errors.Is(err, ErrActivitySkipped) {
			t.Fatalf("past the cap: err %v", err)
		}
	}
	if n, err := SkippedActivity(p); err != nil || n != 3 {
		t.Fatalf("SkippedActivity = %d, %v; want 3", n, err)
	}
	now := time.Now()
	if n, err := TakeSkippedActivity(p, now); err != nil || n != 3 {
		t.Fatalf("TakeSkippedActivity = %d, %v; want 3", n, err)
	}
	if n, err := SkippedActivity(p); err != nil || n != 0 {
		t.Fatalf("after take: %d, %v; want 0", n, err)
	}
	if n, err := TakeSkippedActivity(p, now); err != nil || n != 0 {
		t.Fatalf("second take: %d, %v; want 0", n, err)
	}
	// The counter never matches the drainer's aside glob.
	if _, err := SetAside(p, now); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, rec); err != nil {
		t.Fatalf("after set aside the spool is empty again: %v", err)
	}
	countSkipped(SkippedPath(p))
	ready, err := Ready(p, now.Add(Grace+time.Second))
	if err != nil || len(ready) != 1 || strings.Contains(ready[0].Path, skippedSuffix) {
		t.Fatalf("ready %+v err %v", ready, err)
	}
}

// TestSkipCounterIsBounded: the counter stops at MaxSkippedCount.
func TestSkipCounterIsBounded(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), Filename)
	fillSpool(t, SkippedPath(p), MaxSkippedCount)
	countSkipped(SkippedPath(p))
	if n, err := SkippedActivity(p); err != nil || n != MaxSkippedCount {
		t.Fatalf("SkippedActivity = %d, %v; want %d", n, err, MaxSkippedCount)
	}
}

// fillSpool makes path a file of size bytes (sparse where the OS allows).
func fillSpool(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

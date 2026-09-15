package taskflow

import (
	"testing"
	"time"
)

func t0(min int) time.Time {
	return time.Date(2026, 9, 7, 10, min, 0, 0, time.UTC)
}

func TestBuildOpenIntervals_SingleTaskLifecycle(t *testing.T) {
	transitions := []Transition{
		{Key: "1", FromStatus: "", ToStatus: StatusPending, Ts: t0(0)},
		{Key: "1", FromStatus: StatusPending, ToStatus: StatusInProgress, Ts: t0(1)},
		{Key: "1", FromStatus: StatusInProgress, ToStatus: StatusCompleted, Ts: t0(5)},
	}
	intervals := BuildOpenIntervals(transitions)
	if len(intervals) != 1 {
		t.Fatalf("want 1 interval, got %+v", intervals)
	}
	iv := intervals[0]
	if !iv.HasEnd || !iv.Start.Equal(t0(1)) || !iv.End.Equal(t0(5)) {
		t.Errorf("interval = %+v", iv)
	}
}

func TestBuildOpenIntervals_StillOpen(t *testing.T) {
	transitions := []Transition{
		{Key: "1", ToStatus: StatusInProgress, Ts: t0(1)},
	}
	intervals := BuildOpenIntervals(transitions)
	if len(intervals) != 1 || intervals[0].HasEnd {
		t.Fatalf("want 1 still-open interval, got %+v", intervals)
	}
}

func TestBuildOpenIntervals_PausedThenReopenedProducesTwoWindows(t *testing.T) {
	// in_progress -> pending -> in_progress: a PAUSED task (§R2.3, 9
	// real cases) must close its first window on the pause, not leave
	// it open until (or past) the eventual completion.
	transitions := []Transition{
		{Key: "1", FromStatus: "", ToStatus: StatusInProgress, Ts: t0(0)},
		{Key: "1", FromStatus: StatusInProgress, ToStatus: StatusPending, Ts: t0(2)},
		{Key: "1", FromStatus: StatusPending, ToStatus: StatusInProgress, Ts: t0(5)},
		{Key: "1", FromStatus: StatusInProgress, ToStatus: StatusCompleted, Ts: t0(8)},
	}
	intervals := BuildOpenIntervals(transitions)
	if len(intervals) != 2 {
		t.Fatalf("want 2 windows (paused + resumed), got %+v", intervals)
	}
	first, second := intervals[0], intervals[1]
	if !first.HasEnd || !first.Start.Equal(t0(0)) || !first.End.Equal(t0(2)) {
		t.Errorf("first window = %+v, want [0,2)", first)
	}
	if !second.HasEnd || !second.Start.Equal(t0(5)) || !second.End.Equal(t0(8)) {
		t.Errorf("second window = %+v, want [5,8)", second)
	}
}

func TestBuildOpenIntervals_BlockedClosesWindow(t *testing.T) {
	transitions := []Transition{
		{Key: "1", ToStatus: StatusInProgress, Ts: t0(0)},
		{Key: "1", FromStatus: StatusInProgress, ToStatus: StatusBlocked, Ts: t0(4)},
	}
	intervals := BuildOpenIntervals(transitions)
	if len(intervals) != 1 || !intervals[0].HasEnd || !intervals[0].End.Equal(t0(4)) {
		t.Fatalf("want 1 closed window ending at blocked transition, got %+v", intervals)
	}
}

func TestAttributor_SingleZeroAndSharedBuckets(t *testing.T) {
	intervals := []OpenInterval{
		{Key: "a", Start: t0(0), End: t0(10), HasEnd: true},
		{Key: "b", Start: t0(5), End: t0(15), HasEnd: true},
	}
	at := NewAttributor(intervals)

	if got := at.At(t0(2)); got.Bucket != BucketSingle || got.Key != "a" {
		t.Errorf("t=2: got %+v, want single/a", got)
	}
	if got := at.At(t0(7)); got.Bucket != BucketShared {
		t.Errorf("t=7 (both open): got %+v, want shared", got)
	}
	if got := at.At(t0(12)); got.Bucket != BucketSingle || got.Key != "b" {
		t.Errorf("t=12: got %+v, want single/b", got)
	}
	if got := at.At(t0(20)); got.Bucket != BucketBetweenTasks {
		t.Errorf("t=20 (nothing open): got %+v, want between_tasks", got)
	}
}

func TestSummarize_NeverActivatedAndStillOpen(t *testing.T) {
	transitions := []Transition{
		// Task 1: completed without ever going through in_progress.
		{Key: "1", ToStatus: StatusCompleted, Ts: t0(1)},
		// Task 2: activated, never closed.
		{Key: "2", ToStatus: StatusInProgress, Ts: t0(2)},
		// Task 3: full lifecycle.
		{Key: "3", ToStatus: StatusInProgress, Ts: t0(0)},
		{Key: "3", ToStatus: StatusCompleted, Ts: t0(10)},
	}
	asOf := t0(20)
	summaries := Summarize(transitions, asOf)
	byKey := map[string]TaskSummary{}
	for _, s := range summaries {
		byKey[s.Key] = s
	}

	if s := byKey["1"]; !s.NeverActivated || s.Elapsed != 0 {
		t.Errorf("task 1 = %+v, want never-activated with zero elapsed", s)
	}
	if s := byKey["2"]; !s.StillOpen || s.Elapsed != 18*time.Minute {
		t.Errorf("task 2 = %+v, want still-open elapsed-so-far 18m", s)
	}
	if s := byKey["3"]; s.NeverActivated || s.StillOpen || s.Elapsed != 10*time.Minute {
		t.Errorf("task 3 = %+v, want a clean 10m lifecycle", s)
	}
}

func TestSummarize_DeletedIsTerminalNotCompletion(t *testing.T) {
	transitions := []Transition{
		{Key: "1", ToStatus: StatusInProgress, Ts: t0(0)},
		{Key: "1", ToStatus: StatusDeleted, Ts: t0(3)},
	}
	summaries := Summarize(transitions, t0(20))
	if len(summaries) != 1 {
		t.Fatalf("got %+v", summaries)
	}
	s := summaries[0]
	if s.TerminalStatus != StatusDeleted || s.StillOpen {
		t.Errorf("s = %+v, want terminal=deleted, not still open", s)
	}
}

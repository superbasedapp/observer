package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
)

// TestWatchActivityStamp pins the hook -> daemon activity signal: a stamp
// that already exists at start is only a baseline, a later touch is one
// "prompt" activity, and an unchanged stamp is silent. It polls every 100ms
// instead of the daemon's activityStampPoll, so the quiet checks wait a few
// polls rather than seconds.
func TestWatchActivityStamp(t *testing.T) {
	const poll = 100 * time.Millisecond
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	if err := budgetwarnfile.TouchActivity(dbPath); err != nil {
		t.Fatal(err)
	}
	// Age the baseline so the next touch has a strictly later mtime even on
	// a coarse-mtime filesystem.
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(budgetwarnfile.ActivityPath(dbPath), old, old); err != nil {
		t.Fatal(err)
	}

	var notes atomic.Int32
	var kind atomic.Value
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchActivityStampEvery(ctx, dbPath, poll, func(k string) { kind.Store(k); notes.Add(1) })
		close(done)
	}()

	time.Sleep(5 * poll)
	if n := notes.Load(); n != 0 {
		t.Fatalf("baseline stamp produced %d notes, want 0", n)
	}
	if err := budgetwarnfile.TouchActivity(dbPath); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for notes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if n := notes.Load(); n != 1 {
		t.Fatalf("touch produced %d notes, want 1", n)
	}
	if k, _ := kind.Load().(string); k != activityPrompt {
		t.Fatalf("kind = %q, want %q", k, activityPrompt)
	}
	time.Sleep(5 * poll)
	if n := notes.Load(); n != 1 {
		t.Fatalf("unchanged stamp produced %d notes total, want 1", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop on cancel")
	}
}

//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestProvenanceNudgerScansWhenHeadMoves: a nudge watches the repository
// and scans it once HEAD moves; a second nudge for the same root while the
// watch runs is dropped; a HEAD that never moves gives up without a scan.
func TestProvenanceNudgerScansWhenHeadMoves(t *testing.T) {
	var head atomic.Value
	head.Store("a")
	scanned := make(chan string, 4)
	n := &provenanceNudger{
		ctx:  context.Background(),
		head: func(context.Context, string) string { return head.Load().(string) },
		scan: func(_ context.Context, root string) error { scanned <- root; return nil },
		poll: 10 * time.Millisecond, wait: 2 * time.Second, watching: map[string]bool{},
	}
	if !n.take("/r") || n.take("/r") {
		t.Fatal("the second nudge for a watched root was not dropped")
	}
	time.Sleep(30 * time.Millisecond)
	head.Store("b")
	select {
	case r := <-scanned:
		if r != "/r" {
			t.Fatalf("scanned %q", r)
		}
	case <-time.After(time.Second):
		t.Fatal("no scan after HEAD moved")
	}
	idle := &provenanceNudger{
		ctx:  context.Background(),
		head: func(context.Context, string) string { return "same" },
		scan: func(_ context.Context, root string) error { scanned <- root; return nil },
		poll: 5 * time.Millisecond, wait: 50 * time.Millisecond, watching: map[string]bool{},
	}
	idle.take("/s")
	time.Sleep(150 * time.Millisecond)
	select {
	case r := <-scanned:
		t.Fatalf("scanned %q although HEAD never moved", r)
	default:
	}
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if len(idle.watching) != 0 {
		t.Fatal("the watch was not released")
	}
}

// TestProvenanceHoldNudgeNeedsTheLoop: the hook holds a nudge only while
// the provenance loop's flag exists.
func TestProvenanceHoldNudgeNeedsTheLoop(t *testing.T) {
	layout := t.TempDir()
	provenanceNudgeCandidate.Store(nil)
	t.Cleanup(func() { provenanceNudgeCandidate.Store(nil) })
	provenanceHoldNudge(layout, "/r")
	if provenanceNudgeCandidate.Load() != nil {
		t.Fatal("a nudge was held with the loop off")
	}
	done := provenanceMarkActive(layout)
	provenanceHoldNudge(layout, "/r")
	if c := provenanceNudgeCandidate.Load(); c == nil || c.root != "/r" {
		t.Fatal("no nudge held with the loop on")
	}
	done()
	if _, err := os.Stat(provenanceActiveFlag(layout)); err == nil {
		t.Fatal("the flag outlived the loop")
	}
	provenanceSendNudge() // no daemon listening: bounded, never an error to the hook
	if provenanceNudgeCandidate.Load() != nil {
		t.Fatal("the nudge was not consumed")
	}
}

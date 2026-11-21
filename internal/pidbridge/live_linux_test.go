//go:build linux

package pidbridge

import (
	"context"
	"os"
	"testing"
)

// TestLiveSession pins lane cli-2's read: a row for a live process of its
// tool is a hit, a row for a process that does not match its tool, or a
// pid with no row, is a miss.
func TestLiveSession(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	self := os.Getpid()
	// This test binary's own comm/cmdline contains "pidbridge" (its name),
	// so a row whose tool hint is that word validates.
	if err := s.Write(ctx, Entry{PID: self, SessionID: "sess-live", Tool: "pidbridge"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if e, ok, err := s.LiveSession(ctx, self); err != nil || !ok || e.SessionID != "sess-live" {
		t.Fatalf("LiveSession(self) = %+v, %v, %v", e, ok, err)
	}
	if err := s.Write(ctx, Entry{PID: self, SessionID: "sess-other", Tool: "no-such-tool-binary"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, ok, err := s.LiveSession(ctx, self); err != nil || ok {
		t.Fatalf("LiveSession for a tool the process is not = %v, %v", ok, err)
	}
	if _, ok, err := s.LiveSession(ctx, 999999999); err != nil || ok {
		t.Fatalf("LiveSession(no row) = %v, %v", ok, err)
	}
}

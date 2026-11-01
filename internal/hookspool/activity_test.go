package hookspool

import (
	"path/filepath"
	"testing"
	"time"
)

// TestActivityRecord pins the liveness kind (OBS-7): it is version 3 (a
// version-2 drainer drops it as a newer schema), its session id may be
// empty (the unattributed bucket), it needs an event, and it is never held
// waiting for a session.
func TestActivityRecord(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), Filename)
	now := time.Now()
	if err := Append(p, Record{Tool: "claude-code", Kind: KindActivity, HookEvent: "PreToolUse", Env: map[string]string{"ANTHROPIC_BASE_URL": "loopback"}, Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Record{Tool: "claude-code", Kind: KindActivity, SessionID: "s1", HookEvent: "Stop", Timestamp: now}); err != nil {
		t.Fatal(err)
	}
	if err := Append(p, Record{Tool: "claude-code", Kind: KindActivity}); err == nil {
		t.Fatal("an activity record with no event was accepted")
	}
	if _, err := SetAside(p, now); err != nil {
		t.Fatal(err)
	}
	ready, err := Ready(p, now.Add(Grace+time.Second))
	if err != nil || len(ready) != 1 || len(ready[0].Records) != 2 || ready[0].Dropped != 0 {
		t.Fatalf("ready = %+v err %v", ready, err)
	}
	r := ready[0].Records[0]
	if r.V != 3 || r.SessionID != "" || r.HookEvent != "PreToolUse" || r.Env["ANTHROPIC_BASE_URL"] != "loopback" {
		t.Fatalf("record = %+v", r)
	}
	if r.NeedsSession() || Decide(r, false, now.Add(2*MaxHoldAge)) != Apply {
		t.Fatal("an activity record must apply without a session, never hold or expire")
	}
}

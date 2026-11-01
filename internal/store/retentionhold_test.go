package store

import (
	"context"
	"testing"
	"time"
)

// TestLoadRetentionPushFloor pins T-839 / D-673 one row per node posture: the
// floor is held whenever an enrolment row exists, push running or paused, and
// only a node that is not enrolled runs local-only retention.
func TestLoadRetentionPushFloor(t *testing.T) {
	tests := []struct {
		name       string
		enrolled   bool
		orgEnabled bool
		want       RetentionPushFloor
	}{
		{"not enrolled, org on: not held", false, true, RetentionPushFloor{}},
		{"not enrolled, org off: not held", false, false, RetentionPushFloor{}},
		{"enrolled, push running: held", true, true, RetentionPushFloor{Held: true, ActionsCursor: 7, SessionsCursor: 3, GuardEventsCursor: 11}},
		{"enrolled, push paused: held and flagged", true, false, RetentionPushFloor{Held: true, Paused: true, ActionsCursor: 7, SessionsCursor: 3, GuardEventsCursor: 11}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			ctx := context.Background()
			if tc.enrolled {
				if err := s.WriteEnrolment(ctx, Enrolment{OrgID: "org-1", OrgServerURL: "https://org.example", UserID: "u-1"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.SavePushCursor(ctx, PushCursor{Actions: 7, Sessions: 3, GuardEvents: 11}); err != nil {
				t.Fatal(err)
			}
			got, err := s.LoadRetentionPushFloor(ctx, tc.orgEnabled)
			if err != nil {
				t.Fatalf("LoadRetentionPushFloor: %v", err)
			}
			if got != tc.want {
				t.Fatalf("floor = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRetentionHoldShedRoundTrip pins the doctor evidence: absent until
// recorded, then the latest record wins.
func TestRetentionHoldShedRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, ok, err := s.LoadRetentionHoldShed(ctx); err != nil || ok {
		t.Fatalf("fresh store: ok=%v err=%v, want none", ok, err)
	}
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	for i, want := range []RetentionHoldShed{
		{At: at, Actions: 2, HeldBytes: 10, CapBytes: 5, ShedThrough: "2026-01-01T00:00:00Z"},
		{At: at.Add(time.Hour), Actions: 1, GuardEvents: 3, HeldBytes: 20, CapBytes: 5},
	} {
		if err := s.RecordRetentionHoldShed(ctx, want); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		got, ok, err := s.LoadRetentionHoldShed(ctx)
		if err != nil || !ok || got != want {
			t.Fatalf("load %d = %+v ok=%v err=%v, want %+v", i, got, ok, err, want)
		}
	}
}

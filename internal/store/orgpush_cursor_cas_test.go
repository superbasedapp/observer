package store

import (
	"context"
	"testing"
)

// TestSavePushCursorIfUnchanged_CompareAndSwap pins the CAS contract the push
// loop depends on: the write lands only when the stored cursor is still the one
// the caller read, and a refusal leaves the stored value untouched.
func TestSavePushCursorIfUnchanged_CompareAndSwap(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()

	// A never-pushed agent reads zero, so a CAS against zero is accepted (the
	// very first push must not need a prior SavePushCursor).
	first := PushCursor{Sessions: 1, Actions: 2, APITurns: 1, TokenUsage: 1}
	ok, err := s.SavePushCursorIfUnchanged(ctx, PushCursor{}, first)
	if err != nil {
		t.Fatalf("SavePushCursorIfUnchanged (fresh): %v", err)
	}
	if !ok {
		t.Fatalf("CAS against the zero cursor refused; want accepted")
	}
	if got, _ := s.LoadPushCursor(ctx); got != first {
		t.Fatalf("stored cursor = %+v, want %+v", got, first)
	}

	// Equal expected → accepted, and every field round-trips.
	second := PushCursor{Sessions: 3, Actions: 9, APITurns: 4, TokenUsage: 5, GuardEvents: 2, OTelContent: 7}
	ok, err = s.SavePushCursorIfUnchanged(ctx, first, second)
	if err != nil || !ok {
		t.Fatalf("SavePushCursorIfUnchanged (equal) = %v, %v; want true, nil", ok, err)
	}
	if got, _ := s.LoadPushCursor(ctx); got != second {
		t.Fatalf("stored cursor = %+v, want %+v", got, second)
	}

	// Stale expected → refused, stored value untouched. Both directions are
	// covered because the CAS compares for equality, not ordering: a stale
	// LOWER write (the re-enrol backlog replay) and a stale HIGHER write (which
	// would undo an `observer org backfill --all --confirm` reset to zero).
	for _, tc := range []struct {
		name string
		next PushCursor
	}{
		{"stale lower (would replay history)", first},
		{"stale higher (would undo a backfill reset)", PushCursor{Sessions: 99, Actions: 99}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := s.SavePushCursorIfUnchanged(ctx, PushCursor{Sessions: 42}, tc.next)
			if err != nil {
				t.Fatalf("SavePushCursorIfUnchanged: %v", err)
			}
			if ok {
				t.Fatalf("CAS accepted a stale expected cursor")
			}
			if got, _ := s.LoadPushCursor(ctx); got != second {
				t.Fatalf("refused CAS mutated the stored cursor: %+v, want %+v", got, second)
			}
		})
	}

	// The deliberate reset path (`observer org backfill --all --confirm`) still
	// uses the unconditional save and still wins.
	if err := s.SavePushCursor(ctx, PushCursor{}); err != nil {
		t.Fatalf("SavePushCursor reset: %v", err)
	}
	if got, _ := s.LoadPushCursor(ctx); got != (PushCursor{}) {
		t.Fatalf("backfill reset did not clear the cursor: %+v", got)
	}
	// ...and a cycle that loaded the pre-reset cursor cannot undo it.
	ok, err = s.SavePushCursorIfUnchanged(ctx, second, PushCursor{Sessions: 3, Actions: 9})
	if err != nil {
		t.Fatalf("SavePushCursorIfUnchanged (post-reset): %v", err)
	}
	if ok {
		t.Fatalf("a stale cycle overwrote the backfill reset")
	}
	if got, _ := s.LoadPushCursor(ctx); got != (PushCursor{}) {
		t.Fatalf("stored cursor after refused post-reset save = %+v, want zero", got)
	}
}

package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPushOnce_DoesNotClobberACursorMovedMidCycle reproduces the re-enrolment
// backlog regression deterministically.
//
// PushOnce is a read-then-write on the push cursor: it loads the cursor at the
// top of the cycle and persists the batch's cursor after the server's 200. An
// `observer enroll` run against a node whose daemon is already pushing seeds
// the cursor at the live high-water mark IN BETWEEN — so a blind save wrote the
// cycle's much older cursor back over the seed, and every later tick drained
// the node's whole pre-enrolment history (sb-testnode, 2026-09-07: 29,614
// "eligible" rows immediately after a re-enrol).
//
// The mid-flight seed is simulated inside the test server's handler, which runs
// while PushOnce is blocked on the request. Pre-fix this test fails: PushOnce
// would store the batch cursor (single-digit ids) instead of the seed.
func TestPushOnce_DoesNotClobberACursorMovedMidCycle(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	ctx := context.Background()

	// Stands in for Enroll's `SavePushCursor(CurrentMaxIDs())` on a node with a
	// long local history: strictly above anything this batch can carry.
	seed := store.PushCursor{
		Sessions: 4242, Actions: 29614, APITurns: 1234,
		TokenUsage: 5678, GuardEvents: 90, OTelContent: 12,
	}

	var served int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		// The re-enrolment lands while this push is in flight.
		if err := s.SavePushCursor(r.Context(), seed); err != nil {
			t.Errorf("mid-flight SavePushCursor: %v", err)
		}
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: 1})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	seedActivity(t, s, 4) // 1 session + 4 actions above the zero cursor

	c := newTestClient(t, s, bs)
	res, err := c.PushOnce(ctx)
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if res.Empty || served != 1 {
		t.Fatalf("expected exactly one non-empty push, got %+v (served=%d)", res, served)
	}

	got, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if got != seed {
		t.Fatalf("push cycle clobbered the enrolment seed: cursor = %+v, want %+v", got, seed)
	}

	// And the node stays at the seed: nothing below it is eligible, so the
	// historical backlog never ships.
	res2, err := c.PushOnce(ctx)
	if err != nil {
		t.Fatalf("second PushOnce: %v", err)
	}
	if !res2.Empty {
		t.Fatalf("post-enrolment backlog re-shipped: %+v", res2)
	}
}

// TestPushOnce_AdvancesCursorWhenUncontended is the CAS's other half: with no
// concurrent mover the cycle's cursor is persisted exactly as before.
func TestPushOnce_AdvancesCursorWhenUncontended(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	ctx := context.Background()

	var sent orgcontract.PushEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		sent = decodeEnvelope(t, wire)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: 1})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	seedActivity(t, s, 3)

	c := newTestClient(t, s, bs)
	if _, err := c.PushOnce(ctx); err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	got, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	if got.Actions != 3 || got.Sessions == 0 {
		t.Fatalf("uncontended push did not advance the cursor: %+v (envelope to=%d)", got, sent.CursorTo)
	}
}

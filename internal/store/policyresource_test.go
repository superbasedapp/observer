package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

func newPolicyResourceTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database)
}

// TestBumpEnrolmentGeneration_Sequence pins plan §6.9: a fresh org_key
// starts at generation 1 (not 0 — 0 is reserved for "no row exists yet"),
// each bump is strictly monotonic, and the tombstone bit is set exactly as
// the caller requests, independent of the generation counter.
func TestBumpEnrolmentGeneration_Sequence(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey = "org-key-1"

	g1, err := s.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("first bump: %v", err)
	}
	if g1 != 1 {
		t.Fatalf("first bump generation = %d, want 1", g1)
	}
	row, ok, err := s.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGeneration: row=%+v ok=%v err=%v", row, ok, err)
	}
	if row.Generation != 1 || row.Tombstoned {
		t.Fatalf("row = %+v, want generation=1 tombstoned=false", row)
	}

	g2, err := s.BumpEnrolmentGeneration(ctx, orgKey, true) // unenrol
	if err != nil {
		t.Fatalf("second bump: %v", err)
	}
	if g2 != 2 {
		t.Fatalf("second bump generation = %d, want 2", g2)
	}
	row, ok, err = s.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || !row.Tombstoned {
		t.Fatalf("row after unenrol = %+v ok=%v err=%v, want tombstoned=true", row, ok, err)
	}

	// Re-enrol: the row SURVIVES (never deleted) and keeps advancing —
	// this is the whole point of the table (plan §6.9): it is never
	// deleted across an unenrol/re-enrol cycle.
	g3, err := s.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("third bump: %v", err)
	}
	if g3 != 3 {
		t.Fatalf("third bump generation = %d, want 3", g3)
	}
	row, ok, err = s.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok || row.Tombstoned || row.Generation != 3 {
		t.Fatalf("row after re-enrol = %+v ok=%v err=%v, want generation=3 tombstoned=false", row, ok, err)
	}
}

// TestLoadEnrolmentGeneration_AbsentRow pins the "never bumped" contract: a
// fresh org_key with no row returns ok=false, not a zero-valued row that
// could be confused with a real generation-0 fence.
func TestLoadEnrolmentGeneration_AbsentRow(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	row, ok, err := s.LoadEnrolmentGeneration(ctx, "never-enrolled")
	if err != nil {
		t.Fatalf("LoadEnrolmentGeneration: %v", err)
	}
	if ok {
		t.Fatalf("ok = true, want false for a never-created org_key (row=%+v)", row)
	}
}

// TestPolicyResourceETag_SaveLoadScopedByGeneration pins plan §6.2's ETag
// key format: the generation is baked into the KEY, not merely the value,
// so an ETag saved under generation 1 is invisible to a lookup under
// generation 2 for the SAME org_key/family — exactly the property that
// makes a stale ETag from a superseded generation harmless.
func TestPolicyResourceETag_SaveLoadScopedByGeneration(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey = "org-key-1"
	const family = "admission.input"

	if v, err := s.LoadPolicyResourceETag(ctx, orgKey, 1, family); err != nil || v != "" {
		t.Fatalf("LoadPolicyResourceETag before save = %q err=%v, want empty", v, err)
	}
	if err := s.SavePolicyResourceETag(ctx, orgKey, 1, family, `"etag-gen1"`); err != nil {
		t.Fatalf("SavePolicyResourceETag: %v", err)
	}
	got, err := s.LoadPolicyResourceETag(ctx, orgKey, 1, family)
	if err != nil || got != `"etag-gen1"` {
		t.Fatalf("LoadPolicyResourceETag(gen1) = %q err=%v, want etag-gen1", got, err)
	}
	// A DIFFERENT generation for the SAME org_key/family never sees it.
	if got, err := s.LoadPolicyResourceETag(ctx, orgKey, 2, family); err != nil || got != "" {
		t.Fatalf("LoadPolicyResourceETag(gen2) = %q err=%v, want empty (generation-scoped)", got, err)
	}
	// Overwrite is idempotent.
	if err := s.SavePolicyResourceETag(ctx, orgKey, 1, family, `"etag-gen1b"`); err != nil {
		t.Fatalf("SavePolicyResourceETag overwrite: %v", err)
	}
	if got, err := s.LoadPolicyResourceETag(ctx, orgKey, 1, family); err != nil || got != `"etag-gen1b"` {
		t.Fatalf("LoadPolicyResourceETag after overwrite = %q err=%v", got, err)
	}
}

// TestClearPolicyResourceState_ScopedToOrgKeyOnly pins the identity-change
// clear contract (plan §6.9/§6.10): clearing orgKey's state+etags leaves a
// DIFFERENT org_key's rows untouched, and never touches
// org_enrolment_generation (that table survives on purpose).
func TestClearPolicyResourceState_ScopedToOrgKeyOnly(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgA, orgB = "org-a", "org-b"
	const family = "admission.input"

	for _, ok := range []string{orgA, orgB} {
		if _, err := s.BumpEnrolmentGeneration(ctx, ok, false); err != nil {
			t.Fatalf("bump %s: %v", ok, err)
		}
		if err := s.SavePolicyResourceETag(ctx, ok, 1, family, `"etag"`); err != nil {
			t.Fatalf("save etag %s: %v", ok, err)
		}
		err := s.WithPolicyResourceFence(ctx, ok, family, func(_ context.Context, fence PolicyResourceFence) (*PolicyResourceCommit, error) {
			return &PolicyResourceCommit{Generation: fence.Generation, FloorVersion: 1, LastVersion: 1, BodyHash: "h", MsgDigest: "d"}, nil
		})
		if err != nil {
			t.Fatalf("seed state %s: %v", ok, err)
		}
	}

	if err := s.ClearPolicyResourceState(ctx, orgA); err != nil {
		t.Fatalf("ClearPolicyResourceState: %v", err)
	}

	if _, ok, err := s.LoadPolicyResourceState(ctx, orgA, family); err != nil || ok {
		t.Fatalf("orgA state = ok=%v err=%v, want cleared", ok, err)
	}
	if v, err := s.LoadPolicyResourceETag(ctx, orgA, 1, family); err != nil || v != "" {
		t.Fatalf("orgA etag = %q err=%v, want cleared", v, err)
	}
	// orgB is untouched.
	if _, ok, err := s.LoadPolicyResourceState(ctx, orgB, family); err != nil || !ok {
		t.Fatalf("orgB state = ok=%v err=%v, want still present", ok, err)
	}
	if v, err := s.LoadPolicyResourceETag(ctx, orgB, 1, family); err != nil || v != `"etag"` {
		t.Fatalf("orgB etag = %q err=%v, want still present", v, err)
	}
	// The generation row survives for BOTH — this function never touches it.
	if _, ok, err := s.LoadEnrolmentGeneration(ctx, orgA); err != nil || !ok {
		t.Fatalf("orgA generation row = ok=%v err=%v, want to survive ClearPolicyResourceState", ok, err)
	}
}

// TestWithPolicyResourceFence_FirstInstallThenUpdate pins the two shapes of
// the CAS-fenced write (plan §6.10): an absent row is inserted only under
// the NOT EXISTS predicate, and an existing row is updated only under the
// (org_key, family, generation, floor_version, msg_digest) predicate.
func TestWithPolicyResourceFence_FirstInstallThenUpdate(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey = "org-key-1"
	const family = "admission.input"
	gen, err := s.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("bump: %v", err)
	}

	var sawHasState bool
	err = s.WithPolicyResourceFence(ctx, orgKey, family, func(_ context.Context, fence PolicyResourceFence) (*PolicyResourceCommit, error) {
		sawHasState = fence.HasState
		if fence.Generation != gen {
			t.Fatalf("fence.Generation = %d, want %d", fence.Generation, gen)
		}
		return &PolicyResourceCommit{Generation: gen, FloorVersion: 1, LastVersion: 1, BodyHash: "h1", MsgDigest: "d1"}, nil
	})
	if err != nil {
		t.Fatalf("first fence: %v", err)
	}
	if sawHasState {
		t.Fatal("first call should see HasState=false (no prior row)")
	}
	st, ok, err := s.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil || !ok || st.FloorVersion != 1 || st.MsgDigest != "d1" {
		t.Fatalf("state after first install = %+v ok=%v err=%v", st, ok, err)
	}

	err = s.WithPolicyResourceFence(ctx, orgKey, family, func(_ context.Context, fence PolicyResourceFence) (*PolicyResourceCommit, error) {
		if !fence.HasState || fence.FloorVersion != 1 || fence.MsgDigest != "d1" {
			t.Fatalf("fence on second call = %+v, want HasState with floor=1 digest=d1", fence)
		}
		return &PolicyResourceCommit{Generation: gen, FloorVersion: 2, LastVersion: 2, BodyHash: "h2", MsgDigest: "d2"}, nil
	})
	if err != nil {
		t.Fatalf("second fence: %v", err)
	}
	st, ok, err = s.LoadPolicyResourceState(ctx, orgKey, family)
	if err != nil || !ok || st.FloorVersion != 2 || st.MsgDigest != "d2" {
		t.Fatalf("state after update = %+v ok=%v err=%v", st, ok, err)
	}
}

// TestWithPolicyResourceFence_AbortLeavesNoTrace pins that returning
// (nil, nil) from fn — a legitimate reject, e.g. version_replay — writes
// NOTHING: no state row, no error.
func TestWithPolicyResourceFence_AbortLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey, family = "org-key-1", "admission.input"
	if _, err := s.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("bump: %v", err)
	}
	err := s.WithPolicyResourceFence(ctx, orgKey, family, func(context.Context, PolicyResourceFence) (*PolicyResourceCommit, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatalf("WithPolicyResourceFence: %v", err)
	}
	if _, ok, err := s.LoadPolicyResourceState(ctx, orgKey, family); err != nil || ok {
		t.Fatalf("state after abort = ok=%v err=%v, want no row", ok, err)
	}
}

// TestWithPolicyResourceFence_FnErrorRollsBack pins that an fn error is
// propagated and leaves no row.
func TestWithPolicyResourceFence_FnErrorRollsBack(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey, family = "org-key-1", "admission.input"
	if _, err := s.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("bump: %v", err)
	}
	wantErr := errors.New("boom")
	err := s.WithPolicyResourceFence(ctx, orgKey, family, func(context.Context, PolicyResourceFence) (*PolicyResourceCommit, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wraps %v", err, wantErr)
	}
	if _, ok, err := s.LoadPolicyResourceState(ctx, orgKey, family); err != nil || ok {
		t.Fatalf("state after fn error = ok=%v err=%v, want no row", ok, err)
	}
}

// TestCasUpsertPolicyResourceState_StalePredicateRejected is a white-box
// mutation proof for the defense-in-depth CAS predicate (plan §6.10 /
// R6-B1): calling the UPDATE path with a fence whose floor/digest disagrees
// with the row actually on disk must affect zero rows and return
// ErrPolicyResourceFenceStale — never silently overwrite. This can't be
// triggered through the public WithPolicyResourceFence (which always reads
// its own fence inside the same exclusive transaction), so it exercises the
// unexported helper directly to prove the predicate itself is load-bearing,
// not merely decorative.
func TestCasUpsertPolicyResourceState_StalePredicateRejected(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const orgKey, family = "org-key-1", "admission.input"
	gen, err := s.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("bump: %v", err)
	}
	// Seed a real row via the public path.
	if err := s.WithPolicyResourceFence(ctx, orgKey, family, func(_ context.Context, fence PolicyResourceFence) (*PolicyResourceCommit, error) {
		return &PolicyResourceCommit{Generation: gen, FloorVersion: 1, LastVersion: 1, BodyHash: "h1", MsgDigest: "d1"}, nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer func() { _ = conn.Close() }()

	staleFence := PolicyResourceFence{Generation: gen, HasState: true, FloorVersion: 999, MsgDigest: "not-the-real-digest"}
	err = casUpsertPolicyResourceState(ctx, conn, orgKey, family, staleFence, PolicyResourceCommit{
		Generation: gen, FloorVersion: 2, LastVersion: 2, BodyHash: "h2", MsgDigest: "d2",
	})
	if !errors.Is(err, ErrPolicyResourceFenceStale) {
		t.Fatalf("err = %v, want ErrPolicyResourceFenceStale", err)
	}
	// The real row must be untouched.
	st, ok, lerr := s.LoadPolicyResourceState(ctx, orgKey, family)
	if lerr != nil || !ok || st.FloorVersion != 1 || st.MsgDigest != "d1" {
		t.Fatalf("state after stale attempt = %+v ok=%v err=%v, want unchanged at floor=1/d1", st, ok, lerr)
	}
}

// --- TOFU signing-key pin establishment (review finding B-B6) ---

// countOrgKeyPinRows returns how many guard_policy_state rows exist for the
// org key-pin path. Establish-once means this is 0 before and exactly 1
// after any number of establishment attempts, however they interleave.
func countOrgKeyPinRows(t *testing.T, s *Store, pinPath string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM guard_policy_state WHERE layer = 'org' AND path = ?`, pinPath).Scan(&n); err != nil {
		t.Fatalf("count pin rows: %v", err)
	}
	return n
}

// TestEstablishOrgPolicyKeyPin_Table pins the three sequential outcomes of
// the compare-if-absent primitive: absent establishes, a same-key repeat is
// a no-op that reports the pin, and a different-key attempt NEVER overwrites
// — it reports the established pin so the caller refuses.
func TestEstablishOrgPolicyKeyPin_Table(t *testing.T) {
	ctx := context.Background()
	const pinPath = "https://org.example#policy-key"
	const keyA = "aaaa1111"
	const keyB = "bbbb2222"

	cases := []struct {
		name            string
		prePin          string // "" = no pre-existing pin
		attempt         string
		wantPinned      string
		wantEstablished bool
	}{
		{name: "pin absent — first writer establishes", prePin: "", attempt: keyA, wantPinned: keyA, wantEstablished: true},
		{name: "pin present, same key — no-op, reports pin", prePin: keyA, attempt: keyA, wantPinned: keyA, wantEstablished: false},
		{name: "pin present, different key — refuses to overwrite", prePin: keyA, attempt: keyB, wantPinned: keyA, wantEstablished: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPolicyResourceTestStore(t)
			if tc.prePin != "" {
				pinned, established, err := s.EstablishOrgPolicyKeyPin(ctx, pinPath, tc.prePin, "rail")
				if err != nil || !established || pinned != tc.prePin {
					t.Fatalf("pre-pin: pinned=%q established=%v err=%v", pinned, established, err)
				}
			}
			pinned, established, err := s.EstablishOrgPolicyKeyPin(ctx, pinPath, tc.attempt, "rail")
			if err != nil {
				t.Fatalf("EstablishOrgPolicyKeyPin: %v", err)
			}
			if pinned != tc.wantPinned || established != tc.wantEstablished {
				t.Fatalf("pinned=%q established=%v, want %q/%v", pinned, established, tc.wantPinned, tc.wantEstablished)
			}
			if n := countOrgKeyPinRows(t, s, pinPath); n != 1 {
				t.Fatalf("pin rows = %d, want exactly 1 (establish-once)", n)
			}
			// The unfenced reader must agree with the primitive's verdict.
			got, ok, lerr := s.LoadOrgPolicyKeyPin(ctx, pinPath)
			if lerr != nil || !ok || got != tc.wantPinned {
				t.Fatalf("LoadOrgPolicyKeyPin = %q ok=%v err=%v, want %q", got, ok, lerr, tc.wantPinned)
			}
		})
	}
}

// TestEstablishOrgPolicyKeyPin_NoPinYet pins the empty-store read: no pin
// row means ok=false, not an error and not a bogus empty "pin" that a
// caller could mistake for a match.
func TestEstablishOrgPolicyKeyPin_NoPinYet(t *testing.T) {
	s := newPolicyResourceTestStore(t)
	got, ok, err := s.LoadOrgPolicyKeyPin(context.Background(), "https://org.example#policy-key")
	if err != nil || ok || got != "" {
		t.Fatalf("LoadOrgPolicyKeyPin on empty store = %q ok=%v err=%v, want \"\"/false/nil", got, ok, err)
	}
}

// TestEstablishOrgPolicyKeyPin_RejectsEmptyArgs pins the input guard: an
// empty path or hash is a caller bug, never a silently-written blank pin.
func TestEstablishOrgPolicyKeyPin_RejectsEmptyArgs(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	if _, _, err := s.EstablishOrgPolicyKeyPin(ctx, "", "hash", "rail"); err == nil {
		t.Fatal("empty pinPath: err = nil, want error")
	}
	if _, _, err := s.EstablishOrgPolicyKeyPin(ctx, "p", "", "rail"); err == nil {
		t.Fatal("empty keyHash: err = nil, want error")
	}
}

// TestEstablishOrgPolicyKeyPin_ConcurrentSingleWinner is the B-B6
// regression proof: N goroutines race to establish the FIRST pin, half
// offering key A and half key B, against one store. Compare-if-absent
// requires that exactly one row is written, exactly one caller reports
// established=true, and EVERY caller — winner and losers alike — is handed
// the SAME authoritative hash, so a loser offering the other key can only
// conclude "mismatch, refuse". Run with -race.
//
// The race is made DETERMINISTIC (not scheduling-luck) by holding the
// window between the pin re-read and the insert open through
// testHookKeyPinBeforeInsert: under the fix only the single caller inside
// the BEGIN IMMEDIATE transaction can be in that window, so the barrier
// times out once and the rest observe the committed pin; a non-atomic
// read-then-append would let all N arrive together, trip the barrier, and
// append N conflicting pins — which the row-count assertion below fails on.
func TestEstablishOrgPolicyKeyPin_ConcurrentSingleWinner(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	const pinPath = "https://org.example#policy-key"
	const keyA = "aaaa1111"
	const keyB = "bbbb2222"
	const n = 16

	var barrierMu sync.Mutex
	arrived := 0
	release := make(chan struct{})
	testHookKeyPinBeforeInsert = func() {
		barrierMu.Lock()
		arrived++
		if arrived == n {
			close(release)
		}
		barrierMu.Unlock()
		select {
		case <-release:
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Cleanup(func() { testHookKeyPinBeforeInsert = nil })

	type outcome struct {
		offered     string
		pinned      string
		established bool
		err         error
	}
	out := make([]outcome, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		offered := keyA
		if i%2 == 1 {
			offered = keyB
		}
		wg.Add(1)
		go func(i int, offered string) {
			defer wg.Done()
			<-start
			pinned, established, err := s.EstablishOrgPolicyKeyPin(ctx, pinPath, offered, "rail")
			out[i] = outcome{offered: offered, pinned: pinned, established: established, err: err}
		}(i, offered)
	}
	close(start)
	wg.Wait()

	if rows := countOrgKeyPinRows(t, s, pinPath); rows != 1 {
		t.Fatalf("pin rows = %d, want exactly 1", rows)
	}
	winner, ok, err := s.LoadOrgPolicyKeyPin(ctx, pinPath)
	if err != nil || !ok {
		t.Fatalf("LoadOrgPolicyKeyPin: %q ok=%v err=%v", winner, ok, err)
	}
	if winner != keyA && winner != keyB {
		t.Fatalf("winner = %q, want one of the two offered keys", winner)
	}
	established := 0
	for i, o := range out {
		if o.err != nil {
			t.Fatalf("goroutine %d: EstablishOrgPolicyKeyPin: %v", i, o.err)
		}
		if o.pinned != winner {
			t.Fatalf("goroutine %d (offered %q): pinned = %q, want the single authoritative %q",
				i, o.offered, o.pinned, winner)
		}
		if o.established {
			established++
			if o.offered != winner {
				t.Fatalf("goroutine %d established the pin as %q but the durable pin is %q", i, o.offered, winner)
			}
		}
	}
	if established != 1 {
		t.Fatalf("established=true count = %d, want exactly 1", established)
	}
}

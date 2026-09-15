package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// community_admit_test.go covers AdmitCommunityContribution — the ONE atomic
// admission transaction (Sol re-review N3/N4/N7 + the N8 non-vacuous tests). The
// invariant under test throughout: a REJECTED admission leaves the standing
// grant's row/generation exactly as it was (or absent), because the grant
// registration and the contribution upsert share one transaction that rolls both
// back on any refusal. Ground-truthed by running each case against live PG.

const (
	admitDeviceA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	admitDeviceB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// admitInput builds a valid community admission for (device, gen, window, value)
// carrying the service's own current data dictionary and the UTC-fixed timezone.
func admitInput(deviceID string, gen int64, window string, value float64, now time.Time) store.AdmitCommunityContributionInput {
	return store.AdmitCommunityContributionInput{
		Purpose:              string(cloudcontract.PurposeCohortBenchmarking),
		DeviceID:             deviceID,
		DataDictionaryDigest: cloudcontract.CommunityDataDictionaryDigest(),
		SchemaVersion:        cloudcontract.CommunityContributionSchemaVersion,
		ConsentGeneration:    gen,
		DeclaredTimezone:     "UTC",
		CohortKey:            testCohort,
		MetricID:             metricSPD,
		MetricVersion:        metricVerOne,
		WindowID:             window,
		Value:                value,
		Now:                  now,
	}
}

// grantGenForDevice returns the consent generation of the (account, device,
// purpose) community grant, or (0, false) if none is registered for that device.
func grantGenForDevice(t *testing.T, s *store.Store, acct, deviceID string) (int64, bool) {
	t.Helper()
	grants, err := s.ListCommunityGrants(context.Background(), acct)
	if err != nil {
		t.Fatalf("ListCommunityGrants: %v", err)
	}
	for _, g := range grants {
		if g.DeviceID == deviceID {
			return g.ConsentGeneration, true
		}
	}
	return 0, false
}

// TestAdmitCommunityContributionHappyPath proves the single-transaction happy
// path registers the grant and stores the value together.
func TestAdmitCommunityContributionHappyPath(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	res, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 1, win, 3.5, time.Now()))
	if err != nil {
		t.Fatalf("AdmitCommunityContribution: %v", err)
	}
	if res.GrantAction != store.GrantRegistrationCreated {
		t.Fatalf("GrantAction=%q, want created", res.GrantAction)
	}
	if res.CurrentWindow != win {
		t.Fatalf("CurrentWindow=%q, want %q", res.CurrentWindow, win)
	}
	got, err := s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 3.5 {
		t.Fatalf("stored value=%v err=%v, want 3.5", got, err)
	}
	if gen, ok := grantGenForDevice(t, s, acct, admitDeviceA); !ok || gen != 1 {
		t.Fatalf("grant gen=%d ok=%v, want 1/true", gen, ok)
	}
}

// TestAdmitCommunityContributionDBClockAuthoritative proves Sol N4: the current-
// window decision uses the DB clock, NEVER the Go-side in.Now. Here in.Now and
// in.WindowID both name a FUTURE month — a Go-clock implementation seeded with
// in.Now would happily accept — but the DB clock (this month) rejects it, and no
// grant is created.
func TestAdmitCommunityContributionDBClockAuthoritative(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)

	futureTime := time.Now().UTC().AddDate(0, 2, 0)
	futureWindow := futureTime.Format("2006-01")

	res, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 1, futureWindow, 3.5, futureTime))
	if !errors.Is(err, store.ErrWindowNotCurrent) {
		t.Fatalf("admit(future window, Go-clock=future) err=%v, want ErrWindowNotCurrent", err)
	}
	// The DB-authoritative current window is reported, not the Go-side future.
	if want := community.CurrentWindow(time.Now()); res.CurrentWindow != want {
		t.Fatalf("CurrentWindow=%q, want DB current %q (not the Go-side future)", res.CurrentWindow, want)
	}
	// The doomed request registered/advanced NO grant.
	if gen, ok := grantGenForDevice(t, s, acct, admitDeviceA); ok {
		t.Fatalf("future-window admit left a grant at gen %d — must be atomic-rolled-back", gen)
	}
}

// TestAdmitCommunityContributionRejectionsDoNotAdvanceGrant is the Sol N3
// table-driven core: for every refusal kind, the standing grant's row/generation
// is UNCHANGED after the rejected admission, and a losing second device gets no
// grant at all.
func TestAdmitCommunityContributionRejectionsDoNotAdvanceGrant(t *testing.T) {
	win := inProgressWindow()
	future := time.Now().UTC().AddDate(0, 2, 0).Format("2006-01")
	badDict := cloudcontract.CommunityDataDictionaryDigest() + "-tampered"

	cases := []struct {
		name    string
		refuse  func(s *store.Store, acct string) (store.AdmitCommunityContributionResult, error)
		wantErr error
		// extra asserts the losing second device left no grant behind.
		checkDeviceB bool
	}{
		{
			name: "cross-device conflict (device B, current window, higher gen)",
			refuse: func(s *store.Store, acct string) (store.AdmitCommunityContributionResult, error) {
				return s.AdmitCommunityContribution(context.Background(), acct, admitInput(admitDeviceB, 99, win, 999.0, time.Now()))
			},
			wantErr:      store.ErrCrossDeviceConflict,
			checkDeviceB: true,
		},
		{
			name: "window not current (device B, future window, higher gen)",
			refuse: func(s *store.Store, acct string) (store.AdmitCommunityContributionResult, error) {
				return s.AdmitCommunityContribution(context.Background(), acct, admitInput(admitDeviceB, 99, future, 3.0, time.Now()))
			},
			wantErr:      store.ErrWindowNotCurrent,
			checkDeviceB: true,
		},
		{
			name: "stale generation (device A, older gen)",
			refuse: func(s *store.Store, acct string) (store.AdmitCommunityContributionResult, error) {
				return s.AdmitCommunityContribution(context.Background(), acct, admitInput(admitDeviceA, 3, win, 8.0, time.Now()))
			},
			wantErr: store.ErrCommunityGenerationStale,
		},
		{
			name: "dictionary mismatch (device A, same gen, other dictionary)",
			refuse: func(s *store.Store, acct string) (store.AdmitCommunityContributionResult, error) {
				in := admitInput(admitDeviceA, 5, win, 8.0, time.Now())
				in.DataDictionaryDigest = badDict
				return s.AdmitCommunityContribution(context.Background(), acct, in)
			},
			wantErr: store.ErrCommunityDictionaryMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newStore(t)
			ctx := context.Background()
			acct := makeAccount(t, s)

			// Baseline: device A owns the window at generation 5, value 4.
			if _, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 5, win, 4.0, time.Now())); err != nil {
				t.Fatalf("baseline admit: %v", err)
			}

			if _, err := tc.refuse(s, acct); !errors.Is(err, tc.wantErr) {
				t.Fatalf("refusal err=%v, want %v", err, tc.wantErr)
			}

			// Device A's grant is UNCHANGED at generation 5.
			if gen, ok := grantGenForDevice(t, s, acct, admitDeviceA); !ok || gen != 5 {
				t.Fatalf("device A grant gen=%d ok=%v after refusal — want 5/true (must be unchanged)", gen, ok)
			}
			// Device A's stored value is UNCHANGED at 4.
			got, err := s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
			if err != nil || got != 4.0 {
				t.Fatalf("stored value=%v err=%v after refusal — want 4.0 (unchanged)", got, err)
			}
			// A losing second device left NO grant behind (Sol N3 scenario 1).
			if tc.checkDeviceB {
				if gen, ok := grantGenForDevice(t, s, acct, admitDeviceB); ok {
					t.Fatalf("refused device B registered a grant at gen %d — must be atomic-rolled-back", gen)
				}
			}
		})
	}
}

// TestAdmitCommunityContributionCrossDeviceHint proves the Sol F9 recovery hint:
// on a cross-device conflict the result carries the owning device id and the next
// writable window.
func TestAdmitCommunityContributionCrossDeviceHint(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	if _, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 1, win, 4.0, time.Now())); err != nil {
		t.Fatalf("device A admit: %v", err)
	}
	res, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceB, 1, win, 9.0, time.Now()))
	if !errors.Is(err, store.ErrCrossDeviceConflict) {
		t.Fatalf("device B admit err=%v, want ErrCrossDeviceConflict", err)
	}
	if res.OwnerDeviceID != admitDeviceA {
		t.Fatalf("OwnerDeviceID=%q, want %q", res.OwnerDeviceID, admitDeviceA)
	}
	wantNext := time.Now().UTC().AddDate(0, 1, 0).Format("2006-01")
	if res.NextWindow != wantNext {
		t.Fatalf("NextWindow=%q, want %q", res.NextWindow, wantNext)
	}
}

// TestAdmitCommunityContributionAccountFenceBarrier is the NON-VACUOUS Sol F5/N8a
// fence test. A holder transaction locks the account row (an UPDATE that has not
// yet committed); the admission must BLOCK on its FOR SHARE fence — proven by
// asserting it has not returned while the lock is held. Only after the holder
// commits the account to 'closed' does the admission unblock and observe the
// refusal (ErrAccountClosed), with nothing written.
//
// If FOR SHARE were replaced by an unlocked status read, the admission would NOT
// block (an uncommitted UPDATE is invisible under READ COMMITTED), would read the
// still-'active' row, and would return — success — before the holder commits: the
// first select below would then fail, so this test is not mutation-vacuous.
func TestAdmitCommunityContributionAccountFenceBarrier(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	// Holder: lock the account row via an uncommitted UPDATE (pool login is a
	// superuser, so RLS is bypassed — this stands in for the deletion fence's
	// own UPDATE of the same row).
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	defer func() { _ = holder.Rollback(ctx) }()
	if _, err := holder.Exec(ctx,
		`UPDATE accounts SET status = 'closed', updated_at = now() WHERE account_id = $1::uuid`, acct); err != nil {
		t.Fatalf("holder lock account: %v", err)
	}

	resCh := make(chan error, 1)
	go func() {
		_, e := s.AdmitCommunityContribution(context.Background(), acct, admitInput(admitDeviceA, 1, win, 5.0, time.Now()))
		resCh <- e
	}()

	// The admission MUST be blocked on the FOR SHARE fence while the holder keeps
	// the row locked.
	select {
	case e := <-resCh:
		t.Fatalf("admit returned %v while the account row was lock-held — FOR SHARE fence not taken (vacuous)", e)
	case <-time.After(400 * time.Millisecond):
		// Still blocked: the fence is real.
	}

	// Commit the holder: the account is now 'closed'.
	if err := holder.Commit(ctx); err != nil {
		t.Fatalf("holder commit: %v", err)
	}

	select {
	case e := <-resCh:
		if !errors.Is(e, store.ErrAccountClosed) {
			t.Fatalf("admit after account closed err=%v, want ErrAccountClosed", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("admit did not return after the account lock was released")
	}

	// Nothing was stored and no grant was created (the whole tx rolled back).
	if n := countRows(t, pool, "leaderboard_contributions", acct); n != 0 {
		t.Fatalf("closed-account admit stored %d contribution(s) — want 0", n)
	}
	if _, ok := grantGenForDevice(t, s, acct, admitDeviceA); ok {
		t.Fatalf("closed-account admit registered a grant — want none")
	}
}

// TestAdmitCommunityContributionDeletionBarrier is the Sol N3/N8 barrier test: a
// deletion committing between authenticate and admit leaves NO new grant row.
// Two goroutines sequenced by channels — the deletion commits first, then the
// admission runs and must refuse with nothing left behind.
func TestAdmitCommunityContributionDeletionBarrier(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	deleted := make(chan struct{})
	go func() {
		if _, err := s.CreateDeletionRequest(context.Background(), acct, time.Now()); err != nil {
			t.Errorf("CreateDeletionRequest: %v", err)
		}
		close(deleted)
	}()
	<-deleted // the deletion has committed

	_, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 1, win, 5.0, time.Now()))
	if !errors.Is(err, store.ErrAccountClosed) {
		t.Fatalf("admit after committed deletion err=%v, want ErrAccountClosed", err)
	}
	if n := countRows(t, pool, "leaderboard_contributions", acct); n != 0 {
		t.Fatalf("post-deletion admit stored %d contribution(s) — want 0", n)
	}
	if _, ok := grantGenForDevice(t, s, acct, admitDeviceA); ok {
		t.Fatalf("post-deletion admit registered a grant — want none")
	}
}

// TestAdmitCommunityContributionClaimsLegacyRow proves the Sol N6 product fix: a
// contribution row backfilled to the unowned device_id=” bucket (migration 0029)
// is CLAIMABLE by the first authenticated device that writes it — the ON CONFLICT
// guard treats ” as unowned and stamps the claiming device. After the claim, a
// DIFFERENT device is refused, confirming ownership transferred.
func TestAdmitCommunityContributionClaimsLegacyRow(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	acct := makeAccount(t, s)
	win := inProgressWindow()

	// Seed a legacy unowned ('') row for the CURRENT window (as a superuser, RLS
	// bypassed; the current window passes the freeze trigger).
	if _, err := pool.Exec(ctx,
		`INSERT INTO leaderboard_contributions (account_id, cohort_key, metric_id, metric_version, window_id, device_id, value)
		 VALUES ($1::uuid, $2, $3, $4, $5, '', $6)`,
		acct, testCohort, metricSPD, metricVerOne, win, 2.0); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}

	// The first real device claims it.
	if _, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceA, 1, win, 6.0, time.Now())); err != nil {
		t.Fatalf("claim admit: %v", err)
	}
	got, err := s.AccountContribution(ctx, acct, testCohort, metricSPD, metricVerOne, win)
	if err != nil || got != 6.0 {
		t.Fatalf("value after claim=%v err=%v, want 6.0", got, err)
	}
	var owner string
	if err := pool.QueryRow(ctx,
		`SELECT device_id FROM leaderboard_contributions
		  WHERE account_id=$1::uuid AND cohort_key=$2 AND metric_id=$3 AND metric_version=$4 AND window_id=$5`,
		acct, testCohort, metricSPD, metricVerOne, win).Scan(&owner); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if owner != admitDeviceA {
		t.Fatalf("claimed row owner=%q, want %q", owner, admitDeviceA)
	}

	// A different device is now refused — the claim transferred ownership.
	if _, err := s.AdmitCommunityContribution(ctx, acct, admitInput(admitDeviceB, 1, win, 9.0, time.Now())); !errors.Is(err, store.ErrCrossDeviceConflict) {
		t.Fatalf("post-claim device B admit err=%v, want ErrCrossDeviceConflict", err)
	}
}

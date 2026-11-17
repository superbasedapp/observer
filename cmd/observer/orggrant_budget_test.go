package main

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestHookOrgGrantBudget pins hookOrgGrantBudgetRules, one case per row and
// edge: the grant question has its own budget (at most 4 s), never the
// 500 ms approval budget, and always ends before the hook's watchdog (which
// itself ends before the host's hook timeout).
func TestHookOrgGrantBudget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 14, 19, 34, 0, time.UTC)
	cases := []struct {
		name string
		plan hookFailurePlan
		want time.Duration
	}{
		{name: "row 1: a far watchdog is capped at the default", plan: hookFailurePlan{Deadline: now.Add(28 * time.Second), HostTimeout: 60 * time.Second}, want: defaultHookOrgGrantBudget},
		{name: "row 1: the quick scan spent most of it", plan: hookFailurePlan{Deadline: now.Add(2500 * time.Millisecond)}, want: 1500 * time.Millisecond},
		{name: "row 1: under the reply margin, half of what is left", plan: hookFailurePlan{Deadline: now.Add(800 * time.Millisecond)}, want: 400 * time.Millisecond},
		{name: "row 1: the watchdog is due, the floor", plan: hookFailurePlan{Deadline: now.Add(-time.Second)}, want: hookOrgGrantMinBudget},
		{name: "row 1 wins over the host timeout", plan: hookFailurePlan{Deadline: now.Add(3 * time.Second), HostTimeout: 60 * time.Second}, want: 2 * time.Second},
		{name: "row 2: no watchdog, a long host timeout", plan: hookFailurePlan{HostTimeout: 60 * time.Second}, want: defaultHookOrgGrantBudget},
		{name: "row 2: no watchdog, a 5 s host", plan: hookFailurePlan{HostTimeout: 5 * time.Second}, want: 2 * time.Second},
		{name: "row 2: no watchdog, a 3 s host", plan: hookFailurePlan{HostTimeout: 3 * time.Second}, want: time.Second},
		{name: "row 3: nothing known", plan: hookFailurePlan{}, want: defaultHookOrgGrantBudget},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hookOrgGrantBudget(tc.plan, now)
			if got != tc.want {
				t.Errorf("budget = %v, want %v", got, tc.want)
			}
			if !tc.plan.Deadline.IsZero() && tc.plan.Deadline.After(now) && now.Add(got).After(tc.plan.Deadline) {
				t.Errorf("budget %v outlasts the watchdog deadline", got)
			}
		})
	}
}

// grantNode is a migrated node database holding one verified perpetual
// exempt grant for S-793 (G-11) in force for the next hour.
func grantNode(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	seedVerifiedGrant(t, store.New(database), orgcontract.AccessGrantWire{
		ID: 11, Type: accessgrant.TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
		SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: "S-793",
		StartsAtNs: time.Now().Add(-time.Minute).UnixNano(), ExpiresAtNs: time.Now().Add(time.Hour).UnixNano(),
	})
	return dbPath
}

// slowOpener delays every open by delay (a cold open on a loaded machine),
// giving up when ctx ends, and counts the opens.
func slowOpener(open orgGrantStoreOpener, delay time.Duration, calls *atomic.Int32) orgGrantStoreOpener {
	return func(ctx context.Context) (*store.Store, func(), error) {
		calls.Add(1)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		return open(ctx)
	}
}

// TestHookOrgGrantSlowOpenStillGrants is the 2026-11-13 14:19 UTC report:
// on a loaded machine the open took longer than the 500 ms the question used
// to get, and an in-force grant was missed ("could not be consulted (open:
// context deadline exceeded)"). Under the question's own budget a slow open
// still yields the grant, the peek and the claim share that one open, and
// the old budget still fails the same open, closed and with the note.
func TestHookOrgGrantSlowOpenStillGrants(t *testing.T) {
	pinToolHomes(t)
	dbPath := grantNode(t)
	q := guard.OrgGrantQuery{RuleID: "S-793", Lane: guard.OrgGrantLaneTool, Decision: "ask"}
	cases := []struct {
		name      string
		budget    time.Duration
		wantOK    bool
		wantOpens int32 // granted: exactly; missed: at least
	}{
		{name: "the question's own budget: granted, one open", budget: defaultHookOrgGrantBudget, wantOK: true, wantOpens: 1},
		{name: "the old 500 ms budget: missed, said, retried", budget: defaultHookApprovalBudget, wantOK: false, wantOpens: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opens atomic.Int32
			claim, done := newOrgGrantSession(slowOpener(hookOrgGrantOpener(dbPath), 1200*time.Millisecond, &opens), constOrgGrantBudget(tc.budget))()
			defer done()
			peek := claim(q)
			q := q
			q.Consume = true
			got := claim(q)
			if peek.OK != tc.wantOK || got.OK != tc.wantOK {
				t.Fatalf("peek %+v claim %+v, want ok=%v", peek, got, tc.wantOK)
			}
			if tc.wantOK && got.GrantID != 11 {
				t.Errorf("claim = %+v, want G-11", got)
			}
			if !tc.wantOK && got.Failed == "" {
				t.Errorf("a missed grant must say why: %+v", got)
			}
			// Granted: one open for both questions. Missed: the open that
			// timed out was retried (at least wantOpens attempts).
			if n := opens.Load(); (tc.wantOK && n != tc.wantOpens) || (!tc.wantOK && n < tc.wantOpens) {
				t.Errorf("opens = %d, want %d", n, tc.wantOpens)
			}
		})
	}
}

// TestOpenOrgGrantStoreRetry pins the one bounded retry: a timeout or a lock
// wait is tried once more while time is left; any other answer is final.
func TestOpenOrgGrantStoreRetry(t *testing.T) {
	t.Parallel()
	locked := errors.New("database is locked (5) (SQLITE_BUSY)")
	cases := []struct {
		name      string
		first     error
		budget    time.Duration
		wantErr   bool
		wantCalls int32
	}{
		{name: "first open succeeds", first: nil, budget: time.Second, wantCalls: 1},
		{name: "lock wait, then success", first: locked, budget: time.Second, wantCalls: 2},
		{name: "timeout, then success", first: context.DeadlineExceeded, budget: time.Second, wantCalls: 2},
		{name: "no database: final", first: fs.ErrNotExist, budget: time.Second, wantErr: true, wantCalls: 1},
		{name: "unreadable file: final", first: errors.New("file is not a database (26)"), budget: time.Second, wantErr: true, wantCalls: 1},
		{name: "lock wait with no time left: final", first: locked, budget: 120 * time.Millisecond, wantErr: true, wantCalls: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			open := func(ctx context.Context) (*store.Store, func(), error) {
				if calls.Add(1) == 1 && tc.first != nil {
					if tc.budget < time.Second {
						<-ctx.Done() // the first attempt spends its whole share
					}
					return nil, nil, tc.first
				}
				return &store.Store{}, func() {}, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
			defer cancel()
			_, _, err := openOrgGrantStore(ctx, open)
			if (err != nil) != tc.wantErr || calls.Load() != tc.wantCalls {
				t.Errorf("err %v after %d opens, want err=%v after %d", err, calls.Load(), tc.wantErr, tc.wantCalls)
			}
		})
	}
}

// TestOrgGrantSessionSharesOneOpen: the peek and the claim of one verdict
// open the database once, and done releases it.
func TestOrgGrantSessionSharesOneOpen(t *testing.T) {
	pinToolHomes(t)
	dbPath := grantNode(t)
	var opens, releases atomic.Int32
	open := func(ctx context.Context) (*store.Store, func(), error) {
		opens.Add(1)
		st, release, err := hookOrgGrantOpener(dbPath)(ctx)
		if err != nil {
			return nil, nil, err
		}
		return st, func() { releases.Add(1); release() }, nil
	}
	claim, done := newOrgGrantSession(open, constOrgGrantBudget(defaultHookOrgGrantBudget))()
	q := guard.OrgGrantQuery{RuleID: "S-793", Lane: guard.OrgGrantLaneTool, Decision: "ask"}
	peek := claim(q)
	q.Consume = true
	got := claim(q)
	done()
	if !peek.OK || !got.OK || got.GrantID != 11 {
		t.Fatalf("peek %+v claim %+v", peek, got)
	}
	if opens.Load() != 1 || releases.Load() != 1 {
		t.Errorf("opens %d releases %d, want 1 and 1", opens.Load(), releases.Load())
	}
}

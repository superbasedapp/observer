package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// deletion_billing_test.go is ORGDEL-7: an account deletion cancels, through
// the orgdeletion.Billing seam and BEFORE it deletes anything, every live
// Paddle subscription its purge would delete (the account's own plan, its
// personal org's, an org's already on its way out); a live team org's
// subscription still refuses the deletion (PORTALORG-9); and a cancellation
// that fails refuses the deletion with nothing deleted. No Paddle call is
// made: fakeBilling stands in for cmd/observer-cloud's deletionBilling.

// fakeBilling is an orgdeletion.Billing that records every call and fails
// with fail (when set) or runs during (when set) before it answers.
type fakeBilling struct {
	mu     sync.Mutex
	calls  []orgdeletion.CancelRequest
	fail   error
	during func(req orgdeletion.CancelRequest)
}

func (f *fakeBilling) CancelOrgSubscription(_ context.Context, req orgdeletion.CancelRequest) error {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	fail, during := f.fail, f.during
	f.mu.Unlock()
	if during != nil {
		during(req)
	}
	return fail
}

// canceled returns the subscription ids the fake was asked to cancel.
func (f *fakeBilling) canceled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		out = append(out, c.SubscriptionID)
	}
	return out
}

func (f *fakeBilling) setFail(err error) {
	f.mu.Lock()
	f.fail = err
	f.mu.Unlock()
}

// deletionBillingFixture is one account, its store with a journal at a known
// path and the fake billing seam wired.
type deletionBillingFixture struct {
	s       *store.Store
	pool    *pgxpool.Pool
	acct    string
	billing *fakeBilling
	journal string
	now     time.Time
}

func newDeletionBillingFixture(t *testing.T) deletionBillingFixture {
	t.Helper()
	s, pool := newStore(t)
	s.SetPaddlePriceMap(orgTestPrices)
	path := filepath.Join(t.TempDir(), "orgdel7-journal.jsonl")
	j, err := deletionjournal.NewFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeletionJournal(j)
	b := &fakeBilling{}
	s.SetDeletionBilling(b)
	return deletionBillingFixture{
		s: s, pool: pool, acct: makeAccount(t, s), billing: b, journal: path,
		now: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
	}
}

// insertSubscription writes a subscription row the account pays for (org
// "" is an account-scope subscription).
func (f deletionBillingFixture) insertSubscription(t *testing.T, sub, plan, status, org string) {
	t.Helper()
	var orgArg any
	if org != "" {
		orgArg = org
	}
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO paddle_subscriptions (account_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status, org_id)
		 VALUES ($1::uuid, 'ctm_1', $2, $3, 1, $4, $5::uuid)`, f.acct, sub, plan, status, orgArg); err != nil {
		t.Fatal(err)
	}
}

// teamOrg provisions a team org the account owns, in status.
func (f deletionBillingFixture) teamOrg(t *testing.T, status string) string {
	t.Helper()
	org, err := f.s.ProvisionOrg(context.Background(), f.acct, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: "team-" + strings.ToLower(f.acct[:8]), DisplayName: "Team", Tenancy: store.TenancyManaged,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `UPDATE orgs SET status = $2 WHERE org_id = $1::uuid`, org.OrgID, status); err != nil {
		t.Fatal(err)
	}
	return org.OrgID
}

// personalOrg provisions the account's personal org.
func (f deletionBillingFixture) personalOrg(t *testing.T) string {
	t.Helper()
	org, _, err := f.s.EnsurePersonalOrg(context.Background(), f.acct, "")
	if err != nil {
		t.Fatal(err)
	}
	return org.OrgID
}

// accountStatus reads the account's status.
func (f deletionBillingFixture) accountStatus(t *testing.T) string {
	t.Helper()
	var st string
	if err := f.pool.QueryRow(context.Background(), `SELECT status FROM accounts WHERE account_id = $1::uuid`, f.acct).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// assertNothingDeleted checks a refused deletion left everything in place.
func (f deletionBillingFixture) assertNothingDeleted(t *testing.T, subs int) {
	t.Helper()
	if st := f.accountStatus(t); st != "active" {
		t.Fatalf("account status = %q after a refused deletion, want active", st)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE account_id = $1::uuid`, f.acct); n != subs {
		t.Fatalf("%d subscription rows after a refused deletion, want %d", n, subs)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM deletion_requests WHERE account_id = $1::uuid`, f.acct); n != 0 {
		t.Fatalf("%d deletion requests after a refused deletion", n)
	}
	if b, _ := os.ReadFile(f.journal); strings.Contains(string(b), f.acct) {
		t.Fatalf("the refused deletion was journaled: %s", b)
	}
}

// auditRows returns the account's audit rows of event, details decoded.
func (f deletionBillingFixture) auditRows(t *testing.T, event string) []map[string]string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT detail::text FROM security_audit_events WHERE account_id = $1::uuid AND event_type = $2 ORDER BY created_at, id`, f.acct, event)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAccountDeletionCancelsBilling walks the ORGDEL-7 cases, one fresh
// account per row: which subscriptions the deletion cancels at Paddle (in
// order), what it answers, and the audit it leaves.
func TestAccountDeletionCancelsBilling(t *testing.T) {
	t.Parallel()
	type setup func(t *testing.T, f deletionBillingFixture)
	cases := []struct {
		name  string
		setup setup
		// canceled are the subscriptions the seam is asked to cancel.
		canceled []string
		// scopes are the audit scopes of the confirmed cancellations.
		scopes []string
		// refused: the deletion is refused as paying for a live org.
		refused bool
		// precheckCancel is how many the precheck reports it would cancel
		// when the deletion is refused (otherwise len(canceled)).
		precheckCancel int
	}{
		{
			name:  "no subscription: nothing to cancel",
			setup: func(*testing.T, deletionBillingFixture) {},
		},
		{
			name: "only canceled subscriptions: nothing to cancel",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_old", "plus_beta", "canceled", "")
				f.insertSubscription(t, "sub_older", "plus_beta", "canceled", "")
			},
		},
		{
			name: "personal: a refunded account-scope subscription Paddle still renews is canceled first",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_old", "plus_beta", "canceled", "")
				f.insertSubscription(t, "sub_refunded", "plus_beta", "refunded", "")
			},
			canceled: []string{"sub_refunded"}, scopes: []string{"account"},
		},
		{
			name: "personal: a live account-scope subscription is canceled first",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_acct", "plus_beta", "active", "")
			},
			canceled: []string{"sub_acct"}, scopes: []string{"account"},
		},
		{
			name: "personal: a trialing account-scope subscription is canceled first",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_trial", "plus_beta", "trialing", "")
			},
			canceled: []string{"sub_trial"}, scopes: []string{"account"},
		},
		{
			name: "personal: the personal org's Personal Pro is canceled first",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_pers", "personal_pro", "active", f.personalOrg(t))
			},
			canceled: []string{"sub_pers"}, scopes: []string{"personal_org"},
		},
		{
			name: "org: a live team org's subscription refuses, and nothing is canceled",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_team", "team", "active", f.teamOrg(t, "active"))
			},
			refused: true,
		},
		{
			name: "org: a live team org refuses before the personal plan is canceled",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_acct", "plus_beta", "active", "")
				f.insertSubscription(t, "sub_team", "team", "active", f.teamOrg(t, "active"))
			},
			refused: true, precheckCancel: 1,
		},
		{
			name: "org: an org on its way out has its subscription canceled first",
			setup: func(t *testing.T, f deletionBillingFixture) {
				f.insertSubscription(t, "sub_gone", "team", "active", f.teamOrg(t, "pending_deletion"))
			},
			canceled: []string{"sub_gone"}, scopes: []string{"org"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newDeletionBillingFixture(t)
			tc.setup(t, f)
			subs := countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE account_id = $1::uuid`, f.acct)

			wantCancel := len(tc.canceled)
			if tc.refused {
				wantCancel = tc.precheckCancel
			}
			before, err := f.s.AccountDeletionBilling(ctx, f.acct)
			if err != nil || before.Cancel != wantCancel || !before.CancelAvailable || (len(before.PaysFor) > 0) != tc.refused {
				t.Fatalf("AccountDeletionBilling = %+v, %v; want %d to cancel, refused %v", before, err, wantCancel, tc.refused)
			}

			dr, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now)
			if tc.refused {
				var paid *store.PaysForLiveOrgError
				if !errors.As(err, &paid) {
					t.Fatalf("deletion = %+v, %v; want a PaysForLiveOrgError", dr, err)
				}
				if got := f.billing.canceled(); len(got) != 0 {
					t.Fatalf("a refused deletion canceled %v at Paddle", got)
				}
				f.assertNothingDeleted(t, subs)
				return
			}
			if err != nil || dr.State != "done" || dr.SubscriptionsCanceled != len(tc.canceled) {
				t.Fatalf("deletion = %+v, %v; want done with %d canceled", dr, err, len(tc.canceled))
			}
			if got := f.billing.canceled(); !slices.Equal(got, tc.canceled) {
				t.Fatalf("canceled at Paddle %v, want %v", got, tc.canceled)
			}
			for _, c := range f.billing.calls {
				if c.IdempotencyKey != orgdeletion.AccountCancelKey(f.acct, c.SubscriptionID) {
					t.Fatalf("idempotency key %q", c.IdempotencyKey)
				}
			}
			audits := f.auditRows(t, "deletion_billing_canceled")
			if len(audits) != len(tc.scopes) {
				t.Fatalf("%d cancellation audit rows, want %d", len(audits), len(tc.scopes))
			}
			for i, a := range audits {
				if a["subscription_id"] != tc.canceled[i] || a["scope"] != tc.scopes[i] {
					t.Fatalf("audit %d = %v, want %s scope %s", i, a, tc.canceled[i], tc.scopes[i])
				}
			}
			var detail string
			if err := f.pool.QueryRow(ctx, `SELECT detail->>'subscriptions_canceled' FROM deletion_requests WHERE id = $1::uuid`, dr.ID).Scan(&detail); err != nil ||
				detail != fmt.Sprint(len(tc.canceled)) {
				t.Fatalf("request detail subscriptions_canceled = %q, %v", detail, err)
			}
			if f.accountStatus(t) != "deleted" {
				t.Fatal("account not tombstoned")
			}
			if n := countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE account_id = $1::uuid`, f.acct); n != 0 {
				t.Fatalf("%d subscription rows survived the deletion", n)
			}
		})
	}
}

// TestAccountDeletionCancelsRefundedBillingBeforeThePurge: a full refund or a
// chargeback revokes the plan but does not cancel the Paddle subscription
// (FR-7: Paddle keeps renewing it), so the account deletion cancels a
// refunded or charged-back subscription at Paddle, while its row and the
// account are still there, whatever it paid for: the account's own plan, its
// personal org's, or that of a live team org it only belongs to. Such a row
// holds no live slot (0090), so it never refuses the deletion as paying for a
// live team.
func TestAccountDeletionCancelsRefundedBillingBeforeThePurge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, f deletionBillingFixture) string
		scope string
	}{
		{
			name: "a refunded Personal Pro (account scope)",
			setup: func(t *testing.T, f deletionBillingFixture) string {
				f.insertSubscription(t, "sub_refunded", "plus_beta", "refunded", "")
				return "sub_refunded"
			},
			scope: "account",
		},
		{
			name: "a charged-back account plan",
			setup: func(t *testing.T, f deletionBillingFixture) string {
				f.insertSubscription(t, "sub_charged_back", "plus_beta", "charged_back", "")
				return "sub_charged_back"
			},
			scope: "account",
		},
		{
			name: "the personal org's refunded Personal Pro",
			setup: func(t *testing.T, f deletionBillingFixture) string {
				f.insertSubscription(t, "sub_pers_refunded", "personal_pro", "refunded", f.personalOrg(t))
				return "sub_pers_refunded"
			},
			scope: "personal_org",
		},
		{
			name: "a refunded subscription of a live team org the account only belongs to",
			setup: func(t *testing.T, f deletionBillingFixture) string {
				other := makeAccount(t, f.s)
				org, err := f.s.ProvisionOrg(context.Background(), other, store.ProvisionOrgInput{
					Kind: store.OrgTeam, Slug: "refd-" + strings.ToLower(other[:8]), DisplayName: "Team", Tenancy: store.TenancyManaged,
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(context.Background(), `UPDATE orgs SET status = 'active' WHERE org_id = $1::uuid`, org.OrgID); err != nil {
					t.Fatal(err)
				}
				addMember(t, f.pool, org.OrgID, f.acct, "member")
				f.insertSubscription(t, "sub_team_refunded", "team", "refunded", org.OrgID)
				return "sub_team_refunded"
			},
			scope: "org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newDeletionBillingFixture(t)
			id := tc.setup(t, f)
			// At the cancellation the purge has not run: the row and the
			// account are both still there.
			var rowsAtCancel, activeAtCancel int
			f.billing.during = func(req orgdeletion.CancelRequest) {
				rowsAtCancel = countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE paddle_subscription_id = $1`, req.SubscriptionID)
				activeAtCancel = countAdmin(t, f.pool, `SELECT count(*) FROM accounts WHERE account_id = $1::uuid AND status = 'active'`, f.acct)
			}

			before, err := f.s.AccountDeletionBilling(ctx, f.acct)
			if err != nil || before.Cancel != 1 || len(before.PaysFor) != 0 {
				t.Fatalf("AccountDeletionBilling = %+v, %v; want 1 to cancel and no live org", before, err)
			}
			dr, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now)
			if err != nil || dr.State != "done" || dr.SubscriptionsCanceled != 1 {
				t.Fatalf("deletion = %+v, %v; want done with 1 canceled", dr, err)
			}
			if got := f.billing.canceled(); !slices.Equal(got, []string{id}) {
				t.Fatalf("canceled at Paddle %v, want [%s]", got, id)
			}
			if k := f.billing.calls[0].IdempotencyKey; k != orgdeletion.AccountCancelKey(f.acct, id) {
				t.Fatalf("idempotency key %q", k)
			}
			if rowsAtCancel != 1 || activeAtCancel != 1 {
				t.Fatalf("at the cancellation: %d subscription rows, %d active accounts; want both 1 (cancel before the purge)", rowsAtCancel, activeAtCancel)
			}
			audits := f.auditRows(t, "deletion_billing_canceled")
			if len(audits) != 1 || audits[0]["subscription_id"] != id || audits[0]["scope"] != tc.scope {
				t.Fatalf("cancellation audit = %v, want %s scope %s", audits, id, tc.scope)
			}
			if f.accountStatus(t) != "deleted" {
				t.Fatal("account not tombstoned")
			}
			if n := countAdmin(t, f.pool, `SELECT count(*) FROM paddle_subscriptions WHERE paddle_subscription_id = $1`, id); n != 0 {
				t.Fatalf("%d rows of %s survived the deletion", n, id)
			}
		})
	}
}

// TestAccountDeletionRefundedWithoutABillingSeamIsRefused: with no Paddle
// client a refunded subscription cannot be canceled, so the deletion is
// refused (unavailable) with nothing deleted, never purged uncanceled.
func TestAccountDeletionRefundedWithoutABillingSeamIsRefused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeletionBillingFixture(t)
	f.s.SetDeletionBilling(nil)
	f.insertSubscription(t, "sub_refunded", "plus_beta", "refunded", "")
	_, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now)
	var ce *store.BillingCancelError
	if !errors.As(err, &ce) || ce.Reason != store.BillingCancelUnavailable || ce.SubscriptionID != "sub_refunded" {
		t.Fatalf("deletion err = %v, want BillingCancelUnavailable for sub_refunded", err)
	}
	f.assertNothingDeleted(t, 1)
}

// TestAccountDeletionRefusedWhenCancelFails: a cancellation that does not
// succeed refuses the deletion with a typed reason and deletes nothing; a
// failed attempt is audited with its class; the retry, with Paddle answering,
// completes (the same idempotency key again).
func TestAccountDeletionRefusedWhenCancelFails(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		fail   error
		unwire bool
		reason store.BillingCancelReason
		class  string
		calls  int
	}{
		{"transient failure", orgdeletion.Classed("billing:cancel:http_503", errors.New("paddle unavailable")), false, store.BillingCancelFailed, "billing:cancel:http_503", 1},
		{"transport failure without a class", errors.New("dial tcp: timeout"), false, store.BillingCancelFailed, "internal", 1},
		{"paddle refuses", orgdeletion.Classed("billing:cancel:http_403:forbidden", fmt.Errorf("%w: forbidden", orgdeletion.ErrBillingRefused)), false, store.BillingCancelRefused, "billing:cancel:http_403:forbidden", 1},
		{"the seam reports itself unwired", orgdeletion.ErrSeamUnwired, false, store.BillingCancelUnavailable, "internal", 1},
		{"no billing seam on this deployment", nil, true, store.BillingCancelUnavailable, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newDeletionBillingFixture(t)
			f.insertSubscription(t, "sub_acct", "plus_beta", "active", "")
			if tc.unwire {
				f.s.SetDeletionBilling(nil)
				if b, err := f.s.AccountDeletionBilling(ctx, f.acct); err != nil || b.CancelAvailable || b.Cancel != 1 {
					t.Fatalf("AccountDeletionBilling unwired = %+v, %v", b, err)
				}
			}
			f.billing.setFail(tc.fail)

			_, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now)
			var ce *store.BillingCancelError
			if !errors.Is(err, store.ErrDeletionBillingCancel) || !errors.As(err, &ce) ||
				ce.Reason != tc.reason || ce.SubscriptionID != "sub_acct" || ce.Class != tc.class {
				t.Fatalf("deletion = %v (%+v); want reason %s class %q", err, ce, tc.reason, tc.class)
			}
			if got := len(f.billing.canceled()); got != tc.calls {
				t.Fatalf("%d calls to the seam, want %d", got, tc.calls)
			}
			f.assertNothingDeleted(t, 1)
			if len(f.auditRows(t, "deletion_billing_canceled")) != 0 {
				t.Fatal("a failed cancellation was audited as canceled")
			}
			failed := f.auditRows(t, "deletion_billing_cancel_failed")
			if tc.calls == 0 {
				if len(failed) != 0 {
					t.Fatalf("audited %v without calling the seam", failed)
				}
			} else if len(failed) != 1 || failed[0]["subscription_id"] != "sub_acct" || failed[0]["class"] != tc.class {
				t.Fatalf("failure audit = %v", failed)
			}

			// The retry, Paddle answering: done, the same key asked again.
			if tc.unwire {
				f.s.SetDeletionBilling(f.billing)
			}
			f.billing.setFail(nil)
			dr, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now.Add(time.Minute))
			if err != nil || dr.State != "done" || dr.SubscriptionsCanceled != 1 {
				t.Fatalf("retry = %+v, %v", dr, err)
			}
			keys := map[string]bool{}
			for _, c := range f.billing.calls {
				keys[c.IdempotencyKey] = true
			}
			if len(keys) != 1 || !keys[orgdeletion.AccountCancelKey(f.acct, "sub_acct")] {
				t.Fatalf("idempotency keys %v, want one per subscription", keys)
			}
		})
	}
}

// TestAccountDeletionRefusesASubscriptionThatAppearedMeanwhile: a live
// subscription bound after the cancellation pass read the billing (a checkout
// that finished meanwhile) was not confirmed canceled, so the deletion
// transaction refuses (changed) and deletes nothing; the retry cancels both.
func TestAccountDeletionRefusesASubscriptionThatAppearedMeanwhile(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeletionBillingFixture(t)
	f.insertSubscription(t, "sub_a", "plus_beta", "active", "")
	var once sync.Once
	f.billing.during = func(orgdeletion.CancelRequest) {
		once.Do(func() {
			// The first subscription is canceled at Paddle (its webhook marks
			// it), and a second one binds.
			if _, err := f.pool.Exec(ctx, `UPDATE paddle_subscriptions SET status = 'canceled' WHERE paddle_subscription_id = 'sub_a'`); err != nil {
				t.Error(err)
			}
			f.insertSubscription(t, "sub_b", "plus_beta", "active", "")
		})
	}
	_, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now)
	var ce *store.BillingCancelError
	if !errors.As(err, &ce) || ce.Reason != store.BillingCancelChanged || ce.SubscriptionID != "sub_b" {
		t.Fatalf("deletion = %v, want a changed refusal naming sub_b", err)
	}
	f.assertNothingDeleted(t, 2)
	dr, err := f.s.CreateDeletionRequest(ctx, f.acct, f.now.Add(time.Minute))
	if err != nil || dr.State != "done" || dr.SubscriptionsCanceled != 1 {
		t.Fatalf("retry = %+v, %v", dr, err)
	}
	if got := f.billing.canceled(); !slices.Equal(got, []string{"sub_a", "sub_b"}) {
		t.Fatalf("canceled %v, want sub_a then sub_b", got)
	}
}

// TestAccountDeletionCancelsOnlyAfterTheStepUp: an unusable step-up refuses
// the deletion before any subscription is canceled at Paddle, and a usable
// one is consumed only by the deletion that completes.
func TestAccountDeletionCancelsOnlyAfterTheStepUp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newDeletionBillingFixture(t)
	// A signed-in browser session (the step-up binds to it).
	login, err := f.s.PortalLogin(ctx, "dev", "orgdel7-stepup", 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := f.s.IntrospectBrowserSession(ctx, login.RawSession, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.acct = login.AccountID
	sess := bp.SessionID
	f.insertSubscription(t, "sub_acct", "plus_beta", "active", "")
	_, err = f.s.CreateDeletionRequestWithStepUp(ctx, f.acct, sess, "00000000-0000-4000-8000-0000000000aa", f.now)
	if !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("bogus step-up = %v, want ErrStepUpInvalid", err)
	}
	if got := f.billing.canceled(); len(got) != 0 {
		t.Fatalf("canceled %v on an unauthorized request", got)
	}
	f.assertNothingDeleted(t, 1)

	// A usable step-up, and a cancellation that fails: refused, and the
	// step-up stays usable for the retry.
	authz, err := f.s.CreateStepUpAuthorization(ctx, f.acct, sess, store.StepUpActionDeletion, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.billing.setFail(errors.New("paddle down"))
	if _, err := f.s.CreateDeletionRequestWithStepUp(ctx, f.acct, sess, authz.ID, f.now); !errors.Is(err, store.ErrDeletionBillingCancel) {
		t.Fatalf("deletion with a failing cancel = %v", err)
	}
	f.billing.setFail(nil)
	dr, err := f.s.CreateDeletionRequestWithStepUp(ctx, f.acct, sess, authz.ID, f.now.Add(time.Minute))
	if err != nil || dr.State != "done" {
		t.Fatalf("retry with the same step-up = %+v, %v", dr, err)
	}
}

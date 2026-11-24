package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// The M6.9 / M7a.1 live proofs on PostgreSQL: the console's definer
// functions (owner-only, one open request, the 14-day floor, cancel while
// cooling off), the deletion driver end to end AS THE PRODUCTION WORKER ROLE
// (so every grant and worker policy of 0120/0121 is exercised), the account
// deletion's org precheck and follow-up, and the staff status read.

// delFixture is a database with an owner, a second member and one active,
// placed team org.
type delFixture struct {
	app, api, worker *store.Store
	pool             *pgxpool.Pool
	owner, member    string
	org              store.MyOrg
	journal          *deletionjournal.FileJournal
}

func newDelFixture(t *testing.T) delFixture {
	t.Helper()
	app, pool := newStore(t)
	f := delFixture{app: app, api: newAPIStore(t, pool), worker: newWorkerStore(t, pool), pool: pool}
	f.owner, f.member = makeAccount(t, app), makeAccount(t, app)
	f.org = provisionTeam(t, f.api, f.owner)
	activate(t, pool, f.org.OrgID)
	addMember(t, pool, f.org.OrgID, f.member, "member")
	j, err := deletionjournal.NewFileJournal(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	f.journal = j
	return f
}

// activate marks org created on host h1 at generation 1, as an acked create
// leaves it.
func activate(t *testing.T, pool *pgxpool.Pool, org string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE orgs SET status = 'active', lifecycle_gen = 1, host_id = 'h1' WHERE org_id = $1::uuid`, org); err != nil {
		t.Fatal(err)
	}
}

func addMember(t *testing.T, pool *pgxpool.Pool, org, acct, role string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, $3)`, org, acct, role); err != nil {
		t.Fatal(err)
	}
}

// recBilling records cancellations.
type recBilling struct {
	mu    sync.Mutex
	calls []orgdeletion.CancelRequest
}

func (b *recBilling) CancelOrgSubscription(_ context.Context, r orgdeletion.CancelRequest) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, r)
	return nil
}

// recIdentity records deletions.
type recIdentity struct{ deleted []string }

func (i *recIdentity) DeleteUser(_ context.Context, sub string) error {
	i.deleted = append(i.deleted, sub)
	return nil
}

func (f delFixture) driver(t *testing.T, now *time.Time, b orgdeletion.Billing, id orgdeletion.Identity) *orgdeletion.Driver {
	t.Helper()
	d, err := orgdeletion.New(orgdeletion.Deps{
		Orgs: f.worker, Accounts: f.worker, Journal: f.journal, Billing: b, Identity: id,
		Now: func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func runPass(t *testing.T, d *orgdeletion.Driver) orgdeletion.PassReport {
	t.Helper()
	rep, err := d.Pass(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func orgRow(t *testing.T, pool *pgxpool.Pool, org string) (status string, gen int64) {
	t.Helper()
	if err := pool.QueryRow(context.Background(), `SELECT status, lifecycle_gen FROM orgs WHERE org_id = $1::uuid`, org).
		Scan(&status, &gen); err != nil {
		t.Fatal(err)
	}
	return status, gen
}

func outboxKeys(t *testing.T, pool *pgxpool.Pool, org string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT idempotency_key FROM org_outbox WHERE org_id = $1::uuid AND verb <> 'create_tenant' ORDER BY seq`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func ackOutbox(t *testing.T, pool *pgxpool.Pool, key string) {
	t.Helper()
	tag, err := pool.Exec(context.Background(), `UPDATE org_outbox SET state = 'acked', done_at = now() WHERE idempotency_key = $1`, key)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("ack %s: %v (%d rows)", key, err, tag.RowsAffected())
	}
}

// TestOrgDeletionConsoleRules pins the definer functions' refusals.
func TestOrgDeletionConsoleRules(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	window := time.Now().Add(orgdeletion.DefaultCoolingOff)

	refusal := func(err error) string {
		var r *store.OrgDeletionRefusal
		if errors.As(err, &r) {
			return r.Outcome
		}
		return "error: " + err.Error()
	}
	if _, err := f.api.OpenOrgDeletion(ctx, f.member, f.org.OrgID, window); refusal(err) != "not_owner" {
		t.Errorf("a member opened a deletion: %v", err)
	}
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, time.Now().Add(14*24*time.Hour-2*time.Hour)); err == nil {
		t.Error("a window under the 14-day floor was accepted")
	}
	id, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, window)
	if err != nil || id == "" {
		t.Fatalf("open: %q %v", id, err)
	}
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, window); refusal(err) != "deletion_open" {
		t.Errorf("a second open: %v", err)
	}
	v, ok, err := f.api.OrgDeletionStatus(ctx, f.member, f.org.OrgID)
	if err != nil || !ok || v.RequestID != id || v.State != "cooling_off" || v.Origin != "owner" {
		t.Errorf("member status = %+v %v %v", v, ok, err)
	}
	outsider := makeAccount(t, f.app)
	if _, ok, _ := f.api.OrgDeletionStatus(ctx, outsider, f.org.OrgID); ok {
		t.Error("a non-member read the deletion status")
	}
	if err := f.api.CancelOrgDeletion(ctx, f.member, f.org.OrgID); refusal(err) != "not_owner" {
		t.Errorf("a member canceled: %v", err)
	}
	if err := f.api.CancelOrgDeletion(ctx, f.owner, f.org.OrgID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := f.api.CancelOrgDeletion(ctx, f.owner, f.org.OrgID); err != nil {
		t.Errorf("a repeated cancel is success: %v", err)
	}
	// Still open until the driver restored the org.
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, window); refusal(err) != "deletion_open" {
		t.Errorf("reopen before the restore: %v", err)
	}
	// A provisioning org cannot be deleted from the console.
	other := provisionTeam(t, f.api, f.owner)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, other.OrgID, window); refusal(err) != "org_not_deletable" {
		t.Errorf("a provisioning org: %v", err)
	}
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, "not-a-uuid", window); refusal(err) != "not_owner" {
		t.Errorf("a bad id: %v", err)
	}
}

// TestOrgDeletionDriverEndToEnd walks an owner's deletion to purged as the
// worker role, then checks what is kept.
func TestOrgDeletionDriverEndToEnd(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO oidc_clients (client_id, org_id, redirect_uris)
		VALUES ('org:' || $1, $1::uuid, ARRAY['https://x.example.test/auth/oidc/callback'])`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO org_usage_days (org_id, day, seat_member_ids, machine_identities, sessions, members, report_digest)
		VALUES ($1::uuid, current_date - 2, ARRAY['m1'], 1, 1, 2, repeat('a', 64))`, f.org.OrgID); err != nil {
		t.Fatalf("seed usage day: %v", err)
	}
	now := time.Now().Add(time.Minute)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
		t.Fatal(err)
	}
	b := &recBilling{}
	d := f.driver(t, &now, b, nil)

	runPass(t, d)
	if st, gen := orgRow(t, f.pool, f.org.OrgID); st != "pending_deletion" || gen != 2 {
		t.Fatalf("after announce: %s %d", st, gen)
	}
	if got := outboxKeys(t, f.pool, f.org.OrgID); !slices.Equal(got, []string{"state:" + f.org.OrgID + ":2:pending_deletion"}) {
		t.Fatalf("outbox = %v", got)
	}
	// Idempotent: a second pass inside the window writes nothing.
	runPass(t, d)
	if got := outboxKeys(t, f.pool, f.org.OrgID); len(got) != 1 {
		t.Fatalf("outbox after a quiet pass = %v", got)
	}

	now = now.Add(orgdeletion.DefaultCoolingOff + time.Minute)
	runPass(t, d)
	if st, gen := orgRow(t, f.pool, f.org.OrgID); st != "purging" || gen != 3 {
		t.Fatalf("after fence: %s %d", st, gen)
	}
	want := []string{
		"state:" + f.org.OrgID + ":2:pending_deletion", "state:" + f.org.OrgID + ":3:purging",
		"evict:" + f.org.OrgID + ":3", "state:" + f.org.OrgID + ":4:purged",
	}
	if got := outboxKeys(t, f.pool, f.org.OrgID); !slices.Equal(got, want) {
		t.Fatalf("outbox = %v, want %v", got, want)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM oidc_clients WHERE org_id = $1::uuid AND disabled_at IS NOT NULL`, f.org.OrgID); n != 1 {
		t.Error("the fence did not disable the org's OIDC client")
	}
	if len(b.calls) != 0 {
		t.Errorf("billing called for an org without a live subscription: %+v", b.calls)
	}
	v, _, _ := f.api.OrgDeletionStatus(ctx, f.owner, f.org.OrgID)
	if v.State != "purging" || v.Step != "await_host" {
		t.Fatalf("status while purging = %+v", v)
	}
	if err := f.api.CancelOrgDeletion(ctx, f.owner, f.org.OrgID); err == nil {
		t.Error("a purging deletion was canceled")
	}

	ackOutbox(t, f.pool, "state:"+f.org.OrgID+":4:purged")
	now = now.Add(2 * time.Minute)
	runPass(t, d)
	if st, gen := orgRow(t, f.pool, f.org.OrgID); st != "purged" || gen != 4 {
		t.Fatalf("after finalize: %s %d", st, gen)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_members WHERE org_id = $1::uuid`, f.org.OrgID); n != 0 {
		t.Errorf("%d memberships survived the purge", n)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_deletion_requests WHERE org_id = $1::uuid AND state = 'done' AND step = 'done'`, f.org.OrgID); n != 1 {
		t.Error("the request is not done")
	}
	// Kept: the org row (a tombstone: its slug is not reused), the slug, and
	// the usage days (W16-D9, 10 years).
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_usage_days WHERE org_id = $1::uuid`, f.org.OrgID); n != 1 {
		t.Error("the org's usage day was deleted; usage counts are kept 10 years (W16-D9)")
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_slugs WHERE org_id = $1::uuid`, f.org.OrgID); n == 0 {
		t.Error("the slug row was deleted; it must stay reserved")
	}
	recs, err := f.journal.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := deletionjournal.AcceptedOrgs(recs); !slices.Equal(got, []string{f.org.OrgID}) {
		t.Errorf("journal orgs = %v", got)
	}
	if rep := runPass(t, d); rep.Orgs != 0 {
		t.Errorf("a done request was driven again: %+v", rep)
	}
}

// TestOrgDeletionCancelRestores: a canceled request restores the org.
func TestOrgDeletionCancelRestores(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	now := time.Now().Add(time.Minute)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
		t.Fatal(err)
	}
	d := f.driver(t, &now, nil, nil)
	runPass(t, d)
	if err := f.api.CancelOrgDeletion(ctx, f.owner, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	runPass(t, d)
	if st, gen := orgRow(t, f.pool, f.org.OrgID); st != "active" || gen != 3 {
		t.Fatalf("restored org: %s %d", st, gen)
	}
	v, ok, _ := f.api.OrgDeletionStatus(ctx, f.owner, f.org.OrgID)
	if !ok || v.State != "canceled" || v.Step != "done" {
		t.Fatalf("status = %+v", v)
	}
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
		t.Errorf("a new request after the restore: %v", err)
	}
}

// TestOrgDeletionBlockedAndResumed: a live subscription with no billing seam
// blocks with a named reason; the operator's resume after wiring it runs on.
func TestOrgDeletionBlockedAndResumed(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
		VALUES ($1::uuid, $2::uuid, 'ctm_1', 'sub_live_1', 'team', 1, 'active')`, f.owner, f.org.OrgID); err != nil {
		t.Fatalf("seed a subscription: %v", err)
	}
	now := time.Now().Add(time.Minute)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
		t.Fatal(err)
	}
	unwired := f.driver(t, &now, nil, nil)
	runPass(t, unwired)
	now = now.Add(orgdeletion.DefaultCoolingOff + time.Minute)
	runPass(t, unwired)
	rows, err := f.app.ListDeletions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got store.DeletionStatusRow
	for _, r := range rows {
		if r.Kind == "org" && r.OrgID == f.org.OrgID {
			got = r
		}
	}
	if got.State != "blocked" || got.BlockedReason != orgdeletion.ReasonBillingSeamUnwired || got.Step != "cancel_billing" {
		t.Fatalf("staff row = %+v", got)
	}
	if st, _ := orgRow(t, f.pool, f.org.OrgID); st != "pending_deletion" {
		t.Errorf("an org with a live subscription was fenced: %s", st)
	}
	if ok, err := f.app.ResumeDeletion(ctx, got.RequestID, false, now); err != nil || !ok {
		t.Fatalf("resume: %v %v", ok, err)
	}
	b := &recBilling{}
	runPass(t, f.driver(t, &now, b, nil))
	if len(b.calls) != 1 || b.calls[0].SubscriptionID != "sub_live_1" || b.calls[0].IdempotencyKey != "orgdel:"+got.RequestID {
		t.Fatalf("billing calls = %+v", b.calls)
	}
	if st, _ := orgRow(t, f.pool, f.org.OrgID); st != "purging" {
		t.Errorf("after cancel: %s", st)
	}
}

// TestOrgDeletionCancelsARefundedSubscription: a full refund or a chargeback
// revokes the team's plan but does not cancel the Paddle subscription (FR-7),
// so cancel_billing cancels a refunded or charged-back one before the fence,
// as it does a live one; with no billing seam it blocks instead of purging
// the org with Paddle still renewing it.
func TestOrgDeletionCancelsARefundedSubscription(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"refunded", "charged_back"} {
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			f := newDelFixture(t)
			ctx := context.Background()
			if _, err := f.pool.Exec(ctx, `INSERT INTO paddle_subscriptions (account_id, org_id, paddle_customer_id, paddle_subscription_id, plan_name, plan_version, status)
				VALUES ($1::uuid, $2::uuid, 'ctm_1', 'sub_rev_1', 'team', 1, $3)`, f.owner, f.org.OrgID, status); err != nil {
				t.Fatalf("seed a subscription: %v", err)
			}
			now := time.Now().Add(time.Minute)
			if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
				t.Fatal(err)
			}
			p, err := f.driver(t, &now, &recBilling{}, nil).PreviewOrg(ctx, f.org.OrgID, time.Time{})
			if err != nil || !p.WillCancelSubscription || p.Facts.Subscription.ID != "sub_rev_1" {
				t.Fatalf("preview = %+v, %v; want it to cancel sub_rev_1", p, err)
			}
			unwired := f.driver(t, &now, nil, nil)
			runPass(t, unwired)
			now = now.Add(orgdeletion.DefaultCoolingOff + time.Minute)
			runPass(t, unwired)
			if st, _ := orgRow(t, f.pool, f.org.OrgID); st != "pending_deletion" {
				t.Fatalf("an org whose subscription Paddle still renews was fenced with no billing seam: %s", st)
			}
			rows, err := f.app.ListDeletions(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			var got store.DeletionStatusRow
			for _, r := range rows {
				if r.Kind == "org" && r.OrgID == f.org.OrgID {
					got = r
				}
			}
			if got.State != "blocked" || got.BlockedReason != orgdeletion.ReasonBillingSeamUnwired || got.Step != "cancel_billing" {
				t.Fatalf("staff row = %+v", got)
			}
			if ok, err := f.app.ResumeDeletion(ctx, got.RequestID, false, now); err != nil || !ok {
				t.Fatalf("resume: %v %v", ok, err)
			}
			b := &recBilling{}
			runPass(t, f.driver(t, &now, b, nil))
			if len(b.calls) != 1 || b.calls[0].SubscriptionID != "sub_rev_1" || b.calls[0].IdempotencyKey != "orgdel:"+got.RequestID {
				t.Fatalf("billing calls = %+v", b.calls)
			}
			if st, _ := orgRow(t, f.pool, f.org.OrgID); st != "purging" {
				t.Errorf("after cancel: %s", st)
			}
		})
	}
}

// TestAccountDeletionOrgPrecheck: sole ownership blocks, a plain membership
// does not, and the console's plan names both.
func TestAccountDeletionOrgPrecheck(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	plan, err := f.api.AccountDeletionPlan(ctx, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if plan.CanDelete() || plan.Blockers[0].Code != orgdeletion.BlockerBillingOwner || plan.Blockers[0].OrgID != f.org.OrgID {
		t.Fatalf("owner plan = %+v", plan)
	}
	_, err = f.app.CreateDeletionRequest(ctx, f.owner, time.Now())
	var blocked *store.AccountDeletionBlockedError
	if !errors.As(err, &blocked) || !errors.Is(err, store.ErrAccountDeletionBlocked) {
		t.Fatalf("deleting a team's billing owner: %v", err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM deletion_requests WHERE account_id = $1::uuid`, f.owner); n != 0 {
		t.Error("a refused deletion left a request")
	}
	// The member can leave.
	plan, err = f.api.AccountDeletionPlan(ctx, f.member)
	if err != nil || !plan.CanDelete() || len(plan.Removed) != 1 || plan.Removed[0].OrgID != f.org.OrgID {
		t.Fatalf("member plan = %+v %v", plan, err)
	}
}

// TestAccountDeletionFollowupEndToEnd: a member with a personal org deletes
// the account; the worker deletes the personal org with no window, removes
// the team membership, deactivates the subject on the team's host, leaves
// the team's admins a notice, then deletes the WorkOS user.
func TestAccountDeletionFollowupEndToEnd(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	personal, err := f.api.ProvisionOrg(ctx, f.member, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Personal"})
	if err != nil {
		t.Fatal(err)
	}
	activate(t, f.pool, personal.OrgID)
	if _, err := f.pool.Exec(ctx, `INSERT INTO identity_links (account_id, provider, subject) VALUES ($1::uuid, 'workos', 'user_member_1')`, f.member); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{f.org.OrgID, personal.OrgID} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO org_sub_seen (org_id, sub) VALUES ($1::uuid, 'user_member_1')`, org); err != nil {
			t.Fatal(err)
		}
	}
	dr, err := f.app.CreateDeletionRequest(ctx, f.member, time.Now())
	if err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM account_deletion_followups
		WHERE request_id = $1::uuid AND subs = ARRAY['user_member_1'] AND personal_org_id = $2::uuid`, dr.ID, personal.OrgID); n != 1 {
		t.Fatal("no follow-up with the subject and the personal org")
	}

	now := time.Now().Add(time.Minute)
	id := &recIdentity{}
	d := f.driver(t, &now, nil, id)
	runPass(t, d)
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_members WHERE account_id = $1::uuid`, f.member); n != 0 {
		t.Errorf("%d memberships survived", n)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_members WHERE org_id = $1::uuid`, f.org.OrgID); n != 1 {
		t.Errorf("the team lost other members: %d left", n)
	}
	if st, _ := orgRow(t, f.pool, personal.OrgID); st != "purging" {
		t.Errorf("the personal org was not fenced at once: %s", st)
	}
	deact := "deact:" + f.org.OrgID + ":user_member_1"
	if got := outboxKeys(t, f.pool, f.org.OrgID); !slices.Contains(got, deact) {
		t.Fatalf("team outbox = %v", got)
	}
	if got := outboxKeys(t, f.pool, personal.OrgID); slices.Contains(got, "deact:"+personal.OrgID+":user_member_1") {
		t.Error("the personal org, being purged, got a deactivation")
	}
	notices, err := f.api.OrgDepartureNotices(ctx, f.owner, f.org.OrgID)
	if err != nil || len(notices) != 1 {
		t.Errorf("owner notices = %v %v", notices, err)
	}
	if n, _ := f.api.OrgDepartureNotices(ctx, f.member, f.org.OrgID); len(n) != 0 {
		t.Error("a non-admin read the notices")
	}
	if len(id.deleted) != 0 {
		t.Fatal("the WorkOS user went before the deactivation was acked")
	}
	ackOutbox(t, f.pool, deact)
	now = now.Add(2 * time.Minute)
	runPass(t, d)
	if !slices.Equal(id.deleted, []string{"user_member_1"}) {
		t.Fatalf("identity deletions = %v", id.deleted)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM account_deletion_followups
		WHERE request_id = $1::uuid AND state = 'done' AND cardinality(subs) = 0`, dr.ID); n != 1 {
		t.Error("the follow-up is not done with its subjects forgotten")
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_sub_seen WHERE sub = 'user_member_1'`); n != 0 {
		t.Errorf("%d org_sub_seen rows of the deleted subject survived the follow-up (FR-23)", n)
	}
	rows, err := f.app.ListDeletions(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range rows {
		kinds[r.Kind] = true
	}
	if !kinds["org"] || !kinds["account"] {
		t.Errorf("staff rows = %+v", rows)
	}
}

// TestReapplyOrgDeletionsFromJournal is the restore-then-reconcile proof
// (plan 06 5.3.10 step 5): an org fenced before a restore is driven to the
// fence again whatever the restored database says, an org the restore
// predates is skipped, and a second run changes nothing.
func TestReapplyOrgDeletionsFromJournal(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	now := time.Now().Add(time.Minute)
	reqID, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff))
	if err != nil {
		t.Fatal(err)
	}
	d := f.driver(t, &now, nil, nil)
	runPass(t, d)
	now = now.Add(orgdeletion.DefaultCoolingOff + time.Minute)
	runPass(t, d) // fenced: the journal holds the org
	// A second org journaled whose request the restore lost entirely, and an
	// org the restore predates.
	second := provisionTeam(t, f.api, f.owner)
	activate(t, f.pool, second.OrgID)
	for _, org := range []string{second.OrgID, "11111111-2222-3333-4444-555555555555"} {
		if err := f.journal.Append(ctx, deletionjournal.Record{Event: deletionjournal.EventAccepted, Kind: deletionjournal.KindOrg, OrgID: org, At: now}); err != nil {
			t.Fatal(err)
		}
	}
	// The "restore": the first request back in its window, the org pending.
	if _, err := f.pool.Exec(ctx, `UPDATE org_deletion_requests SET state = 'cooling_off', step = 'cooling_off', purge_gen = NULL,
		purge_after = $2 WHERE request_id = $1::uuid`, reqID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'pending_deletion', lifecycle_gen = 2 WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	f.app.SetDeletionJournal(f.journal)
	n, err := f.app.ReapplyOrgDeletionsFromJournal(ctx, now)
	if err != nil || n != 2 {
		t.Fatalf("reapply = %d %v, want 2", n, err)
	}
	for _, org := range []string{f.org.OrgID, second.OrgID} {
		if c := countAdmin(t, f.pool, `SELECT count(*) FROM org_deletion_requests WHERE org_id = $1::uuid AND step = 'fence' AND state = 'purging'`, org); c != 1 {
			t.Errorf("org %s is not re-armed at the fence", org)
		}
	}
	if n, err := f.app.ReapplyOrgDeletionsFromJournal(ctx, now); err != nil || n != 0 {
		t.Errorf("a second run = %d %v", n, err)
	}
	// The driver fences both again, no cooling-off.
	runPass(t, d)
	for _, org := range []string{f.org.OrgID, second.OrgID} {
		if st, _ := orgRow(t, f.pool, org); st != "purging" {
			t.Errorf("org %s after the reconcile pass: %s", org, st)
		}
	}
}

// TestDeletionWorkerMembershipAccess pins the deletion driver's column
// grants (0120): it reads who is a member and in what role, never when they
// joined, and it may disable an OIDC client but not rewrite one.
func TestDeletionWorkerMembershipAccess(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	for _, c := range []struct {
		table, col, priv string
		want             bool
	}{
		{"org_members", "org_id", "SELECT", true},
		{"org_members", "account_id", "SELECT", true},
		{"org_members", "console_role", "SELECT", true},
		{"org_members", "is_billing_owner", "SELECT", true},
		{"org_members", "created_at", "SELECT", false},
		{"org_members", "console_role", "UPDATE", false},
		{"oidc_clients", "disabled_at", "UPDATE", true},
		{"oidc_clients", "redirect_uris", "UPDATE", false},
		{"oidc_clients", "redirect_uris", "SELECT", false},
		{"oidc_codes", "account_id", "SELECT", false},
		{"account_deletion_followups", "subs", "SELECT", true},
	} {
		if got := columnPriv(t, pool, "sbci_worker", c.table, c.col, c.priv); got != c.want {
			t.Errorf("sbci_worker %s on %s.%s = %v, want %v", c.priv, c.table, c.col, got, c.want)
		}
	}
	// The staff console never reads the subjects.
	if columnPriv(t, pool, "sbci_staff", "account_deletion_followups", "subs", "SELECT") {
		t.Error("sbci_staff reads the deleted account's subjects")
	}
	if !columnPriv(t, pool, "sbci_staff", "account_deletion_followups", "step", "SELECT") {
		t.Error("sbci_staff cannot read a follow-up's step")
	}
	// The console reaches the deletion queue only through the definers.
	for _, p := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		if tablePriv(t, pool, "sbci_api", "org_deletion_requests", p) {
			t.Errorf("sbci_api holds %s on org_deletion_requests", p)
		}
	}
	if tablePriv(t, pool, "sbci_api", "account_deletion_followups", "SELECT") {
		t.Error("sbci_api reads the follow-up queue")
	}
}

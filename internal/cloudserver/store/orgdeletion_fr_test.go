package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// orgdeletion_fr_test.go: the live proofs of the 2026-11-17 review fixes
// (docs/audits/fable-review-2026-11-17.md FR-11, FR-12, FR-23) on PostgreSQL,
// as the production roles.

func refusalOf(err error) string {
	var r *store.OrgDeletionRefusal
	if errors.As(err, &r) {
		return r.Outcome
	}
	if err == nil {
		return ""
	}
	return "error: " + err.Error()
}

// TestOrgDeletionRefusesPersonalOrg (FR-11): the definer refuses a personal
// org, whatever its status, before it looks at the window.
func TestOrgDeletionRefusesPersonalOrg(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	personal, err := f.api.ProvisionOrg(ctx, f.owner, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Personal"})
	if err != nil {
		t.Fatal(err)
	}
	activate(t, f.pool, personal.OrgID)
	window := time.Now().Add(orgdeletion.DefaultCoolingOff)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, personal.OrgID, window); refusalOf(err) != "personal_org" {
		t.Fatalf("a personal org: %v", err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_deletion_requests WHERE org_id = $1::uuid`, personal.OrgID); n != 0 {
		t.Fatal("a refused open wrote a request")
	}
	// The team org still opens.
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, window); err != nil {
		t.Fatalf("a team org: %v", err)
	}
}

// TestOrgLastSeatDayReadsEveryDay (FR-23): one row per case. A zero-seat
// newest day no longer hides an earlier day with seats.
func TestOrgLastSeatDayReadsEveryDay(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		days []struct {
			ago   int
			seats []string
		}
		want int // days ago, -1 for none
	}{
		{name: "no usage day: zero", want: -1},
		{name: "the newest day has seats", days: []struct {
			ago   int
			seats []string
		}{{3, []string{"m1"}}, {1, []string{"m1", "m2"}}}, want: 1},
		{name: "a zero-seat newest day: the earlier seat day", days: []struct {
			ago   int
			seats []string
		}{{5, []string{"m1"}}, {1, nil}}, want: 5},
		{name: "only zero-seat days: zero", days: []struct {
			ago   int
			seats []string
		}{{2, nil}}, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDelFixture(t)
			ctx := context.Background()
			for _, d := range tc.days {
				seats := d.seats
				if seats == nil {
					seats = []string{}
				}
				if _, err := f.pool.Exec(ctx, `INSERT INTO org_usage_days (org_id, day, seat_member_ids, machine_identities, sessions, members, report_digest)
					VALUES ($1::uuid, current_date - $2::int, $3, 1, 1, 2, repeat('a', 64))`, f.org.OrgID, d.ago, seats); err != nil {
					t.Fatal(err)
				}
			}
			got, err := f.api.OrgLastSeatDay(ctx, f.member, f.org.OrgID)
			if err != nil {
				t.Fatal(err)
			}
			var today time.Time
			if err := f.pool.QueryRow(ctx, `SELECT current_date::timestamptz`).Scan(&today); err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.want < 0 && !got.IsZero():
				t.Fatalf("last seat day = %v, want none", got)
			case tc.want >= 0 && !sameDay(got, today.AddDate(0, 0, -tc.want)):
				t.Fatalf("last seat day = %v, want %d days ago", got, tc.want)
			}
			// A non-member reads nothing.
			outsider := makeAccount(t, f.app)
			if d, err := f.api.OrgLastSeatDay(ctx, outsider, f.org.OrgID); err != nil || !d.IsZero() {
				t.Fatalf("an outsider read %v, %v", d, err)
			}
		})
	}
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	return ay == by && am == bm && ad == bd
}

// TestTwoOwnersCannotLeaveATeamOwnerless (FR-23): two owners of a team with
// another member delete their accounts at the same time; exactly one is
// allowed, the other is refused as the sole owner. Run twice, the second
// time in order, which the old count (deleted accounts' rows included) let
// through.
func TestTwoOwnersCannotLeaveATeamOwnerless(t *testing.T) {
	t.Parallel()
	for _, concurrent := range []bool{true, false} {
		f := newDelFixture(t)
		ctx := context.Background()
		second := makeAccount(t, f.app)
		addMember(t, f.pool, f.org.OrgID, second, "owner")
		if _, err := f.pool.Exec(ctx, `UPDATE org_members SET is_billing_owner = false WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 2)
		owners := []string{f.owner, second}
		if concurrent {
			var wg sync.WaitGroup
			for i, acct := range owners {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = f.app.CreateDeletionRequest(ctx, acct, time.Now())
				}()
			}
			wg.Wait()
		} else {
			for i, acct := range owners {
				_, errs[i] = f.app.CreateDeletionRequest(ctx, acct, time.Now())
			}
		}
		ok, refused := 0, 0
		for _, err := range errs {
			var blocked *store.AccountDeletionBlockedError
			switch {
			case err == nil:
				ok++
			case errors.As(err, &blocked) && len(blocked.Blockers) == 1 && blocked.Blockers[0].Code == orgdeletion.BlockerSoleOwnerWithMembers:
				refused++
			default:
				t.Fatalf("concurrent=%v: unexpected error %v", concurrent, err)
			}
		}
		if ok != 1 || refused != 1 {
			t.Fatalf("concurrent=%v: %d deleted, %d refused; want one of each", concurrent, ok, refused)
		}
	}
}

// TestFollowupRowsAreVerified (FR-12): sbci_api cannot insert a follow-up for
// another account (row-level security), and the worker refuses a row that
// does not match a finished account deletion or names an org the account
// did not create as its personal org. One case per verdict.
func TestFollowupRowsAreVerified(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()

	// The console role inserts only its own account's row.
	insert := func(as, account string) error {
		return f.api.WithAccount(ctx, as, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO account_deletion_followups (request_id, account_id, personal_org_id)
				VALUES (gen_random_uuid(), $1::uuid, $2::uuid)`, account, f.org.OrgID)
			return err
		})
	}
	if err := insert(f.member, f.owner); err == nil {
		t.Fatal("sbci_api inserted a follow-up for another account")
	}
	if err := insert(f.member, f.member); err != nil {
		t.Fatalf("sbci_api could not insert its own account's row: %v", err)
	}
	// The console role still reads no row.
	if err := f.api.WithAccount(ctx, f.member, func(ctx context.Context, tx pgx.Tx) error {
		var n int
		return tx.QueryRow(ctx, `SELECT count(*) FROM account_deletion_followups`).Scan(&n)
	}); err == nil {
		t.Fatal("sbci_api read the follow-ups")
	}

	// A real account deletion with a personal org checks out.
	leaver := makeAccount(t, f.app)
	if _, err := f.api.ProvisionOrg(ctx, leaver, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Personal"}); err != nil {
		t.Fatal(err)
	}
	dr, err := f.app.CreateDeletionRequest(ctx, leaver, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	forged := func(account, personalOrg string) string {
		var id string
		if err := f.pool.QueryRow(ctx, `INSERT INTO account_deletion_followups (request_id, account_id, personal_org_id)
			VALUES (gen_random_uuid(), $1::uuid, nullif($2, '')::uuid) RETURNING request_id::text`, account, personalOrg).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	var wrongOrgID string
	if err := f.pool.QueryRow(ctx, `INSERT INTO deletion_requests (account_id, scope, state) VALUES ($1::uuid, 'account', 'done') RETURNING id::text`, f.owner).Scan(&wrongOrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO account_deletion_followups (request_id, account_id, personal_org_id)
		VALUES ($1::uuid, $2::uuid, $3::uuid)`, wrongOrgID, f.owner, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   string
		want string
	}{
		{name: "a finished deletion with its own personal org", id: dr.ID, want: ""},
		{name: "no deletion request behind the row", id: forged(f.owner, ""), want: "no_account_deletion"},
		{name: "a team org named as the personal org", id: wrongOrgID, want: "personal_org_mismatch"},
		{name: "no such row", id: "00000000-0000-0000-0000-00000000abcd", want: "no_followup"},
	} {
		got, err := f.worker.VerifyFollowup(ctx, orgdeletion.AccountFollowup{RequestID: tc.id})
		if err != nil || got != tc.want {
			t.Errorf("%s: VerifyFollowup = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}

	// The driver blocks the forged rows and acts on none of them: the team
	// org named as a personal org keeps its owner's membership and gets no
	// deletion request.
	now := time.Now().Add(time.Minute)
	rep := runPass(t, f.driver(t, &now, nil, nil))
	if rep.Blocked < 2 {
		t.Fatalf("pass = %+v, want the forged rows blocked", rep)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM account_deletion_followups
		WHERE request_id = $1::uuid AND state = 'blocked' AND blocked_reason = 'followup_unverified' AND last_error_class = 'personal_org_mismatch'`, wrongOrgID); n != 1 {
		t.Error("the row naming a team org was not blocked as unverified")
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_members WHERE org_id = $1::uuid AND account_id = $2::uuid`, f.org.OrgID, f.owner); n != 1 {
		t.Error("a forged row removed a membership")
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_deletion_requests WHERE org_id = $1::uuid`, f.org.OrgID); n != 0 {
		t.Error("a forged row opened a deletion of a team org")
	}
	if orgs, fus, err := f.worker.BlockedDeletions(ctx); err != nil || orgs != 0 || fus < 2 {
		t.Errorf("BlockedDeletions = %d, %d, %v", orgs, fus, err)
	}
}

// TestOrgDeletionStepUpRollsBack (FR-23): the console's open consumes the
// step-up in its own transaction: a refused open leaves the authorization
// usable, a successful one spends it, and a spent or foreign one is refused.
func TestOrgDeletionStepUpRollsBack(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	now := time.Now()
	login := func(subject string) (account, session string) {
		t.Helper()
		sess, err := f.api.PortalLogin(ctx, "dev", subject, 0, now)
		if err != nil {
			t.Fatalf("PortalLogin: %v", err)
		}
		bp, err := f.api.IntrospectBrowserSession(ctx, sess.RawSession, now)
		if err != nil {
			t.Fatalf("IntrospectBrowserSession: %v", err)
		}
		return sess.AccountID, bp.SessionID
	}
	owner, sess := login("stepup-owner")
	team := provisionTeam(t, f.api, owner)
	activate(t, f.pool, team.OrgID)
	authz, err := f.api.CreateStepUpAuthorization(ctx, owner, sess, store.StepUpActionDeletion, now)
	if err != nil {
		t.Fatal(err)
	}
	su := store.OrgDeletionStepUp{SessionID: sess, AuthorizationID: authz.ID}
	window := now.Add(orgdeletion.DefaultCoolingOff)

	// A refused open (a provisioning org) does not spend the authorization.
	provisioning := provisionTeam(t, f.api, owner)
	if _, err := f.api.OpenOrgDeletionWithStepUp(ctx, owner, provisioning.OrgID, window, su, now); refusalOf(err) != "org_not_deletable" {
		t.Fatalf("provisioning org: %v", err)
	}
	if _, err := f.api.OpenOrgDeletionWithStepUp(ctx, owner, team.OrgID, window, su, now); err != nil {
		t.Fatalf("the authorization was spent by a refused open: %v", err)
	}
	if _, err := f.api.OpenOrgDeletionWithStepUp(ctx, owner, provisioning.OrgID, window, su, now); !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("a spent authorization: %v", err)
	}
	// Another account's authorization does not open this one's deletion.
	other, sess2 := login("stepup-other")
	a2, err := f.api.CreateStepUpAuthorization(ctx, other, sess2, store.StepUpActionDeletion, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.api.OpenOrgDeletionWithStepUp(ctx, owner, provisioning.OrgID, window, store.OrgDeletionStepUp{SessionID: sess2, AuthorizationID: a2.ID}, now); !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("a foreign authorization: %v", err)
	}
	// No passkey: the session reads as not enrolled.
	if enrolled, at, err := f.api.SessionPasskeyUse(ctx, owner, sess); err != nil || enrolled || !at.IsZero() {
		t.Fatalf("SessionPasskeyUse = %v %v %v", enrolled, at, err)
	}
}

// TestHostWaitIsBoundedLive (FR-23): the fence records the step's start, a
// waiting await_host names its reason in last_error_class, and an overdue
// wait blocks; resume restarts the clock.
func TestHostWaitIsBoundedLive(t *testing.T) {
	t.Parallel()
	f := newDelFixture(t)
	ctx := context.Background()
	now := time.Now().Add(time.Minute)
	if _, err := f.api.OpenOrgDeletion(ctx, f.owner, f.org.OrgID, now.Add(orgdeletion.DefaultCoolingOff)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO org_sub_seen (org_id, sub) VALUES ($1::uuid, 'user_x')`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	d := f.driver(t, &now, nil, nil)
	runPass(t, d)
	now = now.Add(orgdeletion.DefaultCoolingOff + time.Minute)
	runPass(t, d)
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_deletion_requests WHERE org_id = $1::uuid AND step = 'await_host'
		AND last_error_class = 'host_ack_pending' AND step_entered_at > now() + interval '29 days'`, f.org.OrgID); n != 1 {
		t.Fatal("the waiting request does not name its reason or its step's start")
	}
	now = now.Add(orgdeletion.HostPurgeGrace + time.Minute)
	rep := runPass(t, d)
	if len(rep.Blocks) != 1 || rep.Blocks[0].Reason != orgdeletion.ReasonHostPurgeOverdue {
		t.Fatalf("blocks = %+v", rep.Blocks)
	}
	var id string
	if err := f.pool.QueryRow(ctx, `SELECT request_id::text FROM org_deletion_requests WHERE org_id = $1::uuid AND state = 'blocked' AND blocked_reason = 'host_purge_overdue'`, f.org.OrgID).Scan(&id); err != nil {
		t.Fatalf("not blocked overdue: %v", err)
	}
	if ok, err := f.app.ResumeDeletion(ctx, id, false, now); err != nil || !ok {
		t.Fatalf("resume: %v %v", ok, err)
	}
	ackOutbox(t, f.pool, "state:"+f.org.OrgID+":4:purged")
	now = now.Add(time.Minute)
	runPass(t, d)
	if st, _ := orgRow(t, f.pool, f.org.OrgID); st != "purged" {
		t.Fatalf("after resume and ack: %s", st)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_sub_seen WHERE org_id = $1::uuid`, f.org.OrgID); n != 0 {
		t.Error("the purged org's org_sub_seen rows survived")
	}
}

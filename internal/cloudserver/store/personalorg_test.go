package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// personalorg_test.go covers the lazy personal org (personalorg.go; D-IND-1;
// docs/security.md IND-1) over PostgreSQL bound to the production serve role:
// ensure is idempotent and never writes a second member, the cloud's member
// cap of one holds against the org's own owner, a race resolves to one org,
// and a personal org does not count against the team org cap.

func TestPersonalOrgMemberCapOne(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	ctx := context.Background()
	owner, other := makeAccount(t, app), makeAccount(t, app)

	if _, err := api.PersonalOrg(ctx, owner); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("PersonalOrg before ensure = %v, want ErrNotFound", err)
	}
	first, created, err := api.EnsurePersonalOrg(ctx, owner, "example.test")
	if err != nil || !created {
		t.Fatalf("first ensure: created=%v err=%v", created, err)
	}
	if first.Kind != store.OrgPersonal || first.Tenancy != store.TenancyIndividual || first.DisplayName != store.PersonalOrgDisplayName ||
		first.ConsoleRole != store.ConsoleOwner || !first.IsBillingOwner || first.CreatedBy != owner {
		t.Fatalf("ensured org = %+v", first)
	}
	if err := store.ValidateOrgSlug(first.Slug, store.OrgPersonal); err != nil {
		t.Fatalf("minted slug %q: %v", first.Slug, err)
	}
	second, created, err := api.EnsurePersonalOrg(ctx, owner, "example.test")
	if err != nil || created || second.OrgID != first.OrgID {
		t.Fatalf("second ensure: org=%s created=%v err=%v, want %s existing", second.OrgID, created, err, first.OrgID)
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM orgs WHERE created_by=$1::uuid AND kind='personal'`, owner); n != 1 {
		t.Fatalf("account has %d personal orgs, want 1", n)
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, first.OrgID); n != 1 {
		t.Fatalf("personal org has %d members, want 1", n)
	}
	// The create intent was enqueued once, keyed by the org id.
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_outbox WHERE org_id=$1::uuid AND verb='create_tenant'`, first.OrgID); n != 1 {
		t.Fatalf("create_tenant intents = %d, want 1", n)
	}

	// The owner cannot add another account to its personal org (0047 rule 3),
	// in any role.
	for _, role := range []string{"member", "admin", "owner"} {
		err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
			return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, $3)`,
				first.OrgID, other, role)
		})
		if err == nil {
			t.Errorf("the owner added a %s to its personal org", role)
		}
	}
	// Nor can the other account join it.
	if err := asAccount(api, other, func(ctx context.Context, tx pgx.Tx) error {
		return execOne(ctx, tx, `INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`,
			first.OrgID, other)
	}); err == nil {
		t.Error("another account joined a personal org")
	}
	if n := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, first.OrgID); n != 1 {
		t.Fatalf("after the refused writes the personal org has %d members, want 1", n)
	}
	// The other account's own ensure gives it a distinct org.
	theirs, created, err := api.EnsurePersonalOrg(ctx, other, "")
	if err != nil || !created || theirs.OrgID == first.OrgID {
		t.Fatalf("other account ensure: org=%s created=%v err=%v", theirs.OrgID, created, err)
	}

	// Not counted against the team org cap: the allowance is untouched, and
	// the account can still create its full default cap of team orgs.
	a, err := api.TeamOrgAllowance(ctx, owner)
	if err != nil || a.Used != 0 || a.Limit != store.DefaultMaxTeamOrgs {
		t.Fatalf("team allowance after ensure = %+v err=%v, want used 0 of %d", a, err, store.DefaultMaxTeamOrgs)
	}
	for i := 0; i < store.DefaultMaxTeamOrgs; i++ {
		provisionTeam(t, api, owner)
	}
	if _, _, err := api.EnsurePersonalOrg(ctx, owner, ""); err != nil {
		t.Fatalf("ensure with the team cap full: %v", err)
	}
}

func TestEnsurePersonalOrgRaceResolvesToOneOrg(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	owner := makeAccount(t, app)
	const n = 6
	type result struct {
		orgID   string
		created bool
		err     error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			o, c, err := api.EnsurePersonalOrg(context.Background(), owner, "")
			results[i] = result{o.OrgID, c, err}
		}(i)
	}
	close(start)
	wg.Wait()
	createdCount := 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("ensure %d: %v", i, r.err)
		}
		if r.orgID != results[0].orgID {
			t.Fatalf("ensure %d answered org %s, ensure 0 answered %s", i, r.orgID, results[0].orgID)
		}
		if r.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("%d ensures reported created, want exactly 1", createdCount)
	}
	if c := countAdmin(t, pool, `SELECT count(*) FROM org_members WHERE org_id=$1::uuid`, results[0].orgID); c != 1 {
		t.Fatalf("personal org has %d members, want 1", c)
	}
}

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// orgcreate_test.go proves the wave 14 create-request reads against a real
// PostgreSQL (cloud 0092, 0093; ENTLWORK-5 / W14-D2): the worker reads an
// org's slug and kind, and its owner's subject and display address only
// through the two 0093 lookups, which answer for one org still being
// created and list nothing.

// TestOrgCreateOwnerLookup: the subject is the owner's WorkOS link (the
// issuer's rule: workos first, else the oldest link), the address is the
// provider-asserted one, and both answer only while the org is provisioning.
func TestOrgCreateOwnerLookup(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()

	// The owner's first link is the "dev" one makeAccount made; without a
	// workos link, that one is the subject.
	var devSub string
	if err := f.pool.QueryRow(ctx, `SELECT subject FROM identity_links WHERE account_id = $1::uuid`, f.owner).Scan(&devSub); err != nil {
		t.Fatal(err)
	}
	if got, err := f.worker.OrgCreateOwnerSub(ctx, f.org.OrgID); err != nil || got != devSub {
		t.Fatalf("subject (dev link only) = %q, %v; want %q", got, err, devSub)
	}
	// A later workos link wins, as the issuer's sub claim does.
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO identity_links (account_id, provider, subject) VALUES ($1::uuid, 'workos', 'user_01OWNER')`, f.owner); err != nil {
		t.Fatal(err)
	}
	if got, err := f.worker.OrgCreateOwnerSub(ctx, f.org.OrgID); err != nil || got != "user_01OWNER" {
		t.Fatalf("subject = %q, %v; want the workos link", got, err)
	}

	// No recorded address: the hint lookup answers nothing.
	if _, err := f.worker.OrgCreateOwnerEmailHint(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("hint with no address = %v, want ErrNotFound", err)
	}
	if err := f.app.UpsertVerifiedEmail(ctx, f.owner, "owner@example.test", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, err := f.worker.OrgCreateOwnerEmailHint(ctx, f.org.OrgID); err != nil || got != "owner@example.test" {
		t.Fatalf("hint = %q, %v", got, err)
	}

	// The slug and kind, through the 0089 / 0092 column grants.
	if facts, err := f.worker.OrgCreateFacts(ctx, f.org.OrgID); err != nil || facts.Slug != f.org.Slug || facts.Kind != store.OrgTeam {
		t.Fatalf("facts = %+v, %v; want slug %q, team", facts, err, f.org.Slug)
	}

	// Unknown and malformed ids answer nothing.
	for _, id := range []string{"00000000-0000-4000-8000-000000000999", "not-a-uuid"} {
		if _, err := f.worker.OrgCreateOwnerSub(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("subject for %q = %v, want ErrNotFound", id, err)
		}
		if _, err := f.worker.OrgCreateOwnerEmailHint(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("hint for %q = %v, want ErrNotFound", id, err)
		}
		if _, err := f.worker.OrgCreateFacts(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("facts for %q = %v, want ErrNotFound", id, err)
		}
	}

	// Once the tenant exists (status leaves provisioning) neither lookup
	// answers: the worker cannot collect owners of existing tenants.
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = 'active' WHERE org_id = $1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.worker.OrgCreateOwnerSub(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("subject of an active org = %v, want ErrNotFound", err)
	}
	if _, err := f.worker.OrgCreateOwnerEmailHint(ctx, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("hint of an active org = %v, want ErrNotFound", err)
	}
}

// TestOrgCreateOwnerLookupDoesNotList pins the no-listing property of the
// 0093 functions: each takes exactly one org id and returns one scalar text
// (never a set, never an account id); EXECUTE is the worker's and the app
// role's only; the worker still holds no privilege on the tables behind them;
// and a scan of every org through the function as the worker yields the
// owner of the one org being created and nothing for the others.
func TestOrgCreateOwnerLookupDoesNotList(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()

	for _, fn := range []string{"sbci_org_create_owner_sub", "sbci_org_create_owner_email_hint"} {
		var nargs int
		var retset, secdef bool
		var rettype, argtypes string
		err := f.pool.QueryRow(ctx, `
			SELECT p.pronargs, p.proretset, p.prosecdef, p.prorettype::regtype::text, pg_get_function_identity_arguments(p.oid)
			  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
			 WHERE n.nspname = 'public' AND p.proname = $1`, fn).Scan(&nargs, &retset, &secdef, &rettype, &argtypes)
		if err != nil {
			t.Fatalf("%s: %v", fn, err)
		}
		if nargs != 1 || retset || !secdef || rettype != "text" || argtypes != "p_org uuid" {
			t.Fatalf("%s: args %d %s, returns set %v, type %s, definer %v; want one uuid in, one text out, definer",
				fn, nargs, argtypes, retset, rettype, secdef)
		}
		for role, want := range map[string]bool{"sbci_worker": true, "sbci_app": true, "sbci_api": false, "sbci_staff": false, "sbci_aggregator": false} {
			var got bool
			if err := f.pool.QueryRow(ctx, `SELECT has_function_privilege($1, $2 || '(uuid)', 'EXECUTE')`, role, fn).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s EXECUTE %s = %v, want %v", role, fn, got, want)
			}
		}
	}
	for _, tbl := range []string{"identity_links", "org_members", "account_verified_emails", "account_profiles"} {
		if tablePriv(t, f.pool, "sbci_worker", tbl, "SELECT") {
			t.Errorf("sbci_worker holds SELECT on %s; the owner reaches the worker only through the 0093 lookups", tbl)
		}
	}

	// Three orgs: the fixture's (provisioning) and two whose tenants exist.
	for _, status := range []string{"active", "suspended"} {
		o := provisionTeam(t, f.api, makeAccount(t, f.app))
		if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status = $2 WHERE org_id = $1::uuid`, o.OrgID, status); err != nil {
			t.Fatal(err)
		}
	}
	var answered, scanned int
	err := f.worker.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(sbci_org_create_owner_sub(org_id)), count(*) FROM orgs`).Scan(&answered, &scanned)
	})
	if err != nil {
		t.Fatalf("scan as the worker: %v", err)
	}
	if scanned != 3 || answered != 1 {
		t.Fatalf("a scan of %d orgs through the lookup answered %d owners; want only the one being created", scanned, answered)
	}
	var null *string
	if err := f.worker.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_org_create_owner_sub(NULL)`).Scan(&null)
	}); err != nil || null != nil {
		t.Fatalf("NULL org = %v, %v; want NULL", null, err)
	}
}

// TestOrgForEntitlementsDatesTheCreate: the issuer's view carries the ack
// time of the org's create_tenant row (the launch window's anchor), zero
// before the ack.
func TestOrgForEntitlementsDatesTheCreate(t *testing.T) {
	t.Parallel()
	f := newOutboxFixture(t)
	ctx := context.Background()
	v, err := f.worker.OrgForEntitlements(ctx, f.org.OrgID)
	if err != nil || v.Kind != store.OrgTeam || v.Status != "provisioning" || !v.CreatedOnHostAt.IsZero() {
		t.Fatalf("before the ack = %+v, %v", v, err)
	}
	now := claimNow()
	rows, err := f.worker.ClaimOrgOutbox(ctx, store.OrgOutboxClaim{Now: now, LeaseTTL: time.Minute, Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("claim = %d rows, %v", len(rows), err)
	}
	ackAt := now.Add(time.Second).UTC().Truncate(time.Microsecond)
	if err := f.worker.RecordOrgOutboxOutcome(ctx, store.OrgOutboxOutcome{
		OutboxID: rows[0].OutboxID, LeaseToken: rows[0].LeaseToken, Result: store.OutboxResultAcked, Now: ackAt,
		HostState: "active", HostGen: 1, AdoptCreate: true,
	}); err != nil {
		t.Fatal(err)
	}
	v, err = f.worker.OrgForEntitlements(ctx, f.org.OrgID)
	if err != nil || v.Status != "active" || !v.CreatedOnHostAt.Equal(ackAt) {
		t.Fatalf("after the ack = %+v, %v; want created at %s", v, err, ackAt)
	}
	list, err := f.worker.ListOrgsForEntitlements(ctx, "", 10)
	if err != nil || len(list) != 1 || !list[0].CreatedOnHostAt.Equal(ackAt) {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000999", "nope"} {
		if _, err := f.worker.OrgForEntitlements(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("OrgForEntitlements(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// orgoidcclient_test.go proves the provisioning step that registers a new
// org as a client of the platform OIDC issuer (wave 15 lane platform-signin,
// CPSIGN-9): run as the production API role inside a WithAccount
// transaction (the shape of ProvisionOrg's), it writes exactly one client
// with id "org:<org id>" and the one redirect URI the tenant rail sends, a
// retry writes nothing, a rolled-back provisioning leaves nothing, and the
// issuer's own store seam reads the client back. Needs Postgres
// (SBCI_TEST_PG_DSN).

// oidcClientRows reads every oidc_clients row of org as the superuser.
func oidcClientRows(t *testing.T, s interface {
	WithSystem(context.Context, func(context.Context, pgx.Tx) error) error
}, orgID string,
) []oidcissuer.Client {
	t.Helper()
	var out []oidcissuer.Client
	err := s.WithSystem(context.Background(), func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT client_id, org_id::text, redirect_uris FROM oidc_clients WHERE org_id = $1::uuid`, orgID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c oidcissuer.Client
			if err := rows.Scan(&c.ClientID, &c.OrgID, &c.RedirectURIs); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("read oidc_clients: %v", err)
	}
	return out
}

func TestProvisionedOrgRegistersExactlyOneOIDCClient(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool) // the production role: its 0052 grant must suffice
	ctx := context.Background()
	owner := makeAccount(t, app)
	o := provisionTeam(t, api, owner)

	register := func(slug, domain string) error {
		return asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
			return store.RegisterProvisionedOIDCClientTx(ctx, tx, o.OrgID, slug, domain)
		})
	}
	// The tenant domain as an operator might write it: case and a trailing
	// dot are normalized away.
	if err := register(o.Slug, "SuperBased.App."); err != nil {
		t.Fatalf("register: %v", err)
	}
	wantID := "org:" + o.OrgID
	wantURI := "https://" + o.Slug + ".superbased.app/auth/oidc/callback"
	check := func(when string) {
		t.Helper()
		got := oidcClientRows(t, app, o.OrgID)
		if len(got) != 1 || got[0].ClientID != wantID || got[0].OrgID != o.OrgID ||
			len(got[0].RedirectURIs) != 1 || got[0].RedirectURIs[0] != wantURI {
			t.Fatalf("%s: clients = %+v, want exactly {%s %s [%s]}", when, got, wantID, o.OrgID, wantURI)
		}
	}
	check("after the create")

	// A retried create (the provisioning step run again, alone or twice in
	// one transaction) writes nothing.
	if err := register(o.Slug, "superbased.app"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		for range 2 {
			if err := store.RegisterProvisionedOIDCClientTx(ctx, tx, o.OrgID, o.Slug, "superbased.app"); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("retry twice in one transaction: %v", err)
	}
	check("after the retries")

	// A different redirect (another slug) is refused, never rewritten.
	if err := register("other-slug", "superbased.app"); !errors.Is(err, store.ErrOIDCClientConflict) {
		t.Fatalf("register under another slug: %v, want ErrOIDCClientConflict", err)
	}
	check("after the refused rewrite")

	// The issuer's store seam (as the serve process) finds the client, and
	// the tenant rail's redirect matches it byte for byte.
	c, err := api.OIDC().Client(ctx, oidcissuer.ClientIDForOrg(o.OrgID))
	if err != nil || c.Disabled || c.OrgID != o.OrgID {
		t.Fatalf("issuer Client = %+v, %v", c, err)
	}
	if !oidcissuer.RedirectMatches(c.RedirectURIs, wantURI) {
		t.Fatalf("issuer redirect %v does not match %s", c.RedirectURIs, wantURI)
	}

	// Exactly one client per org: a second org gets its own, the first is
	// unchanged.
	o2 := provisionTeam(t, api, owner)
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		return store.RegisterProvisionedOIDCClientTx(ctx, tx, o2.OrgID, o2.Slug, "superbased.app")
	}); err != nil {
		t.Fatalf("register the second org: %v", err)
	}
	if got := oidcClientRows(t, app, o2.OrgID); len(got) != 1 || got[0].ClientID != "org:"+o2.OrgID {
		t.Fatalf("second org clients = %+v", got)
	}
	check("after the second org")
}

func TestProvisionedOIDCClientCommitsWithTheProvisioning(t *testing.T) {
	t.Parallel()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	owner := makeAccount(t, app)
	o := provisionTeam(t, api, owner)

	// The provisioning transaction fails after the client was written: no
	// client survives it.
	boom := errors.New("a later provisioning statement failed")
	err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		if err := store.RegisterProvisionedOIDCClientTx(ctx, tx, o.OrgID, o.Slug, "superbased.app"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("rolled-back provisioning: %v", err)
	}
	if got := oidcClientRows(t, app, o.OrgID); len(got) != 0 {
		t.Fatalf("a rolled-back provisioning left clients %+v", got)
	}

	// No tenant domain (a single-host dev cloud): nothing is registered and
	// the provisioning is not failed for it.
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		return store.RegisterProvisionedOIDCClientTx(ctx, tx, o.OrgID, o.Slug, "  ")
	}); err != nil {
		t.Fatalf("no tenant domain: %v", err)
	}
	if got := oidcClientRows(t, app, o.OrgID); len(got) != 0 {
		t.Fatalf("no tenant domain registered %+v", got)
	}

	// A slug the redirect URI cannot carry is refused (the provisioning
	// fails rather than registering a client nobody can use).
	if err := asAccount(api, owner, func(ctx context.Context, tx pgx.Tx) error {
		return store.RegisterProvisionedOIDCClientTx(ctx, tx, o.OrgID, "bad/slug", "superbased.app")
	}); err == nil {
		t.Fatal("a slug with a path separator was registered")
	}
}

// TestProvisionOrgRegistersTheSigninClient pins the call site landed at the
// wave 15 merge (CPSIGN-9): ProvisionOrg registers the org's platform OIDC
// client inside the provisioning transaction when the tenant domain is set,
// and registers none when it is empty.
func TestProvisionOrgRegistersTheSigninClient(t *testing.T) {
	t.Parallel()
	app, _ := newStore(t)
	owner := makeAccount(t, app)
	slug := fmt.Sprintf("team-%d", subjCounter.Add(1))
	o, err := app.ProvisionOrg(context.Background(), owner, store.ProvisionOrgInput{
		Kind: store.OrgTeam, Slug: slug, DisplayName: "Team " + slug,
		Tenancy: store.TenancyManaged, TenantDomain: "superbased.app",
	})
	if err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}
	got := oidcClientRows(t, app, o.OrgID)
	want := "https://" + slug + ".superbased.app" + oidcissuer.TenantCallbackPath
	if len(got) != 1 || got[0].ClientID != "org:"+o.OrgID || len(got[0].RedirectURIs) != 1 || got[0].RedirectURIs[0] != want {
		t.Fatalf("oidc_clients = %+v, want one client org:%s redirecting to %s", got, o.OrgID, want)
	}

	none := provisionTeam(t, app, makeAccount(t, app))
	if got := oidcClientRows(t, app, none.OrgID); len(got) != 0 {
		t.Fatalf("oidc_clients with no tenant domain = %+v, want none", got)
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestDecideClientRows is one case per clientRules row (W16-D7).
func TestDecideClientRows(t *testing.T) {
	t.Parallel()
	const org = "aaaaaaaa-0000-4000-8000-000000000001"
	want, err := oidcissuer.ClientForOrg(org, "acme", "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	same := store.OIDCClientState{ClientID: want.ClientID, OrgID: org, RedirectURIs: want.RedirectURIs}
	other := same
	other.RedirectURIs = []string{"https://acme.example.com/auth/oidc/callback"}
	disabled := same
	disabled.Disabled = true
	active := store.OIDCBackfillOrg{OrgID: org, Slug: "acme", Kind: store.OrgTeam, Status: "active"}
	cases := []struct {
		name string
		f    clientFacts
		want clientAction
	}{
		{"suspended org", clientFacts{org: store.OIDCBackfillOrg{OrgID: org, Slug: "acme", Status: "suspended"}, want: want}, clientIneligible},
		{"purged org with a client", clientFacts{org: store.OIDCBackfillOrg{OrgID: org, Slug: "acme", Status: "purged"}, existing: &same, want: want}, clientIneligible},
		{"no slug", clientFacts{org: store.OIDCBackfillOrg{OrgID: org, Status: "active"}}, clientNoSlug},
		{"slug the issuer refuses", clientFacts{org: active, wantErr: errors.New("unusable")}, clientNoSlug},
		{"registered the same", clientFacts{org: active, existing: &same, want: want}, clientRegistered},
		{"registered elsewhere", clientFacts{org: active, existing: &other, want: want}, clientConflict},
		{"registered but disabled", clientFacts{org: active, existing: &disabled, want: want}, clientConflict},
		{"provisioning, none", clientFacts{org: store.OIDCBackfillOrg{OrgID: org, Slug: "acme", Status: "provisioning"}, want: want}, clientRegister},
		{"active, none", clientFacts{org: active, want: want}, clientRegister},
	}
	if len(clientRules) != 5 {
		t.Fatalf("clientRules has %d rows; this test covers 5", len(clientRules))
	}
	for _, c := range cases {
		if got := decideClient(c.f); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// TestRegisterClientVerb drives `oidc register-client` (W16-D7, CPSIGN-13)
// against a real PostgreSQL with the roles the verb uses: refusals, a dry
// run that writes nothing, --org and --all-missing applies that register
// every kind, a repeat that reports nothing missing, a suspended org
// skipped, and a client registered differently reported, never rewritten.
func TestRegisterClientVerb(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	app, err := store.NewForRole(pool, store.RoleApp)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := store.NewForRole(pool, store.RoleWorker)
	if err != nil {
		t.Fatal(err)
	}
	api, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatal(err)
	}
	const domain = "superbased.app"
	newOrg := func(slug string, kind store.OrgKind, tenantDomain string) string {
		t.Helper()
		var owner string
		if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING account_id::text`).Scan(&owner); err != nil {
			t.Fatal(err)
		}
		tenancy := store.TenancyManaged
		if kind == store.OrgPersonal {
			tenancy = store.TenancyIndividual
		}
		o, err := api.ProvisionOrg(ctx, owner, store.ProvisionOrgInput{
			Kind: kind, Slug: slug, DisplayName: slug, Tenancy: tenancy, TenantDomain: tenantDomain,
		})
		if err != nil {
			t.Fatalf("provision %s: %v", slug, err)
		}
		return o.OrgID
	}
	team := newOrg("team-before-hook", store.OrgTeam, "")
	personalSlug, err := store.NewPersonalOrgSlug()
	if err != nil {
		t.Fatal(err)
	}
	personal := newOrg(personalSlug, store.OrgPersonal, "")
	hooked := newOrg("team-with-hook", store.OrgTeam, domain)
	suspended := newOrg("team-suspended", store.OrgTeam, "")
	if _, err := pool.Exec(ctx, `UPDATE orgs SET status = 'suspended' WHERE org_id = $1`, suspended); err != nil {
		t.Fatal(err)
	}
	clients := func() map[string]store.OIDCClientState {
		m, err := app.OIDCClientsByOrg(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if n := len(clients()); n != 1 {
		t.Fatalf("clients before = %d, want 1 (the hooked org)", n)
	}

	var out bytes.Buffer
	for name, req := range map[string]registerClientRequest{
		"neither flag":   {TenantDomain: domain},
		"both flags":     {OrgID: team, AllMissing: true, TenantDomain: domain},
		"no domain":      {AllMissing: true},
		"unknown org":    {OrgID: "aaaaaaaa-0000-4000-8000-00000000dead", TenantDomain: domain, Apply: true},
		"malformed org":  {OrgID: "not-a-uuid", TenantDomain: domain, Apply: true},
		"suspended org":  {OrgID: suspended, TenantDomain: domain, Apply: true},
		"bad tenant dom": {OrgID: team, TenantDomain: "Not A Domain", Apply: true},
	} {
		out.Reset()
		if err := runRegisterClient(ctx, &out, worker, app, req); err == nil {
			t.Errorf("%s: accepted:\n%s", name, out.String())
		}
	}
	if n := len(clients()); n != 1 {
		t.Fatalf("refusals wrote clients: %d", n)
	}

	// Dry run over every org: two missing (team, personal), nothing written.
	out.Reset()
	if err := runRegisterClient(ctx, &out, worker, app, registerClientRequest{AllMissing: true, TenantDomain: domain}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dry run", "2 missing", "would register client org:" + team, "would register client org:" + personal, "1 skipped"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "secret") {
		t.Errorf("output mentions a secret:\n%s", out.String())
	}
	if n := len(clients()); n != 1 {
		t.Fatalf("dry run wrote clients: %d", n)
	}

	// --org applies one org.
	out.Reset()
	if err := runRegisterClient(ctx, &out, worker, app, registerClientRequest{OrgID: team, TenantDomain: domain, Apply: true}); err != nil {
		t.Fatal(err)
	}
	c, ok := clients()[team]
	if !ok || c.RedirectURIs[0] != "https://team-before-hook."+domain+"/auth/oidc/callback" {
		t.Fatalf("team client = %+v, %v", c, ok)
	}
	// --org on a registered org: no change, no error.
	out.Reset()
	if err := runRegisterClient(ctx, &out, worker, app, registerClientRequest{OrgID: hooked, TenantDomain: domain, Apply: true}); err != nil ||
		!strings.Contains(out.String(), "already registered") {
		t.Fatalf("registered org = %q, %v", out.String(), err)
	}

	// --all-missing applies the rest (the personal org: every kind).
	out.Reset()
	if err := runRegisterClient(ctx, &out, worker, app, registerClientRequest{AllMissing: true, TenantDomain: domain, Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := clients()[personal]; !ok || !strings.Contains(out.String(), "1 of 1 missing clients registered") {
		t.Fatalf("all-missing apply:\n%s", out.String())
	}
	if _, ok := clients()[suspended]; ok {
		t.Fatal("a suspended org was registered")
	}
	// The acceptance check: nothing missing.
	out.Reset()
	if err := runRegisterClient(ctx, &out, worker, app, registerClientRequest{AllMissing: true, TenantDomain: domain}); err != nil ||
		!strings.Contains(out.String(), "nothing missing (3 registered, 1 skipped") {
		t.Fatalf("repeat = %q, %v", out.String(), err)
	}

	// A client registered under another domain is reported, not rewritten.
	out.Reset()
	err = runRegisterClient(ctx, &out, worker, app, registerClientRequest{AllMissing: true, TenantDomain: "other.example", Apply: true})
	if err == nil || !strings.Contains(out.String(), "refused: client org:"+team) {
		t.Fatalf("other domain = %q, %v; want a conflict", out.String(), err)
	}
	if got := clients()[team].RedirectURIs[0]; got != "https://team-before-hook."+domain+"/auth/oidc/callback" {
		t.Fatalf("the conflict rewrote the client: %s", got)
	}
}

package store_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// oidc_test.go proves the OIDC issuer's store seam and tables (cloud
// migrations 0051-0054, managed-SaaS M6.2) against Postgres: the class and
// grants of every new table, authorize on one replica and token on another
// over one database, single-use codes under concurrency, the atomic
// issued + mirror + sub-seen record, membership through RLS, and the signing
// key lifecycle. Every test needs Postgres (cloudtestpg; SKIPPED loudly
// without SBCI_TEST_PG_DSN).

const oidcTestIssuer = "https://app.example/oauth2"

// oidcTableClasses: every table 0051-0054 creates is class S (no RLS) with
// exactly these grants. A role not listed holds nothing.
var oidcTableClasses = []orgTableClass{
	{"oidc_clients", "S", map[string][]string{
		"sbci_api": {"SELECT", "INSERT"},
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
	}},
	{"oidc_codes", "S", map[string][]string{
		"sbci_api":    {"SELECT", "INSERT", "DELETE"}, // UPDATE is column-level, pinned below
		"sbci_app":    {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"sbci_worker": {"DELETE"}, // M6.9 (0120): the deletion fence drops a deleted org's unused codes; SELECT is client_id only
	}},
	{"oidc_signing_keys", "S", map[string][]string{
		"sbci_api": {"SELECT", "INSERT"},
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
	}},
	{"oidc_issued", "S", map[string][]string{
		"sbci_api": {"INSERT"},
		"sbci_app": {"SELECT", "INSERT"},
	}},
	{"oidc_audit_mirror", "S", map[string][]string{
		"sbci_api": {"INSERT"},
		"sbci_app": {"SELECT", "INSERT", "UPDATE"},
	}},
	// M7a.2 (0087): the support path. sbci_staff's INSERT on the codes is
	// pinned in oidcsupport_test.go (this table's roles exclude sbci_staff).
	{"oidc_support_codes", "S", map[string][]string{
		"sbci_api": {"SELECT", "DELETE"}, // UPDATE is column-level (consumed_at)
		"sbci_app": {"SELECT", "INSERT", "UPDATE", "DELETE"},
	}},
	{"oidc_support_issued", "S", map[string][]string{
		"sbci_api": {"INSERT"},
		"sbci_app": {"SELECT", "INSERT"},
	}},
}

func TestOIDCTableClassesAndGrants(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'oidc\_%'`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	real := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		real[n] = true
	}
	rows.Close()
	for _, c := range oidcTableClasses {
		if !real[c.table] {
			t.Errorf("classified table %s does not exist", c.table)
		}
		delete(real, c.table)
	}
	for n := range real {
		t.Errorf("table %s has no class in oidcTableClasses", n)
	}

	roles := []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app"}
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	for _, c := range oidcTableClasses {
		var rls, force bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, c.table).Scan(&rls, &force); err != nil {
			t.Fatalf("read RLS state of %s: %v", c.table, err)
		}
		if rls || force {
			t.Errorf("%s (class S) has row-level security enabled", c.table)
		}
		for _, role := range roles {
			for _, p := range privs {
				want := false
				for _, g := range c.grants[role] {
					want = want || g == p
				}
				if got := tablePriv(t, pool, role, c.table, p); got != want {
					t.Errorf("%s %s on %s = %v, want %v", role, p, c.table, got, want)
				}
			}
		}
	}
	// sbci_api may only mark a code consumed.
	for col, want := range map[string]bool{"consumed_at": true, "expires_at": false, "account_id": false, "code_challenge": false, "redirect_uri": false} {
		if got := columnPriv(t, pool, "sbci_api", "oidc_codes", col, "UPDATE"); got != want {
			t.Errorf("sbci_api UPDATE on oidc_codes.%s = %v, want %v", col, got, want)
		}
	}
	// The serve role neither reads nor writes the list of every org's
	// subjects; only the 0054 trigger (as sbci_defs) writes it.
	for _, p := range privs {
		if tablePriv(t, pool, "sbci_api", "org_sub_seen", p) {
			t.Errorf("sbci_api holds %s on org_sub_seen", p)
		}
	}
	var definer bool
	var owner string
	if err := pool.QueryRow(ctx,
		`SELECT p.prosecdef, pg_get_userbyid(p.proowner) FROM pg_proc p WHERE p.proname = 'sbci_oidc_note_sub_seen'`).
		Scan(&definer, &owner); err != nil || !definer || owner != "sbci_defs" {
		t.Errorf("sbci_oidc_note_sub_seen: definer %v owner %q (%v), want a SECURITY DEFINER owned by sbci_defs", definer, owner, err)
	}
}

// oidcFixture is an active team org with one member, a client and a shared
// clock far enough ahead that promoted keys are usable.
type oidcFixture struct {
	app   *store.Store
	pool  *pgxpool.Pool
	owner string
	sub   string
	org   store.MyOrg
	rp    oidcRP
	clock *oidctest.Clock
}

type oidcRP struct{ clientID, redirect, verifier, state, nonce string }

func newOIDCFixture(t *testing.T) oidcFixture {
	t.Helper()
	ctx := context.Background()
	app, pool := newStore(t)
	api := newAPIStore(t, pool)
	owner := makeAccount(t, app)
	// The issuer signs the provider-asserted address (A4), never the display
	// profile.
	if err := app.UpsertVerifiedEmail(ctx, owner, "owner@example.com", true, time.Now()); err != nil {
		t.Fatalf("UpsertVerifiedEmail: %v", err)
	}
	var sub string
	if err := pool.QueryRow(ctx, `SELECT subject FROM identity_links WHERE account_id = $1::uuid`, owner).Scan(&sub); err != nil {
		t.Fatalf("read subject: %v", err)
	}
	org := provisionTeam(t, api, owner)
	if _, err := pool.Exec(ctx, `UPDATE orgs SET status = 'active' WHERE org_id = $1::uuid`, org.OrgID); err != nil {
		t.Fatalf("activate org: %v", err)
	}
	client, err := oidcissuer.ClientForOrg(org.OrgID, org.Slug, "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	if err := app.RegisterOIDCClient(ctx, client); err != nil {
		t.Fatalf("RegisterOIDCClient: %v", err)
	}
	return oidcFixture{
		app: app, pool: pool, owner: owner, sub: sub, org: org,
		rp: oidcRP{clientID: client.ClientID, redirect: client.RedirectURIs[0], verifier: strings.Repeat("v", 50), state: "st", nonce: "nn"},
		// Far enough ahead that a key promoted now (24h lead) is usable.
		clock: oidctest.NewClock(time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)),
	}
}

// replica is one serve process: its own sbci_api store and its own signer
// key, registered and promoted the way an operator would.
func (f oidcFixture) replica(t *testing.T, vm string) (*oidcissuer.Issuer, *rsa.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	key := oidctest.NewKey(t)
	signer, err := oidcissuer.NewLocalSigner(oidcTestIssuer, []*rsa.PrivateKey{key}, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: oidcTestIssuer, Store: newAPIStore(t, f.pool).OIDC(), Signer: signer, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.RegisterSignerKeys(ctx, vm); err != nil {
		t.Fatalf("RegisterSignerKeys: %v", err)
	}
	now := time.Now().UTC()
	if err := f.app.SetOIDCSigningKeyStatus(ctx, oidcissuer.Thumbprint(&key.PublicKey), oidcissuer.KeyActive,
		now.Add(oidcissuer.PublicationLead), now, oidcissuer.PublicationLead); err != nil {
		t.Fatalf("promote: %v", err)
	}
	return iss, key
}

func (f oidcFixture) authorize(t *testing.T, iss *oidcissuer.Issuer, account string) string {
	t.Helper()
	// The session authenticated a minute before, on the issuer's own clock
	// (the fixture's, which runs ahead of the wall clock).
	return f.authorizeSession(t, iss, oidcissuer.Session{AccountID: account, AuthTime: f.clock.Now().Add(-time.Minute)})
}

// authorizeSession is authorize from an explicit portal session (its
// authentication time may be zero: not known).
func (f oidcFixture) authorizeSession(t *testing.T, iss *oidcissuer.Issuer, sess oidcissuer.Session) string {
	t.Helper()
	res := iss.Authorize(context.Background(), oidcissuer.AuthorizeRequest{
		ClientID: f.rp.clientID, RedirectURI: f.rp.redirect, ResponseType: "code", Scope: "openid email",
		State: f.rp.state, Nonce: f.rp.nonce, CodeChallenge: oidcissuer.S256Challenge(f.rp.verifier), CodeChallengeMethod: "S256",
	}, sess)
	if res.Outcome != oidcissuer.OutcomeRedirect || res.Err != nil {
		t.Fatalf("authorize = %+v (%v)", res, res.Err)
	}
	i := strings.Index(res.Location, "code=")
	if i < 0 {
		t.Fatalf("no code in %s", res.Location)
	}
	code := res.Location[i+5:]
	if j := strings.IndexByte(code, '&'); j >= 0 {
		code = code[:j]
	}
	return code
}

func (f oidcFixture) token(code string) oidcissuer.TokenRequest {
	return oidcissuer.TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: f.rp.redirect,
		ClientID: f.rp.clientID, CodeVerifier: f.rp.verifier,
	}
}

func TestOIDCAuthorizeAndTokenOnDifferentReplicas(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	a, _ := f.replica(t, "vm-a")
	b, keyB := f.replica(t, "vm-b")

	code := f.authorize(t, a, f.owner)
	resp, err := b.Token(ctx, f.token(code))
	if err != nil {
		t.Fatalf("token on replica B: %v", err)
	}
	c, err := oidcissuer.VerifyRS256(resp.IDToken, oidcissuer.PublicJWK(&keyB.PublicKey))
	if err != nil {
		t.Fatalf("token not signed by replica B's key: %v", err)
	}
	if c.Org != f.org.OrgID || c.Aud != f.rp.clientID || c.Sub != f.sub || c.Email != "owner@example.com" || c.Nonce != f.rp.nonce {
		t.Errorf("claims = %+v", c)
	}
	// auth_time crossed replicas through oidc_codes.auth_time (cloud 0083):
	// the session's authentication a minute before, not the mint time.
	if d := c.Iat - c.AuthTime; c.AuthTime == 0 || d < 55 || d > 120 {
		t.Errorf("auth_time %d, iat %d: want the session's authentication about a minute before iat", c.AuthTime, c.Iat)
	}
	doc, err := a.JWKS(ctx)
	if err != nil || len(doc.Keys) != 2 {
		t.Fatalf("JWKS on replica A = %d keys (%v), want both VMs'", len(doc.Keys), err)
	}

	// The record: issued row, pending mirror row with the jti, and the
	// trigger's org_sub_seen row.
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM oidc_issued WHERE jti=$1 AND org_id=$2::uuid AND account_id=$3::uuid AND sub=$4`,
		c.Jti, f.org.OrgID, f.owner, f.sub); n != 1 {
		t.Errorf("oidc_issued rows = %d", n)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM oidc_audit_mirror WHERE jti=$1 AND state='pending' AND payload->>'sub'=$2 AND NOT payload ? 'email'`,
		c.Jti, f.sub); n != 1 {
		t.Errorf("oidc_audit_mirror rows = %d", n)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_sub_seen WHERE org_id=$1::uuid AND sub=$2`, f.org.OrgID, f.sub); n != 1 {
		t.Errorf("org_sub_seen rows = %d", n)
	}

	// Replay on the other replica: refused.
	if _, err := a.Token(ctx, f.token(code)); err == nil {
		t.Fatal("a code was redeemed twice across replicas")
	}
	// Expiry: 60 seconds.
	code = f.authorize(t, b, f.owner)
	f.clock.Advance(oidcissuer.CodeTTL)
	if _, err := a.Token(ctx, f.token(code)); err == nil {
		t.Fatal("an expired code was redeemed")
	}
	// A second sign-in moves org_sub_seen.last_seen forward, never back.
	f.clock.Advance(time.Hour)
	code = f.authorize(t, a, f.owner)
	if _, err := b.Token(ctx, f.token(code)); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_sub_seen WHERE org_id=$1::uuid AND sub=$2 AND last_seen > first_seen`, f.org.OrgID, f.sub); n != 1 {
		t.Error("org_sub_seen.last_seen did not move forward")
	}
}

// TestOIDCUnknownAuthTimeCrossesAsAbsent: a portal session whose
// authentication time is not known (an ordinary AuthKit sign-in) yields a
// code whose auth_time is NULL, and the token minted from it on the other
// replica carries no auth_time, never a filled-in one (cloud 0083).
func TestOIDCUnknownAuthTimeCrossesAsAbsent(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	a, _ := f.replica(t, "vm-a")
	b, keyB := f.replica(t, "vm-b")

	code := f.authorizeSession(t, a, oidcissuer.Session{AccountID: f.owner})
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM oidc_codes WHERE code_hash=$1 AND auth_time IS NULL`,
		oidcissuer.HashCode(code)); n != 1 {
		t.Fatalf("oidc_codes rows with a NULL auth_time = %d, want 1", n)
	}
	resp, err := b.Token(ctx, f.token(code))
	if err != nil {
		t.Fatalf("token on replica B: %v", err)
	}
	c, err := oidcissuer.VerifyRS256(resp.IDToken, oidcissuer.PublicJWK(&keyB.PublicKey))
	if err != nil {
		t.Fatalf("token not signed by replica B's key: %v", err)
	}
	if c.AuthTime != 0 {
		t.Errorf("auth_time = %d, want none for a session whose authentication time is not known", c.AuthTime)
	}
}

func TestOIDCCodeIsSingleUseUnderConcurrency(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	a, _ := f.replica(t, "vm-a")
	code := f.authorize(t, a, f.owner)
	hash := oidcissuer.HashCode(code)

	const racers = 8
	var wg sync.WaitGroup
	wins := make(chan struct{}, racers)
	now := f.clock.Now()
	for i := 0; i < racers; i++ {
		replica := newAPIStore(t, f.pool).OIDC()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := replica.ConsumeCode(ctx, hash, now); err == nil {
				wins <- struct{}{}
			} else if !errors.Is(err, oidcissuer.ErrNotFound) {
				t.Errorf("ConsumeCode: %v", err)
			}
		}()
	}
	wg.Wait()
	close(wins)
	if n := len(wins); n != 1 {
		t.Fatalf("%d concurrent redemptions won, want exactly 1", n)
	}
}

func TestOIDCRecordIssuanceIsAtomic(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	api := newAPIStore(t, f.pool).OIDC()
	now := time.Now().UTC().Truncate(time.Second)
	iss := oidcissuer.Issuance{
		JTI: strings.Repeat("a", 32), OrgID: f.org.OrgID, AccountID: f.owner, Sub: f.sub, ClientID: f.rp.clientID,
		KID: strings.Repeat("k", 43), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	// The mirror insert fails (its payload names another jti): nothing lands.
	bad := iss
	bad.MirrorPayload = []byte(`{"jti":"someone-else"}`)
	if err := api.RecordIssuance(ctx, bad); err == nil {
		t.Fatal("RecordIssuance succeeded with a failing mirror insert")
	}
	for table, sql := range map[string]string{
		"oidc_issued":  `SELECT count(*) FROM oidc_issued WHERE jti=$1`,
		"org_sub_seen": `SELECT count(*) FROM org_sub_seen WHERE sub=$1`,
	} {
		arg := iss.JTI
		if table == "org_sub_seen" {
			arg = f.sub
		}
		if n := countAdmin(t, f.pool, sql, arg); n != 0 {
			t.Errorf("%s holds %d rows after the failed record", table, n)
		}
	}
	// The good record lands; the same jti a second time is refused.
	payload, err := oidcissuer.AuditMirrorPayload(iss)
	if err != nil {
		t.Fatal(err)
	}
	iss.MirrorPayload = payload
	if err := api.RecordIssuance(ctx, iss); err != nil {
		t.Fatalf("RecordIssuance: %v", err)
	}
	if err := api.RecordIssuance(ctx, iss); err == nil {
		t.Fatal("a jti was recorded twice")
	}
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM org_sub_seen WHERE org_id=$1::uuid AND sub=$2`, f.org.OrgID, f.sub); n != 1 {
		t.Errorf("org_sub_seen rows after one record = %d, want 1", n)
	}
}

func TestOIDCMemberThroughMembership(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	api := newAPIStore(t, f.pool).OIDC()

	m, err := api.Member(ctx, f.owner, f.org.OrgID)
	if err != nil || !m.IsMember || m.OrgStatus != "active" || m.AccountStatus != "active" || !m.RailEnabled ||
		m.Sub != f.sub || m.Email != "owner@example.com" {
		t.Fatalf("owner Member = %+v, %v", m, err)
	}
	outsider := makeAccount(t, f.app)
	if m, err := api.Member(ctx, outsider, f.org.OrgID); err != nil || m.IsMember {
		t.Errorf("outsider Member = %+v, %v; want not a member", m, err)
	}
	if m, err := api.Member(ctx, f.owner, "not-a-uuid"); err != nil || m.IsMember {
		t.Errorf("malformed org Member = %+v, %v", m, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status='suspended' WHERE org_id=$1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if m, _ := api.Member(ctx, f.owner, f.org.OrgID); m.OrgStatus != "suspended" {
		t.Errorf("suspended org reads as %q", m.OrgStatus)
	}
	// Client lookups.
	if c, err := api.Client(ctx, f.rp.clientID); err != nil || c.OrgID != f.org.OrgID || len(c.RedirectURIs) != 1 || c.Disabled {
		t.Errorf("Client = %+v, %v", c, err)
	}
	if _, err := api.Client(ctx, "org:00000000-0000-4000-8000-000000000000"); !errors.Is(err, oidcissuer.ErrNotFound) {
		t.Errorf("unknown client = %v", err)
	}
	// One client per org, and its id must be the org's.
	again, _ := oidcissuer.ClientForOrg(f.org.OrgID, f.org.Slug, "superbased.app")
	if err := f.app.RegisterOIDCClient(ctx, again); err == nil {
		t.Error("a second client was registered for one org")
	}
	forged := again
	forged.ClientID = "org:00000000-0000-4000-8000-000000000000"
	if err := f.app.RegisterOIDCClient(ctx, forged); err == nil {
		t.Error("a client id naming another org was accepted")
	}
}

func TestOIDCSigningKeyLifecycle(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	api := newAPIStore(t, f.pool).OIDC()
	key := oidctest.NewKey(t)
	jwk := oidcissuer.PublicJWK(&key.PublicKey)
	now := time.Now().UTC()

	if err := api.StageSigningKeys(ctx, "vm-a", []oidcissuer.PublicKey{{KID: jwk.Kid, JWK: jwk}}, now); err != nil {
		t.Fatalf("StageSigningKeys: %v", err)
	}
	keys, err := api.SigningKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Status != oidcissuer.KeyStaged || keys[0].JWK != jwk {
		t.Fatalf("SigningKeys = %+v, %v", keys, err)
	}
	if err := f.app.SetOIDCSigningKeyStatus(ctx, jwk.Kid, oidcissuer.KeyActive, now.Add(time.Hour), now, oidcissuer.PublicationLead); err == nil {
		t.Error("a promotion inside the publication lead was accepted")
	}
	if err := f.app.SetOIDCSigningKeyStatus(ctx, jwk.Kid, oidcissuer.KeyRetiring, time.Time{}, now, 0); err == nil {
		t.Error("staged -> retiring was accepted")
	}
	if err := f.app.SetOIDCSigningKeyStatus(ctx, jwk.Kid, oidcissuer.KeyActive, now.Add(oidcissuer.PublicationLead), now, oidcissuer.PublicationLead); err != nil {
		t.Fatalf("promote: %v", err)
	}
	// Restaging the same key is a no-op: a signer restart never demotes it.
	if err := api.StageSigningKeys(ctx, "vm-a", []oidcissuer.PublicKey{{KID: jwk.Kid, JWK: jwk}}, now); err != nil {
		t.Fatal(err)
	}
	if keys, _ := api.SigningKeys(ctx); len(keys) != 1 || keys[0].Status != oidcissuer.KeyActive || keys[0].NotBefore.IsZero() {
		t.Fatalf("after restage: %+v", keys)
	}
	for _, to := range []string{oidcissuer.KeyRetiring, oidcissuer.KeyRetired} {
		if err := f.app.SetOIDCSigningKeyStatus(ctx, jwk.Kid, to, time.Time{}, now, 0); err != nil {
			t.Fatalf("-> %s: %v", to, err)
		}
	}
	if keys, _ := api.SigningKeys(ctx); len(keys) != 0 {
		t.Errorf("a retired key is still listed: %+v", keys)
	}
	if err := f.app.SetOIDCSigningKeyStatus(ctx, strings.Repeat("z", 43), oidcissuer.KeyRetired, time.Time{}, now, 0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown kid = %v, want ErrNotFound", err)
	}
	// The serve role cannot promote.
	if err := newAPIStore(t, f.pool).SetOIDCSigningKeyStatus(ctx, jwk.Kid, oidcissuer.KeyRetired, time.Time{}, now, 0); err == nil {
		t.Error("sbci_api changed a key's status")
	}
	// A malformed key is never staged.
	bad := jwk
	bad.N = "AQAB"
	if err := api.StageSigningKeys(ctx, "vm-a", []oidcissuer.PublicKey{{KID: bad.Kid, JWK: bad}}, now); err == nil {
		t.Error("a malformed key was staged")
	}
}

func TestOIDCSweepCodes(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	a, _ := f.replica(t, "vm-a")
	_ = f.authorize(t, a, f.owner)
	if n := countAdmin(t, f.pool, `SELECT count(*) FROM oidc_codes WHERE account_id=$1::uuid`, f.owner); n != 1 {
		t.Fatalf("codes = %d", n)
	}
	if n, err := newAPIStore(t, f.pool).SweepOIDCCodes(ctx, f.clock.Now()); err != nil || n != 0 {
		t.Fatalf("early sweep removed %d (%v)", n, err)
	}
	n, err := newAPIStore(t, f.pool).SweepOIDCCodes(ctx, f.clock.Now().Add(oidcissuer.CodeTTL+time.Second))
	if err != nil || n != 1 {
		t.Fatalf("sweep removed %d (%v), want 1", n, err)
	}
}

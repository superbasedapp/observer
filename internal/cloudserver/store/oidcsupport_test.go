package store_test

import (
	"context"
	"crypto/rsa"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// oidcsupport_test.go proves the issuer's support path (M7a.2, cloud
// 0087-0088) against Postgres, each half on its real role: the staff process
// writes the support code and its staff_actions row as sbci_staff; the serve
// process (sbci_api) redeems it, re-checks the staff member and the org
// through sbci_support_target, signs and records. Needs Postgres
// (cloudtestpg; SKIPPED loudly without SBCI_TEST_PG_DSN).

func newStaffRoleStore(t *testing.T, f oidcFixture) *store.Store {
	t.Helper()
	s, err := store.NewForRole(f.pool, store.RoleStaff)
	if err != nil {
		t.Fatalf("NewForRole(staff): %v", err)
	}
	return s
}

// supportReplica is a serve replica with the support seam wired.
func (f oidcFixture) supportReplica(t *testing.T, vm string) *oidcissuer.Issuer {
	t.Helper()
	ctx := context.Background()
	key := oidctest.NewKey(t)
	signer, err := oidcissuer.NewLocalSigner(oidcTestIssuer, []*rsa.PrivateKey{key}, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api := newAPIStore(t, f.pool)
	iss, err := oidcissuer.New(oidcissuer.Config{Issuer: oidcTestIssuer, Store: api.OIDC(), Signer: signer, Now: f.clock.Now, Support: api.OIDC()})
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
	return iss
}

func (f oidcFixture) supportCode(t *testing.T, staff *store.Store, staffID string) string {
	t.Helper()
	authz, err := oidcissuer.NewSupportAuthorizer(oidcissuer.SupportAuthorizerConfig{Issuer: oidcTestIssuer, Store: staff.StaffOIDC(), Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	res := authz.Authorize(context.Background(), oidcissuer.AuthorizeRequest{
		ClientID: f.rp.clientID, RedirectURI: f.rp.redirect, ResponseType: "code", Scope: "openid",
		State: f.rp.state, Nonce: f.rp.nonce, CodeChallenge: oidcissuer.S256Challenge(f.rp.verifier), CodeChallengeMethod: "S256",
	}, oidcissuer.StaffSession{StaffID: staffID, AssertedAt: f.clock.Now().Add(-time.Minute)})
	if res.Outcome != oidcissuer.OutcomeRedirect || res.Err != nil {
		t.Fatalf("support authorize = %+v (%v)", res, res.Err)
	}
	u, err := url.Parse(res.Location)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

func TestSupportSignInOverPostgres(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	ctx := context.Background()
	staffID, _ := registerTestStaff(t, f.app, staffauth.RoleSupport, 41, time.Now())
	staff := newStaffRoleStore(t, f)
	iss := f.supportReplica(t, "vm-a")

	code := f.supportCode(t, staff, staffID)
	// The code was written with its staff_actions row, in one transaction.
	var verb, org, target string
	if err := f.pool.QueryRow(ctx,
		`SELECT verb, org_id::text, target FROM staff_actions WHERE subject_staff_id = $1::uuid AND verb = 'support.signin'`, staffID).
		Scan(&verb, &org, &target); err != nil || org != f.org.OrgID || target != f.rp.clientID {
		t.Fatalf("staff action %q %q %q (%v)", verb, org, target, err)
	}
	resp, err := iss.Token(ctx, f.token(code))
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if strings.Contains(resp.IDToken, ".") == false {
		t.Fatal("no token")
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM oidc_support_issued WHERE staff_id = $1::uuid AND org_id = $2::uuid`, staffID, f.org.OrgID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("oidc_support_issued rows = %d (%v)", n, err)
	}
	// Single use, across the two tables.
	if _, err := iss.Token(ctx, f.token(code)); err == nil {
		t.Fatal("support code redeemed twice")
	}
	// A disabled staff member's code is refused at token time.
	code = f.supportCode(t, staff, staffID)
	if _, err := f.pool.Exec(ctx, `UPDATE staff_users SET status = 'disabled', disabled_at = now() WHERE staff_id = $1::uuid`, staffID); err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Token(ctx, f.token(code)); err == nil {
		t.Fatal("a disabled staff member's support code was redeemed")
	}
}

// TestSupportTargetReadsNothingElse: the definer read answers three facts and
// a malformed id is nobody, nowhere.
func TestSupportTargetReadsNothingElse(t *testing.T) {
	t.Parallel()
	f := newOIDCFixture(t)
	api := newAPIStore(t, f.pool)
	staffID, _ := registerTestStaff(t, f.app, staffauth.RoleSupport, 43, time.Now())
	got, err := api.OIDC().SupportTarget(context.Background(), staffID, f.org.OrgID)
	if err != nil || !got.StaffActive || got.OrgStatus != "active" || !got.RailEnabled {
		t.Fatalf("SupportTarget = %+v (%v)", got, err)
	}
	got, err = api.OIDC().SupportTarget(context.Background(), "not-a-uuid", f.org.OrgID)
	if err != nil || got.StaffActive || got.OrgStatus != "" {
		t.Fatalf("malformed staff id = %+v (%v)", got, err)
	}
}

// TestSupportGrantsAreNarrow: sbci_staff may write a support code and read
// the client table, nothing else of the issuer; the serve role cannot write a
// support code (only the staff process mints one).
func TestSupportGrantsAreNarrow(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	for _, tc := range []struct {
		role, table, priv string
		want              bool
	}{
		{"sbci_staff", "oidc_support_codes", "INSERT", true},
		{"sbci_staff", "oidc_support_codes", "SELECT", false},
		{"sbci_staff", "oidc_support_codes", "UPDATE", false},
		{"sbci_staff", "oidc_support_issued", "INSERT", false},
		{"sbci_staff", "oidc_clients", "SELECT", true},
		{"sbci_staff", "oidc_clients", "INSERT", false},
		{"sbci_staff", "oidc_codes", "SELECT", false},
		{"sbci_staff", "oidc_issued", "INSERT", false},
		{"sbci_api", "oidc_support_codes", "INSERT", false},
		{"sbci_api", "staff_users", "SELECT", false},
	} {
		if got := tablePriv(t, pool, tc.role, tc.table, tc.priv); got != tc.want {
			t.Errorf("%s %s on %s = %v, want %v", tc.role, tc.priv, tc.table, got, tc.want)
		}
	}
	if !columnPriv(t, pool, "sbci_api", "oidc_support_codes", "consumed_at", "UPDATE") ||
		columnPriv(t, pool, "sbci_api", "oidc_support_codes", "staff_id", "UPDATE") {
		t.Error("sbci_api may only mark a support code consumed")
	}
}

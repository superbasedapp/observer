package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Stream 4 (row G2-13): the store half of the §10 identity adversarial set and
// the D18 account-lifecycle transitions (create → verify → suspend → revoke →
// delete → reactivate). Every test here must FAIL if the defence it pins is
// removed; the coverage-notes doc maps each §10 row to its test func.
//
// The API half lives in internal/cloudserver/api/s10_*_test.go; this file pins
// the store seams those handlers stand on so a defect cannot hide behind an
// HTTP layer that happens to also refuse.

// portalSessionValid reports whether a raw portal session cookie still resolves
// to a live, active principal.
func portalSessionValid(t *testing.T, s *store.Store, raw string) bool {
	t.Helper()
	bp, err := s.IntrospectBrowserSession(context.Background(), raw, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	return bp.Valid
}

// setAccountStatus forces an account into a lifecycle state the normal seams do
// not expose directly (the deletion path jumps straight to 'deleted', so
// 'closed' has to be set for the reactivation-guard table). It is test-only
// setup, exactly as deletion_w6d_test.go resets status via the raw pool.
func setAccountStatus(t *testing.T, pool *pgxpool.Pool, accountID, status string) {
	t.Helper()
	ct, err := pool.Exec(context.Background(),
		`UPDATE accounts SET status = $2 WHERE account_id = $1::uuid`, accountID, status)
	if err != nil {
		t.Fatalf("force status %q: %v", status, err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("force status %q affected %d rows", status, ct.RowsAffected())
	}
}

// freshPubKey mints a throwaway Ed25519 public key for a device registration.
func freshPubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub
}

// --- §10-I6 no-email-only-merge --------------------------------------------

// TestS10_NoMergeByEmail pins the amendment's hard rule "Never merge accounts
// solely because two identities report the same email." The identity link is
// keyed on (provider, subject) ONLY — email is display-only on Identity and
// never a merge key — so two distinct subjects are two accounts, and one
// subject is always one account, regardless of any email they might carry.
//
// It would fail if resolveOrCreateAccountTx ever keyed on, or fell back to,
// email.
func TestS10_NoMergeByEmail(t *testing.T) {
	s, _ := newStore(t)

	// Same email at the provider, two different WorkOS subjects.
	a := exchangeDevice(t, s, "workos", fmt.Sprintf("user_A_%d", subjCounter.Add(1)))
	b := exchangeDevice(t, s, "workos", fmt.Sprintf("user_B_%d", subjCounter.Add(1)))
	if a.AccountID == b.AccountID {
		t.Fatalf("two distinct subjects merged into one account %s — email-merge leak", a.AccountID)
	}

	// The SAME subject always resolves to the SAME account (device re-enrolment /
	// second device), never a new one.
	sub := fmt.Sprintf("user_same_%d", subjCounter.Add(1))
	c1 := exchangeDevice(t, s, "workos", sub)
	c2 := exchangeDevice(t, s, "workos", sub)
	if c1.AccountID != c2.AccountID {
		t.Fatalf("same subject split across accounts: %s vs %s", c1.AccountID, c2.AccountID)
	}
}

// --- D18 suspend → refuse-remint at every mint path ------------------------

// TestS10_SuspendedRefusesEveryMintPath is the durability property behind the
// WorkOS lifecycle revocation (F8, D18): once an account is suspended, NO entry
// point may mint a fresh credential from the still-valid identity, and the
// credentials suspension revoked stay dead. This is the "a revoked identity
// cannot re-mint via any path" invariant, checked at the store seam every
// handler calls.
func TestS10_SuspendedRefusesEveryMintPath(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sub := fmt.Sprintf("suspendable-%d", subjCounter.Add(1))
	dev := exchangeDevice(t, s, "workos", sub)
	sess, err := s.PortalLogin(ctx, "workos", sub, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	if !tokenValid(t, s, dev.Token) || !portalSessionValid(t, s, sess.RawSession) {
		t.Fatal("precondition: fresh credentials must be valid")
	}

	rev, err := s.RevokeAndSuspendAccount(ctx, dev.AccountID, now)
	if err != nil {
		t.Fatalf("RevokeAndSuspendAccount: %v", err)
	}
	if !rev.Suspended || rev.TokensRevoked == 0 || rev.SessionsRevoked == 0 || rev.DevicesRevoked == 0 {
		t.Fatalf("suspension did not propagate to every credential: %+v", rev)
	}

	// Existing credentials are dead (introspection gates on active + unrevoked).
	if tokenValid(t, s, dev.Token) {
		t.Fatal("api token still valid after suspension")
	}
	if portalSessionValid(t, s, sess.RawSession) {
		t.Fatal("browser session still valid after suspension")
	}

	// And nothing may mint a NEW credential from the same identity.
	if _, err := s.Exchange(ctx, exchangeInputFor(t, s, "workos", sub)); !errors.Is(err, store.ErrAccountSuspended) {
		t.Fatalf("device Exchange on suspended account: err=%v, want ErrAccountSuspended", err)
	}
	if _, err := s.PortalLogin(ctx, "workos", sub, 0, now); !errors.Is(err, store.ErrAccountSuspended) {
		t.Fatalf("PortalLogin on suspended account: err=%v, want ErrAccountSuspended", err)
	}
	// A revoked session cannot be rehydrated into a working CSRF token either.
	if _, err := s.RotateBrowserCSRF(ctx, dev.AccountID, sess.RawSession, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RotateBrowserCSRF on revoked session: err=%v, want ErrNotFound", err)
	}
}

// --- D18 reactivation guard (recovery) -------------------------------------

// TestS10_ReactivateOnlySuspended pins the reactivation transition's whole
// safety property: it lifts ONLY a 'suspended' account, and REFUSES a 'closed'
// or 'deleted' tombstone (irreversible) and a still-'active' account (nothing to
// do). Removing the `AND status = 'suspended'` guard would let a deleted account
// walk back to active — the exact invariant this table forbids.
func TestS10_ReactivateOnlySuspended(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	cases := []struct {
		name    string
		status  string
		wantErr bool
	}{
		{"suspended_reactivates", "suspended", false},
		{"active_refused", "active", true},
		{"closed_refused", "closed", true},
		{"deleted_refused", "deleted", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acct := makeAccount(t, s)
			setAccountStatus(t, pool, acct, tc.status)

			err := s.ReactivateAccount(ctx, acct, now)
			if tc.wantErr {
				if !errors.Is(err, store.ErrAccountNotReactivatable) {
					t.Fatalf("Reactivate(%s): err=%v, want ErrAccountNotReactivatable", tc.status, err)
				}
				// The status must be UNCHANGED — a refused reactivation may not move
				// a tombstone at all.
				if got := statusOf(t, s, acct); got != tc.status {
					t.Fatalf("refused reactivation moved status %s → %s", tc.status, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reactivate(%s): unexpected err %v", tc.status, err)
			}
			if got := statusOf(t, s, acct); got != "active" {
				t.Fatalf("reactivated account status=%s, want active", got)
			}
		})
	}
}

// TestS10_ReactivationRestoresSignIn is the end-to-end recovery flow: a
// suspended identity is refused at sign-in, an operator reactivation lifts the
// suspension, and a FRESH sign-in for the SAME identity succeeds and resolves to
// the SAME account (the identity link was never purged — that is what separates
// recovery from deletion).
func TestS10_ReactivationRestoresSignIn(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sub := fmt.Sprintf("recover-%d", subjCounter.Add(1))
	dev := exchangeDevice(t, s, "workos", sub)
	if _, err := s.RevokeAndSuspendAccount(ctx, dev.AccountID, now); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := s.PortalLogin(ctx, "workos", sub, 0, now); !errors.Is(err, store.ErrAccountSuspended) {
		t.Fatalf("suspended sign-in: err=%v, want ErrAccountSuspended", err)
	}

	if err := s.ReactivateAccount(ctx, dev.AccountID, now); err != nil {
		t.Fatalf("ReactivateAccount: %v", err)
	}

	sess, err := s.PortalLogin(ctx, "workos", sub, 0, now)
	if err != nil {
		t.Fatalf("post-reactivation sign-in: %v", err)
	}
	if sess.AccountID != dev.AccountID {
		t.Fatalf("recovery re-keyed the account: %s → %s", dev.AccountID, sess.AccountID)
	}
	// The OLD revoked device token stays dead — recovery is "you may mint new
	// credentials", not "your dead tokens revive".
	if tokenValid(t, s, dev.Token) {
		t.Fatal("reactivation resurrected a revoked device token")
	}
}

// --- D18 delete → sign-in is a fresh account -------------------------------

// TestS10_DeletionThenSignInIsAFreshAccount pins the deletion-then-login
// semantics: user-initiated deletion purges the identity link and tombstones the
// account 'deleted' irreversibly, so a later sign-in with the SAME subject mints
// a BRAND-NEW active account (a clean start) and can never resurrect the deleted
// account's data or flip its tombstone back to active.
func TestS10_DeletionThenSignInIsAFreshAccount(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sub := fmt.Sprintf("delete-then-login-%d", subjCounter.Add(1))
	first := exchangeDevice(t, s, "workos", sub)

	if _, err := s.CreateDeletionRequest(ctx, first.AccountID, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if got := statusOf(t, s, first.AccountID); got != "deleted" {
		t.Fatalf("post-deletion status=%s, want deleted", got)
	}

	// Same subject signs in again: a NEW account, and the old tombstone is
	// untouched.
	second := exchangeDevice(t, s, "workos", sub)
	if second.AccountID == first.AccountID {
		t.Fatal("sign-in after deletion resurrected the deleted account")
	}
	if got := statusOf(t, s, second.AccountID); got != "active" {
		t.Fatalf("fresh post-deletion account status=%s, want active", got)
	}
	if got := statusOf(t, s, first.AccountID); got != "deleted" {
		t.Fatalf("deletion tombstone changed to %s after re-login", got)
	}
	// The reactivation lever cannot touch a deleted tombstone either.
	if err := s.ReactivateAccount(ctx, first.AccountID, now); !errors.Is(err, store.ErrAccountNotReactivatable) {
		t.Fatalf("Reactivate(deleted): err=%v, want ErrAccountNotReactivatable", err)
	}
}

// --- §10-I5 cross-account repository isolation (RLS + WHERE scope) ----------

// TestS10_CrossAccountRepositoryIsolation samples the tenant-scoped write seams
// with a FOREIGN account id: a credential owned by account A can never be
// addressed under account B's scope. Every seam here derives its scope from the
// caller-supplied account and the RLS GUC, so a well-formed id from another
// tenant matches zero rows.
func TestS10_CrossAccountRepositoryIsolation(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	victim := exchangeDevice(t, s, "workos", fmt.Sprintf("victim-%d", subjCounter.Add(1)))
	attacker := exchangeDevice(t, s, "workos", fmt.Sprintf("attacker-%d", subjCounter.Add(1)))
	victimTokenID := tokenIDOf(t, s, victim.Token)
	victimDeviceID := victim.DeviceID

	// Attacker tries to revoke the victim's token under the attacker's scope.
	if err := s.RevokeAPIToken(ctx, attacker.AccountID, victimTokenID, now); err != nil {
		t.Fatalf("RevokeAPIToken (foreign) returned error instead of no-op: %v", err)
	}
	if !tokenValid(t, s, victim.Token) {
		t.Fatal("cross-account RevokeAPIToken killed the victim's token")
	}

	// Attacker tries to revoke the victim's device under the attacker's scope.
	if err := s.RevokeDevice(ctx, attacker.AccountID, victimDeviceID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RevokeDevice (foreign): err=%v, want ErrNotFound", err)
	}
	if !tokenValid(t, s, victim.Token) {
		t.Fatal("cross-account RevokeDevice killed the victim's token")
	}
}

// exchangeInputFor builds a valid ExchangeInput (fresh nonce + keypair) for
// (provider, subject) so a suspended-account remint attempt reaches the status
// gate rather than failing on a spent nonce.
func exchangeInputFor(t *testing.T, s *store.Store, provider, subject string) store.ExchangeInput {
	t.Helper()
	nonce, err := s.MintNonce(context.Background(), store.DefaultNonceTTL, time.Now())
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub := freshPubKey(t)
	return store.ExchangeInput{
		Provider: provider, Subject: subject, PublicKey: pub,
		Label: "remint-attempt", RawNonce: nonce, Now: time.Now(),
	}
}

// statusOf reads an account's lifecycle status through the AccountStatus seam.
func statusOf(t *testing.T, s *store.Store, accountID string) string {
	t.Helper()
	st, err := s.AccountStatus(context.Background(), accountID)
	if err != nil {
		t.Fatalf("AccountStatus: %v", err)
	}
	return st
}

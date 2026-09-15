package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// sha256Hex mirrors the store's internal hashSecret (hex sha256) so a test can
// address a row by the hash of the raw secret it holds.
func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func hashOf(raw string) string { return sha256Hex(raw) }

func loginTxn(stateHash string, now time.Time) store.AuthTransactionInput {
	return store.AuthTransactionInput{
		StateHash:    stateHash,
		PKCEVerifier: "verifier-" + stateHash[:8],
		NonceHash:    hashOf("nonce-" + stateHash[:8]),
		RedirectURI:  "https://app.example/portal/auth/workos/callback",
		Purpose:      store.AuthPurposeLogin,
		ReturnTo:     "/portal/",
		Now:          now,
	}
}

func TestAuthTransactionSingleUse(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	stateHash := hashOf("state-single-use")
	in := loginTxn(stateHash, now)
	id, err := s.CreateAuthTransaction(ctx, in)
	if err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	if id == "" {
		t.Fatal("CreateAuthTransaction returned an empty id")
	}

	txn, err := s.ConsumeAuthTransaction(ctx, stateHash, now)
	if err != nil {
		t.Fatalf("ConsumeAuthTransaction: %v", err)
	}
	if txn.PKCEVerifier != in.PKCEVerifier {
		t.Fatalf("verifier round-trip: got %q want %q", txn.PKCEVerifier, in.PKCEVerifier)
	}
	if txn.Purpose != store.AuthPurposeLogin || txn.RedirectURI != in.RedirectURI || txn.ReturnTo != "/portal/" {
		t.Fatalf("consumed transaction mismatched: %+v", txn)
	}
	if txn.AccountID != "" || txn.SessionID != "" || txn.Action != "" {
		t.Fatalf("login transaction carried a step-up binding: %+v", txn)
	}

	// Replay: the second consume finds nothing.
	if _, err := s.ConsumeAuthTransaction(ctx, stateHash, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replayed consume err=%v, want ErrNotFound", err)
	}
}

func TestAuthTransactionRejectsUnknownAndExpired(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	if _, err := s.ConsumeAuthTransaction(ctx, hashOf("never-minted"), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown state err=%v, want ErrNotFound", err)
	}

	stateHash := hashOf("state-expired")
	in := loginTxn(stateHash, now)
	in.TTL = time.Minute
	if _, err := s.CreateAuthTransaction(ctx, in); err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	// Two minutes later the row is past expires_at.
	if _, err := s.ConsumeAuthTransaction(ctx, stateHash, now.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired consume err=%v, want ErrNotFound", err)
	}
}

func TestAuthTransactionPKCEVerifierEncryptedAtRest(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	stateHash := hashOf("state-encrypted")
	in := loginTxn(stateHash, now)
	in.PKCEVerifier = "a-very-recognizable-verifier-value"
	if _, err := s.CreateAuthTransaction(ctx, in); err != nil {
		t.Fatalf("CreateAuthTransaction: %v", err)
	}
	var stored []byte
	if err := pool.QueryRow(ctx,
		`SELECT pkce_verifier_enc FROM auth_transactions WHERE state_hash = $1`, stateHash).Scan(&stored); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if strings.Contains(string(stored), in.PKCEVerifier) {
		t.Fatal("PKCE verifier is stored in the clear")
	}
}

func TestAuthTransactionPurposeShapeRefused(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	account := makeAccount(t, s)

	cases := []struct {
		name string
		mut  func(*store.AuthTransactionInput)
	}{
		{"login with account binding", func(in *store.AuthTransactionInput) { in.AccountID = account }},
		{"login with action", func(in *store.AuthTransactionInput) { in.Action = store.StepUpActionDeletion }},
		{"step-up without session", func(in *store.AuthTransactionInput) {
			in.Purpose = store.AuthPurposeStepUp
			in.Action = store.StepUpActionDeletion
			in.AccountID = account
		}},
		{"unknown purpose", func(in *store.AuthTransactionInput) { in.Purpose = "sideways" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := loginTxn(hashOf("shape-"+tc.name), now)
			tc.mut(&in)
			if _, err := s.CreateAuthTransaction(ctx, in); err == nil {
				t.Fatal("CreateAuthTransaction accepted a mis-shaped transaction")
			}
		})
	}
}

func TestRotateBrowserCSRF(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sess, err := s.PortalLogin(ctx, "dev", "rotate-rita", 0, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	rot, err := s.RotateBrowserCSRF(ctx, sess.AccountID, sess.RawSession, now)
	if err != nil {
		t.Fatalf("RotateBrowserCSRF: %v", err)
	}
	if rot.RawCSRFToken == "" || rot.RawCSRFToken == sess.RawCSRFToken {
		t.Fatalf("rotation returned an empty or unchanged token (%q)", rot.RawCSRFToken)
	}
	if !rot.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("rotation reported expiry %v, want the session's %v", rot.ExpiresAt, sess.ExpiresAt)
	}
	// The stored hash now matches the NEW token: introspection reflects it.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	if bp.CSRFHash != sha256Hex(rot.RawCSRFToken) {
		t.Fatal("session csrf_hash does not match the rotated token")
	}
	if bp.CSRFHash == sha256Hex(sess.RawCSRFToken) {
		t.Fatal("the pre-rotation token still validates")
	}

	// A revoked session cannot mint a CSRF token.
	if err := s.RevokeBrowserSession(ctx, sess.AccountID, sess.RawSession, now); err != nil {
		t.Fatalf("RevokeBrowserSession: %v", err)
	}
	if _, err := s.RotateBrowserCSRF(ctx, sess.AccountID, sess.RawSession, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotate on revoked session err=%v, want ErrNotFound", err)
	}
}

func TestRotateBrowserCSRFExpiredSession(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sess, err := s.PortalLogin(ctx, "dev", "rotate-expired", time.Minute, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	if _, err := s.RotateBrowserCSRF(ctx, sess.AccountID, sess.RawSession, now.Add(2*time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotate on expired session err=%v, want ErrNotFound", err)
	}
}

// stepUpFixture signs an account into the portal and mints a deletion step-up
// bound to that session.
func stepUpFixture(t *testing.T, s *store.Store, subject string, now time.Time) (store.PortalSession, string, string) {
	t.Helper()
	ctx := context.Background()
	sess, err := s.PortalLogin(ctx, "dev", subject, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin: %v", err)
	}
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err != nil {
		t.Fatalf("IntrospectBrowserSession: %v", err)
	}
	authz, err := s.CreateStepUpAuthorization(ctx, sess.AccountID, bp.SessionID, store.StepUpActionDeletion, now)
	if err != nil {
		t.Fatalf("CreateStepUpAuthorization: %v", err)
	}
	if !authz.ExpiresAt.After(now) || authz.ExpiresAt.After(now.Add(store.DefaultStepUpTTL+time.Second)) {
		t.Fatalf("step-up expiry %v is not within the ≤5 minute bound from %v", authz.ExpiresAt, now)
	}
	return sess, bp.SessionID, authz.ID
}

func TestDeletionWithStepUpHappyPath(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sess, sessionID, authzID := stepUpFixture(t, s, "stepup-sam", now)
	dr, err := s.CreateDeletionRequestWithStepUp(ctx, sess.AccountID, sessionID, authzID, now)
	if err != nil {
		t.Fatalf("CreateDeletionRequestWithStepUp: %v", err)
	}
	if dr.State != "done" || dr.ID == "" {
		t.Fatalf("unexpected deletion request: %+v", dr)
	}
	// The deletion ran: the browser session is PURGED — introspection finds no
	// row (ErrNotFound) or, at minimum, reports it invalid. Either way the live
	// portal cookie stops working.
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err == nil && bp.Valid {
		t.Fatal("the deletion did not invalidate the browser session")
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("IntrospectBrowserSession: unexpected err=%v", err)
	}
	// The authorization is spent: a second deletion is refused.
	if _, err := s.CreateDeletionRequestWithStepUp(ctx, sess.AccountID, sessionID, authzID, now); !errors.Is(err, store.ErrStepUpInvalid) {
		t.Fatalf("replayed step-up err=%v, want ErrStepUpInvalid", err)
	}
}

func TestDeletionWithStepUpRejectsBadBindings(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	// Two accounts, each with its own live step-up.
	sessA, sessionA, authzA := stepUpFixture(t, s, "bind-alice", now)
	sessB, sessionB, _ := stepUpFixture(t, s, "bind-bob", now)

	otherAction, err := s.CreateStepUpAuthorization(ctx, sessA.AccountID, sessionA, store.StepUpActionExport, now)
	if err != nil {
		t.Fatalf("CreateStepUpAuthorization(export): %v", err)
	}
	expired, err := s.CreateStepUpAuthorization(ctx, sessA.AccountID, sessionA, store.StepUpActionDeletion, now.Add(-10*time.Minute))
	if err != nil {
		t.Fatalf("CreateStepUpAuthorization(expired): %v", err)
	}

	cases := []struct {
		name      string
		account   string
		sessionID string
		authzID   string
		when      time.Time
	}{
		{"wrong account", sessB.AccountID, sessionB, authzA, now},
		{"wrong session", sessA.AccountID, sessionB, authzA, now},
		{"wrong action", sessA.AccountID, sessionA, otherAction.ID, now},
		{"expired", sessA.AccountID, sessionA, expired.ID, now},
		{"unknown id", sessA.AccountID, sessionA, "00000000-0000-0000-0000-000000000000", now},
		{"malformed id", sessA.AccountID, sessionA, "not-a-uuid", now},
		{"empty id", sessA.AccountID, sessionA, "", now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CreateDeletionRequestWithStepUp(ctx, tc.account, tc.sessionID, tc.authzID, tc.when)
			if !errors.Is(err, store.ErrStepUpInvalid) {
				t.Fatalf("err=%v, want ErrStepUpInvalid", err)
			}
		})
	}

	// None of those refusals deleted anything: alice's own valid step-up still
	// works, which proves no partial deletion ran and the row was not consumed.
	if _, err := s.CreateDeletionRequestWithStepUp(ctx, sessA.AccountID, sessionA, authzA, now); err != nil {
		t.Fatalf("valid step-up after refusals: %v", err)
	}
}

// TestStepUpAuthorizationRLSScoped pins that step_up_authorizations really is a
// TENANT table: read it as sbci_app under another account's GUC and the row is
// invisible, exactly like every other account-owned table (0004's model).
func TestStepUpAuthorizationRLSScoped(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	sessA, _, _ := stepUpFixture(t, s, "rls-alice", now)
	sessB, _, _ := stepUpFixture(t, s, "rls-bob", now)

	countAs := func(viewer string) int {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE sbci_app`); err != nil {
			t.Fatalf("set role: %v", err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('sbci.account_id', $1, true)`, viewer); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM step_up_authorizations`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	if got := countAs(sessA.AccountID); got != 1 {
		t.Fatalf("alice sees %d step-ups, want only her own", got)
	}
	if got := countAs(sessB.AccountID); got != 1 {
		t.Fatalf("bob sees %d step-ups, want only his own", got)
	}
}

func TestCreateStepUpAuthorizationValidates(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	account := makeAccount(t, s)

	if _, err := s.CreateStepUpAuthorization(ctx, account, "00000000-0000-0000-0000-000000000000", "teleport", now); err == nil {
		t.Fatal("accepted an unknown step-up action")
	}
	if _, err := s.CreateStepUpAuthorization(ctx, account, "", store.StepUpActionDeletion, now); err == nil {
		t.Fatal("accepted an empty session id")
	}
}

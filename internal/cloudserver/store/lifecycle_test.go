package store_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Store-level cover for the W1 "lifecycle phase 1" primitives (plan §3 W1,
// D17/D18): single-token revocation, account-wide access revocation, and the
// idempotent WorkOS event ledger.

// exchangeDevice mints a fresh device + token for (provider, subject).
func exchangeDevice(t *testing.T, s *store.Store, provider, subject string) store.ExchangeResult {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	nonce, err := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	if err != nil {
		t.Fatalf("MintNonce: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	res, err := s.Exchange(ctx, store.ExchangeInput{
		Provider: provider, Subject: subject, PublicKey: pub,
		Label: "lifecycle-test", RawNonce: nonce, Now: now,
	})
	if err != nil {
		t.Fatalf("Exchange(%s/%s): %v", provider, subject, err)
	}
	return res
}

// tokenIDOf resolves the api_tokens row id behind a raw bearer — the same
// non-secret identifier the API middleware carries into POST /v1/logout.
func tokenIDOf(t *testing.T, s *store.Store, raw string) string {
	t.Helper()
	p, err := s.IntrospectToken(context.Background(), raw, time.Now())
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	return p.TokenID
}

func tokenValid(t *testing.T, s *store.Store, raw string) bool {
	t.Helper()
	p, err := s.IntrospectToken(context.Background(), raw, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	return p.Valid
}

// TestRevokeAPITokenRevokesOnlyThatToken pins the D17 primitive: the presented
// token dies, a SIBLING token on the same account keeps working (logging out
// one device must not sign the account out everywhere), and the device
// registration itself is untouched so the device can log in again.
func TestRevokeAPITokenRevokesOnlyThatToken(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	subject := fmt.Sprintf("logout-%d", subjCounter.Add(1))
	first := exchangeDevice(t, s, "dev", subject)
	second := exchangeDevice(t, s, "dev", subject) // same identity, second device
	if first.AccountID != second.AccountID {
		t.Fatalf("same identity resolved to two accounts: %s vs %s", first.AccountID, second.AccountID)
	}

	if err := s.RevokeAPIToken(ctx, first.AccountID, tokenIDOf(t, s, first.Token), time.Now()); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if tokenValid(t, s, first.Token) {
		t.Fatal("the revoked token still introspects as valid")
	}
	if !tokenValid(t, s, second.Token) {
		t.Fatal("revoking one token killed a sibling device's token")
	}

	devices, err := s.ListDevices(ctx, first.AccountID)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range devices {
		if d.RevokedAt != nil {
			t.Fatalf("device %s was revoked by a token logout; logout must revoke the TOKEN only", d.ID)
		}
	}
}

// TestRevokeAPITokenIdempotent pins the "already revoked ⇒ no error" contract
// the /v1/logout handler relies on to answer 200 rather than 404/500.
func TestRevokeAPITokenIdempotent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	res := exchangeDevice(t, s, "dev", fmt.Sprintf("idem-%d", subjCounter.Add(1)))
	tokenID := tokenIDOf(t, s, res.Token)

	for i := 0; i < 3; i++ {
		if err := s.RevokeAPIToken(ctx, res.AccountID, tokenID, time.Now()); err != nil {
			t.Fatalf("RevokeAPIToken call %d: %v", i+1, err)
		}
	}
	if tokenValid(t, s, res.Token) {
		t.Fatal("token still valid after revocation")
	}

	// A malformed / foreign token id is the already-gone case, not an error.
	if err := s.RevokeAPIToken(ctx, res.AccountID, "not-a-uuid", time.Now()); err != nil {
		t.Fatalf("RevokeAPIToken with a malformed id should be a no-op, got %v", err)
	}
	if err := s.RevokeAPIToken(ctx, res.AccountID, "", time.Now()); err == nil {
		t.Fatal("RevokeAPIToken with an EMPTY id must be rejected (a caller bug, not an absent row)")
	}
}

// TestRevokeAllForAccount pins the D18 propagation primitive: every credential
// dies, another account is untouched, and NO data is deleted (access revocation
// is not deletion — the account stays readable and its consent record survives).
func TestRevokeAllForAccount(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	victimSubject := fmt.Sprintf("victim-%d", subjCounter.Add(1))
	bystanderSubject := fmt.Sprintf("bystander-%d", subjCounter.Add(1))
	victim := exchangeDevice(t, s, "workos", victimSubject)
	bystander := exchangeDevice(t, s, "workos", bystanderSubject)

	// The portal and device paths share ONE account per identity, so signing in
	// under the same subject opens a browser session on the victim's account.
	victimSess, err := s.PortalLogin(ctx, "workos", victimSubject, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin(victim): %v", err)
	}
	if victimSess.AccountID != victim.AccountID {
		t.Fatalf("portal login resolved to %s, want the victim account %s", victimSess.AccountID, victim.AccountID)
	}
	bystanderSess, err := s.PortalLogin(ctx, "workos", bystanderSubject, 0, now)
	if err != nil {
		t.Fatalf("PortalLogin(bystander): %v", err)
	}

	rev, err := s.RevokeAllForAccount(ctx, victim.AccountID, now)
	if err != nil {
		t.Fatalf("RevokeAllForAccount: %v", err)
	}
	if rev.DevicesRevoked != 1 || rev.TokensRevoked != 1 || rev.SessionsRevoked != 1 {
		t.Fatalf("unexpected revocation counts: %+v", rev)
	}

	if tokenValid(t, s, victim.Token) {
		t.Fatal("victim API token still valid after account-wide revocation")
	}
	bp, err := s.IntrospectBrowserSession(ctx, victimSess.RawSession, now)
	if err != nil {
		t.Fatalf("IntrospectBrowserSession(victim): %v", err)
	}
	if bp.Valid {
		t.Fatal("victim browser session still valid after account-wide revocation")
	}
	if !tokenValid(t, s, bystander.Token) {
		t.Fatal("a bystander account's token was revoked — revocation must be tenant-scoped")
	}
	if bp2, err := s.IntrospectBrowserSession(ctx, bystanderSess.RawSession, now); err != nil || !bp2.Valid {
		t.Fatalf("a bystander account's portal session was revoked (err=%v valid=%v)", err, bp2.Valid)
	}

	// Access revocation is NOT deletion: the account's data must remain readable
	// (the deletion path is the only thing that fences the account and tombstones).
	if _, err := s.CurrentConsent(ctx, victim.AccountID); err != nil {
		t.Fatalf("victim account data unreadable after revocation: %v", err)
	}

	// Idempotent: a second pass flips nothing and reports zeros honestly.
	again, err := s.RevokeAllForAccount(ctx, victim.AccountID, now)
	if err != nil {
		t.Fatalf("second RevokeAllForAccount: %v", err)
	}
	if again != (store.AccessRevocation{}) {
		t.Fatalf("second revocation should flip nothing, got %+v", again)
	}
}

// TestWorkOSEventLedgerIsIdempotent pins the at-least-once intake contract: the
// first record is fresh, a redelivery is not, processed_at is write-once — and,
// crucially (F7), a redelivery of a recorded-but-UNPROCESSED event still
// reports Processed=false so the caller re-runs the handling.
func TestWorkOSEventLedgerIsIdempotent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	id := fmt.Sprintf("event_%d", subjCounter.Add(1))

	intake, err := s.RecordWorkOSEvent(ctx, id, "user.deleted", now)
	if err != nil {
		t.Fatalf("RecordWorkOSEvent: %v", err)
	}
	if !intake.Fresh {
		t.Fatal("first delivery of an event id must be fresh")
	}
	if intake.Processed {
		t.Fatal("a just-recorded event must not report itself processed")
	}
	intake, err = s.RecordWorkOSEvent(ctx, id, "user.deleted", now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordWorkOSEvent (replay): %v", err)
	}
	if intake.Fresh {
		t.Fatal("a redelivered event id must NOT be fresh (dedupe is the whole point)")
	}
	if intake.Processed {
		t.Fatal("a redelivery of an UNPROCESSED event must report Processed=false so the handler retries")
	}

	ev, err := s.GetWorkOSEvent(ctx, id)
	if err != nil {
		t.Fatalf("GetWorkOSEvent: %v", err)
	}
	if ev.ProcessedAt != nil {
		t.Fatal("a recorded-but-unhandled event must leave processed_at NULL")
	}

	if err := s.MarkWorkOSEventProcessed(ctx, id, now); err != nil {
		t.Fatalf("MarkWorkOSEventProcessed: %v", err)
	}
	// Once stamped, a redelivery reports Processed=true — the duplicate-ack path.
	if intake, err := s.RecordWorkOSEvent(ctx, id, "user.deleted", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("RecordWorkOSEvent (post-processing replay): %v", err)
	} else if intake.Fresh || !intake.Processed {
		t.Fatalf("post-processing replay = %+v, want {Fresh:false Processed:true}", intake)
	}
	ev, err = s.GetWorkOSEvent(ctx, id)
	if err != nil {
		t.Fatalf("GetWorkOSEvent after processing: %v", err)
	}
	if ev.ProcessedAt == nil {
		t.Fatal("processed_at was not stamped")
	}
	first := *ev.ProcessedAt

	// Write-once: a duplicate stamp must not move the timestamp.
	if err := s.MarkWorkOSEventProcessed(ctx, id, now.Add(time.Hour)); err != nil {
		t.Fatalf("re-MarkWorkOSEventProcessed: %v", err)
	}
	ev, err = s.GetWorkOSEvent(ctx, id)
	if err != nil {
		t.Fatalf("GetWorkOSEvent after re-stamp: %v", err)
	}
	if !ev.ProcessedAt.Equal(first) {
		t.Fatalf("processed_at moved on a duplicate stamp: %v -> %v", first, *ev.ProcessedAt)
	}

	if _, err := s.GetWorkOSEvent(ctx, "event_never_seen"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown event should be ErrNotFound, got %v", err)
	}
}

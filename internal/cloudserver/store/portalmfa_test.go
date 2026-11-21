package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/portalmfa"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// portalSession signs a dev account in and returns its account and session ids.
func portalSession(t *testing.T, s *store.Store, sub string, now time.Time) (string, string) {
	t.Helper()
	ctx := context.Background()
	sess, err := s.PortalLogin(ctx, "dev", sub, 24*time.Hour, now, store.WithFreshAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	bp, err := s.IntrospectBrowserSession(ctx, sess.RawSession, now)
	if err != nil || !bp.Valid {
		t.Fatalf("introspect: %v", err)
	}
	return bp.AccountID, bp.SessionID
}

// testCodes mints a batch and returns the codes and their hashes.
func testCodes(t *testing.T) ([]string, []string) {
	t.Helper()
	codes, err := portalmfa.NewRecoveryCodes(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i], _ = portalmfa.HashRecoveryCode(c)
	}
	return codes, out
}

func testHashes(t *testing.T) []string {
	t.Helper()
	_, h := testCodes(t)
	return h
}

// TestPortalPasskeyStore covers the C2 store seam against Postgres: the first
// passkey stores the recovery codes and marks the session; a ceremony is bound
// to its account and session and single use; another account sees nothing
// (row-level security); the counter is compare-and-set; a recovery code is
// single use; removing the last passkey deletes the codes.
func TestPortalPasskeyStore(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	a, sessA := portalSession(t, s, fmt.Sprintf("mfa-a-%d", subjCounter.Add(1)), now)
	b, sessB := portalSession(t, s, fmt.Sprintf("mfa-b-%d", subjCounter.Add(1)), now)

	st, err := s.PortalSecondFactorState(ctx, a, sessA)
	if err != nil || st.Enrolled || st.Pending() || st.AuthTime.IsZero() {
		t.Fatalf("fresh state = %+v, %v", st, err)
	}

	// A ceremony is bound to account and session, single use.
	ch := bytes.Repeat([]byte{7}, 32)
	if err := s.BeginPortalPasskeyCeremony(ctx, a, sessA, "cer-1", store.PortalCeremonyRegister, ch, "laptop", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumePortalPasskeyCeremony(ctx, b, sessB, "cer-1", store.PortalCeremonyRegister, now); !errors.Is(err, store.ErrPortalCeremonyInvalid) {
		t.Fatalf("other account consumed: %v", err)
	}
	if _, err := s.ConsumePortalPasskeyCeremony(ctx, a, sessA, "cer-1", store.PortalCeremonyAssert, now); !errors.Is(err, store.ErrPortalCeremonyInvalid) {
		t.Fatalf("wrong kind consumed: %v", err)
	}
	cer, err := s.ConsumePortalPasskeyCeremony(ctx, a, sessA, "cer-1", store.PortalCeremonyRegister, now)
	if err != nil || cer.Label != "laptop" || !bytes.Equal(cer.Challenge, ch) {
		t.Fatalf("consume = %+v, %v", cer, err)
	}
	if _, err := s.ConsumePortalPasskeyCeremony(ctx, a, sessA, "cer-1", store.PortalCeremonyRegister, now); !errors.Is(err, store.ErrPortalCeremonyInvalid) {
		t.Fatalf("second consume: %v", err)
	}

	cred := staffauth.NewCredential{ID: bytes.Repeat([]byte{1}, 32), PublicKey: []byte{0xa5, 1, 2}, SignCount: 4}
	codes, hashes := testCodes(t)
	res, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: a, SessionID: sessA, Cred: cred, Label: cer.Label, RecoveryHashes: hashes, Now: now,
	})
	if err != nil || !res.First || len(res.AMR) != 2 || res.AMR[0] != "hwk" {
		t.Fatalf("register = %+v, %v", res, err)
	}
	if _, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: b, SessionID: sessB, Cred: cred, RecoveryHashes: testHashes(t), Now: now,
	}); !errors.Is(err, store.ErrPortalPasskeyExists) {
		t.Fatalf("same credential on another account = %v", err)
	}
	st, _ = s.PortalSecondFactorState(ctx, a, sessA)
	if !st.Enrolled || st.Pending() || st.Method != portalmfa.MethodPasskey || !st.MultiFactor() || st.RecoveryCodesLeft != 10 {
		t.Fatalf("after first enrol = %+v", st)
	}
	// A second passkey does not replace the codes.
	cred2 := staffauth.NewCredential{ID: bytes.Repeat([]byte{2}, 32), PublicKey: []byte{1}, BackupEligible: true}
	if res, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: a, SessionID: sessA, Cred: cred2, RecoveryHashes: testHashes(t), Now: now,
	}); err != nil || res.First {
		t.Fatalf("second register = %+v, %v", res, err)
	}

	// Row-level security: B sees none of A's.
	if ids, err := s.PortalPasskeyIDs(ctx, b); err != nil || len(ids) != 0 {
		t.Fatalf("B sees %d passkeys (%v)", len(ids), err)
	}
	if _, err := s.PortalPasskeyForAssertion(ctx, b, cred.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("B reads A's passkey: %v", err)
	}

	// The counter is compare-and-set.
	stored, err := s.PortalPasskeyForAssertion(ctx, a, cred.ID)
	if err != nil || stored.SignCount != 4 || !bytes.Equal(stored.UserHandle, portalmfa.UserHandle(a)) {
		t.Fatalf("for assertion = %+v, %v", stored, err)
	}
	if err := s.CompletePortalPasskeyAssertion(ctx, a, sessA, cred.ID, 3, 9, res.AMR, now); !errors.Is(err, store.ErrPortalPasskeyStale) {
		t.Fatalf("stale counter = %v", err)
	}
	if err := s.CompletePortalPasskeyAssertion(ctx, a, sessA, cred.ID, 4, 9, []string{"hwk", "mfa"}, now); err != nil {
		t.Fatal(err)
	}

	// Recovery codes are single use and per account.
	h0, _ := portalmfa.HashRecoveryCode(codes[0])
	if _, err := s.RedeemPortalRecoveryCode(ctx, b, sessB, h0, now); !errors.Is(err, store.ErrRecoveryCodeInvalid) {
		t.Fatalf("B redeemed A's code: %v", err)
	}
	if left, err := s.RedeemPortalRecoveryCode(ctx, a, sessA, h0, now); err != nil || left != 9 {
		t.Fatalf("redeem = %d, %v", left, err)
	}
	if _, err := s.RedeemPortalRecoveryCode(ctx, a, sessA, h0, now); !errors.Is(err, store.ErrRecoveryCodeInvalid) {
		t.Fatalf("second redeem = %v", err)
	}
	st, _ = s.PortalSecondFactorState(ctx, a, sessA)
	if st.Method != portalmfa.MethodRecoveryCode || st.MultiFactor() {
		t.Fatalf("after recovery = %+v", st)
	}

	// Removing the last passkey turns the second factor off.
	if left, err := s.RevokePortalPasskey(ctx, a, sessA, cred.ID, now); err != nil || left != 1 {
		t.Fatalf("revoke = %d, %v", left, err)
	}
	if left, err := s.RevokePortalPasskey(ctx, a, sessA, cred2.ID, now); err != nil || left != 0 {
		t.Fatalf("revoke last = %d, %v", left, err)
	}
	if _, err := s.RevokePortalPasskey(ctx, a, sessA, cred2.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoke again = %v", err)
	}
	st, _ = s.PortalSecondFactorState(ctx, a, sessA)
	if st.Enrolled || st.RecoveryCodesLeft != 0 {
		t.Fatalf("after removing all = %+v", st)
	}
	if err := s.ReplacePortalRecoveryCodes(ctx, a, testHashes(t), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("codes without a passkey = %v", err)
	}
	// A revoked credential id cannot be registered again.
	if _, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: a, SessionID: sessA, Cred: cred, RecoveryHashes: testHashes(t), Now: now,
	}); !errors.Is(err, store.ErrPortalPasskeyExists) {
		t.Fatalf("re-register revoked = %v", err)
	}
}

// TestDeviceApprovalAndSessionClearing covers the FR-6 and FR-24 store rules
// against Postgres: a new device of a passkey account exchanges only with a
// live single-use approval; an account without a passkey is unchanged; revoking
// a passkey clears the second-factor mark of the account's OTHER sessions; the
// recovery-code failure counter locks and clears.
func TestDeviceApprovalAndSessionClearing(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	subj := fmt.Sprintf("mfa-dev-%d", subjCounter.Add(1))
	a, sessA := portalSession(t, s, subj, now)

	exchange := func() (store.ExchangeResult, error, []byte) {
		in := exchangeInputFor(t, s, "dev", subj)
		res, err := s.Exchange(ctx, in)
		return res, err, in.PublicKey
	}
	// No passkey: any new device registers.
	if _, err, _ := exchange(); err != nil {
		t.Fatalf("no-passkey exchange = %v", err)
	}

	cred := staffauth.NewCredential{ID: bytes.Repeat([]byte{9}, 32), PublicKey: []byte{0xa5, 1, 2}, SignCount: 1}
	_, hashes := testCodes(t)
	if _, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: a, SessionID: sessA, Cred: cred, RecoveryHashes: hashes, Now: now,
	}); err != nil {
		t.Fatal(err)
	}

	// Passkey account: a new device is refused without an approval.
	in := exchangeInputFor(t, s, "dev", subj)
	if _, err := s.Exchange(ctx, in); !errors.Is(err, store.ErrDeviceApprovalRequired) {
		t.Fatalf("unapproved exchange = %v", err)
	}
	// An approval for the thumbprint admits it once; a second new exchange of
	// the same key is a known device, a different key needs its own approval.
	if _, err := s.ApproveDevice(ctx, a, sessA, store.Thumbprint(in.PublicKey), portalmfa.DeviceApprovalTTL, now); err != nil {
		t.Fatal(err)
	}
	in.RawNonce, _ = s.MintNonce(ctx, store.DefaultNonceTTL, time.Now())
	in.Now = time.Now()
	if _, err := s.Exchange(ctx, in); err != nil {
		t.Fatalf("approved exchange = %v", err)
	}
	other := exchangeInputFor(t, s, "dev", subj)
	if _, err := s.Exchange(ctx, other); !errors.Is(err, store.ErrDeviceApprovalRequired) {
		t.Fatalf("other device = %v", err)
	}
	// An expired approval does not admit.
	if _, err := s.ApproveDevice(ctx, a, sessA, store.Thumbprint(other.PublicKey), time.Second, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	other.RawNonce, _ = s.MintNonce(ctx, store.DefaultNonceTTL, time.Now())
	other.Now = time.Now()
	if _, err := s.Exchange(ctx, other); !errors.Is(err, store.ErrDeviceApprovalRequired) {
		t.Fatalf("expired approval = %v", err)
	}

	// Revoking a passkey clears the OTHER sessions' second-factor mark.
	cred2 := staffauth.NewCredential{ID: bytes.Repeat([]byte{8}, 32), PublicKey: []byte{0xa5, 3, 4}, SignCount: 1}
	if _, err := s.RegisterPortalPasskey(ctx, store.RegisterPortalPasskeyInput{
		AccountID: a, SessionID: sessA, Cred: cred2, RecoveryHashes: testHashes(t), Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	sess2, err := s.PortalLogin(ctx, "dev", subj, 24*time.Hour, now, store.WithFreshAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	bp, err := s.IntrospectBrowserSession(ctx, sess2.RawSession, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompletePortalPasskeyAssertion(ctx, a, bp.SessionID, cred.ID, 1, 2, []string{"hwk", "mfa"}, now); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.PortalSecondFactorState(ctx, a, bp.SessionID); st.Pending() {
		t.Fatalf("second session should be marked: %+v", st)
	}
	if _, err := s.RevokePortalPasskey(ctx, a, sessA, cred.ID, now); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.PortalSecondFactorState(ctx, a, bp.SessionID); !st.Pending() {
		t.Fatalf("revoking a passkey left the other session marked: %+v", st)
	}
	if st, _ := s.PortalSecondFactorState(ctx, a, sessA); st.Pending() {
		t.Fatalf("the revoking session lost its mark: %+v", st)
	}

	// Recovery-code failures lock at the threshold and clear on demand.
	for i := 1; i <= portalmfa.RecoveryMaxFailures; i++ {
		tripped, until, err := s.NoteRecoveryFailure(ctx, a, now)
		if err != nil || tripped != (i == portalmfa.RecoveryMaxFailures) || (tripped && !until.After(now)) {
			t.Fatalf("failure %d = %v %v %v", i, tripped, until, err)
		}
	}
	if st, _ := s.RecoveryFailureState(ctx, a); !portalmfa.RecoveryLocked(st, now) {
		t.Fatalf("state after lockout = %+v", st)
	}
	if err := s.ClearRecoveryFailures(ctx, a); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.RecoveryFailureState(ctx, a); portalmfa.RecoveryLocked(st, now) || st.Failures != 0 {
		t.Fatalf("state after clear = %+v", st)
	}
}

package store_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestStaffPasskeyCap proves operator ruling Staff 2 (L-83) against Postgres:
// a staff member holds at most staffauth.MaxActivePasskeys unrevoked passkeys.
// The sixth is refused at the code's redemption (begin) and, for a ceremony
// begun while a slot was free, at the finish; each refusal leaves a refused
// credential.registered row and the enrolment code unspent; a revoked passkey
// frees its slot; passkeys already over the cap are never deleted.
func TestStaffPasskeyCap(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()

	staffID, _ := registerTestStaff(t, s, staffauth.RoleAdmin, 10, now)
	enrol := func() string {
		t.Helper()
		e, err := s.EnrolStaff(ctx, store.EnrolStaffInput{StaffID: staffID, Reason: "another key", Now: now})
		if err != nil {
			t.Fatalf("EnrolStaff: %v", err)
		}
		return e.RawCode
	}
	begin := func(code string, seed byte) (string, error) {
		t.Helper()
		cer := fmt.Sprintf("cap-ceremony-%d", seed)
		_, err := s.BeginStaffRegistration(ctx, code, cer, testChallenge(seed), now)
		return cer, err
	}
	finish := func(cer string, seed byte) error {
		t.Helper()
		c, err := s.ConsumeStaffCeremony(ctx, cer, store.StaffCeremonyRegister, now)
		if err != nil {
			t.Fatalf("consume %s: %v", cer, err)
		}
		return s.RegisterStaffCredential(ctx, c, testCredential(seed), "key", now)
	}
	refusedRows := func() int {
		t.Helper()
		acts, err := s.ListStaffActions(ctx, 500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, a := range acts {
			if a.Verb == string(staffauth.VerbCredentialRegistered) && a.Result == "refused" && a.SubjectStaffID == staffID {
				n++
			}
		}
		return n
	}

	// Passkeys two to four the plain way.
	for seed := byte(11); seed <= 13; seed++ {
		cer, err := begin(enrol(), seed)
		if err != nil {
			t.Fatalf("begin %d: %v", seed, err)
		}
		if err := finish(cer, seed); err != nil {
			t.Fatalf("register %d: %v", seed, err)
		}
	}
	// Two ceremonies begun at four: the first fills the fifth slot, the
	// second is refused at the finish, logged, its code left unspent.
	codeA, codeB := enrol(), enrol()
	cerA, err := begin(codeA, 14)
	if err != nil {
		t.Fatalf("begin A: %v", err)
	}
	cerB, err := begin(codeB, 15)
	if err != nil {
		t.Fatalf("begin B: %v", err)
	}
	if err := finish(cerA, 14); err != nil {
		t.Fatalf("register the fifth: %v", err)
	}
	if err := finish(cerB, 15); !errors.Is(err, staffauth.ErrPasskeyLimit) {
		t.Fatalf("register the sixth at the finish = %v, want ErrPasskeyLimit", err)
	}
	if got := refusedRows(); got != 1 {
		t.Fatalf("refused rows after the finish refusal = %d, want 1", got)
	}
	// At five, the redemption itself is refused and logged.
	if _, err := begin(codeB, 16); !errors.Is(err, staffauth.ErrPasskeyLimit) {
		t.Fatalf("begin the sixth = %v, want ErrPasskeyLimit", err)
	}
	if got := refusedRows(); got != 2 {
		t.Fatalf("refused rows after the begin refusal = %d, want 2", got)
	}
	// Revoking one frees a slot, and the refused code (still unspent)
	// registers the replacement.
	if err := s.RevokeStaffCredential(ctx, staffID, testCredential(11).ID, "lost key", now); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cer, err := begin(codeB, 17)
	if err != nil {
		t.Fatalf("begin after revoke: %v", err)
	}
	if err := finish(cer, 17); err != nil {
		t.Fatalf("register after revoke: %v", err)
	}

	// A member already over the cap (passkeys added before it existed) keeps
	// every one: only a further registration is refused.
	for seed := byte(18); seed <= 19; seed++ {
		cred := testCredential(seed)
		if _, err := pool.Exec(ctx,
			`INSERT INTO staff_webauthn_credentials (credential_id, staff_id, public_key, sign_count, transports, label, created_at)
			 VALUES ($1, $2::uuid, $3, 0, '{}', 'legacy', $4)`, cred.ID, staffID, cred.PublicKey, now); err != nil {
			t.Fatalf("seed a legacy passkey: %v", err)
		}
	}
	if _, err := begin(enrol(), 20); !errors.Is(err, staffauth.ErrPasskeyLimit) {
		t.Fatalf("begin over the cap = %v, want ErrPasskeyLimit", err)
	}
	var active int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM staff_webauthn_credentials WHERE staff_id = $1::uuid AND revoked_at IS NULL`, staffID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != staffauth.MaxActivePasskeys+2 {
		t.Errorf("active passkeys over the cap = %d, want %d (none deleted)", active, staffauth.MaxActivePasskeys+2)
	}
	for _, seed := range []byte{18, 19} {
		if _, _, err := s.StaffCredentialForAssertion(ctx, testCredential(seed).ID); err != nil {
			t.Errorf("legacy passkey %d no longer signs in: %v", seed, err)
		}
	}
}

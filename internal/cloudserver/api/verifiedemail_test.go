package api_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestWorkOSSignInRefreshesProviderEmail drives real WorkOS sign-ins (A4):
// each one records WorkOS's address and email_verified flag for the account,
// replacing what the previous sign-in recorded, with a missing flag stored as
// unverified. The step-up re-authentication refreshes it the same way.
func TestWorkOSSignInRefreshesProviderEmail(t *testing.T) {
	h := newWorkOSHarness(t, true)
	const subject = "vera"
	var account string
	for _, step := range []struct {
		name, field  string
		wantVerified bool
	}{
		{"verified", `,"email_verified":true`, true},
		{"unverified replaces verified", `,"email_verified":false`, false},
		{"verified again", `,"email_verified":true`, true},
		{"flag missing is unverified", ``, false},
	} {
		h.workos.setEmailVerifiedField(step.field)
		_, _, acct := h.signIn(t, subject)
		if account == "" {
			account = acct
		} else if acct != account {
			t.Fatalf("%s: the same subject resolved to account %s, then %s", step.name, account, acct)
		}
		email, verified, ok := readVerifiedEmail(t, h, account)
		if !ok || email != subject+"@example.test" || verified != step.wantVerified {
			t.Fatalf("%s: stored (%q, %v, row=%v), want (%q, %v)", step.name, email, verified, ok, subject+"@example.test", step.wantVerified)
		}
	}

	// The step-up leg is a fresh provider sign-in too.
	hc, _, acct := h.signIn(t, subject)
	h.workos.setEmailVerifiedField(`,"email_verified":true`)
	_ = h.stepUp(t, hc, subject, "export")
	if _, verified, ok := readVerifiedEmail(t, h, acct); !ok || !verified {
		t.Fatalf("step-up did not refresh the flag: verified=%v row=%v", verified, ok)
	}
}

// readVerifiedEmail reads the account's provider-asserted row through the
// harness's owner pool.
func readVerifiedEmail(t *testing.T, h *workosHarness, account string) (string, bool, bool) {
	t.Helper()
	var email string
	var verified bool
	err := h.store.Pool().QueryRow(context.Background(),
		`SELECT email, email_verified FROM account_verified_emails WHERE account_id = $1::uuid`, account).Scan(&email, &verified)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, false
	}
	if err != nil {
		t.Fatalf("read account_verified_emails: %v", err)
	}
	return email, verified, true
}

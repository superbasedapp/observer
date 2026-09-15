package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// accountprofile_test.go pins the display-identity row (migration 0033): the
// upsert converges on the latest provider claims, the bounds are enforced by
// the writer (not by a column type), a profile is never invented for an account
// that has none, and account deletion PURGES it — the one row that holds a
// plain-text email must not survive a deletion.

func TestUpsertAccountProfileRoundTripsAndConverges(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	// No profile yet: the zero value, and NOT an error — the portal must be able
	// to degrade to the account id rather than fail.
	got, err := s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile (absent): %v", err)
	}
	if !got.Empty() {
		t.Fatalf("a fresh account already has a profile: %+v", got)
	}

	if err := s.UpsertAccountProfile(ctx, acct, "dev@example.test", "Dev Example", now); err != nil {
		t.Fatalf("UpsertAccountProfile: %v", err)
	}
	got, err = s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile: %v", err)
	}
	if got.Email != "dev@example.test" || got.DisplayName != "Dev Example" {
		t.Fatalf("profile = %+v, want dev@example.test / Dev Example", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("updated_at was not stored")
	}

	// A second sign-in with changed provider claims CONVERGES (one row per
	// account, latest wins) rather than accumulating rows.
	later := now.Add(time.Hour)
	if err := s.UpsertAccountProfile(ctx, acct, "renamed@example.test", "Renamed Example", later); err != nil {
		t.Fatalf("UpsertAccountProfile (second): %v", err)
	}
	got, err = s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile (second): %v", err)
	}
	if got.Email != "renamed@example.test" || got.DisplayName != "Renamed Example" {
		t.Fatalf("profile did not converge: %+v", got)
	}
}

func TestUpsertAccountProfileBoundsAndNoOps(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	// An all-empty upsert writes nothing: a row that says nothing is worse than
	// no row (it would make "unknown" indistinguishable from "blank").
	if err := s.UpsertAccountProfile(ctx, acct, "", "", now); err != nil {
		t.Fatalf("UpsertAccountProfile (empty): %v", err)
	}
	got, err := s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile: %v", err)
	}
	if !got.Empty() {
		t.Fatalf("an all-empty upsert wrote a row: %+v", got)
	}

	// Over-long values are TRUNCATED (a sign-in never fails over a cosmetic
	// field) on a rune boundary, so the stored value stays valid UTF-8.
	longEmail := strings.Repeat("é", 400) + "@example.test" // 2 bytes per rune
	longName := strings.Repeat("ü", 400)
	if err := s.UpsertAccountProfile(ctx, acct, longEmail, longName, now); err != nil {
		t.Fatalf("UpsertAccountProfile (long): %v", err)
	}
	got, err = s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile (long): %v", err)
	}
	if len(got.Email) > store.AccountProfileMaxEmailBytes {
		t.Errorf("stored email is %d bytes, over the %d bound", len(got.Email), store.AccountProfileMaxEmailBytes)
	}
	if len(got.DisplayName) > store.AccountProfileMaxNameBytes {
		t.Errorf("stored display_name is %d bytes, over the %d bound", len(got.DisplayName), store.AccountProfileMaxNameBytes)
	}
	for _, v := range []string{got.Email, got.DisplayName} {
		if !utf8.ValidString(v) {
			t.Errorf("truncation split a rune: %q", v)
		}
	}

	// An empty account id is refused loudly rather than writing an unscoped row.
	if err := s.UpsertAccountProfile(ctx, "", "x@example.test", "X", now); err == nil {
		t.Error("UpsertAccountProfile accepted an empty account id")
	}
}

// TestAccountDeletionPurgesProfile is the deletion half: the display identity
// is the only row holding a plain-text email, so it must be gone the moment the
// account is deleted — not 24 months later when the tombstone sweep fires the
// FK cascade.
func TestAccountDeletionPurgesProfile(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	if err := s.UpsertAccountProfile(ctx, acct, "purge-me@example.test", "Purge Me", now); err != nil {
		t.Fatalf("UpsertAccountProfile: %v", err)
	}
	if n := countRows(t, pool, "account_profiles", acct); n != 1 {
		t.Fatalf("fixture did not populate account_profiles (n=%d)", n)
	}

	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}
	if n := countRows(t, pool, "account_profiles", acct); n != 0 {
		t.Errorf("account_profiles kept %d row(s) after deletion; the email must be purged", n)
	}
	// The account row itself survives as a pseudonymized tombstone, so this is a
	// real purge of the profile, not an artefact of the row having cascaded away.
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM accounts WHERE account_id=$1::uuid`, acct).Scan(&status); err != nil {
		t.Fatalf("read account: %v", err)
	}
	if status != "deleted" {
		t.Fatalf("account status=%q, want deleted", status)
	}
}

// TestUpsertAccountProfileRefusedAfterDeletion is the resurrection half of the
// purge test above. Deletion purges the profile row, but the `accounts` row
// SURVIVES as a `status='deleted'` tombstone — RLS still matches the tenant and
// the FK still resolves — so a profile upsert arriving AFTER the deletion
// committed would happily re-create a plain-text email on a deleted account.
//
// The window is real, not theoretical: sign-in creates the session in one
// transaction and the profile upsert runs in a SECOND one (it is best-effort
// and must never fail a sign-in), so a deletion can commit in between. The
// upsert therefore fences the account status INSIDE its own write transaction
// and fails closed, exactly like every other tenant write (Sol F5).
func TestUpsertAccountProfileRefusedAfterDeletion(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}

	err := s.UpsertAccountProfile(ctx, acct, "resurrect@example.test", "Resurrect Me", now.Add(time.Minute))
	if !errors.Is(err, store.ErrAccountClosed) {
		t.Fatalf("UpsertAccountProfile on a deleted account err=%v, want ErrAccountClosed", err)
	}
	if n := countRows(t, pool, "account_profiles", acct); n != 0 {
		t.Errorf("account_profiles holds %d row(s) after an upsert on a deleted account — "+
			"the deletion was undone by a late sign-in write", n)
	}
}

// TestUpsertAccountProfileRaceWithDeletionLeavesNoRow pins the actual
// interleaving the fence exists for: a sign-in whose session transaction has
// already committed, a deletion that commits next, and the sign-in's own
// trailing profile upsert landing last. Running the three in that order is the
// interleaving — the upsert is a separate transaction, so a deletion that
// commits before it is indistinguishable from one that committed a week ago.
//
// The account must end with NO profile row: not the pre-deletion one (purged),
// and not a fresh one written by the straggler.
func TestUpsertAccountProfileRaceWithDeletionLeavesNoRow(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	// 1. An earlier sign-in stored a profile.
	if err := s.UpsertAccountProfile(ctx, acct, "racer@example.test", "Racer", now); err != nil {
		t.Fatalf("UpsertAccountProfile (pre-deletion): %v", err)
	}
	if n := countRows(t, pool, "account_profiles", acct); n != 1 {
		t.Fatalf("fixture did not populate account_profiles (n=%d)", n)
	}

	// 2. The deletion commits — the session for the in-flight sign-in already
	//    exists, so nothing upstream will stop the write below.
	if _, err := s.CreateDeletionRequest(ctx, acct, now.Add(time.Second)); err != nil {
		t.Fatalf("CreateDeletionRequest: %v", err)
	}

	// 3. The in-flight sign-in's trailing best-effort upsert lands.
	err := s.UpsertAccountProfile(ctx, acct, "racer@example.test", "Racer", now.Add(2*time.Second))
	if !errors.Is(err, store.ErrAccountClosed) {
		t.Fatalf("the straggler upsert err=%v, want ErrAccountClosed", err)
	}

	if n := countRows(t, pool, "account_profiles", acct); n != 0 {
		t.Errorf("account_profiles holds %d row(s) after the deletion/upsert interleaving — "+
			"a deleted account regained a stored email", n)
	}
	got, err := s.AccountProfile(ctx, acct)
	if err != nil {
		t.Fatalf("AccountProfile: %v", err)
	}
	if !got.Empty() {
		t.Errorf("a deleted account still reads back a profile: %+v", got)
	}
}

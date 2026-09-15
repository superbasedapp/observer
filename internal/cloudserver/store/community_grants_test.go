package store_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// community_grants_test.go covers the W5 standing-grant REGISTRATION state
// machine + its retention/deletion lifecycle. Ground truth for the sweep's
// FK-safe behaviour with a retained community_grants row was established by
// calling SweepRetention against live PG (a temporary probe) before these were
// written.

// testCommunityDeviceID is the default authenticated device a
// communityGrantInput() call registers under. Sol F8's regression test below
// registers a SECOND, distinct device to prove the two never contend.
const testCommunityDeviceID = "11111111-1111-1111-1111-111111111111"

func communityGrantInput(gen int64, now time.Time) store.CommunityGrantInput {
	return store.CommunityGrantInput{
		Purpose:              string(cloudcontract.PurposeCohortBenchmarking),
		DeviceID:             testCommunityDeviceID,
		DataDictionaryDigest: cloudcontract.CommunityDataDictionaryDigest(),
		SchemaVersion:        cloudcontract.CommunityContributionSchemaVersion,
		ConsentGeneration:    gen,
		Now:                  now,
	}
}

// communityGrantInputForDevice is communityGrantInput with the device
// overridden, for multi-device tests.
func communityGrantInputForDevice(deviceID string, gen int64, now time.Time) store.CommunityGrantInput {
	in := communityGrantInput(gen, now)
	in.DeviceID = deviceID
	return in
}

func TestRegisterCommunityGrantStateMachine(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	// First sight → created.
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); err != nil || action != store.GrantRegistrationCreated {
		t.Fatalf("first register: action=%q err=%v, want created/nil", action, err)
	}
	// Same generation, same binding → unchanged.
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); err != nil || action != store.GrantRegistrationUnchanged {
		t.Fatalf("same-gen register: action=%q err=%v, want unchanged/nil", action, err)
	}
	// Higher generation → updated (the whole binding moves with the developer).
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(2, now)); err != nil || action != store.GrantRegistrationUpdated {
		t.Fatalf("higher-gen register: action=%q err=%v, want updated/nil", action, err)
	}
	// Lower generation → stale, refused.
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); !errors.Is(err, store.ErrCommunityGenerationStale) {
		t.Fatalf("lower-gen register err=%v, want ErrCommunityGenerationStale", err)
	}
	// Same generation, different dictionary digest → dictionary mismatch.
	badDict := communityGrantInput(2, now)
	badDict.DataDictionaryDigest = "sha256:not-the-served-dictionary"
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, badDict); !errors.Is(err, store.ErrCommunityDictionaryMismatch) {
		t.Fatalf("dict-mismatch register err=%v, want ErrCommunityDictionaryMismatch", err)
	}
	// Same generation, different schema version → terms mismatch.
	badTerms := communityGrantInput(2, now)
	badTerms.SchemaVersion = "community_contribution.v2-imaginary"
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, badTerms); !errors.Is(err, store.ErrCommunityGrantTermsMismatch) {
		t.Fatalf("terms-mismatch register err=%v, want ErrCommunityGrantTermsMismatch", err)
	}
	// Incomplete binding → refused before any write.
	incomplete := communityGrantInput(3, now)
	incomplete.DataDictionaryDigest = ""
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, incomplete); !errors.Is(err, store.ErrCommunityBindingIncomplete) {
		t.Fatalf("incomplete-binding register err=%v, want ErrCommunityBindingIncomplete", err)
	}
}

func TestRegisterCommunityGrantRefusedAfterRevocation(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Deleting the account revokes the registration (retain-then-revoke).
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// A later upload for a revoked registration is refused, never re-registered.
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(2, now)); !errors.Is(err, store.ErrCommunityGrantRevoked) {
		t.Fatalf("post-revocation register err=%v, want ErrCommunityGrantRevoked", err)
	}
}

// TestDeletionRevokesCommunityGrant proves the deletion pass revokes but RETAINS
// the registration row (the consent-registration fact), like structural_grants.
func TestDeletionRevokesCommunityGrant(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var count int
	var revoked *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT count(*), max(revoked_at) FROM community_grants WHERE account_id=$1::uuid`, acct).
		Scan(&count, &revoked); err != nil {
		t.Fatalf("read community_grants: %v", err)
	}
	if count != 1 {
		t.Fatalf("community_grants rows after deletion=%d, want 1 (retained)", count)
	}
	if revoked == nil {
		t.Fatal("community_grants row survived deletion but was NOT revoked")
	}
}

// TestRetentionSweepAgesOutCommunityGrant is the F9-class check: a retained
// community_grants row must not block the 24-month account DELETE, and must be
// aged out by the sweep.
func TestRetentionSweepAgesOutCommunityGrant(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInput(1, now)); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := s.CreateDeletionRequest(ctx, acct, now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE accounts SET deleted_at=$2, purge_after=$3 WHERE account_id=$1::uuid`,
		acct, now.Add(-25*30*24*time.Hour), now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	r, err := s.SweepRetention(ctx, now)
	if err != nil {
		t.Fatalf("SweepRetention with a retained community_grants row (F9-class FK check): %v", err)
	}
	if r.AccountsPurged != 1 {
		t.Fatalf("accounts_purged=%d, want 1", r.AccountsPurged)
	}
	assertCount(t, pool, "community_grants", acct, 0)
	assertCount(t, pool, "accounts", acct, 0)
}

// TestRegisterCommunityGrantDeviceIndependence is the Sol F8 regression: two
// devices under the SAME account registering the SAME purpose must not
// contend. Before 0028, community_grants was keyed only by (account_id,
// purpose), so whichever device most recently advanced the row's generation
// would make every OTHER device's registration look "stale" — a device could
// never even be REGISTERED (let alone advance) once another device had raced
// ahead. This proves live against PG that:
//
//  1. Device A registering a high generation, then Device B registering a
//     LOW generation for the first time, still CREATES Device B's own row
//     (not refused as stale) — because they are different device rows.
//  2. Device A driving its generation to math.MaxInt64 does not lock Device B
//     out of registering or subsequently advancing its OWN generation.
//  3. The existing same-device monotonic-generation rule is untouched: a
//     lower generation on the SAME device is still refused as stale.
func TestRegisterCommunityGrantDeviceIndependence(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	acct := makeAccount(t, s)

	const (
		deviceA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		deviceB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	)

	// Device A registers at generation 5, then races its own generation all
	// the way up to math.MaxInt64 — the highest generation the column's CHECK
	// constraint allows.
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInputForDevice(deviceA, 5, now)); err != nil || action != store.GrantRegistrationCreated {
		t.Fatalf("device A first register: action=%q err=%v, want created/nil", action, err)
	}
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInputForDevice(deviceA, math.MaxInt64, now)); err != nil || action != store.GrantRegistrationUpdated {
		t.Fatalf("device A generation-max register: action=%q err=%v, want updated/nil", action, err)
	}

	// Device B, first sight, at generation 1 — far BELOW device A's current
	// generation. Ground truth: this must be CREATED, not refused stale — the
	// bug this closes would have compared against device A's row and returned
	// ErrCommunityGenerationStale here.
	grantB, actionB, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInputForDevice(deviceB, 1, now))
	if err != nil {
		t.Fatalf("device B first register got err=%v (F8 regression: device A's high generation must not stale-lock device B), want nil", err)
	}
	if actionB != store.GrantRegistrationCreated {
		t.Fatalf("device B first register: action=%q, want created", actionB)
	}
	if grantB.DeviceID != deviceB {
		t.Fatalf("device B grant DeviceID=%q, want %q", grantB.DeviceID, deviceB)
	}
	if grantB.ConsentGeneration != 1 {
		t.Fatalf("device B grant ConsentGeneration=%d, want 1", grantB.ConsentGeneration)
	}

	// Device B can then advance its OWN generation independently of device A.
	if _, action, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInputForDevice(deviceB, 2, now)); err != nil || action != store.GrantRegistrationUpdated {
		t.Fatalf("device B advance: action=%q err=%v, want updated/nil", action, err)
	}

	// The existing same-device monotonic rule still holds: a LOWER generation
	// on device A itself is still refused stale (unaffected by device B).
	if _, _, err := s.RegisterCommunityGrant(ctx, acct, communityGrantInputForDevice(deviceA, 1, now)); !errors.Is(err, store.ErrCommunityGenerationStale) {
		t.Fatalf("device A lower-gen register err=%v, want ErrCommunityGenerationStale", err)
	}

	// Ground truth at the row level: TWO rows exist for this (account,
	// purpose), one per device, each carrying its own generation.
	rows, err := pool.Query(ctx,
		`SELECT device_id, consent_generation FROM community_grants
		  WHERE account_id = $1::uuid AND purpose = $2
		  ORDER BY device_id`,
		acct, string(cloudcontract.PurposeCohortBenchmarking))
	if err != nil {
		t.Fatalf("read community_grants rows: %v", err)
	}
	defer rows.Close()
	got := map[string]int64{}
	for rows.Next() {
		var dev string
		var gen int64
		if err := rows.Scan(&dev, &gen); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[dev] = gen
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("community_grants rows for (account,purpose)=%d, want 2 (one per device)", len(got))
	}
	if got[deviceA] != math.MaxInt64 {
		t.Fatalf("device A stored generation=%d, want math.MaxInt64", got[deviceA])
	}
	if got[deviceB] != 2 {
		t.Fatalf("device B stored generation=%d, want 2", got[deviceB])
	}
}

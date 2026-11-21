package store_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staffcredentials_test.go proves the operator's passkey management and the
// login-membership read against Postgres (rulings A2, A3): several passkeys
// per staff member, revocation of one ending only its own sessions, and a
// staff-bound Store reaching no customer table.

func TestStaffCredentialsListAndRevoke(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	s, err := store.NewForRole(pool, store.RoleStaff)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	staffID := enrolAndRegister(t, s, nil, now, bytes.Repeat([]byte{1}, 32))
	enrolAndRegister(t, s, &staffID, now.Add(time.Minute), bytes.Repeat([]byte{2}, 32))

	creds, err := s.ListStaffCredentials(ctx, staffID)
	if err != nil || len(creds) != 2 {
		t.Fatalf("ListStaffCredentials = %d, %v; want 2", len(creds), err)
	}
	for _, c := range creds {
		if !c.Active() || c.Label != "key" {
			t.Errorf("credential %x = %+v", c.ID, c)
		}
	}
	if _, err := s.ListStaffCredentials(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown staff member: err = %v", err)
	}
	if err := s.RevokeStaffCredential(ctx, staffID, bytes.Repeat([]byte{1}, 32), "", now); err == nil {
		t.Error("revoked without a reason")
	}
	if err := s.RevokeStaffCredential(ctx, staffID, bytes.Repeat([]byte{9}, 32), "lost", now); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown credential: err = %v", err)
	}
	if err := s.RevokeStaffCredential(ctx, staffID, bytes.Repeat([]byte{1}, 32), "lost", now); err != nil {
		t.Fatalf("RevokeStaffCredential: %v", err)
	}
	creds, err = s.ListStaffCredentials(ctx, staffID)
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, c := range creds {
		if c.Active() {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active after one revocation = %d, want 1", active)
	}
	if _, _, err := s.StaffCredentialForAssertion(ctx, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoked credential still found for assertion: %v", err)
	}
	if _, _, err := s.StaffCredentialForAssertion(ctx, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Errorf("the other credential: %v", err)
	}
}

// enrolAndRegister enrols (or, with existing, re-enrols) a staff member and
// registers a credential with id through a register ceremony.
func enrolAndRegister(t *testing.T, s *store.Store, existing *string, now time.Time, id []byte) string {
	t.Helper()
	ctx := context.Background()
	in := store.EnrolStaffInput{DisplayName: "Ops", Role: staffauth.RoleOps, Reason: "test", Now: now}
	if existing != nil {
		in = store.EnrolStaffInput{StaffID: *existing, Reason: "backup", Now: now}
	}
	e, err := s.EnrolStaff(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	ceremony := "ceremony-" + string(rune('a'+id[0]))
	if _, err := s.BeginStaffRegistration(ctx, e.RawCode, ceremony, bytes.Repeat([]byte{id[0]}, staffauth.ChallengeBytes), now); err != nil {
		t.Fatal(err)
	}
	c, err := s.ConsumeStaffCeremony(ctx, ceremony, store.StaffCeremonyRegister, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterStaffCredential(ctx, c, staffauth.NewCredential{ID: id, PublicKey: []byte{1, 2, 3}}, "key", now); err != nil {
		t.Fatal(err)
	}
	return e.Staff.StaffID
}

func TestStaffBoundStoreReachesNoCustomerTable(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	s, err := store.NewForRole(pool, store.RoleStaff)
	if err != nil {
		t.Fatal(err)
	}
	if s.Role() != store.RoleStaff {
		t.Fatalf("role = %s", s.Role())
	}
	// A customer-plane read through the staff-bound store runs as
	// sbci_staff and is refused by the grants.
	if _, err := s.OverviewStats(context.Background(), "00000000-0000-4000-8000-000000000000"); err == nil {
		t.Fatal("a staff-bound store read a customer table")
	}
	m, err := s.LoginMemberships(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A superuser (the usual harness login) is a member of every role.
	if m.Login == "" || (m.Superuser && (!m.Staff || !m.API || !m.Worker)) {
		t.Errorf("memberships = %+v", m)
	}
}

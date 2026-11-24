package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staff_test.go proves the staff console's tables and store seam (cloud
// migrations 0068-0070, managed-SaaS M6.8) against Postgres: the role, the
// grants and role-bound policies, the append-only action log, single-use
// enrolment codes and ceremonies, the session rules and the availability
// inputs' logging. Every test needs Postgres (cloudtestpg; SKIPPED loudly
// without SBCI_TEST_PG_DSN).

// staffTables is every table 0069 creates, with each role's table-level
// grants (column-level UPDATE grants are pinned separately).
var staffTables = []struct {
	table  string
	grants map[string][]string
}{
	{"staff_users", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}}},
	{"staff_webauthn_credentials", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}}},
	{"staff_enrolments", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}}},
	{"staff_ceremonies", map[string][]string{"sbci_staff": {"SELECT", "INSERT", "DELETE"}}},
	{"staff_sessions", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}}},
	{"staff_actions", map[string][]string{"sbci_staff": {"SELECT", "INSERT"}}},
	{"availability_inputs", map[string][]string{
		"sbci_staff":  {"SELECT", "INSERT", "UPDATE", "DELETE"},
		"sbci_worker": {"SELECT"},
	}},
}

func TestStaffTableClassesAndGrants(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	ctx := context.Background()

	// Every staff table is declared, and only those.
	rows, err := pool.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE 'staff\_%' OR tablename = 'availability_inputs')`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	real := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		real[n] = true
	}
	rows.Close()
	if len(real) != len(staffTables) {
		t.Errorf("staff tables in the schema = %v, declared %d", real, len(staffTables))
	}

	roles := []string{"sbci_api", "sbci_worker", "sbci_aggregator", "sbci_app", "sbci_staff"}
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	for _, c := range staffTables {
		if !real[c.table] {
			t.Errorf("declared table %s does not exist", c.table)
			continue
		}
		var rls, force bool
		if err := pool.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`, c.table).Scan(&rls, &force); err != nil {
			t.Fatalf("RLS state of %s: %v", c.table, err)
		}
		if !rls || !force {
			t.Errorf("%s: row-level security enabled %v forced %v, want both", c.table, rls, force)
		}
		for _, role := range roles {
			for _, p := range privs {
				want := false
				for _, g := range c.grants[role] {
					want = want || g == p
				}
				if got := tableLevelPriv(t, pool, role, c.table, p); got != want {
					t.Errorf("%s table-level %s on %s = %v, want %v", role, p, c.table, got, want)
				}
			}
		}
	}

	// Column-level UPDATE: only the mutable columns.
	for _, c := range []struct {
		table, column string
		want          bool
	}{
		{"staff_webauthn_credentials", "sign_count", true},
		{"staff_webauthn_credentials", "last_used_at", true},
		{"staff_webauthn_credentials", "revoked_at", true},
		{"staff_webauthn_credentials", "public_key", false},
		{"staff_webauthn_credentials", "staff_id", false},
		{"staff_enrolments", "used_at", true},
		{"staff_enrolments", "expires_at", false},
		{"staff_ceremonies", "consumed_at", true},
		{"staff_ceremonies", "challenge", false},
		{"staff_sessions", "revoked_at", true},
		{"staff_sessions", "idle_expires_at", true},
		{"staff_sessions", "webauthn_at", false},
		{"staff_sessions", "staff_id", false},
		{"staff_users", "staff_role", false},
		{"staff_actions", "reason", false},
	} {
		if got := columnPriv(t, pool, "sbci_staff", c.table, c.column, "UPDATE"); got != c.want {
			t.Errorf("sbci_staff UPDATE on %s.%s = %v, want %v", c.table, c.column, got, c.want)
		}
	}

	// sbci_staff reaches no customer table.
	for _, table := range []string{"accounts", "identity_links", "browser_sessions", "api_tokens", "analysis_results", "evidence_blobs", "orgs", "org_members", "oidc_codes", "availability_docs"} {
		for _, p := range privs {
			if tablePriv(t, pool, "sbci_staff", table, p) {
				t.Errorf("sbci_staff holds %s on customer table %s", p, table)
			}
		}
	}

	// The role cannot log in or bypass row-level security.
	var login, bypass bool
	if err := pool.QueryRow(ctx, `SELECT rolcanlogin, rolbypassrls FROM pg_roles WHERE rolname = 'sbci_staff'`).Scan(&login, &bypass); err != nil {
		t.Fatalf("read sbci_staff: %v", err)
	}
	if login || bypass {
		t.Errorf("sbci_staff login=%v bypassrls=%v, want both false", login, bypass)
	}
}

// asRole runs sql as role in a rolled-back transaction and returns its
// error.
func asRole(t *testing.T, pool *pgxpool.Pool, role, sql string, args ...any) error {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// role is one of this file's literals, never input.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL ROLE %s", role)); err != nil {
		t.Fatalf("set role %s: %v", role, err)
	}
	_, err = tx.Exec(ctx, sql, args...)
	return err
}

func enrolTestStaff(t *testing.T, s *store.Store, role staffauth.Role, now time.Time) store.StaffEnrolment {
	t.Helper()
	e, err := s.EnrolStaff(context.Background(), store.EnrolStaffInput{
		DisplayName: fmt.Sprintf("Staff %d", subjCounter.Add(1)), Role: role, Reason: "test enrolment", Now: now,
	})
	if err != nil {
		t.Fatalf("EnrolStaff: %v", err)
	}
	return e
}

func testChallenge(b byte) []byte { return bytes.Repeat([]byte{b}, staffauth.ChallengeBytes) }

func testCredential(seed byte) staffauth.NewCredential {
	return staffauth.NewCredential{ID: bytes.Repeat([]byte{seed}, 20), PublicKey: bytes.Repeat([]byte{seed + 1}, 32)}
}

// registerTestStaff enrols, registers a credential and returns the staff id
// and credential id.
func registerTestStaff(t *testing.T, s *store.Store, role staffauth.Role, seed byte, now time.Time) (string, []byte) {
	t.Helper()
	ctx := context.Background()
	e := enrolTestStaff(t, s, role, now)
	cer := fmt.Sprintf("ceremony-%d", subjCounter.Add(1))
	if _, err := s.BeginStaffRegistration(ctx, e.RawCode, cer, testChallenge(seed), now); err != nil {
		t.Fatalf("BeginStaffRegistration: %v", err)
	}
	c, err := s.ConsumeStaffCeremony(ctx, cer, store.StaffCeremonyRegister, now)
	if err != nil {
		t.Fatalf("ConsumeStaffCeremony: %v", err)
	}
	cred := testCredential(seed)
	if err := s.RegisterStaffCredential(ctx, c, cred, "key", now); err != nil {
		t.Fatalf("RegisterStaffCredential: %v", err)
	}
	return e.Staff.StaffID, cred.ID
}

func TestStaffActionsAreAppendOnlyAndRoleBound(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	now := time.Now()
	enrolTestStaff(t, s, staffauth.RoleAdmin, now)

	if err := asRole(t, pool, "sbci_staff", `UPDATE staff_actions SET reason = 'rewritten'`); err == nil {
		t.Error("sbci_staff rewrote the action log")
	}
	if err := asRole(t, pool, "sbci_staff", `DELETE FROM staff_actions`); err == nil {
		t.Error("sbci_staff deleted from the action log")
	}
	for _, role := range []string{"sbci_api", "sbci_app", "sbci_worker", "sbci_aggregator"} {
		if err := asRole(t, pool, role, `SELECT 1 FROM staff_users`); err == nil {
			t.Errorf("%s read staff_users", role)
		}
		if err := asRole(t, pool, role, `SELECT 1 FROM staff_sessions`); err == nil {
			t.Errorf("%s read staff_sessions", role)
		}
	}
	if err := asRole(t, pool, "sbci_staff", `SELECT 1 FROM accounts`); err == nil {
		t.Error("sbci_staff read accounts")
	}
	if err := asRole(t, pool, "sbci_worker", `SELECT 1 FROM availability_inputs`); err != nil {
		t.Errorf("sbci_worker cannot read availability_inputs: %v", err)
	}
}

func TestStaffEnrolmentCodeIsSingleUse(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()
	e := enrolTestStaff(t, s, staffauth.RoleAdmin, now)

	// Two ceremonies from one code: the code yields one credential.
	if _, err := s.BeginStaffRegistration(ctx, e.RawCode, "cer-a", testChallenge(1), now); err != nil {
		t.Fatalf("begin a: %v", err)
	}
	if _, err := s.BeginStaffRegistration(ctx, e.RawCode, "cer-b", testChallenge(2), now); err != nil {
		t.Fatalf("begin b: %v", err)
	}
	a, err := s.ConsumeStaffCeremony(ctx, "cer-a", store.StaffCeremonyRegister, now)
	if err != nil {
		t.Fatalf("consume a: %v", err)
	}
	b, err := s.ConsumeStaffCeremony(ctx, "cer-b", store.StaffCeremonyRegister, now)
	if err != nil {
		t.Fatalf("consume b: %v", err)
	}
	if err := s.RegisterStaffCredential(ctx, a, testCredential(3), "", now); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := s.RegisterStaffCredential(ctx, b, testCredential(5), "", now); !errors.Is(err, store.ErrStaffEnrolmentInvalid) {
		t.Fatalf("register b = %v, want ErrStaffEnrolmentInvalid", err)
	}
	if _, err := s.BeginStaffRegistration(ctx, e.RawCode, "cer-c", testChallenge(4), now); !errors.Is(err, store.ErrStaffEnrolmentInvalid) {
		t.Fatalf("begin after use = %v, want ErrStaffEnrolmentInvalid", err)
	}
	// A ceremony is spent once, and only as its own kind.
	if _, err := s.ConsumeStaffCeremony(ctx, "cer-a", store.StaffCeremonyRegister, now); !errors.Is(err, store.ErrStaffCeremonyInvalid) {
		t.Fatalf("second consume = %v", err)
	}
	if err := s.BeginStaffAssertion(ctx, "cer-d", testChallenge(6), now); err != nil {
		t.Fatalf("begin assert: %v", err)
	}
	if _, err := s.ConsumeStaffCeremony(ctx, "cer-d", store.StaffCeremonyRegister, now); !errors.Is(err, store.ErrStaffCeremonyInvalid) {
		t.Fatalf("assert ceremony consumed as register = %v", err)
	}
	if _, err := s.ConsumeStaffCeremony(ctx, "cer-d", store.StaffCeremonyAssert, now.Add(store.StaffCeremonyTTL+time.Second)); !errors.Is(err, store.ErrStaffCeremonyInvalid) {
		t.Fatalf("expired ceremony = %v", err)
	}
	// An expired code is refused.
	late := enrolTestStaff(t, s, staffauth.RoleOps, now)
	if _, err := s.BeginStaffRegistration(ctx, late.RawCode, "cer-e", testChallenge(7), late.ExpiresAt.Add(time.Second)); !errors.Is(err, store.ErrStaffEnrolmentInvalid) {
		t.Fatalf("expired code = %v", err)
	}
	// The same credential cannot be registered twice.
	again, err := s.EnrolStaff(ctx, store.EnrolStaffInput{StaffID: e.Staff.StaffID, Reason: "second key", Now: now})
	if err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	if _, err := s.BeginStaffRegistration(ctx, again.RawCode, "cer-f", testChallenge(8), now); err != nil {
		t.Fatalf("begin f: %v", err)
	}
	f, err := s.ConsumeStaffCeremony(ctx, "cer-f", store.StaffCeremonyRegister, now)
	if err != nil {
		t.Fatalf("consume f: %v", err)
	}
	if err := s.RegisterStaffCredential(ctx, f, testCredential(3), "", now); !errors.Is(err, store.ErrStaffCredentialExists) {
		t.Fatalf("duplicate credential = %v", err)
	}
}

func TestEnrolStaffValidation(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		in   store.EnrolStaffInput
	}{
		{"unknown role", store.EnrolStaffInput{DisplayName: "A", Role: "root", Reason: "r"}},
		{"empty name", store.EnrolStaffInput{DisplayName: " ", Role: staffauth.RoleOps, Reason: "r"}},
		{"no reason", store.EnrolStaffInput{DisplayName: "A", Role: staffauth.RoleOps}},
		{"ttl too long", store.EnrolStaffInput{DisplayName: "A", Role: staffauth.RoleOps, Reason: "r", TTL: 2 * time.Hour}},
		{"unknown staff id", store.EnrolStaffInput{StaffID: "00000000-0000-4000-8000-000000000000", Reason: "r"}},
	} {
		if _, err := s.EnrolStaff(ctx, c.in); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

func TestStaffSessionLifecycle(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	staffID, credID := registerTestStaff(t, s, staffauth.RoleOps, 10, now)

	cred, user, err := s.StaffCredentialForAssertion(ctx, credID)
	if err != nil || user.StaffID != staffID || user.Role != staffauth.RoleOps || cred.SignCount != 0 {
		t.Fatalf("StaffCredentialForAssertion = %+v %+v %v", cred, user, err)
	}
	if !bytes.Equal(cred.UserHandle, store.StaffUserHandle(staffID)) || len(cred.UserHandle) != 16 {
		t.Fatalf("user handle = %x", cred.UserHandle)
	}
	start := func(stored, next uint32, prior string, at time.Time) (store.StaffSession, error) {
		return s.StartStaffSession(ctx, store.StartStaffSessionInput{
			StaffID: staffID, CredentialID: credID, StoredSignCount: stored, NewSignCount: next,
			PriorRawSession: prior, TTL: time.Hour, IdleTTL: 10 * time.Minute, Now: at,
		})
	}
	first, err := start(0, 1, "", now)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	p, err := s.IntrospectStaffSession(ctx, first.RawSession, now.Add(time.Minute), 10*time.Minute)
	if err != nil || p.StaffID != staffID || !p.AssertedAt.Equal(now) {
		t.Fatalf("introspect = %+v %v", p, err)
	}
	// A stale stored counter (a concurrent use of the same assertion) starts nothing.
	if _, err := start(0, 1, "", now); !errors.Is(err, store.ErrStaffCredentialStale) {
		t.Fatalf("stale counter = %v", err)
	}
	// A new sign-in revokes the prior session.
	second, err := start(1, 2, first.RawSession, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if _, err := s.IntrospectStaffSession(ctx, first.RawSession, now.Add(3*time.Minute), 10*time.Minute); !errors.Is(err, store.ErrStaffSessionInvalid) {
		t.Fatalf("prior session = %v, want invalid", err)
	}
	// Idle expiry, then a session past its windows.
	if _, err := s.IntrospectStaffSession(ctx, second.RawSession, now.Add(2*time.Minute+11*time.Minute), 10*time.Minute); !errors.Is(err, store.ErrStaffSessionInvalid) {
		t.Fatalf("idle session = %v, want invalid", err)
	}
	third, err := start(2, 3, "", now.Add(20*time.Minute))
	if err != nil {
		t.Fatalf("third start: %v", err)
	}
	if _, err := s.IntrospectStaffSession(ctx, third.RawSession, now.Add(20*time.Minute+time.Hour), 2*time.Hour); !errors.Is(err, store.ErrStaffSessionInvalid) {
		t.Fatalf("expired session = %v, want invalid", err)
	}
	// Sign-out.
	fourth, err := start(3, 4, "", now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("fourth start: %v", err)
	}
	if err := s.EndStaffSession(ctx, staffID, fourth.RawSession, now.Add(31*time.Minute)); err != nil {
		t.Fatalf("end: %v", err)
	}
	if _, err := s.IntrospectStaffSession(ctx, fourth.RawSession, now.Add(31*time.Minute), 10*time.Minute); !errors.Is(err, store.ErrStaffSessionInvalid) {
		t.Fatalf("ended session = %v", err)
	}
	// A customer session token is not a staff session, and an empty one is refused.
	if _, err := s.IntrospectStaffSession(ctx, "", now, time.Minute); !errors.Is(err, store.ErrStaffSessionInvalid) {
		t.Fatalf("empty session = %v", err)
	}
	actions, err := s.ListStaffActions(ctx, 50)
	if err != nil {
		t.Fatalf("ListStaffActions: %v", err)
	}
	verbs := map[string]int{}
	for _, a := range actions {
		verbs[a.Verb]++
	}
	if verbs[string(staffauth.VerbSessionStarted)] < 4 || verbs[string(staffauth.VerbSessionEnded)] < 1 || verbs[string(staffauth.VerbCredentialRegistered)] < 1 || verbs[string(staffauth.VerbEnrolmentMinted)] < 1 {
		t.Fatalf("action log verbs = %v", verbs)
	}
}

func TestAvailabilityInputsAreLoggedWithTheirChange(t *testing.T) {
	t.Parallel()
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Now()
	staffID, _ := registerTestStaff(t, s, staffauth.RoleOps, 20, now)

	const org = "33333333-3333-4333-8333-333333333333"
	// A value the envelope would refuse is never stored (STAFF-8): here
	// an org row asking for a platform-wide ingest pause.
	bad, err := staffauth.ValidateAvailabilityInput("org_controls", org, []byte(`{"org":"*","ingest":{"mode":"pause"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailabilityInput(ctx, staffID, bad, "should be refused", now); !errors.Is(err, availcompose.ErrInvalidInput) {
		t.Fatalf("invalid value: err = %v, want availcompose.ErrInvalidInput", err)
	}
	in, err := staffauth.ValidateAvailabilityInput("org_controls", org, []byte(`{"org":"`+org+`","ingest":{"mode":"pause"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailabilityInput(ctx, staffID, in, "incident 1", now); err != nil {
		t.Fatalf("set: %v", err)
	}
	in2, _ := staffauth.ValidateAvailabilityInput("org_controls", org, []byte(`{"org":"`+org+`","ingest":{"mode":"throttle","rate_per_minute":10}}`))
	if err := s.SetAvailabilityInput(ctx, staffID, in2, "incident 1, easing", now.Add(time.Minute)); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := s.SetAvailabilityInput(ctx, staffID, in2, " ", now); err == nil {
		t.Fatal("a blank reason was accepted")
	}
	rows, err := s.ListAvailabilityInputs(ctx)
	if err != nil || len(rows) != 1 || rows[0].Author != staffauth.Actor(staffID) || rows[0].Reason != "incident 1, easing" {
		t.Fatalf("inputs = %+v %v", rows, err)
	}
	if err := s.DeleteAvailabilityInput(ctx, staffID, staffauth.SectionOrgControls, org, "incident over", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := s.DeleteAvailabilityInput(ctx, staffID, staffauth.SectionOrgControls, org, "again", now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM availability_inputs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("inputs left = %d (%v)", n, err)
	}
	// Each change is logged with its reason and the value it replaced.
	var detail []byte
	if err := pool.QueryRow(ctx,
		`SELECT detail FROM staff_actions WHERE verb = 'availability.set' AND reason = 'incident 1, easing'`).Scan(&detail); err != nil {
		t.Fatalf("read log: %v", err)
	}
	var d struct {
		Value    map[string]any `json:"value"`
		Previous map[string]any `json:"previous"`
	}
	mode := func(m map[string]any) any {
		ing, _ := m["ingest"].(map[string]any)
		return ing["mode"]
	}
	if err := json.Unmarshal(detail, &d); err != nil || mode(d.Previous) != "pause" || mode(d.Value) != "throttle" {
		t.Fatalf("logged detail = %s (%v)", detail, err)
	}
	for verb, want := range map[string]int{"availability.set": 2, "availability.deleted": 1} {
		var got int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM staff_actions WHERE verb = $1 AND actor = $2`, verb, staffauth.Actor(staffID)).Scan(&got); err != nil || got != want {
			t.Errorf("%s rows = %d (%v), want %d", verb, got, err, want)
		}
	}
}

// TestStaffRoleVocabularyMatchesTheCheck pins staffauth.KnownRoles and
// KnownSections against the database CHECKs.
func TestStaffRoleVocabularyMatchesTheCheck(t *testing.T) {
	t.Parallel()
	_, pool := newStore(t)
	for _, r := range staffauth.KnownRoles {
		if err := asRole(t, pool, "sbci_staff", `INSERT INTO staff_users (display_name, staff_role) VALUES ('x', $1)`, string(r)); err != nil {
			t.Errorf("role %s refused by the CHECK: %v", r, err)
		}
	}
	if err := asRole(t, pool, "sbci_staff", `INSERT INTO staff_users (display_name, staff_role) VALUES ('x', 'root')`); err == nil {
		t.Error("the CHECK accepted an unknown role")
	}
	for _, sec := range staffauth.KnownSections {
		if err := asRole(t, pool, "sbci_staff",
			`INSERT INTO availability_inputs (section, key, value, reason, author, updated_at)
			 VALUES ($1, 'k', '{}', 'r', 'staff:00000000-0000-4000-8000-000000000000', now())`, string(sec)); err != nil {
			t.Errorf("section %s refused by the CHECK: %v", sec, err)
		}
	}
}

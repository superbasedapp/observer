package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// staffconsole_test.go covers the staff console's org reads (staffconsole.go,
// cloud 0133) and the filtered action log. Every test needs Postgres
// (cloudtestpg; SKIPPED loudly without SBCI_TEST_PG_DSN).

const staffTestKeyID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestStaffOrgReads(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()

	// A fresh org: registry fields, one member, a pending create intent, no
	// grant, subscription, usage, document or deletion.
	orgs, err := f.s.ListStaffOrgs(ctx)
	if err != nil || len(orgs) != 1 {
		t.Fatalf("ListStaffOrgs = %+v err=%v, want the one org", orgs, err)
	}
	o := orgs[0]
	if o.OrgID != f.org.OrgID || o.Kind != "team" || o.Slug != f.org.Slug || o.Members != 1 || o.Status == "" || o.Tenancy != "managed" {
		t.Fatalf("org = %+v", o)
	}
	if o.Grant != nil || o.Subscription != nil || o.Usage != nil || o.Entitlements != nil {
		t.Fatalf("a fresh org carries derived facts: %+v", o)
	}
	d, err := f.s.StaffOrgDetail(ctx, f.org.OrgID)
	if err != nil {
		t.Fatalf("StaffOrgDetail: %v", err)
	}
	if len(d.Grants) != 0 || len(d.Usage) != 0 || d.Entitlements != nil || d.Deletion != nil {
		t.Fatalf("fresh detail = %+v", d)
	}
	if len(d.Intents) != 1 || d.Intents[0].Verb != "create_tenant" || d.Intents[0].State != "pending" {
		t.Fatalf("intents = %+v, want the pending create_tenant", d.Intents)
	}

	// Grant, usage, a signed document and a deletion request.
	if _, _, err := f.s.GrantOrgPlan(ctx, store.OrgPlanGrantInput{
		OrgID: f.org.OrgID, Kind: store.OrgTeam, Plan: "business", Reason: "internal org",
	}, time.Now()); err != nil {
		t.Fatalf("GrantOrgPlan: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_usage_days (org_id, day, seat_member_ids, machine_identities, sessions, members, report_digest)
		 VALUES ($1::uuid, '2026-11-14', '{a,b,c}', 2, 10, 4, repeat('a', 64)),
		        ($1::uuid, '2026-11-13', '{a}', 1, 1, 1, repeat('b', 64))`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	body := `{"schema":"sbo-entitlements-v1","kind":"team","plan":{"name":"business","version":1,"label":"Business"}}`
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_entitlement_docs (org_id, version, body, signature, key_id, issued_at, issued_by)
		 VALUES ($1::uuid, 1, 'x'::bytea, decode(repeat('00', 64), 'hex'), $2, now() - interval '1 hour', 'system'),
		        ($1::uuid, 2, convert_to($3, 'UTF8'), decode(repeat('00', 64), 'hex'), $2, now(), 'system')`,
		f.org.OrgID, staffTestKeyID, body); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_deletion_requests (org_id, requested_by, state, blocked_reason)
		 VALUES ($1::uuid, $2::uuid, 'blocked', 'host_refused')`, f.org.OrgID, f.owner); err != nil {
		t.Fatal(err)
	}

	orgs, err = f.s.ListStaffOrgs(ctx)
	if err != nil || len(orgs) != 1 {
		t.Fatalf("ListStaffOrgs after = %+v err=%v", orgs, err)
	}
	o = orgs[0]
	if o.Grant == nil || o.Grant.Action != "grant" || o.Grant.PlanName != "business" || o.Grant.PlanVersion < 1 {
		t.Errorf("grant = %+v", o.Grant)
	}
	if o.Usage == nil || o.Usage.Day != "2026-11-14" || o.Usage.Seats != 3 || o.Usage.Members != 4 {
		t.Errorf("usage = %+v, want the latest day", o.Usage)
	}
	if o.Entitlements == nil || o.Entitlements.Version != 2 {
		t.Errorf("entitlements = %+v, want version 2", o.Entitlements)
	}

	d, err = f.s.StaffOrgDetail(ctx, f.org.OrgID)
	if err != nil {
		t.Fatalf("StaffOrgDetail after: %v", err)
	}
	if len(d.Grants) != 1 || d.Grants[0].Actor != "operator" || d.Grants[0].Reason != "internal org" {
		t.Errorf("grant history = %+v, want the operator row with its reason", d.Grants)
	}
	if len(d.Usage) != 2 || d.Usage[0].Day != "2026-11-14" || d.Usage[0].Sessions != 10 || d.Usage[0].MachineIdentities != 2 {
		t.Errorf("usage = %+v", d.Usage)
	}
	if d.Entitlements == nil || d.Entitlements.Version != 2 || d.Entitlements.KeyID != staffTestKeyID ||
		d.Entitlements.BodyBytes != len(body) || !json.Valid(d.Entitlements.Body) || !strings.Contains(string(d.Entitlements.Body), "business") {
		t.Errorf("entitlements doc = %+v", d.Entitlements)
	}
	if d.Deletion == nil || d.Deletion.State != "blocked" || d.Deletion.BlockedReason != "host_refused" {
		t.Errorf("deletion = %+v", d.Deletion)
	}

	// Unknown and malformed ids.
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "nope", ""} {
		if _, err := f.s.StaffOrgDetail(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("StaffOrgDetail(%q) = %v, want ErrNotFound", id, err)
		}
	}
}

func TestStaffAvailabilityDocument(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	if _, err := s.StaffAvailabilityDocument(ctx); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no envelope yet: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO availability_docs (version, body, signature, key_id, issued_at, issued_by)
		 VALUES (1, convert_to('{"org_controls":[]}', 'UTF8'), decode(repeat('00', 64), 'hex'), $1, now() - interval '1 hour', 'system'),
		        (7, convert_to('{"org_controls":[{"org":"*"}]}', 'UTF8'), decode(repeat('00', 64), 'hex'), $1, now(), 'system')`,
		staffTestKeyID); err != nil {
		t.Fatal(err)
	}
	doc, err := s.StaffAvailabilityDocument(ctx)
	if err != nil || doc.Version != 7 || !strings.Contains(string(doc.Body), `"*"`) {
		t.Fatalf("envelope = %+v err=%v, want version 7", doc, err)
	}
}

// TestStaffReadsRefuseOtherRoles: the 0133 definers are the staff role's
// alone; a customer or worker transaction cannot call them.
func TestStaffReadsRefuseOtherRoles(t *testing.T) {
	_, pool := newStore(t)
	ctx := context.Background()
	for _, role := range []string{"sbci_api", "sbci_worker", "sbci_app"} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, `SET LOCAL ROLE `+role)
		if err == nil {
			_, err = tx.Exec(ctx, `SELECT * FROM sbci_staff_orgs(NULL)`)
		}
		_ = tx.Rollback(ctx)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s called sbci_staff_orgs: %v", role, err)
		}
	}
}

func TestListStaffActionsFiltered(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	e := enrolTestStaff(t, s, staffauth.RoleOps, now)
	orgA, orgB := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	in, err := staffauth.ValidateAvailabilityInput("org_controls", orgA, []byte(`{"org":"`+orgA+`","ingest":{"mode":"pause"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAvailabilityInput(ctx, e.Staff.StaffID, in, "pause org a", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO staff_actions (at, actor, verb, subject_staff_id, org_id, target, reason, result) VALUES
		 ($1, $2, 'support.signin', $3::uuid, $4::uuid, 'client', 'ticket 1', 'ok'),
		 ($5, $2, 'support.signin', $3::uuid, $6::uuid, 'client', 'ticket 2', 'ok')`,
		now.Add(2*time.Minute), staffauth.Actor(e.Staff.StaffID), e.Staff.StaffID, orgA, now.Add(3*time.Minute), orgB); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		f    store.StaffActionFilter
		want []string // reasons, newest first
	}{
		{"org a: its support sign-in and its org_controls change", store.StaffActionFilter{OrgID: orgA}, []string{"ticket 1", "pause org a"}},
		{"verb", store.StaffActionFilter{Verb: "support.signin"}, []string{"ticket 2", "ticket 1"}},
		{"before", store.StaffActionFilter{Verb: "support.signin", Before: now.Add(3 * time.Minute)}, []string{"ticket 1"}},
		{"limit", store.StaffActionFilter{Verb: "support.signin", Limit: 1}, []string{"ticket 2"}},
		{"availability", store.StaffActionFilter{Verb: string(staffauth.VerbAvailabilitySet), Actor: staffauth.Actor(e.Staff.StaffID)}, []string{"pause org a"}},
		{"malformed org matches nothing", store.StaffActionFilter{OrgID: "x"}, nil},
	}
	for _, c := range cases {
		got, err := s.ListStaffActionsFiltered(ctx, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var reasons []string
		for _, a := range got {
			reasons = append(reasons, a.Reason)
		}
		if strings.Join(reasons, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: reasons = %v, want %v", c.name, reasons, c.want)
		}
	}
}

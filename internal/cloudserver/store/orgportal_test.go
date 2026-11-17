package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// orgportal_test.go covers the console's org reads and its rename
// (orgportal.go, cloud 0091; docs/security.md PORTALORG-2, PORTALORG-7).

func TestOrgSlugAvailable(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_slugs (slug, org_id, is_alias, alias_until) VALUES ('old-acme', $1::uuid, true, now() - interval '1 day')`,
		f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	other := makeAccount(t, f.s)
	cases := []struct {
		slug string
		want bool
	}{
		{f.org.Slug, false},
		{"fresh-team", true},
		{"old-acme", false}, // an expired alias still holds the key
	}
	for _, tc := range cases {
		got, err := f.s.OrgSlugAvailable(ctx, other, tc.slug)
		if err != nil || got != tc.want {
			t.Errorf("OrgSlugAvailable(%q) = %v err=%v, want %v", tc.slug, got, err, tc.want)
		}
	}
	// The answer matches what provisioning does with the free one.
	if _, err := f.s.ProvisionOrg(ctx, other, store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "fresh-team", DisplayName: "Fresh", Tenancy: store.TenancyManaged}); err != nil {
		t.Fatalf("provision the free slug: %v", err)
	}
	if got, _ := f.s.OrgSlugAvailable(ctx, other, "fresh-team"); got {
		t.Error("a just-provisioned slug still reads available")
	}
	if _, err := f.s.ProvisionOrg(ctx, other, store.ProvisionOrgInput{Kind: store.OrgTeam, Slug: "old-acme", DisplayName: "X", Tenancy: store.TenancyManaged}); !errors.Is(err, store.ErrOrgSlugTaken) {
		t.Errorf("provisioning a slug read as taken: %v", err)
	}
}

func TestOrgCreateStatusAndSeats(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	stranger := makeAccount(t, f.s)

	cs, err := f.s.OrgCreateStatus(ctx, f.owner, f.org.OrgID)
	if err != nil || cs.State != "pending" || cs.Attempts != 0 || cs.LastErrorClass != "" || cs.DoneAt != nil {
		t.Fatalf("fresh create status = %+v err=%v", cs, err)
	}
	if _, err := f.s.OrgCreateStatus(ctx, stranger, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("non-member read the create status: %v", err)
	}
	if _, err := f.s.OrgCreateStatus(ctx, f.owner, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("malformed id: %v", err)
	}
	// The host waitlisted it.
	if _, err := f.pool.Exec(ctx,
		`UPDATE org_outbox SET attempts=1, last_error_class='refused:capacity_waitlist', next_attempt_at=now() + interval '15 minutes'
		  WHERE org_id=$1::uuid AND verb='create_tenant'`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	cs, err = f.s.OrgCreateStatus(ctx, f.owner, f.org.OrgID)
	if err != nil || cs.LastErrorClass != "refused:capacity_waitlist" || cs.Attempts != 1 {
		t.Fatalf("waitlisted status = %+v err=%v", cs, err)
	}

	if _, err := f.s.OrgSeatsInUse(ctx, f.owner, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("seats with no usage day: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_usage_days (org_id, day, seat_member_ids, machine_identities, sessions, members, report_digest)
		 VALUES ($1::uuid, '2026-11-14', '{a,b,c}', 2, 10, 4, repeat('a', 64)),
		        ($1::uuid, '2026-11-13', '{a}', 1, 1, 1, repeat('b', 64))`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	seats, err := f.s.OrgSeatsInUse(ctx, f.owner, f.org.OrgID)
	if err != nil || seats.Seats != 3 || seats.Members != 4 || seats.Day.Format("2006-01-02") != "2026-11-14" {
		t.Fatalf("seats = %+v err=%v, want the latest day's 3", seats, err)
	}
	if _, err := f.s.OrgSeatsInUse(ctx, stranger, f.org.OrgID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("non-member read seats: %v", err)
	}
}

func TestRenameOrgRules(t *testing.T) {
	f := newOrgBillingFixture(t)
	ctx := context.Background()
	member := makeAccount(t, f.s)
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO org_members (org_id, account_id, console_role) VALUES ($1::uuid, $2::uuid, 'member')`,
		f.org.OrgID, member); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RenameOrg(ctx, f.owner, f.org.OrgID, "Acme Two"); !errors.Is(err, store.ErrOrgProvisioning) {
		t.Fatalf("rename while provisioning: %v, want ErrOrgProvisioning", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status='active' WHERE org_id=$1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		account string
		display string
		want    error
	}{
		{"plain member", member, "Nope", store.ErrOrgRenameForbidden},
		{"empty name", f.owner, "   ", store.ErrOrgInputInvalid},
		{"owner", f.owner, "  Acme Two ", nil},
	}
	for _, tc := range cases {
		org, err := f.s.RenameOrg(ctx, tc.account, f.org.OrgID, tc.display)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
		if tc.want == nil && (org.DisplayName != "Acme Two" || org.Slug != f.org.Slug) {
			t.Errorf("%s: org=%+v", tc.name, org)
		}
	}
	if _, err := f.pool.Exec(ctx, `UPDATE orgs SET status='pending_deletion' WHERE org_id=$1::uuid`, f.org.OrgID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.RenameOrg(ctx, f.owner, f.org.OrgID, "Late"); !errors.Is(err, store.ErrOrgNotRenamable) {
		t.Errorf("rename while pending deletion: %v", err)
	}
}

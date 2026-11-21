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

// TestTeamCreateAllowlist proves the W17 gate against Postgres (cloud 0130):
// with the switch on a team create needs an active entry for the account or
// for the domain of its VERIFIED email; an unverified email at a listed domain
// does not count; a personal org is never checked; with the switch off nothing
// changes; a removed entry stops further creates; each change writes one
// staff_actions row; a duplicate active entry is refused.
func TestTeamCreateAllowlist(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	ctx := context.Background()
	now := time.Now()

	create := func(acct string, gate bool) error {
		t.Helper()
		slug := fmt.Sprintf("team-%d", subjCounter.Add(1))
		_, err := s.ProvisionOrg(ctx, acct, store.ProvisionOrgInput{
			Kind: store.OrgTeam, Slug: slug, DisplayName: "Team " + slug, Tenancy: store.TenancyManaged, TeamAllowlist: gate,
		})
		return err
	}
	allowed := func(acct string) bool {
		t.Helper()
		ok, err := s.TeamCreateAllowed(ctx, acct)
		if err != nil {
			t.Fatalf("TeamCreateAllowed: %v", err)
		}
		return ok
	}

	stranger := makeAccount(t, s)
	if err := create(stranger, true); !errors.Is(err, store.ErrTeamCreateNotAllowed) {
		t.Fatalf("stranger create with the gate on = %v, want ErrTeamCreateNotAllowed", err)
	}
	if allowed(stranger) {
		t.Fatal("stranger reported allowed")
	}
	// The switch off: the cap alone, as before.
	if err := create(stranger, false); err != nil {
		t.Fatalf("stranger create with the gate off: %v", err)
	}
	// A personal org is never checked.
	if _, err := s.ProvisionOrg(ctx, stranger, store.ProvisionOrgInput{Kind: store.OrgPersonal, DisplayName: "Me", TeamAllowlist: true}); err != nil {
		t.Fatalf("personal org with the gate on: %v", err)
	}

	// An account entry.
	invited := makeAccount(t, s)
	e, err := s.AddTeamAllowlistEntry(ctx, staffauth.AllowlistEntry{Kind: staffauth.AllowlistAccount, Value: invited},
		store.TeamAllowlistChange{Reason: "internal canary", Now: now})
	if err != nil {
		t.Fatalf("add account: %v", err)
	}
	if !allowed(invited) {
		t.Fatal("invited account not allowed")
	}
	if err := create(invited, true); err != nil {
		t.Fatalf("invited create: %v", err)
	}
	if _, err := s.AddTeamAllowlistEntry(ctx, staffauth.AllowlistEntry{Kind: staffauth.AllowlistAccount, Value: invited},
		store.TeamAllowlistChange{Reason: "again", Now: now}); !errors.Is(err, store.ErrTeamAllowlistExists) {
		t.Fatalf("duplicate add = %v, want ErrTeamAllowlistExists", err)
	}

	// A domain entry: verified matches, unverified does not, another domain
	// and a subdomain do not.
	if _, err := s.AddTeamAllowlistEntry(ctx, staffauth.AllowlistEntry{Kind: staffauth.AllowlistEmailDomain, Value: "Marmut.App"},
		store.TeamAllowlistChange{Reason: "our own domain", Now: now}); err != nil {
		t.Fatalf("add domain: %v", err)
	}
	cases := []struct {
		email    string
		verified bool
		want     bool
	}{
		{"alice@marmut.app", true, true},
		{"ALICE@MARMUT.APP", true, true},
		{"bob@marmut.app", false, false},
		{"carol@eng.marmut.app", true, false},
		{"dave@marmut.app.evil.example", true, false},
		{"erin@example.com", true, false},
	}
	for _, c := range cases {
		acct := makeAccount(t, s)
		if err := s.UpsertVerifiedEmail(ctx, acct, c.email, c.verified, now); err != nil {
			t.Fatalf("UpsertVerifiedEmail: %v", err)
		}
		if got := allowed(acct); got != c.want {
			t.Errorf("%s verified=%v: allowed = %v, want %v", c.email, c.verified, got, c.want)
		}
		err := create(acct, true)
		if c.want && err != nil {
			t.Errorf("%s: create = %v", c.email, err)
		}
		if !c.want && !errors.Is(err, store.ErrTeamCreateNotAllowed) {
			t.Errorf("%s: create = %v, want ErrTeamCreateNotAllowed", c.email, err)
		}
	}

	// Remove the account entry: the existing team org stays, a further create
	// is refused; removing it again is not found.
	if _, err := s.RemoveTeamAllowlistEntry(ctx, e.EntryID, store.TeamAllowlistChange{Reason: "canary over", Now: now}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := create(invited, true); !errors.Is(err, store.ErrTeamCreateNotAllowed) {
		t.Fatalf("create after removal = %v", err)
	}
	if _, err := s.RemoveTeamAllowlistEntry(ctx, e.EntryID, store.TeamAllowlistChange{Reason: "again", Now: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second remove = %v, want ErrNotFound", err)
	}
	if _, err := s.RemoveTeamAllowlistEntry(ctx, "not-a-uuid", store.TeamAllowlistChange{Reason: "x", Now: now}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed remove = %v, want ErrNotFound", err)
	}
	// A removed entry may be added again.
	if _, err := s.AddTeamAllowlistEntry(ctx, staffauth.AllowlistEntry{Kind: staffauth.AllowlistAccount, Value: invited},
		store.TeamAllowlistChange{Reason: "back in", Now: now}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	// A reason is required.
	if _, err := s.AddTeamAllowlistEntry(ctx, staffauth.AllowlistEntry{Kind: staffauth.AllowlistEmailDomain, Value: "example.org"},
		store.TeamAllowlistChange{Reason: "  ", Now: now}); !errors.Is(err, staffauth.ErrReasonRequired) {
		t.Fatalf("blank reason = %v", err)
	}

	active, err := s.ListTeamAllowlist(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.ListTeamAllowlist(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || len(all) != 3 || !all[0].Active() || all[2].Active() {
		t.Fatalf("list: %d active, %d in all (%+v)", len(active), len(all), all)
	}

	acts, err := s.ListStaffActions(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	added, removed := 0, 0
	for _, a := range acts {
		switch a.Verb {
		case string(staffauth.VerbTeamAllowlistAdded):
			added++
			if a.Actor != staffauth.ActorOperator || a.Result != "ok" || a.Target == "" {
				t.Errorf("added row %+v", a)
			}
		case string(staffauth.VerbTeamAllowlistRemoved):
			removed++
		}
	}
	if added != 3 || removed != 1 {
		t.Fatalf("staff_actions: %d added, %d removed rows, want 3 and 1", added, removed)
	}
}

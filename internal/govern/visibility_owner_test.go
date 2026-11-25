package govern

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// ownerGrant is visGrant with the owner-managed capability and the tenancy
// the cmd boundary fills from the enrolment row (grantFromStore).
func ownerGrant(consent, tenancy string, ownerManaged bool, authority ...string) *Grant {
	g := visGrant(consent, authority...)
	g.Tenancy = tenancy
	g.OwnerManaged = ownerManaged
	return g
}

// TestOwnerManagedVisibility is finding F12 (v1.42.1 ship-readiness audit) as
// widened by the operator ruling of 2026-11-24: a machine its owner manages
// from a personal organization of one starts with every page and every
// Settings section visible (the owner is the administrator), while a team
// member's managed machine keeps today's defaults and an individual machine
// has none. One case per audience and per rule the capability meets.
func TestOwnerManagedVisibility(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const (
		H = nodegov.VisibilityHidden
		R = nodegov.VisibilityReadOnly
		V = nodegov.VisibilityVisible
	)
	ownerPages := []string{
		"app-traces", "app-sessions", "app-analytics", "app-end-users",
		"app-evals", "app-scores", "app-prompts", "app-alerts", "egress", "routing", "policies",
	}
	cases := []struct {
		name         string
		grant        *Grant
		delivered    Delivered
		wantAudience nodegov.ManagedAudience
		wantOwner    bool
		page         nodegov.Visibility // every ownerPages entry
		pageSrc      VisibilitySource
		nav          map[string]nodegov.Visibility
		settings     map[string]nodegov.Visibility
	}{
		{
			name:         "owner-managed managed enrolment: every page and section stays visible",
			grant:        ownerGrant(ConsentManaged, TenancyManaged, true, AuthorityEnforceBudget),
			wantAudience: nodegov.ManagedAudienceOwner, wantOwner: true,
			page: V, pageSrc: VisibilitySourceDefault,
			nav: map[string]nodegov.Visibility{
				"security": V, "code-security": V, "egress": V,
				"compression": V, "remote": V, "agent-config": V, "sessions": V, "privacy": V,
			},
			settings: map[string]nodegov.Visibility{
				"routing": V, "observability": V,
				"guard": V, "otel": V, "cloud": V, "pricing": V, "proxy": V, "enrolment": V,
				"secrets": V, "intel": V, "hooks": V, "retention": V,
			},
		},
		{
			name:         "team managed enrolment: today's defaults",
			grant:        ownerGrant(ConsentManaged, TenancyManaged, false, AuthorityEnforceBudget),
			wantAudience: nodegov.ManagedAudienceTeam,
			page:         H, pageSrc: VisibilitySourceDefault,
			nav: map[string]nodegov.Visibility{
				"security": H, "egress": H, "compression": R, "sessions": V,
			},
			settings: map[string]nodegov.Visibility{
				"routing": H, "observability": H, "guard": H, "pricing": R, "enrolment": V,
			},
		},
		{
			name:         "owner capability on an individual enrolment: no defaults at all",
			grant:        ownerGrant(ConsentInteractive, TenancyIndividual, true, AuthorityDashboardVisibility),
			wantAudience: nodegov.ManagedAudienceTeam,
			page:         V, pageSrc: VisibilitySourceNone,
			nav:      map[string]nodegov.Visibility{"security": V, "compression": V},
			settings: map[string]nodegov.Visibility{"routing": V, "guard": V},
		},
		{
			// The audience is still the owner's, but a refused grant applies
			// no defaults of any audience (ManagedDefaultsApply).
			name: "owner-managed but the grant expired: no defaults",
			grant: func() *Grant {
				g := ownerGrant(ConsentManaged, TenancyManaged, true)
				g.ExpiresAt = now.Add(-time.Hour)
				return g
			}(),
			wantAudience: nodegov.ManagedAudienceOwner, wantOwner: true,
			page: V, pageSrc: VisibilitySourceNone,
			nav: map[string]nodegov.Visibility{"security": V},
		},
		{
			name:         "owner-managed, the owner's own body hides Routing: the org's list wins",
			grant:        ownerGrant(ConsentManaged, TenancyManaged, true),
			delivered:    visBody(t, nodegov.PolicyInput{HiddenSections: []string{"routing"}}),
			wantAudience: nodegov.ManagedAudienceOwner, wantOwner: true,
			// The other nine owner pages keep the owner default; routing is
			// asserted on its own below through nav.
			page: V, pageSrc: VisibilitySourceDefault,
			nav: map[string]nodegov.Visibility{"security": V},
		},
		{
			// The owner publishes from their online dashboard: an explicit
			// read-only lock and a hide beat the owner's visible default,
			// exactly as an admin's directive does on a team machine.
			name:  "owner-managed, the owner locks Security and hides OTel export: the org's lists win",
			grant: ownerGrant(ConsentManaged, TenancyManaged, true),
			delivered: visBody(t, nodegov.PolicyInput{
				ReadOnlySections: []string{"security"}, HiddenSettings: []string{"otel"},
			}),
			wantAudience: nodegov.ManagedAudienceOwner, wantOwner: true,
			page: V, pageSrc: VisibilitySourceDefault,
			nav:      map[string]nodegov.Visibility{"security": R, "remote": V},
			settings: map[string]nodegov.Visibility{"otel": H, "guard": V},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Resolve(tc.delivered, tc.grant, visLive, now)
			if got := e.ManagedAudience(); got != tc.wantAudience {
				t.Fatalf("ManagedAudience = %q, want %q (managed %v, state %s)", got, tc.wantAudience, e.Managed, e.State)
			}
			if e.OwnerManaged != tc.wantOwner {
				t.Fatalf("Effective.OwnerManaged = %v, want %v", e.OwnerManaged, tc.wantOwner)
			}
			orgHidden := map[string]bool{}
			for _, id := range e.HiddenSections {
				orgHidden[id] = true
			}
			vis := e.DashboardVisibility()
			for _, id := range ownerPages {
				lvl, src := e.NavVisibility(id)
				if orgHidden[id] {
					if lvl != H || src != VisibilitySourceOrg {
						t.Errorf("nav %q = (%s, %s), want the org's hide", id, lvl, src)
					}
					continue
				}
				if lvl != tc.page || src != tc.pageSrc {
					t.Errorf("nav %q = (%s, %s), want (%s, %s)", id, lvl, src, tc.page, tc.pageSrc)
				}
				if vis.Sections[id].Level != lvl || contains(vis.HiddenSections, id) != (lvl == H) {
					t.Errorf("DashboardVisibility disagrees with NavVisibility for %q", id)
				}
			}
			for id, want := range tc.nav {
				if got, _ := e.NavVisibility(id); got != want {
					t.Errorf("nav %q = %s, want %s", id, got, want)
				}
			}
			for id, want := range tc.settings {
				if got, _ := e.SettingsVisibility(id); got != want {
					t.Errorf("settings %q = %s, want %s", id, got, want)
				}
				if e.IsSettingsSectionHidden(id) != (want == H) {
					t.Errorf("IsSettingsSectionHidden(%q) disagrees with SettingsVisibility", id)
				}
			}
		})
	}
}

// TestOwnerManagedHashUnchanged pins the decision recorded on
// Effective.OwnerManaged: like Managed, the audience is not part of Hash (the
// address of the applied org body the sidecar and its exceptions file bind
// to), because the default table is compiled in and every visibility read
// resolves it live. A self-healed owner_managed flag must not rewrite the
// sidecar or unbind its exceptions file.
func TestOwnerManagedHashUnchanged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := visBody(t, nodegov.PolicyInput{HiddenSections: []string{"remote"}})
	team := Resolve(body, ownerGrant(ConsentManaged, TenancyManaged, false, AuthoritySettingsPin), visLive, now)
	owner := Resolve(body, ownerGrant(ConsentManaged, TenancyManaged, true, AuthoritySettingsPin), visLive, now)
	if team.Hash == "" || team.Hash != owner.Hash {
		t.Fatalf("hash team %q owner %q: the audience must not change the applied body's address", team.Hash, owner.Hash)
	}
	if team.OwnerManaged || !owner.OwnerManaged {
		t.Fatalf("OwnerManaged team %v owner %v", team.OwnerManaged, owner.OwnerManaged)
	}
}

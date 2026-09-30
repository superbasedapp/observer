package govern

import (
	"sort"
	"strings"
	"testing"
)

// TestMCPAccessEnforcementAuthorityIsManagedOnly pins the individual-plane
// guarantee for the fifth enforce.* sibling (Agent Access parking decision
// B9, doc3 §12.8): enforce.mcp_access is in the closed vocabulary, is
// managed-only, is NOT an extraction authority (it governs a MODE, never the
// share directive class), and is honoured only under managed tenancy — an
// individual node's relay stays local-stricter-wins even if a server puts
// the token in its grant.
func TestMCPAccessEnforcementAuthorityIsManagedOnly(t *testing.T) {
	if !KnownAuthority(AuthorityEnforceMCPAccess) {
		t.Fatal("enforce.mcp_access is not in the closed authority vocabulary")
	}
	if !ManagedAuthority(AuthorityEnforceMCPAccess) {
		t.Fatal("enforce.mcp_access is not managed-only — an individual node's relay could be made org-authoritative")
	}
	if ExtractionAuthority(AuthorityEnforceMCPAccess) {
		t.Fatal("enforce.mcp_access classifies as an EXTRACTION authority — it would authorize the share directive class, which it must never do")
	}
	if !EnforcementAuthority(AuthorityEnforceMCPAccess) {
		t.Fatal("enforce.mcp_access is not classified EnforcementAuthority")
	}
	if RetiredAuthority(AuthorityEnforceMCPAccess) {
		t.Fatal("enforce.mcp_access reports retired")
	}
	individual := Effective{Managed: false, Authority: []string{AuthorityEnforceMCPAccess}}
	if individual.GrantsMCPAccessEnforcement() {
		t.Fatal("an individual node granted enforce.mcp_access reports an org-authoritative relay")
	}
	if individual.GrantsAnyEnforcement() {
		t.Fatal("an individual node granted enforce.mcp_access reports SOME org enforcement")
	}
	managed := Effective{Managed: true, Authority: []string{AuthorityEnforceMCPAccess}}
	if !managed.GrantsMCPAccessEnforcement() {
		t.Fatal("a managed node granted enforce.mcp_access does not report an org-authoritative relay")
	}
	if !managed.GrantsAnyEnforcement() {
		t.Fatal("a managed node granted enforce.mcp_access does not report any org enforcement")
	}
	// A refused grant grants nothing, exactly like every sibling.
	refused := Effective{State: StateGrantSignatureInvalid, Managed: true, Authority: []string{AuthorityEnforceMCPAccess}}
	if refused.GrantsMCPAccessEnforcement() {
		t.Fatal("a REFUSED grant carrying enforce.mcp_access still reports an org-authoritative relay")
	}
}

// TestHonoredAuthorityStripsMCPAccessOnIndividual is the resolver-side half:
// HonoredAuthority keeps enforce.mcp_access under managed-class consent and
// strips it under interactive consent, so no directive keyed on it can fire
// on the individual plane.
func TestHonoredAuthorityStripsMCPAccessOnIndividual(t *testing.T) {
	cases := []struct {
		consentMode string
		wantKept    bool
	}{
		{ConsentInteractive, false},
		{"", false},
		{ConsentManaged, true},
		{ConsentIdP, true},
	}
	for _, tc := range cases {
		t.Run("consent="+tc.consentMode, func(t *testing.T) {
			g := testGrant()
			g.ConsentMode = tc.consentMode
			g.Authority = []string{AuthorityDashboardVisibility, AuthorityEnforceMCPAccess}
			got := HonoredAuthority(g)
			kept := false
			for _, a := range got {
				if a == AuthorityEnforceMCPAccess {
					kept = true
				}
			}
			if kept != tc.wantKept {
				t.Fatalf("HonoredAuthority under %q kept enforce.mcp_access=%v, want %v (honoured=%v)", tc.consentMode, kept, tc.wantKept, got)
			}
			// The individual-plane token beside it is never touched.
			if len(got) == 0 || got[0] != AuthorityDashboardVisibility {
				t.Fatalf("HonoredAuthority dropped the individual-plane token: %v", got)
			}
		})
	}
}

// TestEnterpriseAuthoritySetCarriesMCPAccess pins the Arc-4 ruling for the
// new sibling: an enterprise-posture mint carries enforce.mcp_access by
// default (org-authoritative on managed nodes), while the set still omits
// the three per-subsystem enforce tokens that stay an authored per-org act.
func TestEnterpriseAuthoritySetCarriesMCPAccess(t *testing.T) {
	set := EnterpriseAuthoritySet()
	if !sort.StringsAreSorted(set) {
		t.Fatalf("EnterpriseAuthoritySet() is not sorted: %v", set)
	}
	has := func(tok string) bool {
		for _, a := range set {
			if a == tok {
				return true
			}
		}
		return false
	}
	for _, want := range []string{AuthoritySettingsPin, AuthorityEnforceBudget, AuthorityEnforceMCPAccess} {
		if !has(want) {
			t.Errorf("EnterpriseAuthoritySet() omits governing token %q: %v", want, set)
		}
	}
	for _, absent := range []string{AuthorityEnforceRouting, AuthorityEnforceAdmission, AuthorityEnforceEgress} {
		if has(absent) {
			t.Errorf("EnterpriseAuthoritySet() carries %q, which stays an authored per-org act", absent)
		}
	}
}

// TestEnforcementAuthoritiesIsTheClosedEnforceFamily pins the ONE owner of
// the enforce.* list: sorted, deduplicated, every member Known + Managed +
// carrying the enforce. prefix, and no Known enforce.-prefixed token outside
// it (the family and the vocabulary cannot drift apart).
func TestEnforcementAuthoritiesIsTheClosedEnforceFamily(t *testing.T) {
	fam := EnforcementAuthorities()
	if !sort.StringsAreSorted(fam) {
		t.Fatalf("EnforcementAuthorities() is not sorted: %v", fam)
	}
	seen := map[string]bool{}
	for _, tok := range fam {
		if seen[tok] {
			t.Errorf("EnforcementAuthorities() lists %q twice", tok)
		}
		seen[tok] = true
		if !strings.HasPrefix(tok, "enforce.") {
			t.Errorf("EnforcementAuthorities() carries %q, which is not an enforce.* token", tok)
		}
		if !KnownAuthority(tok) || !ManagedAuthority(tok) {
			t.Errorf("EnforcementAuthorities() carries %q, which is not Known+Managed", tok)
		}
		if ExtractionAuthority(tok) {
			t.Errorf("EnforcementAuthorities() carries %q, which is also an extraction authority", tok)
		}
		if !EnforcementAuthority(tok) {
			t.Errorf("EnforcementAuthority(%q) is false for a family member", tok)
		}
	}
	if len(fam) != 5 {
		t.Fatalf("EnforcementAuthorities() has %d tokens, want the five siblings: %v", len(fam), fam)
	}
	if EnforcementAuthority(AuthorityExtractManaged) || EnforcementAuthority("enforce.something_new") {
		t.Fatal("EnforcementAuthority() classifies a token outside the family")
	}
}

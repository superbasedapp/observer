package govern

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestModuleEnforceTokensTouchList pins security plan 7.2 rows 1 to 14 that
// live in this package, for both module enforce tokens (roadmap F0-7):
// known, managed-only (stripped on an individual node), super-admin to mint,
// in the closed enforce family, not proxy-resident, not an extraction
// authority, in no default authority set, exempt from family mapping with a
// reason, and an accessor that fires only on a managed node holding it.
func TestModuleEnforceTokensTouchList(t *testing.T) {
	accessors := map[string]func(Effective) bool{
		AuthorityEnforceSecurity: Effective.GrantsSecurityEnforcement,
		AuthorityEnforceSandbox:  Effective.GrantsSandboxEnforcement,
	}
	inSet := func(set []string, tok string) bool {
		for _, s := range set {
			if s == tok {
				return true
			}
		}
		return false
	}
	for tok, grants := range accessors {
		t.Run(tok, func(t *testing.T) {
			if !KnownAuthority(tok) || !ManagedAuthority(tok) || !SuperAdminAuthority(tok) || !EnforcementAuthority(tok) {
				t.Fatal("rows 1 to 4: known, managed, super-admin, enforcement")
			}
			if ExtractionAuthority(tok) {
				t.Fatal("row 5: not an extraction authority")
			}
			if inSet(EnterpriseAuthoritySet(), tok) || inSet(ManagedEnrolmentAuthoritySet(), tok) {
				t.Fatal("row 6: never auto-granted")
			}
			if reason := exemptFromFamilyMapping[tok]; reason != "gates a managed pull, not a resource family" || len(GovernedFamilies([]string{tok})) != 0 {
				t.Fatalf("row 7: maps to no family, with its reason (got %q)", reason)
			}
			if proxyResident, ok := proxyResidentEnforcement[tok]; !ok || proxyResident {
				t.Fatal("row 11: proxyResidentEnforcement false")
			}
			if (Effective{Authority: []string{tok}, Managed: true}).RequiresProxyRoute() {
				t.Fatal("row 11: the token must not require a proxy route")
			}
			if !grants(Effective{Managed: true, Authority: []string{tok}}) || grants(Effective{Authority: []string{tok}}) {
				t.Fatal("row 4: the accessor fires only on a managed node")
			}
			if got := HonoredAuthority(&Grant{Authority: []string{tok}, ConsentMode: ConsentInteractive}); len(got) != 0 {
				t.Fatalf("row 3: an individual node strips it, got %v", got)
			}
			if got := HonoredAuthority(&Grant{Authority: []string{tok}, ConsentMode: ConsentManaged}); len(got) != 1 {
				t.Fatalf("row 3: a managed consent keeps it, got %v", got)
			}
		})
	}
}

// TestManagedPullRailsNameRealAuthorities pins orgcontract's rail table to
// these constants (orgcontract spells them to stay free of this package).
func TestManagedPullRailsNameRealAuthorities(t *testing.T) {
	want := map[string]string{"security": AuthorityEnforceSecurity, "sandbox": AuthorityEnforceSandbox}
	for _, r := range orgcontract.ManagedPullRails {
		if want[r.Name] != r.Authority {
			t.Errorf("rail %s names %q, want %q", r.Name, r.Authority, want[r.Name])
		}
		if !EnforcementAuthority(r.Authority) {
			t.Errorf("rail %s's authority is not an enforce token", r.Name)
		}
	}
}

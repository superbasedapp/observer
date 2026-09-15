package govern

import "testing"

// TestLowerFloatAndLowerIntNeverRaise is the org-budget plan's W3a gate: the
// numeric composition an INDIVIDUAL node applies to an org-distributed cap can
// only tighten. Table-driven, one row per case of the "0 means unset" rule.
func TestLowerFloatAndLowerIntNeverRaise(t *testing.T) {
	cases := []struct {
		name             string
		local, org, want float64
	}{
		{"both unset stays off", 0, 0, 0},
		{"org tighter wins", 5, 2, 2},
		{"local tighter survives an org that is looser", 5, 8, 5},
		{"equal is stable", 5, 5, 5},
		{"local unset takes the org cap", 0, 2, 2},
		{"org unset leaves the local cap", 5, 0, 5},
		{"a negative org value is unset, never a cap of nothing", 5, -1, 5},
		{"a negative local value is unset", -1, 2, 2},
		{"both negative stays off", -3, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LowerFloat(tc.local, tc.org); got != tc.want {
				t.Errorf("LowerFloat(%v, %v) = %v, want %v", tc.local, tc.org, got, tc.want)
			}
			if got := LowerInt(int64(tc.local), int64(tc.org)); got != int64(tc.want) {
				t.Errorf("LowerInt(%v, %v) = %v, want %v", int64(tc.local), int64(tc.org), got, int64(tc.want))
			}
		})
	}
}

// TestLowerNumbersAreNeverLooserThanLocal is the property statement behind the
// table: for every (local, org) pair with a real local cap, the result is at
// most the local cap. A future "improvement" that let an org raise a cap on an
// individual node fails here rather than in production.
func TestLowerNumbersAreNeverLooserThanLocal(t *testing.T) {
	for _, local := range []float64{0.5, 1, 5, 1000} {
		for _, org := range []float64{0, 0.1, 1, 5, 1e9, -1} {
			if got := LowerFloat(local, org); got > local {
				t.Fatalf("LowerFloat(%v, %v) = %v, which RAISES the node's own cap", local, org, got)
			}
		}
	}
}

// TestBudgetEnforcementAuthorityIsManagedOnly pins the individual-plane
// guarantee: enforce.budget is honoured only under managed-class consent, so
// an individual node can never be made org-authoritative even if a server puts
// the token in its grant.
func TestBudgetEnforcementAuthorityIsManagedOnly(t *testing.T) {
	if !KnownAuthority(AuthorityEnforceBudget) {
		t.Fatal("enforce.budget is not in the closed authority vocabulary")
	}
	if !ManagedAuthority(AuthorityEnforceBudget) {
		t.Fatal("enforce.budget is not managed-only — an individual node could be made org-authoritative")
	}
	if ExtractionAuthority(AuthorityEnforceBudget) {
		t.Fatal("enforce.budget classifies as an EXTRACTION authority — it would authorize the share directive class, which it must never do")
	}
	individual := Effective{Managed: false, Authority: []string{AuthorityEnforceBudget}}
	if individual.GrantsBudgetEnforcement() {
		t.Fatal("an individual node granted enforce.budget reports org-authoritative budgets")
	}
	managed := Effective{Managed: true, Authority: []string{AuthorityEnforceBudget}}
	if !managed.GrantsBudgetEnforcement() {
		t.Fatal("a managed node granted enforce.budget does not report org-authoritative budgets")
	}
}

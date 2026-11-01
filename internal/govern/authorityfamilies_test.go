package govern

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// authorityConstValues collects the value of every package-level string
// constant whose name starts with "Authority" from this package's non-test
// sources. The drift test is built from it rather than from a hand list
// (review C156-42: the old hand list had silently dropped extract.intel,
// extract.tasks and five more tokens, so a missing family row went unseen).
func authorityConstValues(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range af.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Authority") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatalf("unquote %s: %v", name.Name, err)
					}
					seen[v] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// allKnownAuthorityTokens is every Authority* constant KnownAuthority
// recognises, derived from the source, never hand-maintained.
func allKnownAuthorityTokens(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, v := range authorityConstValues(t) {
		if KnownAuthority(v) {
			out = append(out, v)
		}
	}
	return out
}

func TestGovernedFamilies_TableDriven(t *testing.T) {
	cases := []struct {
		name      string
		authority []string
		want      []string
	}{
		{name: "nil authority", authority: nil, want: nil},
		{name: "empty authority", authority: []string{}, want: nil},
		{
			name:      "single node.governance token",
			authority: []string{AuthorityDashboardVisibility},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "enforce.admission maps to admission.input",
			authority: []string{AuthorityEnforceAdmission},
			want:      []string{familyAdmissionInput},
		},
		{
			name:      "enforce.egress maps to egress.routing_guardrail",
			authority: []string{AuthorityEnforceEgress},
			want:      []string{familyEgressGuardrail},
		},
		{
			name:      "enforce.routing maps to gateway.providers",
			authority: []string{AuthorityEnforceRouting},
			want:      []string{familyGatewayProviders},
		},
		{
			name:      "enforce.budget maps to node.governance (the declared fallback)",
			authority: []string{AuthorityEnforceBudget},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "enforce.mcp_access maps to tools.mcp_access (its own resource family)",
			authority: []string{AuthorityEnforceMCPAccess},
			want:      []string{familyToolsMCPAccess},
		},
		{
			name:      "mixed authority set, deduplicated and sorted",
			authority: []string{AuthorityExtractToolBodies, AuthorityEnforceAdmission},
			want:      []string{familyAdmissionInput, familyNodeGovernance},
		},
		{
			name:      "two node.governance tokens dedupe to one family",
			authority: []string{AuthorityDashboardVisibility, AuthoritySettingsPin, AuthorityCapturePin},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "all three enforce tokens plus a node.governance token",
			authority: []string{AuthorityEnforceRouting, AuthorityEnforceAdmission, AuthorityEnforceEgress, AuthorityFeatureLock},
			want:      []string{familyAdmissionInput, familyEgressGuardrail, familyGatewayProviders, familyNodeFeatures, familyNodeGovernance},
		},
		{
			// C156-04 / T-354: feature locks, tools.disallow and the G8 tool
			// and feature grants live in node.features; the grant carrying
			// feature.lock must consent to it or they are inert.
			name:      "feature.lock governs node.governance AND node.features",
			authority: []string{AuthorityFeatureLock},
			want:      []string{familyNodeFeatures, familyNodeGovernance},
		},
		{
			name:      "extract.intel maps to node.governance (C156-42)",
			authority: []string{AuthorityExtractIntel},
			want:      []string{familyNodeGovernance},
		},
		{
			name:      "retired capture.raise contributes nothing",
			authority: []string{AuthorityCaptureRaise},
			want:      nil,
		},
		{
			name:      "unknown token contributes nothing",
			authority: []string{"some.future.token"},
			want:      nil,
		},
		{
			name:      "a retired token alongside a real one: only the real family counts",
			authority: []string{AuthorityCaptureRaise, AuthorityExtractFolders},
			want:      []string{familyNodeGovernance},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := GovernedFamilies(tc.authority)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("GovernedFamilies(%v) = %v, want %v", tc.authority, got, tc.want)
			}
		})
	}
}

// TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt is the drift guard:
// every token KnownAuthority recognises either maps to at least one family,
// or is named in exemptFromFamilyMapping. A future authority token that maps
// to nothing must be a conscious addition to the exemption list, never a
// silent fallthrough.
func TestGovernedFamilies_EveryKnownAuthorityMapsOrIsExempt(t *testing.T) {
	toks := allKnownAuthorityTokens(t)
	// A sanity floor so a parser regression cannot make this test vacuous.
	if len(toks) < 20 {
		t.Fatalf("only %d known authority tokens found in source; the AST walk is broken", len(toks))
	}
	for _, tok := range toks {
		families := GovernedFamilies([]string{tok})
		if reason, exempt := exemptFromFamilyMapping[tok]; exempt && reason == "" {
			t.Errorf("KnownAuthority token %q is exempt from family mapping with no reason", tok)
		}
		if _, exempt := exemptFromFamilyMapping[tok]; len(families) == 0 && !exempt {
			t.Errorf("KnownAuthority token %q maps to no policy family and is not in exemptFromFamilyMapping - "+
				"add a row to authorityFamilyTable, or a conscious exemption with a reason", tok)
		}
		if _, exempt := exemptFromFamilyMapping[tok]; len(families) > 0 && exempt {
			t.Errorf("KnownAuthority token %q is in exemptFromFamilyMapping but ALSO maps to %v - "+
				"remove it from the exemption list, or remove its authorityFamilyTable row", tok, families)
		}
	}
}

// TestAuthorityConstantsAreAllKnown closes the other half of the drift: an
// Authority* constant added to the source but left out of KnownAuthority's
// switch fails here instead of silently escaping the family check above.
func TestAuthorityConstantsAreAllKnown(t *testing.T) {
	for _, v := range authorityConstValues(t) {
		if !KnownAuthority(v) {
			t.Errorf("Authority* constant %q is not in KnownAuthority's switch", v)
		}
	}
}

// TestManagedEnrolmentAuthoritySetGovernsNodeFeatures pins the managed default
// at this layer: the default managed grant carries feature.lock, so its
// governed families include node.features (C156-04).
func TestManagedEnrolmentAuthoritySetGovernsNodeFeatures(t *testing.T) {
	got := GovernedFamilies(ManagedEnrolmentAuthoritySet())
	for _, f := range got {
		if f == familyNodeFeatures {
			return
		}
	}
	t.Fatalf("GovernedFamilies(EnterpriseAuthoritySet()) = %v, want it to include %q", got, familyNodeFeatures)
}

func TestManagedGovernedFamilies(t *testing.T) {
	cases := []struct {
		name      string
		authority []string
		want      []string
	}{
		{name: "nothing governed stays nil", authority: nil, want: nil},
		{name: "retired token only stays nil", authority: []string{AuthorityCaptureRaise}, want: nil},
		// The pre-T-311 enterprise-posture grant: no feature.lock, yet a
		// managed node must still accept node.features (C156-04).
		{
			name: "enterprise set without feature.lock still governs node.features", authority: EnterpriseAuthoritySet(),
			want: []string{familyNodeFeatures, familyNodeGovernance, familySecurityScanning, familyTerminalsIsolation, familyToolsMCPAccess},
		},
		{
			name: "a single extract token on a managed grant", authority: []string{AuthorityExtractCache},
			want: []string{familyNodeFeatures, familyNodeGovernance, familySecurityScanning, familyTerminalsIsolation},
		},
		{
			name: "feature.lock dedupes", authority: []string{AuthorityFeatureLock},
			want: []string{familyNodeFeatures, familyNodeGovernance, familySecurityScanning, familyTerminalsIsolation},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ManagedGovernedFamilies(tc.authority); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ManagedGovernedFamilies(%v) = %v, want %v", tc.authority, got, tc.want)
			}
		})
	}
}

func TestManagedFamilyBackfill(t *testing.T) {
	gov := []string{familyNodeFeatures, familyNodeGovernance}
	cases := []struct {
		name       string
		governed   []string
		offered    []string
		haveRecord bool
		present    []string
		want       []string
	}{
		{name: "pre-fix node: no record, node.features missing", governed: gov, present: []string{familyNodeGovernance}, want: []string{familyNodeFeatures}},
		{name: "pre-fix node with no list at all owes every governed family", governed: gov, want: []string{familyNodeFeatures, familyNodeGovernance}},
		{name: "everything present: nothing owed", governed: gov, present: gov, want: nil},
		{name: "record present and offered: a developer removal is respected", governed: gov, offered: gov, haveRecord: true, present: []string{familyNodeGovernance}, want: nil},
		{name: "record lists only the old set: a newly governed family is owed", governed: gov, offered: []string{familyNodeGovernance}, haveRecord: true, present: []string{familyNodeGovernance}, want: []string{familyNodeFeatures}},
		{name: "offered ignored when haveRecord is false", governed: gov, offered: gov, present: nil, want: []string{familyNodeFeatures, familyNodeGovernance}},
		{name: "nothing governed: nothing owed", governed: nil, present: nil, want: nil},
		{name: "present extras are never removed nor reported", governed: []string{familyNodeFeatures}, present: []string{familyAdmissionInput}, want: []string{familyNodeFeatures}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ManagedFamilyBackfill(tc.governed, tc.offered, tc.haveRecord, tc.present)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ManagedFamilyBackfill = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGovernedFamilies_UnknownTokensNeverFabricated(t *testing.T) {
	got := GovernedFamilies([]string{"admission.input", "node.governance", "definitely-not-a-real-token"})
	if got != nil {
		t.Errorf("GovernedFamilies must never fabricate a family for a token outside authorityFamilyTable, got %v", got)
	}
}

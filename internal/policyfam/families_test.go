package policyfam

import "testing"

// TestSupportedFamiliesDriveDispatch is the registry contract test: every
// family listed in SupportedFamilies must compile a minimal valid body
// through CompileFamilyBody and then answer SpecRequestsEnforceMode without
// panicking. A family added to SupportedFamilies without a matching case in
// either dispatch function fails this test loudly instead of panicking at
// runtime on a live publish.
func TestSupportedFamiliesDriveDispatch(t *testing.T) {
	minimalBody := map[string]string{
		FamilyAdmissionInput:   `{"mode":"enforce"}`,
		FamilyEgressGuardrail:  `{"mode":"enforce"}`,
		FamilyGatewayProviders: `{"upstreams":{"main":{"base_url":"https://example.com"}}}`,
		// node.governance's minimal body is a bare schema declaration: an
		// EMPTY governance policy is valid and meaningful ("you are managed,
		// with no restriction"), so this is the smallest real body, not a
		// degenerate one.
		FamilyNodeGovernance: `{"schema":1}`,
		// node.features' minimal body is the empty object: a policy that
		// governs none of the four features (every seam stays fail-open)
		// is valid and meaningful, mirroring node.governance's minimal
		// body above.
		FamilyNodeFeatures:    `{}`,
		FamilyPlaneBAdmission: `{"admission":{"mode":"enforce"}}`,
	}

	if len(minimalBody) != len(SupportedFamilies) {
		t.Fatalf("this test's minimalBody table has %d entries but SupportedFamilies has %d — add a case for the new family", len(minimalBody), len(SupportedFamilies))
	}

	for _, family := range SupportedFamilies {
		t.Run(family, func(t *testing.T) {
			body, ok := minimalBody[family]
			if !ok {
				t.Fatalf("no minimal body registered for family %q in this test", family)
			}
			spec, canon, err := CompileFamilyBody(family, []byte(body), 4096)
			if err != nil {
				t.Fatalf("CompileFamilyBody(%q): %v", family, err)
			}
			if len(canon) == 0 {
				t.Errorf("CompileFamilyBody(%q) returned empty canonical body", family)
			}

			var enforced bool
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("SpecRequestsEnforceMode(%q) panicked: %v", family, r)
					}
				}()
				enforced = SpecRequestsEnforceMode(family, spec)
			}()
			// gateway.providers always requires enforce; the other two
			// families' minimal bodies above are deliberately "enforce" mode
			// too, so every row here is expected true — this asserts the
			// dispatch actually ran, not a specific posture policy.
			if !enforced {
				t.Errorf("SpecRequestsEnforceMode(%q) = false, want true for this test's minimal body", family)
			}
		})
	}
}

// TestIsSupportedFamily checks the boolean predicate against the registry
// plus one deliberately-unknown family.
func TestIsSupportedFamily(t *testing.T) {
	for _, family := range SupportedFamilies {
		if !IsSupportedFamily(family) {
			t.Errorf("IsSupportedFamily(%q) = false, want true", family)
		}
	}
	if IsSupportedFamily("nonexistent.family") {
		t.Error("IsSupportedFamily(\"nonexistent.family\") = true, want false")
	}
}

// TestCompileFamilyBodyUnsupportedFamily checks the closed-set error path.
func TestCompileFamilyBodyUnsupportedFamily(t *testing.T) {
	if _, _, err := CompileFamilyBody("nonexistent.family", []byte(`{}`), 4096); err == nil {
		t.Fatal("expected an error for an unsupported family")
	}
}

// TestSpecRequestsEnforceModeUnsupportedFamilyPanics documents the caller
// contract: an unknown family is a caller bug, not a runtime condition.
func TestSpecRequestsEnforceModeUnsupportedFamilyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic for an unsupported family")
		}
	}()
	SpecRequestsEnforceMode("nonexistent.family", nil)
}

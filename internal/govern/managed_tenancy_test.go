package govern

import "testing"

// TestManagedAuthorityVocabulary pins the closed vocabulary: the four
// managed-only tokens are KNOWN (so a grant can carry them and a node can
// read them) AND classified managed; the pre-managed tokens are known and
// NOT managed.
func TestManagedAuthorityVocabulary(t *testing.T) {
	managed := []string{
		AuthorityEnforceRouting, AuthorityEnforceAdmission,
		AuthorityEnforceEgress, AuthorityEnforceBudget,
		AuthorityEnforceMCPAccess, AuthorityExtractManaged,
		AuthorityExtractCodeintel, AuthorityExtractProcess,
		AuthorityExtractTerminal,
		AuthorityExtractToolBodies, AuthorityExtractFolders,
		AuthorityExtractTraces, AuthorityExtractCache,
		AuthorityExtractRouting, AuthorityExtractPredictions,
	}
	for _, tok := range managed {
		if !KnownAuthority(tok) {
			t.Errorf("%q is not KnownAuthority — a grant carrying it would report as unknown_authority", tok)
		}
		if !ManagedAuthority(tok) {
			t.Errorf("%q is not classified ManagedAuthority", tok)
		}
	}
	notManaged := []string{
		AuthorityDashboardVisibility, AuthoritySettingsPin,
		AuthorityCapturePin, AuthorityFeatureLock, AuthorityCaptureRaise,
	}
	for _, tok := range notManaged {
		if !KnownAuthority(tok) {
			t.Errorf("%q unexpectedly left KnownAuthority", tok)
		}
		if ManagedAuthority(tok) {
			t.Errorf("%q must NOT be classified ManagedAuthority", tok)
		}
	}
}

// TestManagedConsent pins the single classifier every managed-class gate
// must call: ConsentManaged and ConsentIdP are managed-class, everything
// else (including the empty string and ConsentInteractive) is not.
func TestManagedConsent(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{ConsentManaged, true},
		{ConsentIdP, true},
		{ConsentInteractive, false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			if got := ManagedConsent(tc.mode); got != tc.want {
				t.Errorf("ManagedConsent(%q) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}

// TestHonoredAuthorityGatesManagedOnManagedTenancy is the load-bearing
// individual-plane guarantee: a managed-only authority is honoured ONLY when
// the grant carries managed-class consent (ManagedConsent) — ConsentManaged
// (the scripted/MDM token rail) or ConsentIdP (ACP-P6c's IdP-verified
// device-code enrolment, where the browser approval is the consent of
// record). On an interactive-consent grant it is stripped, so no directive
// keyed on it can ever fire.
func TestHonoredAuthorityGatesManagedOnManagedTenancy(t *testing.T) {
	tokens := []string{AuthorityDashboardVisibility, AuthorityEnforceRouting, AuthorityExtractManaged}

	cases := []struct {
		name        string
		consentMode string
		wantAll     bool
	}{
		{"interactive-stripped", ConsentInteractive, false},
		{"managed-token-kept", ConsentManaged, true},
		{"idp-kept", ConsentIdP, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := testGrant()
			g.ConsentMode = tc.consentMode
			g.Authority = tokens
			got := HonoredAuthority(g)
			if tc.wantAll {
				if len(got) != 3 {
					t.Fatalf("%s grant honoured %v, want all three (managed authorities kept)", tc.consentMode, got)
				}
				return
			}
			if len(got) != 1 || got[0] != AuthorityDashboardVisibility {
				t.Fatalf("%s grant honoured %v, want only [%s] (managed authorities stripped)", tc.consentMode, got, AuthorityDashboardVisibility)
			}
		})
	}

	if HonoredAuthority(nil) != nil {
		t.Fatal("a nil grant must honour nothing")
	}
}

// TestResolveManagedFlagFollowsConsentMode pins that Effective.Managed — the
// predicate the T8 transparency banner and P3 enforcement branch on — is true
// iff the grant carries managed-class consent (ManagedConsent): ConsentManaged
// or ConsentIdP. A merely-interactive grant, or no grant at all, is not
// managed.
func TestResolveManagedFlagFollowsConsentMode(t *testing.T) {
	live := testLive()

	cases := []struct {
		name        string
		consentMode string
		want        bool
	}{
		{"interactive", ConsentInteractive, false},
		{"managed-token", ConsentManaged, true},
		{"idp", ConsentIdP, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := testGrant()
			g.ConsentMode = tc.consentMode
			if eff := Resolve(Delivered{}, g, live, testNow); eff.Managed != tc.want {
				t.Errorf("ConsentMode=%q resolved Managed=%v, want %v", tc.consentMode, eff.Managed, tc.want)
			}
		})
	}

	// No grant → not managed (the ungoverned/BYO default).
	if eff := Resolve(Delivered{}, nil, live, testNow); eff.Managed {
		t.Error("an ungranted node resolved Managed=true")
	}
}

// TestRaiseBoolIsManagedOnly is the extraction-raise guarantee: RaiseBool
// turns a tier ON from an org directive ONLY on a managed posture. On an
// individual posture it is inert, whatever the org directed — so the
// individual plane can never be server-raised.
func TestRaiseBoolIsManagedOnly(t *testing.T) {
	share := map[string]any{"full_tool_bodies": true}

	individual := Effective{Managed: false, Share: share}
	if individual.RaiseBool("full_tool_bodies", false) {
		t.Error("RaiseBool raised a tier on an INDIVIDUAL posture — the individual plane must never be server-raised")
	}

	managed := Effective{Managed: true, Share: share}
	if !managed.RaiseBool("full_tool_bodies", false) {
		t.Error("RaiseBool did not raise a tier a managed org directed on")
	}
	// Absent/false directive never raises, even when managed.
	if managed.RaiseBool("full_content", false) {
		t.Error("RaiseBool raised a tier the org did not direct")
	}
	// current already true short-circuits true (lowering is LowerBool's job).
	if !managed.RaiseBool("absent_key", true) {
		t.Error("RaiseBool must return true when current is already true")
	}
}

// TestGrantsManagedExtraction pins the single gate the managed extraction
// raise is guarded by: managed tenancy AND the extract.managed authority.
func TestGrantsManagedExtraction(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{"managed+extract", true, []string{AuthorityExtractManaged}, true},
		{"managed+other-only", true, []string{AuthorityCapturePin}, false},
		{"individual+extract", false, []string{AuthorityExtractManaged}, false},
		{"managed+none", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsManagedExtraction(); got != tc.want {
				t.Errorf("GrantsManagedExtraction() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestGrantsCodeintelExtraction pins the DISTINCT per-tier gate (Arc 4 P5f):
// the codeintel raise requires managed tenancy AND extract.codeintel
// specifically — the umbrella extract.managed does NOT unlock it, and neither
// does any other extraction authority (highest-sensitivity tiers get their own
// explicit consent, operator ruling).
func TestGrantsCodeintelExtraction(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{"managed+codeintel", true, []string{AuthorityExtractCodeintel}, true},
		{"managed+umbrella-only", true, []string{AuthorityExtractManaged}, false},
		{"individual+codeintel", false, []string{AuthorityExtractCodeintel}, false},
		{"managed+none", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsCodeintelExtraction(); got != tc.want {
				t.Errorf("GrantsCodeintelExtraction() = %v, want %v", got, tc.want)
			}
			// The umbrella predicate must NOT be flipped on by a per-tier grant.
			if len(tc.auth) == 1 && tc.auth[0] == AuthorityExtractCodeintel && e.GrantsManagedExtraction() {
				t.Error("extract.codeintel must not satisfy GrantsManagedExtraction — the tiers are independent")
			}
		})
	}
}

// TestGrantsProcessExtraction pins the DISTINCT per-tier gate (Arc 4 P5g): the
// process raise requires managed tenancy AND extract.process specifically —
// neither the umbrella extract.managed nor the sibling extract.codeintel
// unlocks it.
func TestGrantsProcessExtraction(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{"managed+process", true, []string{AuthorityExtractProcess}, true},
		{"managed+umbrella-only", true, []string{AuthorityExtractManaged}, false},
		{"managed+codeintel-only", true, []string{AuthorityExtractCodeintel}, false},
		{"individual+process", false, []string{AuthorityExtractProcess}, false},
		{"managed+none", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsProcessExtraction(); got != tc.want {
				t.Errorf("GrantsProcessExtraction() = %v, want %v", got, tc.want)
			}
			if len(tc.auth) == 1 && tc.auth[0] == AuthorityExtractProcess &&
				(e.GrantsManagedExtraction() || e.GrantsCodeintelExtraction()) {
				t.Error("extract.process must not satisfy any other extraction predicate")
			}
		})
	}
}

// TestGrantsTerminalExtraction pins the DISTINCT per-tier gate (Arc 4 P5h): the
// terminal raise requires managed tenancy AND extract.terminal specifically —
// no other extraction authority unlocks it. This is the gate on the deliberate
// reversal of the terminal_run / remote_audit never-ships pins.
func TestGrantsTerminalExtraction(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{"managed+terminal", true, []string{AuthorityExtractTerminal}, true},
		{"managed+umbrella-only", true, []string{AuthorityExtractManaged}, false},
		{"managed+process-only", true, []string{AuthorityExtractProcess}, false},
		{"individual+terminal", false, []string{AuthorityExtractTerminal}, false},
		{"managed+none", true, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsTerminalExtraction(); got != tc.want {
				t.Errorf("GrantsTerminalExtraction() = %v, want %v", got, tc.want)
			}
			if len(tc.auth) == 1 && tc.auth[0] == AuthorityExtractTerminal &&
				(e.GrantsManagedExtraction() || e.GrantsCodeintelExtraction() || e.GrantsProcessExtraction()) {
				t.Error("extract.terminal must not satisfy any other extraction predicate")
			}
		})
	}
}

// headlinePredicate pairs a per-tier headline token with its predicate so the
// P4a independence + alias tests can walk all six generically.
type headlinePredicate struct {
	token string
	fn    func(Effective) bool
}

func headlinePredicates() []headlinePredicate {
	return []headlinePredicate{
		{AuthorityExtractToolBodies, Effective.GrantsToolBodiesExtraction},
		{AuthorityExtractFolders, Effective.GrantsFoldersExtraction},
		{AuthorityExtractTraces, Effective.GrantsTracesExtraction},
		{AuthorityExtractCache, Effective.GrantsCacheExtraction},
		{AuthorityExtractRouting, Effective.GrantsRoutingExtraction},
		{AuthorityExtractPredictions, Effective.GrantsPredictionsExtraction},
	}
}

// TestGrantsHeadlinePerTierIndependence pins the P4a split: each headline
// per-tier predicate fires for its OWN token on a managed node and for NO
// sibling headline token, and is always inert on the individual plane.
func TestGrantsHeadlinePerTierIndependence(t *testing.T) {
	preds := headlinePredicates()
	for i, self := range preds {
		t.Run(self.token, func(t *testing.T) {
			// Own token on a managed node: fires.
			managed := Effective{Managed: true, Authority: []string{self.token}}
			if !self.fn(managed) {
				t.Errorf("%s did not satisfy its own predicate on a managed node", self.token)
			}
			// Own token on the individual plane: inert.
			individual := Effective{Managed: false, Authority: []string{self.token}}
			if self.fn(individual) {
				t.Errorf("%s satisfied its predicate on the INDIVIDUAL plane — managed gate broken", self.token)
			}
			// No sibling headline token fires for this token, and neither do
			// the three high-sensitivity predicates.
			for j, other := range preds {
				if j == i {
					continue
				}
				if other.fn(managed) {
					t.Errorf("granting %s also satisfied the %s predicate — tiers must be independent", self.token, other.token)
				}
			}
			if managed.GrantsCodeintelExtraction() || managed.GrantsProcessExtraction() || managed.GrantsTerminalExtraction() {
				t.Errorf("granting headline %s unlocked a high-sensitivity tier", self.token)
			}
		})
	}
}

// TestUmbrellaExtractManagedRaisesAllHeadline pins back-compat: a legacy grant
// carrying ONLY extract.managed still satisfies every headline per-tier
// predicate (the alias clause), so it raises all six tiers exactly as it did
// before the P4a split — while STILL not unlocking the three high-sensitivity
// tiers (those never ride the umbrella).
func TestUmbrellaExtractManagedRaisesAllHeadline(t *testing.T) {
	managed := Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}
	for _, p := range headlinePredicates() {
		if !p.fn(managed) {
			t.Errorf("umbrella extract.managed did not satisfy the %s predicate — back-compat broken", p.token)
		}
	}
	if managed.GrantsCodeintelExtraction() || managed.GrantsProcessExtraction() || managed.GrantsTerminalExtraction() {
		t.Error("umbrella extract.managed unlocked a high-sensitivity tier — the ruling forbids this")
	}
	// On the individual plane the umbrella is fully inert.
	individual := Effective{Managed: false, Authority: []string{AuthorityExtractManaged}}
	for _, p := range headlinePredicates() {
		if p.fn(individual) {
			t.Errorf("umbrella extract.managed satisfied %s on the INDIVIDUAL plane", p.token)
		}
	}
}

// TestGrantsEnforcementPerFamily pins the Arc 4 P3 §R23-lift gates: each
// enforcement predicate requires managed tenancy AND its OWN enforce.* token,
// no sibling enforce token and no extract.managed umbrella satisfies it, and
// it is always inert on the individual plane.
func TestGrantsEnforcementPerFamily(t *testing.T) {
	preds := []struct {
		token string
		fn    func(Effective) bool
	}{
		{AuthorityEnforceRouting, Effective.GrantsRoutingEnforcement},
		{AuthorityEnforceAdmission, Effective.GrantsAdmissionEnforcement},
		{AuthorityEnforceEgress, Effective.GrantsEgressEnforcement},
		{AuthorityEnforceBudget, Effective.GrantsBudgetEnforcement},
		{AuthorityEnforceMCPAccess, Effective.GrantsMCPAccessEnforcement},
	}
	// The predicate table above must cover the closed enforce.* family
	// exactly — a sibling added to EnforcementAuthorities without its own
	// predicate row here is the half-wired state this test exists to catch.
	if want := EnforcementAuthorities(); len(preds) != len(want) {
		t.Fatalf("preds covers %d enforce.* tokens, EnforcementAuthorities() has %d: %v", len(preds), len(want), want)
	}
	for _, p := range preds {
		if !EnforcementAuthority(p.token) {
			t.Fatalf("%q has a predicate row but EnforcementAuthority() does not classify it", p.token)
		}
	}
	for i, self := range preds {
		t.Run(self.token, func(t *testing.T) {
			// Own token, managed: fires.
			if !self.fn(Effective{Managed: true, Authority: []string{self.token}}) {
				t.Errorf("%s did not satisfy its own predicate on a managed node", self.token)
			}
			// Own token, individual: inert.
			if self.fn(Effective{Managed: false, Authority: []string{self.token}}) {
				t.Errorf("%s fired on the INDIVIDUAL plane", self.token)
			}
			// The umbrella extract.managed must NOT satisfy an enforce gate.
			if self.fn(Effective{Managed: true, Authority: []string{AuthorityExtractManaged}}) {
				t.Errorf("extract.managed umbrella satisfied the enforce gate %s", self.token)
			}
			// No sibling enforce token satisfies this one.
			managed := Effective{Managed: true, Authority: []string{self.token}}
			for j, other := range preds {
				if j == i {
					continue
				}
				if other.fn(managed) {
					t.Errorf("granting %s also satisfied the %s enforce gate", self.token, other.token)
				}
			}
		})
	}
}

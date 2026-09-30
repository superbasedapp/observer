package govern

import "testing"

// TestGrantsEnterpriseContent pins the truth table for the enterpriseGranted
// disjunct (design §5.3 item 4, re-ruled by Agent Access R9.5 / R11.10 on
// 2026-09-24): GrantsEnterpriseContent is e.Managed AND the org-signed
// extract.managed umbrella — the sanctioned raise of an already-enrolled
// teams/enterprise node to full content. The three highest-sensitivity
// DETAIL tokens (codeintel / process / terminal) are NOT required: they gate
// their own detail tables, not the raw content columns
// store.ShareOptions.shipsRawContent() governs. A grant that carried all
// four (the pre-2026-09-24 bar) still satisfies the predicate, so nothing
// that was raised is lowered; the umbrella alone — the shape the enterprise
// mint and the 2026-09-21 demo estate actually issued — now raises too. An
// unmanaged node is refused whatever the grant carries, and no OTHER token
// (cache, routing, the strict detail tokens without the umbrella) can
// substitute for extract.managed.
func TestGrantsEnterpriseContent(t *testing.T) {
	all4 := []string{
		AuthorityExtractManaged,
		AuthorityExtractCodeintel,
		AuthorityExtractProcess,
		AuthorityExtractTerminal,
	}

	cases := []struct {
		name    string
		managed bool
		auth    []string
		want    bool
	}{
		{name: "umbrella alone + managed: granted (R9.5 default raise)", managed: true, auth: []string{AuthorityExtractManaged}, want: true},
		{name: "all four tokens + managed: still granted (pre-ruling bar is a superset)", managed: true, auth: all4, want: true},
		{name: "umbrella alone but unmanaged: refused", managed: false, auth: []string{AuthorityExtractManaged}, want: false},
		{name: "all four tokens but unmanaged: refused", managed: false, auth: all4, want: false},
		{name: "zero value: refused", managed: false, auth: nil, want: false},
		{name: "managed but no tokens at all: refused", managed: true, auth: nil, want: false},
		{
			name:    "the three strict detail tokens WITHOUT the umbrella: refused",
			managed: true,
			auth:    []string{AuthorityExtractCodeintel, AuthorityExtractProcess, AuthorityExtractTerminal},
			want:    false,
		},
		{
			name:    "headline per-tier tokens without the umbrella do not substitute",
			managed: true,
			auth:    []string{AuthorityExtractCache, AuthorityExtractRouting, AuthorityExtractFolders, AuthorityExtractToolBodies},
			want:    false,
		},
		{
			name:    "umbrella plus unrelated extras: granted (extras are harmless)",
			managed: true,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCache, AuthorityExtractRouting},
			want:    true,
		},
		{
			name:    "umbrella present but managed=false overrides everything",
			managed: false,
			auth:    []string{AuthorityExtractManaged, AuthorityExtractCodeintel, AuthorityExtractProcess, AuthorityExtractTerminal, AuthorityExtractObsEgress},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth}
			if got := e.GrantsEnterpriseContent(); got != tc.want {
				t.Errorf("GrantsEnterpriseContent() = %v, want %v (managed=%v auth=%v)", got, tc.want, tc.managed, tc.auth)
			}
		})
	}
}

// TestEnterpriseContentInForce pins the lowering half (doc3 §11.7 W4f:
// "intentional post-migration admin LOWERING is preserved"): the grant's
// raise is live unless the org's signed body carries an explicit
// share.full_content = false directive. An absent, true, or malformed
// directive leaves the raise in force; a false directive on a node the
// grant would otherwise raise yields to the admin; and no directive of any
// kind can turn an ungranted node ON (the individual plane stays lowering-
// only).
func TestEnterpriseContentInForce(t *testing.T) {
	umbrella := []string{AuthorityExtractManaged, AuthorityCapturePin}
	cases := []struct {
		name    string
		managed bool
		auth    []string
		share   map[string]any
		want    bool
	}{
		{name: "granted, no directive: in force", managed: true, auth: umbrella, share: nil, want: true},
		{name: "granted, org pins true: in force", managed: true, auth: umbrella, share: map[string]any{"full_content": true}, want: true},
		{name: "granted, org lowers to false: NOT in force (admin lowering preserved)", managed: true, auth: umbrella, share: map[string]any{"full_content": false}, want: false},
		{name: "granted, malformed directive: in force (not authority to change anything)", managed: true, auth: umbrella, share: map[string]any{"full_content": "no"}, want: true},
		{name: "granted, a different key lowered: in force", managed: true, auth: umbrella, share: map[string]any{"full_tool_bodies": false}, want: true},
		{name: "ungranted managed node, org says true: still off (the directive cannot raise here)", managed: true, auth: []string{AuthorityCapturePin}, share: map[string]any{"full_content": true}, want: false},
		{name: "individual node with the umbrella and org true: off", managed: false, auth: umbrella, share: map[string]any{"full_content": true}, want: false},
		{name: "zero value: off", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Effective{Managed: tc.managed, Authority: tc.auth, Share: tc.share}
			if got := e.EnterpriseContentInForce(); got != tc.want {
				t.Errorf("EnterpriseContentInForce() = %v, want %v (managed=%v auth=%v share=%v)", got, tc.want, tc.managed, tc.auth, tc.share)
			}
		})
	}
}

// TestRefusedGrantGrantsNothing pins the systemic gate W4f's tampered-grant
// test exposed: normalize keeps Managed + Authority populated on every LOUD
// posture (for display), so without GrantRefused every Grants* predicate
// honoured a grant the resolver had just refused. Each refused state must
// answer false to the strict, umbrella and enterprise predicates alike; the
// live states (and the zero State a synthetic test posture carries) keep
// answering true.
func TestRefusedGrantGrantsNothing(t *testing.T) {
	auth := []string{AuthorityExtractManaged, AuthorityEnforceBudget, AuthorityExtractCache}
	cases := []struct {
		state State
		live  bool
	}{
		{StateNoGrant, false},
		{StateGrantExpired, false},
		{StateIdentityChanged, false},
		{StateKeyPinMismatch, false},
		{StateGrantSignatureInvalid, false},
		{State(""), true},
		{StateNoPolicy, true},
		{StateInert, true},
		{StateApplied, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			e := Effective{State: tc.state, Managed: true, Authority: auth}
			if e.GrantRefused() == tc.live {
				t.Fatalf("GrantRefused() = %v for %q, want %v", e.GrantRefused(), tc.state, !tc.live)
			}
			for name, got := range map[string]bool{
				"GrantsBudgetEnforcement":  e.GrantsBudgetEnforcement(),
				"GrantsManagedExtraction":  e.GrantsManagedExtraction(),
				"GrantsCacheExtraction":    e.GrantsCacheExtraction(),
				"GrantsEnterpriseContent":  e.GrantsEnterpriseContent(),
				"EnterpriseContentInForce": e.EnterpriseContentInForce(),
			} {
				if got != tc.live {
					t.Errorf("%s = %v under state %q, want %v", name, got, tc.state, tc.live)
				}
			}
		})
	}
}

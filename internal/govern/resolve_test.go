package govern

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

var testNow = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func testSpec() nodegov.PolicySpec {
	spec, _, err := nodegov.CompileBody([]byte(`{"schema":1,"sections":{"hidden":["benchmarks","remote"],"read_only":["policies"],"settings_hidden":["process"],"settings_read_only":["guard"]},"notice":{"org_display_name":"Acme"}}`), 1<<20)
	if err != nil {
		panic(err)
	}
	return spec
}

func testDelivered() Delivered {
	return Delivered{Present: true, Version: 14, BodyHash: "bh", Spec: testSpec()}
}

func testGrant() *Grant {
	return &Grant{
		OrgKey:       "ok1",
		Generation:   3,
		OrgName:      "Acme",
		KeyPinSHA256: "pin1",
		Authority:    []string{AuthorityDashboardVisibility},
		ConsentMode:  ConsentInteractive,
		GrantedAt:    testNow.Add(-time.Hour),
		ExpiresAt:    testNow.Add(30 * 24 * time.Hour),
	}
}

func testLive() LiveIdentity {
	return LiveIdentity{Enrolled: true, OrgKey: "ok1", Generation: 3, KeyPinSHA256: "pin1"}
}

// TestResolveTableRows is one case per row of the §3.7 resolution table.
func TestResolveTableRows(t *testing.T) {
	expired := testGrant()
	expired.ExpiresAt = testNow.Add(-time.Minute)

	wrongGen := testGrant()
	wrongGen.Generation = 2

	wrongPin := testGrant()
	wrongPin.KeyPinSHA256 = "pin-other"

	// Track C item 1. The tampered fixture is ALSO expired and on a stale
	// generation, which is the ordering assertion: the integrity row must
	// win over both, because a document that does not verify has no
	// trustworthy expiry or generation to judge it by.
	tampered := testGrant()
	tampered.Integrity = GrantIntegrityInvalid
	tampered.ExpiresAt = testNow.Add(-time.Minute)
	tampered.Generation = 2

	// The untouched grant explicitly marked VALID must resolve exactly as
	// the unchecked one does — verification adds a loud state, it never
	// changes the happy path.
	verified := testGrant()
	verified.Integrity = GrantIntegrityValid

	// capture.raise is RETIRED and grants nothing, so a grant carrying only
	// it is a grant with no authority for any directive class — which is
	// exactly why it is still a useful fixture for the "class dropped"
	// row (review n1: this is one of the six sites the retirement touches).
	noAuthority := testGrant()
	noAuthority.Authority = []string{AuthorityCaptureRaise}

	cases := []struct {
		name       string
		delivered  Delivered
		grant      *Grant
		live       LiveIdentity
		wantState  State
		wantActive bool
		wantHidden int
		wantDrop   string
	}{
		{"row 1: no grant ignores a valid body", testDelivered(), nil, testLive(), StateNoGrant, false, 0, ""},
		{"row 2: expired grant reverts", testDelivered(), expired, testLive(), StateGrantExpired, false, 0, ""},
		{"row 3: generation changed", testDelivered(), wrongGen, testLive(), StateIdentityChanged, false, 0, ""},
		{"row 3: unenrolled", testDelivered(), testGrant(), LiveIdentity{}, StateIdentityChanged, false, 0, ""},
		{"row 3b: key pin mismatch", testDelivered(), wrongPin, testLive(), StateKeyPinMismatch, false, 0, ""},
		{"row 1b: tampered grant outranks expiry and identity", testDelivered(), tampered, testLive(), StateGrantSignatureInvalid, false, 0, ""},
		{"row 1b: an explicitly verified grant applies exactly as today", testDelivered(), verified, testLive(), StateApplied, true, 2, ""},
		{"row 5: grant but nothing published", Delivered{}, testGrant(), testLive(), StateNoPolicy, false, 0, ""},
		{"row 6a: authority missing drops the class", testDelivered(), noAuthority, testLive(), StateInert, true, 0, ReasonNotPreauthorized},
		{"row 6b: accept-path inert verdict is carried through", Delivered{Present: true, Version: 14, Spec: testSpec(), InertReason: "not_preauthorized"}, testGrant(), testLive(), StateInert, true, 0, "not_preauthorized"},
		{"row 6c: applied in full", testDelivered(), testGrant(), testLive(), StateApplied, true, 2, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Resolve(tc.delivered, tc.grant, tc.live, testNow)
			if e.State != tc.wantState {
				t.Fatalf("State = %q, want %q", e.State, tc.wantState)
			}
			if e.Active != tc.wantActive {
				t.Fatalf("Active = %v, want %v", e.Active, tc.wantActive)
			}
			if len(e.HiddenSections) != tc.wantHidden {
				t.Fatalf("HiddenSections = %v, want %d entries", e.HiddenSections, tc.wantHidden)
			}
			if tc.wantDrop == "" {
				if len(e.Dropped) != 0 {
					t.Fatalf("Dropped = %v, want none", e.Dropped)
				}
			} else {
				if len(e.Dropped) != 1 || e.Dropped[0].Reason != tc.wantDrop {
					t.Fatalf("Dropped = %v, want one entry with reason %q", e.Dropped, tc.wantDrop)
				}
			}
			// Every branch must produce non-nil lists so the JSON surface is
			// [] and the SPA never has to null-check.
			if e.HiddenSections == nil || e.ReadOnlySections == nil || e.HiddenSettings == nil || e.ReadOnlySettings == nil {
				t.Fatalf("Resolve returned a nil list: %+v", e)
			}
		})
	}
}

// TestResolveAppliesEveryList proves the applied branch carries all four
// lists, not just the nav ones.
func TestResolveAppliesEveryList(t *testing.T) {
	e := Resolve(testDelivered(), testGrant(), testLive(), testNow)
	if got := len(e.HiddenSections); got != 2 {
		t.Fatalf("HiddenSections = %v", e.HiddenSections)
	}
	if got := len(e.ReadOnlySections); got != 1 {
		t.Fatalf("ReadOnlySections = %v", e.ReadOnlySections)
	}
	if got := len(e.HiddenSettings); got != 1 {
		t.Fatalf("HiddenSettings = %v", e.HiddenSettings)
	}
	if got := len(e.ReadOnlySettings); got != 1 {
		t.Fatalf("ReadOnlySettings = %v", e.ReadOnlySettings)
	}
	if !e.IsNavSectionHidden("remote") || e.IsNavSectionHidden("cost") {
		t.Fatalf("IsNavSectionHidden misreports: %+v", e.HiddenSections)
	}
	if !e.IsSettingsSectionReadOnly("guard") {
		t.Fatalf("IsSettingsSectionReadOnly misreports: %+v", e.ReadOnlySettings)
	}
	if e.Notice.OrgDisplayName != "Acme" {
		t.Fatalf("Notice = %+v", e.Notice)
	}
}

// TestResolveIsPure pins the hash-stability property: same inputs, same
// output — and a DROPPED posture never hashes like the applied one, which is
// the fact that stops a partial application reporting as convergence.
func TestResolveIsPure(t *testing.T) {
	a := Resolve(testDelivered(), testGrant(), testLive(), testNow)
	b := Resolve(testDelivered(), testGrant(), testLive(), testNow)
	if a.Hash != b.Hash || a.Hash == "" {
		t.Fatalf("Resolve is not a pure function of its inputs: %q vs %q", a.Hash, b.Hash)
	}
	noAuth := testGrant()
	noAuth.Authority = nil
	c := Resolve(testDelivered(), noAuth, testLive(), testNow)
	if c.Hash == a.Hash {
		t.Fatal("a posture that dropped every directive hashes like the applied one — a partial application could masquerade as convergence")
	}
}

// TestResolveReportsUnknownAuthority pins the forward-compat rule: a token a
// newer server offered is ignored by the resolver and REPORTED, never a
// failure and never silently swallowed.
func TestResolveReportsUnknownAuthority(t *testing.T) {
	g := testGrant()
	g.Authority = []string{AuthorityDashboardVisibility, "telemetry.exfiltrate"}
	e := Resolve(testDelivered(), g, testLive(), testNow)
	if e.State != StateApplied {
		t.Fatalf("State = %q, want the known token to still apply", e.State)
	}
	if len(e.UnknownAuthority) != 1 || e.UnknownAuthority[0] != "telemetry.exfiltrate" {
		t.Fatalf("UnknownAuthority = %v, want the unrecognised token reported", e.UnknownAuthority)
	}
	if len(e.Authority) != 1 || e.Authority[0] != AuthorityDashboardVisibility {
		t.Fatalf("Authority = %v, want only the known token", e.Authority)
	}
}

// TestResolveZeroValueIsDormant is the solo-node claim at the resolver level:
// zero inputs produce a posture that hides nothing and is not Active.
func TestResolveZeroValueIsDormant(t *testing.T) {
	e := Resolve(Delivered{}, nil, LiveIdentity{}, testNow)
	if e.Active || e.State != StateNoGrant {
		t.Fatalf("zero-value Resolve = %+v, want dormant no_grant", e)
	}
	if len(e.HiddenSections)+len(e.ReadOnlySections)+len(e.HiddenSettings)+len(e.ReadOnlySettings) != 0 {
		t.Fatalf("zero-value Resolve applied directives: %+v", e)
	}
}

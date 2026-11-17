package entitlements

import (
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestEvaluateDocRules: one row per row of docRules, plus the in-force path.
func TestEvaluateDocRules(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	biz, _ := Plan("business", 1)
	doc := func(mut func(*Body)) *Document {
		d := mustDoc(t, biz, "org-a")
		if mut != nil {
			mut(&d.Body)
		}
		return &d
	}
	cases := []struct {
		name     string
		kind     Kind
		doc      *Document
		source   Source
		fallback Fallback
		plan     string
	}{
		{name: "no document", kind: KindTeam, doc: nil, source: SourceFloor, fallback: FallbackNoDocument, plan: "team_lapsed"},
		{name: "kind mismatch", kind: KindPersonal, doc: doc(nil), source: SourceFloor, fallback: FallbackKindMismatch, plan: "personal_free"},
		{name: "not yet valid", kind: KindTeam, doc: doc(func(b *Body) { b.NotBefore = now.Unix() + 1 }), source: SourceFloor, fallback: FallbackNotYetValid, plan: "team_lapsed"},
		{name: "expired at not_after", kind: KindTeam, doc: doc(func(b *Body) { b.NotAfter = now.Unix() }), source: SourceFloor, fallback: FallbackExpired, plan: "team_lapsed"},
		{name: "in force inside the window", kind: KindTeam, doc: doc(func(b *Body) { b.NotBefore, b.NotAfter = now.Unix(), now.Unix()+1 }), source: SourceDocument, plan: "business"},
		{name: "in force with no window", kind: KindTeam, doc: doc(nil), source: SourceDocument, plan: "business"},
		{name: "unknown kind", kind: "galactic", doc: doc(nil), source: SourceFloor, fallback: FallbackUnknownKind},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := Evaluate(tc.kind, tc.doc, now)
			if e.Source() != tc.source || e.Fallback() != tc.fallback || e.Plan().Name != tc.plan || e.Kind() != tc.kind {
				t.Fatalf("Evaluate = %s/%s/%s, want %s/%s/%s", e.Source(), e.Fallback(), e.Plan().Name, tc.source, tc.fallback, tc.plan)
			}
			if tc.source == SourceDocument && e.Version() != 1 {
				t.Fatalf("Version = %d", e.Version())
			}
			if tc.source == SourceFloor && e.Version() != 0 {
				t.Fatalf("floor Version = %d", e.Version())
			}
		})
	}
}

// TestComposeRules: one row per compose rule.
func TestComposeRules(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	pro, _ := Plan("personal_pro", 1)
	d := mustDoc(t, pro, "org-p")
	d.Body.Caps[CapPushMBPerDay] = 5 // below the floor's 20: the floor wins
	d.Body.Caps[CapMachineIdentitiesMax] = Unlimited
	d.Body.Caps["future.cap"] = 7 // unknown to this binary
	d.Body.Caps[CapSeatsMin] = 3  // known, not a personal cap
	d.Body.Capabilities = append(d.Body.Capabilities, "org.future", "org.email")
	d.Body.Terms = map[TermName]string{TermEnrichmentTier: "paid"} // not a personal term
	e := Evaluate(KindPersonal, &d, now)

	if l := e.Cap(CapRetentionDays); !l.Set || l.N != 60 {
		t.Errorf("retention = %+v, want the document's 60", l)
	}
	if l := e.Cap(CapPushMBPerDay); l.N != 20 {
		t.Errorf("push = %+v, want the floor's 20 (a document never narrows)", l)
	}
	if l := e.Cap(CapMachineIdentitiesMax); !l.Unlimited {
		t.Errorf("machine identities = %+v, want Unlimited", l)
	}
	if l := e.Cap(CapMembersMax); l.N != 1 {
		t.Errorf("members = %+v, want the floor's 1 (absent falls back)", l)
	}
	if !e.Has("org.digest") || e.Has("org.saml") || !e.Has("org.email") || !e.Has("org.core") {
		t.Errorf("Has: digest %v saml %v email %v core %v", e.Has("org.digest"), e.Has("org.saml"), e.Has("org.email"), e.Has("org.core"))
	}
	if e.Has("org.future") || e.Has("no.such") {
		t.Error("an unknown component is entitled")
	}
	if l := e.Cap(CapSeatsMin); l.Set || l.Allows(0) {
		t.Errorf("a cap that does not apply = %+v; it must be unset and allow nothing", l)
	}
	if _, ok := e.Term(TermEnrichmentTier); ok {
		t.Error("a term that does not apply to the kind was applied")
	}
	wantIgnored := []string{"cap future.cap", "cap seats.min", "capability org.email", "capability org.future", "term enrichment.tier"}
	if got := e.Ignored(); !slices.Equal(got, wantIgnored) {
		t.Errorf("Ignored = %q, want %q", got, wantIgnored)
	}
}

// TestTermsReplaceTheFloor: an account document's terms replace the floor's.
func TestTermsReplaceTheFloor(t *testing.T) {
	t.Parallel()
	plus, _ := Plan("plus_beta", 5)
	d := mustDoc(t, plus, "acct-1")
	e := Evaluate(KindAccount, &d, time.Unix(1, 0))
	if v, _ := e.Term(TermEnrichmentBudgetPool); v != "plus_beta" {
		t.Fatalf("budget pool = %q", v)
	}
	floor := Evaluate(KindAccount, nil, time.Unix(1, 0))
	if v, _ := floor.Term(TermEnrichmentBudgetPool); v != "free" {
		t.Fatalf("floor budget pool = %q", v)
	}
}

// TestLimitAllows: one row per Limit shape.
func TestLimitAllows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		l    Limit
		n    int64
		want bool
	}{
		{Limit{N: 3, Set: true}, 3, true},
		{Limit{N: 3, Set: true}, 4, false},
		{Limit{N: 0, Set: true}, 1, false},
		{Limit{Unlimited: true, Set: true}, 1 << 40, true},
		{Limit{}, 0, false},
	} {
		if got := tc.l.Allows(tc.n); got != tc.want {
			t.Errorf("%+v.Allows(%d) = %v", tc.l, tc.n, got)
		}
	}
}

// TestComponentInputIsResolversLayerThree drives components.Resolve with the
// entitlement: a Business-only module on a Team document resolves blocked
// not_entitled, the same module on Business is active, and an included one
// is active on the lapsed floor.
func TestComponentInputIsResolversLayerThree(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	team, _ := Plan("team", 1)
	biz, _ := Plan("business", 1)
	td, bd := mustDoc(t, team, "org-t"), mustDoc(t, biz, "org-b")
	selected := []string{"org.saml", "org.assistant", "org.oidc"}
	resolve := func(e Effective) components.ResolveResult {
		return components.Resolve(components.ResolveInput{
			Binary: components.BinaryOrg, Selected: selected,
			Governance: &components.Governance{Entitled: e.ComponentInput()},
		})
	}
	type want struct {
		id     string
		state  components.State
		reason components.Reason
	}
	for _, tc := range []struct {
		name string
		e    Effective
		want []want
	}{
		{name: "team", e: Evaluate(KindTeam, &td, now), want: []want{
			{"org.saml", components.StateBlocked, components.ReasonNotEntitled},
			{"org.assistant", components.StateActive, components.ReasonSelected},
			{"org.oidc", components.StateActive, components.ReasonSelected},
			{"org.core", components.StateActive, components.ReasonCore},
		}},
		{name: "business", e: Evaluate(KindTeam, &bd, now), want: []want{
			{"org.saml", components.StateActive, components.ReasonSelected},
			{"org.assistant", components.StateActive, components.ReasonSelected},
		}},
		{name: "lapsed", e: Evaluate(KindTeam, nil, now), want: []want{
			{"org.saml", components.StateBlocked, components.ReasonNotEntitled},
			{"org.assistant", components.StateBlocked, components.ReasonNotEntitled},
			{"org.oidc", components.StateActive, components.ReasonSelected},
		}},
		{name: "unknown kind is core only", e: Evaluate("galactic", nil, now), want: []want{
			{"org.oidc", components.StateBlocked, components.ReasonNotEntitled},
			{"org.core", components.StateActive, components.ReasonCore},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := resolve(tc.e)
			for _, w := range tc.want {
				d, ok := res.Decision(w.id)
				if !ok || d.State != w.state || d.Reason != w.reason {
					t.Errorf("%s = %+v, want %s/%s", w.id, d, w.state, w.reason)
				}
			}
		})
	}
}

// TestSelfHostedFloorChangesNothing is the single-mode golden check for this
// layer: the D-6 community floor entitles every server component, so a
// self-hosted server with no licence resolves exactly as with no
// entitlement layer at all.
func TestSelfHostedFloorChangesNothing(t *testing.T) {
	t.Parallel()
	e := Evaluate(KindSelfHosted, nil, time.Unix(1, 0))
	for _, b := range serverBinaries() {
		var all []string
		for _, c := range components.ForBinary(b) {
			all = append(all, c.ID)
		}
		base := components.Resolve(components.ResolveInput{Binary: b, Selected: all})
		with := components.Resolve(components.ResolveInput{Binary: b, Selected: all, Governance: &components.Governance{Entitled: e.ComponentInput()}})
		if !slices.Equal(base.Decisions, with.Decisions) {
			t.Errorf("%s: the community floor changes the resolution", b)
		}
	}
	if l := e.Cap(CapMembersMax); l.N != 10 {
		t.Errorf("community members = %+v, want 10 (D-6)", l)
	}
}

// TestCapabilitiesAreSortedAndIncludeTheIncluded: the input lists every
// included component even on a floor that grants nothing.
func TestCapabilitiesAreSortedAndIncludeTheIncluded(t *testing.T) {
	t.Parallel()
	e := Evaluate(KindTeam, nil, time.Unix(1, 0))
	got := e.Capabilities()
	if !slices.IsSorted(got) {
		t.Fatal("not sorted")
	}
	if !slices.Equal(got, GatedIDs(GateIncluded)) {
		t.Fatalf("lapsed capabilities = %q, want the included set", got)
	}
}

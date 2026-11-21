package planechoice

import (
	"strings"
	"testing"
)

func TestParseChoiceClosedTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Choice
		ok   bool
	}{
		{"coding", ChoiceCoding, true},
		{"apps", ChoiceApps, true},
		{"both", ChoiceBoth, true},
		{" apps ", ChoiceApps, true},
		{"", ChoiceNone, false},
		{"APPS", ChoiceNone, false},
		{"apps,coding", ChoiceNone, false},
		{"../apps", ChoiceNone, false},
		{"/apps", ChoiceNone, false},
		{"none", ChoiceNone, false},
	} {
		got, ok := ParseChoice(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("ParseChoice(%q) = %q,%v want %q,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestParseIntentSourceClosedTable(t *testing.T) {
	for _, s := range []string{"for_link", "connect", "apps_on", "installer"} {
		if _, ok := ParseIntentSource(s); !ok {
			t.Errorf("ParseIntentSource(%q) refused", s)
		}
	}
	for _, s := range []string{"", "web", "connect?x=1", "Connect"} {
		if _, ok := ParseIntentSource(s); ok {
			t.Errorf("ParseIntentSource(%q) accepted", s)
		}
	}
}

// TestAvailabilityRules: one case per row of availabilityRules.
func TestAvailabilityRules(t *testing.T) {
	cases := []struct {
		state  ComponentState
		avail  bool
		reason string
	}{
		{ComponentActive, true, ""},
		{ComponentAvailable, true, ""},
		{ComponentAbsent, false, "not_in_build"},
		{ComponentBlocked, false, "blocked"},
		{ComponentUnknown, false, "unknown"},
	}
	if len(cases) != len(availabilityRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(availabilityRules))
	}
	for _, tc := range cases {
		got := AppsAvailable(tc.state)
		if got.Available != tc.avail || got.Reason != tc.reason {
			t.Errorf("AppsAvailable(%s) = %+v", tc.state, got)
		}
		if !got.Available && got.Text == "" {
			t.Errorf("AppsAvailable(%s): unavailable without a reason text", tc.state)
		}
	}
	// An unrecognised state is never available.
	if AppsAvailable("managed").Available {
		t.Error("an unknown state read as available")
	}
}

// TestCodingRules: one case per coding fact input row.
func TestCodingRules(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want bool
		by   string
	}{
		{"stored apps wins over history", Inputs{Stored: ChoiceApps, CodingHistory: true, Intent: ChoiceCoding}, false, "the stored choice decides"},
		{"intent names coding", Inputs{Intent: ChoiceBoth}, true, "the arrival intent names coding"},
		{"history found", Inputs{CodingHistory: true, Intent: ChoiceApps}, true, "AI coding history found"},
		{"no signal", Inputs{}, false, "no coding signal"},
	}
	if len(cases) != len(codingRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(codingRules))
	}
	for i, tc := range cases {
		f := Derive(tc.in)
		if f.Coding != tc.want || f.CodingBy != tc.by || f.CodingBy != codingRules[i].name {
			t.Errorf("%s: coding=%v by %q", tc.name, f.Coding, f.CodingBy)
		}
	}
}

// TestAppsRules: one case per apps fact input row.
func TestAppsRules(t *testing.T) {
	cases := []struct {
		name string
		in   Inputs
		want bool
	}{
		{"not available beats everything", Inputs{AppsAvailable: false, AppsOn: true, Stored: ChoiceApps, Intent: ChoiceApps, TraceSeen: true}, false},
		{"AI Apps on beats a stored coding", Inputs{AppsAvailable: true, AppsOn: true, Stored: ChoiceCoding}, true},
		{"a trace arrived", Inputs{AppsAvailable: true, TraceSeen: true, Stored: ChoiceCoding}, true},
		{"stored choice decides", Inputs{AppsAvailable: true, Stored: ChoiceCoding, Intent: ChoiceApps}, false},
		{"intent names apps", Inputs{AppsAvailable: true, Intent: ChoiceApps}, true},
		{"no signal", Inputs{AppsAvailable: true}, false},
	}
	if len(cases) != len(appsRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(appsRules))
	}
	for i, tc := range cases {
		f := Derive(tc.in)
		if f.Apps != tc.want || f.AppsBy != appsRules[i].name {
			t.Errorf("%s: apps=%v by %q, want %v by %q", tc.name, f.Apps, f.AppsBy, tc.want, appsRules[i].name)
		}
	}
}

// TestRules: one case per row of the four-row table.
func TestRules(t *testing.T) {
	cases := []struct {
		row       int
		in        Inputs
		track     Track
		ask       bool
		offerApps bool
	}{
		{1, Inputs{CodingHistory: true, AppsOn: true, AppsAvailable: true}, TrackBoth, false, false},
		{2, Inputs{Intent: ChoiceApps, AppsAvailable: true}, TrackApps, false, false},
		{3, Inputs{CodingHistory: true, AppsAvailable: true}, TrackCoding, false, true},
		{4, Inputs{AppsAvailable: true}, TrackCoding, true, false},
	}
	if len(cases) != len(Rules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(Rules))
	}
	for _, tc := range cases {
		d := Decide(tc.in)
		if d.Row != tc.row || d.Track != tc.track || d.Ask != tc.ask || d.OfferApps != tc.offerApps {
			t.Errorf("row %d: got %+v", tc.row, d)
		}
	}
}

// TestRulesCoverEveryPair: each (coding, apps) pair matches exactly one row.
func TestRulesCoverEveryPair(t *testing.T) {
	for _, c := range []bool{false, true} {
		for _, a := range []bool{false, true} {
			n := 0
			for _, r := range Rules {
				if r.Coding == c && r.Apps == a {
					n++
				}
			}
			if n != 1 {
				t.Errorf("(coding=%v, apps=%v) matches %d rows", c, a, n)
			}
		}
	}
}

// TestRow3OffersAppsOnlyWhenAvailable: the quiet line is never shown where
// AI Apps cannot be turned on (a managed edition).
func TestRow3OffersAppsOnlyWhenAvailable(t *testing.T) {
	d := Decide(Inputs{CodingHistory: true, AppsAvailable: false, Intent: ChoiceApps})
	if d.Row != 3 || d.OfferApps {
		t.Fatalf("got %+v, want row 3 without the offer", d)
	}
}

// TestPlanScenarios walks the plan's named cases end to end.
func TestPlanScenarios(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    Inputs
		track Track
	}{
		{"P-01: history and AI Apps on is Both", Inputs{CodingHistory: true, AppsOn: true, AppsAvailable: true}, TrackBoth},
		{"4.1: coder turns AI Apps on", Inputs{CodingHistory: true, Stored: ChoiceCoding, AppsOn: true, AppsAvailable: true}, TrackBoth},
		{"P-02: managed edition with apps intent stays coding", Inputs{Intent: ChoiceApps, AppsAvailable: false}, TrackCoding},
		{"fresh machine from the apps door", Inputs{Intent: ChoiceApps, AppsAvailable: true}, TrackApps},
		{"Settings: apps only on a coder's machine", Inputs{Stored: ChoiceApps, CodingHistory: true, AppsAvailable: true}, TrackApps},
	} {
		if got := Decide(tc.in).Track; got != tc.track {
			t.Errorf("%s: track %s, want %s", tc.name, got, tc.track)
		}
	}
}

// TestConsentRules: one case per row of the sentence builder.
func TestConsentRules(t *testing.T) {
	notEnrolled := BuildConsent(ConsentFacts{Tiers: []string{"traces"}})
	if notEnrolled.Sentence != "Stays on this machine." || notEnrolled.Shared || notEnrolled.Row != consentRules[0].name {
		t.Errorf("not enrolled: %+v", notEnrolled)
	}
	noTier := BuildConsent(ConsentFacts{Enrolled: true, Org: "Acme"})
	if noTier.Sentence != "Stays on this machine." || noTier.Shared {
		t.Errorf("enrolled, no tier: %+v", noTier)
	}
	shared := BuildConsent(ConsentFacts{Enrolled: true, Org: "Acme", Tiers: []string{"traces", "summary", "bogus"}})
	if shared.Sentence != "Also sent to Acme (summaries, trace structure)." || !shared.Shared || shared.Row != consentRules[1].name {
		t.Errorf("enrolled with tiers: %+v", shared)
	}
	if strings.Contains(shared.Sentence, "bogus") {
		t.Error("an unknown tier key reached the sentence")
	}
	noName := BuildConsent(ConsentFacts{Enrolled: true, Tiers: []string{"egress"}})
	if noName.Sentence != "Also sent to your organization (egress decisions)." {
		t.Errorf("no org name: %q", noName.Sentence)
	}
	if strings.Contains(shared.Sentence+notEnrolled.Sentence, "Nothing leaves") {
		t.Error("the retired wording came back")
	}
}

func TestConsentReceiverNote(t *testing.T) {
	if c := BuildConsent(ConsentFacts{}); !c.LoopbackOnly || c.ReceiverNote != "(this machine only)" {
		t.Errorf("loopback: %+v", c)
	}
	if c := BuildConsent(ConsentFacts{AllowNonLoopback: true}); c.LoopbackOnly || c.ReceiverNote != "" {
		t.Errorf("non-loopback: %+v", c)
	}
}

func TestEveryShareTierHasALabel(t *testing.T) {
	seen := map[string]bool{}
	for _, st := range ShareTiers {
		if st.Key == "" || st.Label == "" || seen[st.Key] {
			t.Errorf("bad tier row %+v", st)
		}
		seen[st.Key] = true
	}
}

// TestEnableRules: one case per row of enableRules.
func TestEnableRules(t *testing.T) {
	listening := Receiver{State: ReceiverListening, HTTPAddr: "127.0.0.1:4318"}
	cases := []struct {
		name string
		f    EnableFacts
		want EnableOutcome
		fix  bool
	}{
		{"not in this build", EnableFacts{InBuild: false, Editions: []string{"developer", "full"}}, OutcomeNotInBuild, true},
		{"blocked", EnableFacts{InBuild: true, Component: ComponentBlocked}, OutcomeBlocked, true},
		{"refused", EnableFacts{InBuild: true, Component: ComponentAvailable, Refused: "pinned by your organization"}, OutcomeRefused, false},
		{"write failed", EnableFacts{InBuild: true, Component: ComponentAvailable, WriteError: "disk full"}, OutcomeConfigFailed, false},
		{"bind failed", EnableFacts{InBuild: true, Component: ComponentActive, Receiver: Receiver{State: ReceiverBindFailed, HTTPAddr: "127.0.0.1:4318", Error: "address already in use"}}, OutcomeBindFailed, true},
		{"no answer", EnableFacts{InBuild: true, Component: ComponentActive, Receiver: Receiver{State: ReceiverNoAnswer}}, OutcomeNoAnswer, true},
		{"on", EnableFacts{InBuild: true, Component: ComponentActive, Receiver: listening}, OutcomeOn, false},
	}
	if len(cases) != len(enableRules) {
		t.Fatalf("%d cases for %d rows", len(cases), len(enableRules))
	}
	for i, tc := range cases {
		r := ClassifyEnable(tc.f)
		if r.Outcome != tc.want || r.Rule != enableRules[i].name || (r.Fix != "") != tc.fix {
			t.Errorf("%s: %+v", tc.name, r)
		}
		if r.OK != (tc.want == OutcomeOn) {
			t.Errorf("%s: OK=%v", tc.name, r.OK)
		}
	}
	// The absent component reads as not in this build even when compiled.
	if r := ClassifyEnable(EnableFacts{InBuild: true, Component: ComponentAbsent}); r.Outcome != OutcomeNotInBuild {
		t.Errorf("absent component: %+v", r)
	}
	// The bind failure names the fix key.
	r := ClassifyEnable(cases[4].f)
	if !strings.Contains(r.Fix, "[ingest.otel] http_addr") || !strings.Contains(r.Message, "address already in use") {
		t.Errorf("bind failure wording: %+v", r)
	}
	// The refusal names the editions that have it and the reinstall command.
	r = ClassifyEnable(cases[0].f)
	if !strings.Contains(r.Message, "developer and full") || !strings.Contains(r.Fix, "--edition developer") {
		t.Errorf("not-in-build wording: %+v", r)
	}
}

package frontdoor

import "testing"

// TestDestinationRules is one case per row of destinationRules.
func TestDestinationRules(t *testing.T) {
	t.Parallel()
	if len(destinationRules) != 3 {
		t.Fatalf("destinationRules has %d rows; this test covers 3", len(destinationRules))
	}
	cases := []struct {
		row  string
		d    Destination
		want Kind
	}{
		{"not attached", Destination{Managed: true, OrgName: "ignored"}, KindLocal},
		{"managed", Destination{Attached: true, Managed: true, OrgName: "Acme"}, KindManaged},
		{"individual", Destination{Attached: true, OrgName: "Acme"}, KindIndividual},
	}
	for _, tc := range cases {
		if got := Sentence(Facts{Destination: tc.d}).Kind; got != tc.want {
			t.Errorf("%s: kind = %q, want %q", tc.row, got, tc.want)
		}
	}
}

func TestSentence(t *testing.T) {
	t.Parallel()
	acme := Destination{Attached: true, OrgName: "Acme", Managed: true, MemberEmail: "dev@acme.example"}
	cases := []struct {
		name string
		f    Facts
		want string
	}{
		{"unsigned, local", Facts{}, "Local only"},
		{"signed out, local", Facts{Identity: IdentitySignedOut}, "Local only"},
		{"signed in, local", Facts{Identity: IdentitySignedIn}, "Local only · signed in to SuperBased"},
		{"managed", Facts{Destination: acme}, "Acme (managed) as dev@acme.example"},
		{"managed, signed in", Facts{Destination: acme, Identity: IdentitySignedIn}, "Acme (managed) as dev@acme.example · signed in to SuperBased"},
		{"managed, locked", Facts{Destination: func() Destination { d := acme; d.Locked = true; return d }()}, "Acme (managed, locked) as dev@acme.example"},
		{"individual", Facts{Destination: Destination{Attached: true, OrgName: "Personal", MemberEmail: "you@example.com"}}, "Personal (individual) as you@example.com"},
		{"no name: the host", Facts{Destination: Destination{Attached: true, ServerURL: "https://org.example:8443/"}}, "org.example:8443 (individual)"},
		{"no name, no URL", Facts{Destination: Destination{Attached: true}}, "an organization (individual)"},
		{"a lock with no destination says nothing", Facts{Destination: Destination{Locked: true}}, "Local only"},
	}
	for _, tc := range cases {
		if got := Sentence(tc.f).Sentence; got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestStatusParts(t *testing.T) {
	t.Parallel()
	st := Sentence(Facts{Destination: Destination{Attached: true, OrgName: "Acme", Managed: true, Locked: true}, Identity: IdentitySignedOut})
	if st.Kind != KindManaged || st.Destination != "Acme" || st.SignedIn || !st.IdentityKnown || !st.Locked {
		t.Fatalf("status = %+v", st)
	}
	if st := Sentence(Facts{}); st.IdentityKnown || st.SignedIn || st.Destination != "" {
		t.Fatalf("unknown identity = %+v", st)
	}
}

// TestConnectionFacts (Getting started v2 lane 8 job 2): the connection's
// recorded name wins in the sentence and the status, the online address is
// passed on for a button (never in the sentence), and a local machine has
// neither.
func TestConnectionFacts(t *testing.T) {
	t.Parallel()
	personal := Destination{
		Attached: true, OrgName: "u-abcdefgh", ServerURL: "https://u-abcdefgh.superbased.app",
		DisplayName: "your personal dashboard", OnlineURL: "https://u-abcdefgh.superbased.app/", MemberEmail: "you@example.com",
	}
	st := Sentence(Facts{Destination: personal})
	if st.Sentence != "Your personal dashboard (individual) as you@example.com" {
		t.Fatalf("sentence = %q", st.Sentence)
	}
	if st.DisplayName != "your personal dashboard" || st.OnlineURL != "https://u-abcdefgh.superbased.app/" {
		t.Fatalf("status = %+v", st)
	}
	team := Destination{Attached: true, Managed: true, OrgName: "acme", ServerURL: "https://acme.superbased.app"}
	if st := Sentence(Facts{Destination: team}); st.DisplayName != "acme" || st.OnlineURL != "https://acme.superbased.app" {
		t.Fatalf("no recorded facts: the org name and its server, got %+v", st)
	}
	if st := Sentence(Facts{Destination: Destination{Attached: true, OnlineURL: "javascript:alert(1)"}}); st.OnlineURL != "" {
		t.Fatalf("a non-http online address was passed on: %q", st.OnlineURL)
	}
	if st := Sentence(Facts{}); st.DisplayName != "" || st.OnlineURL != "" {
		t.Fatalf("local = %+v", st)
	}
}

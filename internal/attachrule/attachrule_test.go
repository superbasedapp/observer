package attachrule

import "testing"

var (
	personal = Destination{Kind: KindPersonal, OrgID: "p1", Name: "Personal"}
	acme     = Destination{Kind: KindTeamOrg, Tenancy: TenancyManaged, OrgID: "acme", Name: "Acme"}
	acmeReq  = Destination{Kind: KindTeamOrg, OrgID: "acme", Name: "Acme"}
	globex   = Destination{Kind: KindTeamOrg, OrgID: "globex", Name: "Globex"}
	selfHost = Destination{Kind: KindPrivateServer, OrgID: "https://obs.example", Name: "Self"}
	lockAcme = &Lock{Destination: acmeReq, AskWho: "it@acme.example"}
)

func TestTableRowIDs(t *testing.T) {
	t.Parallel()
	if len(table) != 11 {
		t.Fatalf("table has %d rows, want 11", len(table))
	}
	seen := map[int]int{}
	for i, r := range table {
		seen[r.ID]++
		if r.ID != i+1 {
			t.Errorf("row at index %d has ID %d", i, r.ID)
		}
	}
	for id := 1; id <= 11; id++ {
		if seen[id] != 1 {
			t.Errorf("row ID %d appears %d times", id, seen[id])
		}
	}
}

func TestDecideRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		row   int
		in    Input
		check func(t *testing.T, d Decision)
	}{
		{
			"row 1 locked attach elsewhere refused", 1,
			Input{Current: acme, Lock: lockAcme, Intent: IntentAttach, Requested: globex},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse || d.Refusal.Reason != RefusalLocked ||
					d.Refusal.LockOrgName != "Acme" || d.Refusal.AskWho != "it@acme.example" {
					t.Errorf("got %+v %+v", d, d.Refusal)
				}
			},
		},
		{
			"row 1 locked disconnect refused", 1,
			Input{Current: acme, Lock: lockAcme, Intent: IntentDisconnect},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse || d.Refusal.Reason != RefusalLocked {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 1 locked identity only allowed", 1,
			Input{Current: acme, Lock: lockAcme, Intent: IntentIdentityOnly},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || !d.DestinationUnchanged {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 1 locked attach to the locked org allowed", 1,
			Input{Lock: lockAcme, Intent: IntentAttach, Requested: acmeReq},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || d.Target.OrgID != "acme" {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 2 identity only", 2,
			Input{Current: acme, Intent: IntentIdentityOnly},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || !d.DestinationUnchanged || d.Drain {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 3 disconnect drains", 3,
			Input{Current: personal, Intent: IntentDisconnect},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || !d.Drain {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 3 disconnect with nothing attached", 3,
			Input{Intent: IntentDisconnect},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || d.Drain {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 4 managed to other team org", 4,
			Input{Current: acme, Intent: IntentAttach, Requested: globex},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllowWithConfirmation || !d.Drain || !d.ShowLeftBehind ||
					d.ConfirmOrgName != "Acme" || d.Target.OrgID != "globex" {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 4 managed to private server", 4,
			Input{Current: acme, Intent: IntentAttach, Requested: selfHost},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllowWithConfirmation {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 5 managed to personal refused before M10", 5,
			Input{Current: acme, Intent: IntentAttach, Requested: personal, PolicyAllowsSecondDestination: true},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse || d.Refusal.Reason != RefusalPersonalOnManaged {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 5 after M10 policy forbids", 5,
			Input{Current: acme, Intent: IntentAttach, Requested: personal, MultiEnabled: true},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse || d.Refusal.Reason != RefusalPolicyNoSecondDestination {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 5 after M10 policy allows", 5,
			Input{Current: acme, Intent: IntentAttach, Requested: personal, MultiEnabled: true, PolicyAllowsSecondDestination: true},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || d.Drain {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 6 individual to team org", 6,
			Input{Current: personal, Intent: IntentAttach, Requested: globex},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || !d.Drain || !d.ShowLeftBehind {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 6 fresh machine with explicit server", 6,
			Input{Intent: IntentAttach, Requested: selfHost},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || d.Drain || d.ShowLeftBehind {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 7 one org", 7,
			Input{Intent: IntentAttach, Listed: []Destination{globex}},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeOfferOne || d.Target.OrgID != "globex" || !d.ChooserMayBeIncomplete {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 8 several orgs", 8,
			Input{Intent: IntentAttach, Listed: []Destination{personal, globex}},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeShowChooser || len(d.Choices) != 2 || !d.ChooserMayBeIncomplete {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 9 no orgs", 9,
			Input{Intent: IntentAttach},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeOfferCreatePersonal || !d.OfferEnterAddress {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 10 re-consent on an individual enrolment", 10,
			Input{Current: personal, Intent: IntentReconsent},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeAllow || d.Target.OrgID != "p1" || d.DestinationUnchanged {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 10 re-consent on a managed enrolment", 10,
			Input{Current: acme, Intent: IntentReconsent},
			func(t *testing.T, d Decision) {
				if d.Refusal == nil || d.Refusal.Reason != RefusalAlreadyAttached {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 10 re-consent with nothing attached", 10,
			Input{Intent: IntentReconsent},
			func(t *testing.T, d Decision) {
				if d.Refusal == nil || d.Refusal.Reason != RefusalUnsupported {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 11 zero intent", 11,
			Input{Current: acme},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse || d.Refusal.Reason != RefusalUnsupported {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 11 already attached", 11,
			Input{Current: acme, Intent: IntentAttach, Requested: acmeReq},
			func(t *testing.T, d Decision) {
				if d.Refusal == nil || d.Refusal.Reason != RefusalAlreadyAttached {
					t.Errorf("got %+v", d)
				}
			},
		},
		{
			"row 11 managed attach with nothing requested", 11,
			Input{Current: acme, Intent: IntentAttach},
			func(t *testing.T, d Decision) {
				if d.Outcome != OutcomeRefuse {
					t.Errorf("got %+v", d)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// No earlier row may match: the case belongs to its row alone.
			for _, r := range table[:tc.row-1] {
				if r.Match(tc.in) {
					t.Fatalf("earlier row %d also matches", r.ID)
				}
			}
			if !table[tc.row-1].Match(tc.in) {
				t.Fatalf("row %d does not match", tc.row)
			}
			d := Decide(tc.in)
			if d.Row != tc.row {
				t.Fatalf("Decide matched row %d, want %d", d.Row, tc.row)
			}
			tc.check(t, d)
		})
	}
}

// TestOrderMatters proves the table order decides collisions.
func TestOrderMatters(t *testing.T) {
	t.Parallel()
	// A locked node asked to disconnect hits row 1 (refuse), not row 3.
	d := Decide(Input{Current: acme, Lock: lockAcme, Intent: IntentDisconnect})
	if d.Row != 1 || d.Outcome != OutcomeRefuse {
		t.Errorf("locked disconnect: row %d outcome %v", d.Row, d.Outcome)
	}
	// Without the lock the same input is row 3.
	if d := Decide(Input{Current: acme, Intent: IntentDisconnect}); d.Row != 3 {
		t.Errorf("unlocked disconnect: row %d", d.Row)
	}
	// Identity only on a locked node is allowed by row 1, not refused.
	if d := Decide(Input{Current: acme, Lock: lockAcme, Intent: IntentIdentityOnly}); d.Row != 1 || d.Outcome != OutcomeAllow {
		t.Errorf("locked identity-only: row %d outcome %v", d.Row, d.Outcome)
	}
	// Identity only never reaches the switch rows even with a request set.
	if d := Decide(Input{Current: acme, Intent: IntentIdentityOnly, Requested: globex}); d.Row != 2 {
		t.Errorf("identity-only with request: row %d", d.Row)
	}
}

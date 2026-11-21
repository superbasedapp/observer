package secassess

import (
	"testing"
)

func scannerRow(kind ID) Relaxation {
	r, _ := RelaxationFor(kind, RuleScanner)
	return r
}

func tierRelaxRow(kind ID) Relaxation {
	r, _ := RelaxationFor(kind, TierKey)
	return r
}

func onPolicy() Policy {
	return Policy{
		Relax:          map[ID]bool{PentestLocal: true, RedTeamLocal: true},
		ScopedApproval: true, MaxTier: "internet", Scope: ScopeSession, MaxMinutes: 60,
	}
}

// TestConsentRoute: one row per row of the consent table (plan section 13.4),
// by the row's id and name, so a row added without a case fails
// TestConsentRowsAllCovered.
func TestConsentRoute(t *testing.T) {
	t.Parallel()
	ask := RuleFacts{Lock: LockUntouched, Decision: "ask"}
	cases := []struct {
		name  string
		in    ConsentInput
		route Route
		row   string
		code  string
	}{
		{"C1 kind switch off", ConsentInput{Row: scannerRow(PentestLocal), Policy: Policy{ScopedApproval: true}, Tenancy: TenancyIndividual, Rule: ask}, RouteRefused, "C1", CodeRelaxDisabled},
		{"C1 scoped approval off", ConsentInput{Row: scannerRow(PentestLocal), Policy: Policy{Relax: map[ID]bool{PentestLocal: true}}, Tenancy: TenancyIndividual, Rule: ask}, RouteRefused, "C1", CodeRelaxDisabled},
		{"C2 nothing to lift (flag)", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Rule: RuleFacts{Lock: LockUntouched, Decision: "flag"}}, RouteNotNeeded, "C2", ""},
		{"C2 nothing to lift (allow)", ConsentInput{Row: scannerRow(RedTeamLocal), Policy: onPolicy(), Tenancy: TenancyManaged, Rule: RuleFacts{Lock: LockLocked, Decision: "allow"}}, RouteNotNeeded, "C2", ""},
		{"C3 the org marked it overridable", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyManaged, Enrolled: true, Rule: RuleFacts{Lock: LockOverridable, Decision: "ask"}}, RouteSelf, "C3", ""},
		{"C3 overridable on an unresolved node", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyUnresolved, Rule: RuleFacts{Lock: LockOverridable, Decision: "ask"}}, RouteSelf, "C3", ""},
		{"C4 untouched on an individual node", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Rule: ask}, RouteSelf, "C4", ""},
		{"C4 an unknown decision still needs a lift", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Rule: RuleFacts{Lock: LockUntouched}}, RouteSelf, "C4", ""},
		{"C5 locked on an individual node, enrolled", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Enrolled: true, Rule: RuleFacts{Lock: LockLocked, Decision: "ask"}}, RouteOrgRequest, "C5", ""},
		{"C5 untouched on a managed node never self-approves", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyManaged, Enrolled: true, Rule: ask}, RouteOrgRequest, "C5", ""},
		{"C5 an unresolved tenancy asks the org", ConsentInput{Row: scannerRow(RedTeamLocal), Policy: onPolicy(), Tenancy: TenancyUnresolved, Enrolled: true, Rule: ask}, RouteOrgRequest, "C5", ""},
		{"C6 no org to ask", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyManaged, Rule: ask}, RouteRefused, "C6", CodeNeedsOrg},
		{"C6 locked, not enrolled", ConsentInput{Row: scannerRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Rule: RuleFacts{Lock: LockLocked, Decision: "deny"}}, RouteRefused, "C6", CodeNeedsOrg},

		{"T1 kind switch off", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: Policy{MaxTier: "internet"}, Tenancy: TenancyIndividual, Tier: TierFacts{Live: "internet", Hosts: []string{"registry.npmjs.org"}}}, RouteRefused, "T1", CodeRelaxDisabled},
		{"T1 already confined", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "proxy_only"}}, RouteNotNeeded, "T1", ""},
		{"T1 above the configured maximum", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: Policy{Relax: map[ID]bool{PentestLocal: true}, MaxTier: "proxy_only"}, Tenancy: TenancyIndividual, Tier: TierFacts{Live: "internet", Hosts: []string{"a.example.com"}}}, RouteRefused, "T1", CodeTierAboveMax},
		{"T1 host tier", ConsentInput{Row: tierRelaxRow(RedTeamLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "host"}}, RouteRefused, "T1", CodeTierUnsupported},
		{"T1 none tier", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "none"}}, RouteRefused, "T1", CodeTierUnsupported},
		{"T1 no host list", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "internet"}}, RouteRefused, "T1", CodeNeedsAllowHosts},
		{"T2 individual node", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "", Hosts: []string{"registry.npmjs.org"}}}, RouteSelf, "T2", ""},
		{"T2 an org pin that left no host is a narrowed list", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "internet", NoHostPinned: true}}, RouteSelf, "T2", ""},
		{"T3 managed node", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyManaged, Enrolled: true, Tier: TierFacts{Live: "internet", Hosts: []string{"registry.npmjs.org"}}}, RouteRefused, "T3", CodeNeedsOrgSetting},
		{"T3 unresolved tenancy", ConsentInput{Row: tierRelaxRow(PentestLocal), Policy: onPolicy(), Tenancy: TenancyUnresolved, Tier: TierFacts{Live: "internet", Hosts: []string{"registry.npmjs.org"}}}, RouteRefused, "T3", CodeNeedsOrgSetting},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ConsentRoute(tc.in)
			if got.Route != tc.route || got.Row != tc.row || got.Code != tc.code {
				t.Fatalf("got %+v, want route %s row %s code %q", got, tc.route, tc.row, tc.code)
			}
			if got.Route != RouteSelf && got.Reason == "" {
				t.Fatalf("a %s answer carries no sentence", got.Route)
			}
		})
	}
}

// TestConsentRowsAllCovered: every row of the table has a case in
// TestConsentRoute above. The names are listed here once so a row added to the
// table without one fails.
func TestConsentRowsAllCovered(t *testing.T) {
	t.Parallel()
	want := []string{
		"C1 kind switch off", "C1 scoped approval off", "C2 nothing to lift", "C3 the org marked the rule overridable",
		"C4 untouched on an individual node", "C5 the organization decides", "C6 no organization to ask",
		"T1 kind switch off", "T1 already confined", "T1 above the configured maximum", "T1 host or none tier", "T1 no host list",
		"T2 individual node", "T3 managed node",
	}
	got := ConsentRowNames()
	if len(got) != len(want) {
		t.Fatalf("the consent table has %d rows, the test lists %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d is %q, the test expects %q", i, got[i], want[i])
		}
	}
}

// TestConsentNeverSelfOnManagedWithoutOverride: no input on a managed or
// unresolved node reaches the self route unless the rule is overridable (the
// managed lock is never weakened, invariant 5), for any lock and decision.
func TestConsentNeverSelfOnManagedWithoutOverride(t *testing.T) {
	t.Parallel()
	for _, ten := range []Tenancy{TenancyManaged, TenancyUnresolved} {
		for _, lock := range []Lock{LockUntouched, LockLocked} {
			for _, dec := range []string{"", "allow", "flag", "ask", "deny"} {
				for _, enrolled := range []bool{true, false} {
					for _, kind := range RelaxKinds() {
						for _, row := range RelaxationsFor(kind) {
							got := ConsentRoute(ConsentInput{
								Row: row, Policy: onPolicy(), Tenancy: ten, Enrolled: enrolled,
								Rule: RuleFacts{Lock: lock, Decision: dec}, Tier: TierFacts{Live: "internet", Hosts: []string{"a.example.com"}},
							})
							if got.Route == RouteSelf {
								t.Errorf("%s %s %s %s enrolled=%v: %+v", ten, lock, dec, row.Key, enrolled, got)
							}
						}
					}
				}
			}
		}
	}
}

// TestPlanRelaxations: a rule absent from the guard's answer reads as locked
// (fail-closed), and a kind with no rows has no plan rows.
func TestPlanRelaxations(t *testing.T) {
	t.Parallel()
	rows := PlanRelaxations(PentestLocal, PlanInput{Policy: onPolicy(), Tenancy: TenancyIndividual, Tier: TierFacts{Live: "proxy_only"}})
	if len(rows) != 2 {
		t.Fatalf("rows %+v", rows)
	}
	if r, _ := PlanRowFor(rows, RuleScanner); r.Route != RouteRefused || r.Code != CodeNeedsOrg {
		t.Fatalf("an unanswered rule did not fail closed: %+v", r)
	}
	if r, _ := PlanRowFor(rows, TierKey); r.Route != RouteNotNeeded {
		t.Fatalf("tier row: %+v", r)
	}
	if got := PlanRelaxations(ThreatModel, PlanInput{Policy: onPolicy()}); len(got) != 0 {
		t.Fatalf("threat_model must have no relaxation rows: %+v", got)
	}
}

// TestReportRoute: one case per row of the report table.
func TestReportRoute(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		in    ReportInput
		write bool
		row   string
	}{
		{"R1 managed always writes", ReportInput{Tenancy: TenancyManaged}, true, "R1"},
		{"R1 unresolved always writes", ReportInput{Tenancy: TenancyUnresolved, ReportToOrg: false}, true, "R1"},
		{"R2 individual who reports", ReportInput{Tenancy: TenancyIndividual, ReportToOrg: true}, true, "R2"},
		{"R3 individual who does not", ReportInput{Tenancy: TenancyIndividual}, false, "R3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			write, row := ReportRoute(tc.in)
			if write != tc.write || row != tc.row {
				t.Fatalf("got %v %s, want %v %s", write, row, tc.write, tc.row)
			}
		})
	}
}

// TestReportValidation: one row per combination of the run's reporting, the
// tenancy and the node's own switch.
func TestReportValidation(t *testing.T) {
	cases := []struct {
		name     string
		tenancy  Tenancy
		reported bool
		on       bool
		want     bool
	}{
		{"not reported at all", TenancyIndividual, false, true, false},
		{"individual, switch on", TenancyIndividual, true, true, true},
		{"individual, switch off", TenancyIndividual, true, false, false},
		{"managed always writes it", TenancyManaged, true, false, true},
		{"unresolved always writes it", TenancyUnresolved, true, false, true},
		{"managed but not reported", TenancyManaged, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReportValidation(tc.tenancy, tc.reported, tc.on); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

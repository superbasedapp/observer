package orgbudget

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// tokenBody builds a one-period org body carrying a token cap.
func tokenBody(period string, capTokens int64, enforcement string) orgcontract.BudgetPolicyBody {
	return orgcontract.BudgetPolicyBody{
		Version:       41,
		ResolvedScope: "team:eng",
		CapTokens:     capTokens,
		Period:        period,
		Timezone:      "UTC",
		Enforcement:   enforcement,
		Caps: []orgcontract.BudgetPolicyCap{{
			Period: period, Timezone: "UTC", CapTokens: capTokens,
			Enforcement: enforcement, ResolvedScope: "team:eng",
		}},
	}
}

// TestOrgBudgetLowersButNeverRaisesOnAnIndividualNode is the plan's §4 W3b
// first failing-first case: an individual node applies min(local, org) per
// unit, and 0 means "unset" in both directions.
func TestOrgBudgetLowersButNeverRaisesOnAnIndividualNode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		localMonth int64
		orgMonth   int64
		want       int64
	}{
		{"a looser org cap never raises the node's own", 5_000_000, 8_000_000, 5_000_000},
		{"a tighter org cap lowers the node's own", 5_000_000, 2_000_000, 2_000_000},
		{"an unset local window is turned ON by the org", 0, 2_000_000, 2_000_000},
		{"an unset org cap leaves the local one alone", 5_000_000, 0, 5_000_000},
		{"both unset stays unset", 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			local := Thresholds{MonthlyTokens: tc.localMonth}
			body := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, tc.orgMonth, orgcontract.BudgetPolicyEnforcementHard)
			got, posture := Compose(local, body, Capabilities{
				FromOrg: true, HaveBody: true,
				FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
			})
			if got.MonthlyTokens != tc.want {
				t.Errorf("monthly_tokens = %d, want %d", got.MonthlyTokens, tc.want)
			}
			if posture.Source != orgcontract.BudgetSourceOrgLowered {
				t.Errorf("source = %q, want %q", posture.Source, orgcontract.BudgetSourceOrgLowered)
			}
		})
	}
}

// TestManagedNodeWithEnforceBudgetIsOrgAuthoritative pins the capability that
// separates the two compositions: ONLY a managed node holding enforce.budget
// may have its cap RAISED by the org.
func TestManagedNodeWithEnforceBudgetIsOrgAuthoritative(t *testing.T) {
	t.Parallel()

	local := Thresholds{MonthlyTokens: 5_000_000, Hard: true}
	body := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 8_000_000, orgcontract.BudgetPolicyEnforcementSoft)

	withAuthority, pAuth := Compose(local, body, Capabilities{
		FromOrg: true, HaveBody: true, OrgAuthoritative: true,
		FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	})
	if withAuthority.MonthlyTokens != 8_000_000 {
		t.Errorf("with enforce.budget: monthly_tokens = %d, want the org's 8000000",
			withAuthority.MonthlyTokens)
	}
	if withAuthority.Hard {
		t.Error("with enforce.budget: hard stayed true, but the org authored soft — the org's enforcement mode is authoritative in BOTH directions on a managed node")
	}
	if pAuth.Source != orgcontract.BudgetSourceOrgAuthoritative {
		t.Errorf("source = %q, want %q", pAuth.Source, orgcontract.BudgetSourceOrgAuthoritative)
	}

	without, pWithout := Compose(local, body, Capabilities{
		FromOrg: true, HaveBody: true, OrgAuthoritative: false,
		FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	})
	if without.MonthlyTokens != 5_000_000 {
		t.Errorf("without the authority: monthly_tokens = %d, want the node's own 5000000 — a looser org cap must never raise it",
			without.MonthlyTokens)
	}
	if !without.Hard {
		t.Error("without the authority: hard was cleared by the org's soft mode — lowering-only means the developer's own hard flag survives")
	}
	if pWithout.Source != orgcontract.BudgetSourceOrgLowered {
		t.Errorf("source = %q, want %q", pWithout.Source, orgcontract.BudgetSourceOrgLowered)
	}
}

// TestUnreachableOrgKeepsLocalAndSaysSo is the fail-open requirement: an
// unreachable org changes NOTHING, and the posture reports the fact rather
// than leaving a reader to infer it.
func TestUnreachableOrgKeepsLocalAndSaysSo(t *testing.T) {
	t.Parallel()

	local := Thresholds{MonthlyTokens: 5_000_000, DailyUSD: 12, Hard: true}
	got, posture := Compose(local, orgcontract.BudgetPolicyBody{}, Capabilities{
		FromOrg: true, HaveBody: false,
		FetchState: orgcontract.BudgetFetchUnreachable, GuardMode: "enforce",
	})
	if !reflect.DeepEqual(got, local) {
		t.Errorf("thresholds = %+v, want the local ones unchanged %+v", got, local)
	}
	if posture.LastFetchOK {
		t.Error("last_fetch_ok = true after an unreachable org")
	}
	if posture.FromOrg != true {
		t.Error("from_org must still report the node's OPT-IN, not whether the fetch worked")
	}
	if posture.Source != orgcontract.BudgetSourceLocal {
		t.Errorf("source = %q, want %q", posture.Source, orgcontract.BudgetSourceLocal)
	}
	if posture.FetchState != orgcontract.BudgetFetchUnreachable {
		t.Errorf("fetch_state = %q, want %q", posture.FetchState, orgcontract.BudgetFetchUnreachable)
	}
	if !posture.Capped {
		t.Error("capped = false, but the node's own thresholds are set")
	}
}

// TestFromOrgOffIsByteIdenticalToTodaysBehaviour pins the default: with the
// opt-in off, a body in hand changes nothing at all.
func TestFromOrgOffIsByteIdenticalToTodaysBehaviour(t *testing.T) {
	t.Parallel()

	local := Thresholds{MonthlyTokens: 5_000_000}
	body := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 1, orgcontract.BudgetPolicyEnforcementHard)
	got, posture := Compose(local, body, Capabilities{
		FromOrg: false, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
	})
	if !reflect.DeepEqual(got, local) {
		t.Errorf("thresholds = %+v, want %+v — from_org=false must apply nothing", got, local)
	}
	if posture.Source != orgcontract.BudgetSourceLocal || posture.LastFetchOK {
		t.Errorf("posture = %+v, want local + last_fetch_ok=false", posture)
	}
}

// TestPeriodMapsToTheRightWindow walks the §3.3c period table, including the
// periods that map to NOTHING. rolling_30d must never silently become the
// monthly window.
func TestPeriodMapsToTheRightWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		period      string
		wantDaily   int64
		wantMonthly int64
	}{
		{orgcontract.BudgetPolicyPeriodCalendarDay, 900, 0},
		{orgcontract.BudgetPolicyPeriodCalendarMonth, 0, 900},
		{orgcontract.BudgetPolicyPeriodRolling30d, 0, 0},
		{"calendar_fortnight", 0, 0}, // a period this build does not know
	}
	for _, tc := range cases {
		t.Run(tc.period, func(t *testing.T) {
			t.Parallel()
			got, _ := Compose(Thresholds{}, tokenBody(tc.period, 900, orgcontract.BudgetPolicyEnforcementHard),
				Capabilities{FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK})
			if got.DailyTokens != tc.wantDaily {
				t.Errorf("daily_tokens = %d, want %d", got.DailyTokens, tc.wantDaily)
			}
			if got.MonthlyTokens != tc.wantMonthly {
				t.Errorf("monthly_tokens = %d, want %d", got.MonthlyTokens, tc.wantMonthly)
			}
			if got.SessionTokens != 0 || got.WeeklyTokens != 0 {
				t.Errorf("session/weekly = %d/%d, want 0/0 — the org vocabulary has no period meaning either window",
					got.SessionTokens, got.WeeklyTokens)
			}
		})
	}
}

// TestUnmappedPeriodsCarryTheirReason keeps the table honest: a period that
// maps to no window must be PRESENT with the reason, not absent.
func TestUnmappedPeriodsCarryTheirReason(t *testing.T) {
	t.Parallel()
	for _, r := range periodRules {
		if r.window == windowNone && r.reason == "" {
			t.Errorf("period %q maps to no window and carries no reason — an unmapped row must say why", r.period)
		}
		if r.window != windowNone && r.reason != "" {
			t.Errorf("period %q maps to %q yet carries an unmapped-reason", r.period, r.window)
		}
	}
}

// TestMultiPeriodBodyFillsEveryWindow is why the wire carries a caps LIST: an
// org that authored both a daily and a monthly cap must land both — each with
// ITS OWN enforcement.
//
// This test used to assert the fold (`got.Hard == true` and nothing else),
// i.e. that a `soft` daily cap DENIED on the node. Round 2's MEDIUM-3 is
// exactly that: the gateway warns on that cap (gwstore's capRow.soft()) and
// the node blocked, from one authored budget. The assertion below is the
// honest rule — the node-wide flag says "something denies", SoftWindows says
// which windows must not.
func TestMultiPeriodBodyFillsEveryWindow(t *testing.T) {
	t.Parallel()

	body := orgcontract.BudgetPolicyBody{
		Version: 7, Period: orgcontract.BudgetPolicyPeriodCalendarDay,
		CapTokens: 100_000, Enforcement: orgcontract.BudgetPolicyEnforcementSoft,
		Caps: []orgcontract.BudgetPolicyCap{
			{Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 100_000, Enforcement: orgcontract.BudgetPolicyEnforcementSoft},
			{Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: 2_000_000, Enforcement: orgcontract.BudgetPolicyEnforcementHard},
		},
	}
	got, posture := Compose(Thresholds{}, body, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	})
	if got.DailyTokens != 100_000 || got.MonthlyTokens != 2_000_000 {
		t.Errorf("daily/monthly = %d/%d, want 100000/2000000 — a single-period read would drop one",
			got.DailyTokens, got.MonthlyTokens)
	}
	if !got.Hard {
		t.Error("hard = false, but the MONTHLY cap is enforcement=hard — some window must deny")
	}
	// The daily cap is `soft`, so it must warn, not deny — and so must the two
	// windows the org authored nothing for (the node's own hard flag is off).
	if want := []string{"daily"}; !reflect.DeepEqual(got.SoftWindows, want) {
		t.Errorf("soft_windows = %v, want %v — a soft daily cap must warn on the node exactly "+
			"as it warns at the gateway; folding the strictest mode across periods denies it", got.SoftWindows, want)
	}
	if !posture.Hard || !posture.Capped {
		t.Errorf("posture = %+v, want hard + capped", posture)
	}
}

// TestSoftDailyAndHardMonthlyAgreeWithTheGatewayRule is MEDIUM-3's agreement
// test: for the SAME authored budget the node and the gateway must reach the
// same verdict per window.
//
// The gateway's rule is one line — internal/aigateway/gwstore's
// `capRow.soft()`, "a breach admits-and-warns iff enforcement == \"soft\"",
// applied per projected cap. gatewayDenies below is that rule, restated here
// (this package may not import aigateway); vocab agreement between the two
// enforcement alphabets is already pinned by budgetproject's vocab_test.
func TestSoftDailyAndHardMonthlyAgreeWithTheGatewayRule(t *testing.T) {
	t.Parallel()

	// The gateway denies a breach unless the cap's own enforcement is "soft"
	// (an unknown mode fails CLOSED there). `report` never projects at all, so
	// it reaches no gateway cap — the node's equivalent is "does not deny".
	gatewayDenies := func(enforcement string) bool {
		switch enforcement {
		case orgcontract.BudgetPolicyEnforcementSoft, "report":
			return false
		default:
			return true
		}
	}

	cases := []struct{ daily, monthly string }{
		{orgcontract.BudgetPolicyEnforcementSoft, orgcontract.BudgetPolicyEnforcementHard},
		{orgcontract.BudgetPolicyEnforcementHard, orgcontract.BudgetPolicyEnforcementSoft},
		{orgcontract.BudgetPolicyEnforcementHard, orgcontract.BudgetPolicyEnforcementHard},
		{"report", orgcontract.BudgetPolicyEnforcementHard},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.daily+"_daily/"+tc.monthly+"_monthly", func(t *testing.T) {
			t.Parallel()
			body := orgcontract.BudgetPolicyBody{
				Version: 9,
				Caps: []orgcontract.BudgetPolicyCap{
					{Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 1_000_000, Enforcement: tc.daily},
					{Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: 30_000_000, Enforcement: tc.monthly},
				},
			}
			// A MANAGED node, so the org's modes are authoritative in both
			// directions — the deployment the gateway also fronts.
			got, _ := Compose(Thresholds{}, body, Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true,
				FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
			})
			soft := map[string]bool{}
			for _, w := range got.SoftWindows {
				soft[w] = true
			}
			for window, enforcement := range map[string]string{"daily": tc.daily, "monthly": tc.monthly} {
				nodeDenies := got.Hard && !soft[window]
				if want := gatewayDenies(enforcement); nodeDenies != want {
					t.Errorf("%s cap (enforcement=%s): node denies = %v, gateway denies = %v — "+
						"one authored budget, two chokepoints, one answer", window, enforcement, nodeDenies, want)
				}
			}
		})
	}
}

// TestWindowCalendarsTravelWithTheAdoptedCap is MEDIUM-2's node half: an
// adopted org cap brings its own timezone onto the window it governs, and a
// cap that governs nothing brings none.
func TestWindowCalendarsTravelWithTheAdoptedCap(t *testing.T) {
	t.Parallel()

	const la = "America/Los_Angeles"
	tests := []struct {
		name             string
		local            Thresholds
		cap              orgcontract.BudgetPolicyCap
		authoritative    bool
		wantDailyZone    string
		wantDailyTokens  int64
		wantExplanation  string
		monthlyUntouched bool
	}{
		{
			name:  "an adopted daily cap brings its calendar",
			local: Thresholds{},
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 1_000_000, Timezone: la,
			},
			wantDailyZone: la, wantDailyTokens: 1_000_000,
			wantExplanation:  "the org turned the window on, so its calendar governs it",
			monthlyUntouched: true,
		},
		{
			name:  "a LOOSER org cap on an individual node adopts nothing, calendar included",
			local: Thresholds{DailyTokens: 100_000},
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 5_000_000, Timezone: la,
			},
			wantDailyZone: "", wantDailyTokens: 100_000,
			wantExplanation: "govern.LowerInt kept the developer's tighter ceiling; a cap that does " +
				"not govern must not move their day boundary either",
			monthlyUntouched: true,
		},
		{
			name:  "an authoritative org replaces the number AND the calendar",
			local: Thresholds{DailyTokens: 100_000},
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 5_000_000, Timezone: la,
			},
			authoritative: true,
			wantDailyZone: la, wantDailyTokens: 5_000_000,
			wantExplanation:  "managed + enforce.budget: the org's row is the row",
			monthlyUntouched: true,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := orgcontract.BudgetPolicyBody{Version: 4, Caps: []orgcontract.BudgetPolicyCap{tc.cap}}
			got, _ := Compose(tc.local, body, Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: tc.authoritative,
				FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
			})
			if got.DailyTokens != tc.wantDailyTokens {
				t.Errorf("daily tokens = %d, want %d", got.DailyTokens, tc.wantDailyTokens)
			}
			if got.DailyTimezone != tc.wantDailyZone {
				t.Errorf("daily timezone = %q, want %q — %s", got.DailyTimezone, tc.wantDailyZone, tc.wantExplanation)
			}
			if tc.monthlyUntouched && got.MonthlyTimezone != "" {
				t.Errorf("monthly timezone = %q, want empty — the org authored no monthly cap", got.MonthlyTimezone)
			}
		})
	}
}

// TestUSDCapsRideTheSameComposition pins that the second unit is not an
// afterthought: a USD org cap composes identically.
func TestUSDCapsRideTheSameComposition(t *testing.T) {
	t.Parallel()

	body := orgcontract.BudgetPolicyBody{
		Version: 3, Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapUSD: 40,
		Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		Caps: []orgcontract.BudgetPolicyCap{
			{Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapUSD: 40, Enforcement: orgcontract.BudgetPolicyEnforcementHard},
		},
	}
	got, _ := Compose(Thresholds{MonthlyUSD: 100}, body, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
	})
	if got.MonthlyUSD != 40 {
		t.Errorf("monthly_usd = %v, want 40", got.MonthlyUSD)
	}
}

// TestNegativeOrgCapIsUnsetNotATightCap: a negative number arriving from a
// remote body must never become "everything is over budget".
func TestNegativeOrgCapIsUnsetNotATightCap(t *testing.T) {
	t.Parallel()

	for _, authoritative := range []bool{false, true} {
		got, _ := Compose(Thresholds{MonthlyTokens: 5_000_000},
			tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, -1, orgcontract.BudgetPolicyEnforcementHard),
			Capabilities{FromOrg: true, HaveBody: true, OrgAuthoritative: authoritative, FetchState: orgcontract.BudgetFetchOK})
		if got.MonthlyTokens != 5_000_000 {
			t.Errorf("authoritative=%v: monthly_tokens = %d, want the local 5000000",
				authoritative, got.MonthlyTokens)
		}
	}
}

// TestAuthoritativeOrgNeverDeletesAnUnauthoredWindow: an org that wrote a
// monthly cap and no daily cap must not wipe the developer's daily ceiling.
func TestAuthoritativeOrgNeverDeletesAnUnauthoredWindow(t *testing.T) {
	t.Parallel()

	local := Thresholds{DailyTokens: 300_000, MonthlyTokens: 5_000_000}
	got, _ := Compose(local, tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 9_000_000, orgcontract.BudgetPolicyEnforcementHard),
		Capabilities{FromOrg: true, HaveBody: true, OrgAuthoritative: true, FetchState: orgcontract.BudgetFetchOK})
	if got.DailyTokens != 300_000 {
		t.Errorf("daily_tokens = %d, want the local 300000 — the org authored no daily cap, so replacing it with 0 would DELETE a ceiling",
			got.DailyTokens)
	}
	if got.MonthlyTokens != 9_000_000 {
		t.Errorf("monthly_tokens = %d, want the org's 9000000", got.MonthlyTokens)
	}
}

func TestManagedProtectionTracksOnlyAdoptedHardUnits(t *testing.T) {
	t.Parallel()
	local := Thresholds{SessionUSD: 0.10, DailyTokens: 50}
	body := orgcontract.BudgetPolicyBody{Version: 9, Caps: []orgcontract.BudgetPolicyCap{
		{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 0.35,
			Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		},
		{
			Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: 1_000,
			Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		},
	}}
	eff, _ := Compose(local, body, Capabilities{
		FromOrg: true, HaveBody: true, OrgAuthoritative: true,
		FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	})
	want := BudgetProtection{DailyUSD: true, MonthlyTokens: true}
	if eff.Protection != want {
		t.Fatalf("protection = %+v, want %+v", eff.Protection, want)
	}
	if eff.SessionUSD != local.SessionUSD || eff.DailyTokens != local.DailyTokens {
		t.Fatalf("preserved local ceilings changed: %+v", eff)
	}
}

func TestManagedProtectionDoesNotAuthorizeUnitSibling(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		local Thresholds
		cap   orgcontract.BudgetPolicyCap
		want  BudgetProtection
	}{
		{
			name:  "USD cap leaves local token sibling unprotected",
			local: Thresholds{DailyTokens: 50},
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 0.35,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			},
			want: BudgetProtection{DailyUSD: true},
		},
		{
			name:  "token cap leaves local USD sibling unprotected",
			local: Thresholds{DailyUSD: 0.20},
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 100,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			},
			want: BudgetProtection{DailyTokens: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eff, _ := Compose(tc.local, orgcontract.BudgetPolicyBody{
				Version: 10, Caps: []orgcontract.BudgetPolicyCap{tc.cap},
			}, Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true,
				FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
			})
			if eff.Protection != tc.want {
				t.Fatalf("protection = %+v, want %+v", eff.Protection, tc.want)
			}
		})
	}
}

func TestNonHardOrUnverifiedBudgetCarriesNoNumericProtection(t *testing.T) {
	t.Parallel()
	hard := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 1_000,
		orgcontract.BudgetPolicyEnforcementHard)
	soft := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 1_000,
		orgcontract.BudgetPolicyEnforcementSoft)
	none := orgcontract.EmptyBudgetPolicyBody(11)
	for _, tc := range []struct {
		name         string
		local        Thresholds
		body         orgcontract.BudgetPolicyBody
		caps         Capabilities
		wantRequired bool
	}{
		{
			name: "individual hard cap", body: hard,
			caps: Capabilities{FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "managed soft cap", body: soft,
			caps: Capabilities{FromOrg: true, HaveBody: true, OrgAuthoritative: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "managed zero cap",
			body: tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 0,
				orgcontract.BudgetPolicyEnforcementHard),
			caps: Capabilities{FromOrg: true, HaveBody: true, OrgAuthoritative: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "local only", local: Thresholds{
				MonthlyTokens: 500, Protection: BudgetProtection{MonthlyTokens: true},
			},
			caps: Capabilities{FromOrg: false, HaveBody: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "managed explicit none", body: none,
			caps: Capabilities{FromOrg: true, HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "managed missing body uses B-625", local: Thresholds{MonthlyTokens: 500},
			caps:         Capabilities{FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true, FetchState: orgcontract.BudgetFetchUnverified},
			wantRequired: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eff, _ := Compose(tc.local, tc.body, tc.caps)
			if eff.Protection.Any() {
				t.Fatalf("numeric protection = %+v, want none", eff.Protection)
			}
			if eff.BudgetRequired != tc.wantRequired {
				t.Fatalf("BudgetRequired = %v, want %v", eff.BudgetRequired, tc.wantRequired)
			}
		})
	}
}

// TestPostureRowIsEnumOnly asserts at THIS layer (the one that builds it) that
// the wire row carries no number and no scope label.
func TestPostureRowIsEnumOnly(t *testing.T) {
	t.Parallel()

	body := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 40_000_000, orgcontract.BudgetPolicyEnforcementHard)
	_, posture := Compose(Thresholds{}, body, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	})
	row := posture.Row()
	if row.EnforcementPoint != orgcontract.BudgetPointGuard {
		t.Errorf("enforcement_point = %q, want %q", row.EnforcementPoint, orgcontract.BudgetPointGuard)
	}
	if row.Coverage != orgcontract.BudgetCoverageProxyOnly {
		t.Errorf("coverage = %q, want %q — node budget enforcement is proxy-path only", row.Coverage, orgcontract.BudgetCoverageProxyOnly)
	}
	if !row.Capped {
		t.Error("capped = false after an org cap landed")
	}
	// The resolved scope names a TEAM. It must appear nowhere on the row.
	for _, s := range []string{row.EnforcementPoint, row.Mode, row.Source, row.FetchState, row.Coverage} {
		if s == body.ResolvedScope {
			t.Errorf("the posture row carries the resolved scope %q — that names a team", s)
		}
	}
	// Pricing arc §3.3: Compose composes CAPS. It must leave the two pricing
	// fields untouched, because the price table rides a different rail with a
	// different signature domain and a different failure ladder, and the ONE
	// place the two meet is the daemon boundary. A Compose that started
	// guessing a pricing source would be a second owner of that vocabulary.
	if row.PricingSource != "" || row.PricingVersion != 0 {
		t.Errorf("Compose set pricing_source=%q pricing_version=%d — it must set neither; "+
			"the boundary (cmd/observer/orgbudget_wire.go) owns those",
			row.PricingSource, row.PricingVersion)
	}
	// Row is the ONE mapping from posture to wire, so the pricing pair must
	// travel through it rather than being appended at the boundary.
	withPricing := posture
	withPricing.PricingSource = orgcontract.PricingSourceOrgAuthoritative
	withPricing.PricingVersion = 12
	pr := withPricing.Row()
	if pr.PricingSource != orgcontract.PricingSourceOrgAuthoritative || pr.PricingVersion != 12 {
		t.Errorf("Row() dropped the pricing pair: source=%q version=%d",
			pr.PricingSource, pr.PricingVersion)
	}
	// And the number that IS admitted must be the only one: nothing shaped
	// like a rate may reach the wire row through this layer.
	if pr.PricingVersion != 12 {
		t.Error("pricing_version did not survive Row()")
	}
}

// TestGuardModeNormalizes keeps the posture inside the closed mode enum.
func TestGuardModeNormalizes(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"enforce": "enforce", "observe": "observe", "advise": "observe",
		"off": "off", "": "off", "banana": "off",
	}
	for in, want := range cases {
		_, posture := Compose(Thresholds{}, orgcontract.BudgetPolicyBody{}, Capabilities{GuardMode: in})
		if posture.Mode != want {
			t.Errorf("mode(%q) = %q, want %q", in, posture.Mode, want)
		}
	}
}

// TestComposeFailClosedMatrix walks the FULL capability cross-product for
// ruling R2: individual vs managed, body vs no body, from_org on vs off,
// fetch ok vs failed. One row per state the boundary can actually hand in.
//
// The two properties it exists to pin, because both are invisible in any
// single case:
//
//   - a MANAGED node holding enforce.budget blocks when no verified body has
//     ever reached it, whatever the fetch failed with;
//   - an INDIVIDUAL node is byte-identical to the pre-R2 build in every one of
//     these states — the fail-closed path must be unreachable without the
//     grant.
func TestComposeFailClosedMatrix(t *testing.T) {
	t.Parallel()

	local := Thresholds{MonthlyTokens: 5_000_000}
	body := tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 2_000_000,
		orgcontract.BudgetPolicyEnforcementHard)

	// noneBody is the org's SIGNED EXPLICIT NONE: a verified document that
	// authors no cap at all (orgcontract.EmptyBudgetPolicyBody).
	noneBody := orgcontract.EmptyBudgetPolicyBody(41)

	cases := []struct {
		name string
		caps Capabilities
		// body overrides the capped body for the rows that need a different
		// document; nil means the capped one.
		body *orgcontract.BudgetPolicyBody
		// wantBlocked is the fail-closed outcome.
		wantBlocked  bool
		wantMonthly  int64
		wantSource   string
		wantCoverage string
		wantLastOK   bool
	}{
		{
			name:        "individual / no body / from_org on / unreachable -> local, fail OPEN",
			caps:        Capabilities{FromOrg: true, FetchState: orgcontract.BudgetFetchUnreachable},
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly,
		},
		{
			name:        "individual / no body / from_org off -> local, fail OPEN",
			caps:        Capabilities{FetchState: orgcontract.BudgetFetchDisabled},
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly,
		},
		{
			name:        "individual / body / from_org on / ok -> lowered",
			caps:        Capabilities{FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK},
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgLowered,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastOK: true,
		},
		{
			name:        "individual / body / from_org OFF -> the body is discarded",
			caps:        Capabilities{HaveBody: true, FetchState: orgcontract.BudgetFetchOK},
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly,
		},
		{
			name: "managed / no body / from_org on / unreachable -> BLOCKED",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchUnreachable,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			// The live 2026-09-13 estate shape: the body arrives and is
			// REFUSED because the signature does not verify. A managed node
			// must not quietly run its own numbers on that.
			name: "managed / no VERIFIED body / unverified -> BLOCKED, fetch_state preserved",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchUnverified,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			// The org answered 404: it has no budget for this member. Under
			// R2 that is still "no verified body", so it still blocks — the
			// 404 is unsigned and an org that requires budgets must publish
			// one. Documented in docs/budgets.md as the operational trap.
			name: "managed / no_budget (404) -> BLOCKED",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchNoBudget,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			name: "managed / no body / from_org OFF -> still BLOCKED (the node's opt-out is not the authority)",
			caps: Capabilities{
				OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchDisabled,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			name: "managed / body / ok -> authoritative, NOT blocked",
			caps: Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchOK,
			},
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgAuthoritative,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastOK: true,
		},
		{
			// THE OUTAGE CASE: orgclient keeps serving its cached verified
			// body across a failed poll, so the last verified numbers stay in
			// force and the posture says last_fetch_ok=false. It must NOT
			// block — a network blip is not a missing budget.
			name: "managed / CACHED verified body / unreachable -> last body stays in force",
			caps: Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchUnreachable,
			},
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgAuthoritative,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly,
		},
		{
			// THE SIGNED EXPLICIT NONE (org-observer fundamentals follow-up):
			// the org verifiably says it authored nothing for this caller. It
			// must NOT block - a managed fleet in an org that deliberately
			// authors no budgets would otherwise never make a request - and it
			// must not invent a ceiling either.
			name: "managed / signed explicit NONE -> no block, no ceiling invented",
			caps: Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchOK,
			},
			body:        &noneBody,
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceOrgAuthoritative,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastOK: true,
		},
		{
			name: "managed / body / from_org OFF -> applied anyway (the org is authoritative)",
			caps: Capabilities{
				HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchOK,
			},
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgAuthoritative,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastOK: true,
		},
		// ------------------------------------------------------------------
		// The remaining fetch states a MANAGED node can report with no body
		// (finding M6). Each is a different operator story and they all have
		// to land on the same verdict, because "why we could not get a body"
		// never changes "we do not have one".
		// ------------------------------------------------------------------
		{
			// The org has published no [policy].signing_key_path, so the rail
			// cannot serve anything this node could trust. The org-server
			// startup WARN names this one by configuration; here it is what
			// the node does about it.
			name: "managed / no body / channel_off -> BLOCKED",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchChannelOff,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			// An expired or revoked bearer. Tempting to fail open ("the org
			// threw us out"), and exactly wrong: a revoked node is the LAST
			// one that should get to run uncapped.
			name: "managed / no body / auth_failed -> BLOCKED",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchAuthFailed,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			// Unenrolled while still carrying a managed grant — the window
			// between `observer org leave` and the grant expiring. The grant
			// is what makes the node managed, and it has not lapsed.
			name: "managed / no body / not_enrolled -> BLOCKED",
			caps: Capabilities{
				FromOrg: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchNotEnrolled,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		// ------------------------------------------------------------------
		// REQUIRED WITHOUT AUTHORITATIVE (finding M6). The two flags are
		// resolved from the same grant today, so this pair should not occur —
		// which is exactly why it is pinned: if they ever diverge, the answer
		// must still be defined, and "required" must be the half that decides
		// whether to block.
		// ------------------------------------------------------------------
		{
			name: "required WITHOUT authoritative / no body -> still BLOCKED",
			caps: Capabilities{
				FromOrg: true, RequireOrgBudget: true, OrgAuthoritative: false,
				FetchState: orgcontract.BudgetFetchUnverified,
			},
			wantBlocked: true, wantMonthly: 5_000_000,
			wantSource:   orgcontract.BudgetSourceLocal,
			wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
		},
		{
			// With a body the block lifts, and the composition is LOWERING —
			// authority, not requirement, is what makes the org's numbers
			// override the node's.
			name: "required WITHOUT authoritative / body -> lowered, not blocked",
			caps: Capabilities{
				FromOrg: true, HaveBody: true, RequireOrgBudget: true, OrgAuthoritative: false,
				FetchState: orgcontract.BudgetFetchOK,
			},
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgLowered,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly, wantLastOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := body
			if tc.body != nil {
				in = *tc.body
			}
			eff, posture := Compose(local, in, tc.caps)
			if eff.BudgetRequired != tc.wantBlocked {
				t.Fatalf("BudgetRequired = %v, want %v", eff.BudgetRequired, tc.wantBlocked)
			}
			if eff.MonthlyTokens != tc.wantMonthly {
				t.Errorf("monthly tokens = %d, want %d", eff.MonthlyTokens, tc.wantMonthly)
			}
			if posture.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", posture.Source, tc.wantSource)
			}
			if posture.Coverage != tc.wantCoverage {
				t.Errorf("coverage = %q, want %q", posture.Coverage, tc.wantCoverage)
			}
			if posture.LastFetchOK != tc.wantLastOK {
				t.Errorf("last_fetch_ok = %v, want %v", posture.LastFetchOK, tc.wantLastOK)
			}
			if tc.wantBlocked {
				if !posture.Hard || !posture.Capped || !eff.Hard {
					t.Errorf("a blocking posture must report hard+capped; got %+v / eff.Hard=%v", posture, eff.Hard)
				}
				if posture.FetchState != tc.caps.FetchState {
					t.Errorf("fetch_state = %q, want the fetch's own %q — the diagnosis must survive the block",
						posture.FetchState, tc.caps.FetchState)
				}
			}
		})
	}
}

// TestPreCompositionRulesAreNamedAndOrdered pins the table itself: fail-closed
// is asked FIRST (its condition is a subset of the fail-open row's, so the
// reverse order would answer a managed node with the individual answer), and
// every row carries a name.
func TestPreCompositionRulesAreNamedAndOrdered(t *testing.T) {
	t.Parallel()
	want := []string{"org_budget_required", "local_unchanged"}
	if len(preCompositionRules) != len(want) {
		t.Fatalf("preCompositionRules has %d rows, want %d", len(preCompositionRules), len(want))
	}
	for i, name := range want {
		if preCompositionRules[i].name != name {
			t.Errorf("row %d = %q, want %q", i, preCompositionRules[i].name, name)
		}
	}
}

// TestSignedExplicitNoneNeverInventsACeiling walks the none body on a node
// with NO local ceiling of its own — the shape that would be catastrophic if
// an empty body were read as a cap of zero.
func TestSignedExplicitNoneNeverInventsACeiling(t *testing.T) {
	t.Parallel()

	none := orgcontract.EmptyBudgetPolicyBody(7)
	for _, tc := range []struct {
		name string
		caps Capabilities
	}{
		{
			name: "individual",
			caps: Capabilities{FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK},
		},
		{
			name: "managed and required",
			caps: Capabilities{
				FromOrg: true, HaveBody: true, OrgAuthoritative: true, RequireOrgBudget: true,
				FetchState: orgcontract.BudgetFetchOK,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eff, posture := Compose(Thresholds{}, none, tc.caps)
			if eff.BudgetRequired {
				t.Error("a signed explicit none blocked the node")
			}
			if capped(eff) || posture.Capped {
				t.Errorf("a signed explicit none produced a ceiling: %+v", eff)
			}
			if !posture.LastFetchOK {
				t.Error("last_fetch_ok = false on a VERIFIED none — the server said this, and the surface must know it")
			}
			if posture.Coverage != orgcontract.BudgetCoverageProxyOnly {
				t.Errorf("coverage = %q, want proxy_only", posture.Coverage)
			}
		})
	}
}

// TestBodyEmptyAgreesWithCapsOf pins the contract's Empty() against the rule
// this package actually applies. Two definitions of "authors nothing" that can
// disagree is how a none body ends up blocking a fleet.
func TestBodyEmptyAgreesWithCapsOf(t *testing.T) {
	t.Parallel()
	bodies := []orgcontract.BudgetPolicyBody{
		orgcontract.EmptyBudgetPolicyBody(3),
		{},
		tokenBody(orgcontract.BudgetPolicyPeriodCalendarMonth, 10, orgcontract.BudgetPolicyEnforcementHard),
		// A legacy single-period body with no Caps list.
		{Version: 2, Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapTokens: 5},
	}
	for _, b := range bodies {
		if got, want := b.Empty(), len(capsOf(b)) == 0; got != want {
			t.Errorf("Empty() = %v but capsOf finds %d caps for %+v", got, len(capsOf(b)), b)
		}
	}
}

// TestResolvedScopeNoneSeparatesTwoIdenticalShapes is finding M2's node-side
// pin. Both bodies below compose to Capped=false with a verified fetch, and
// the org dashboard tells the operator opposite things about them — so the bit
// that separates them has to be decided HERE, where the body is still in hand.
func TestResolvedScopeNoneSeparatesTwoIdenticalShapes(t *testing.T) {
	t.Parallel()

	caps := Capabilities{
		FromOrg: true, OrgAuthoritative: true, HaveBody: true,
		FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce",
	}
	cases := []struct {
		name string
		body orgcontract.BudgetPolicyBody
		want bool
	}{
		{
			name: "a signed body with no caps is the explicit none",
			body: orgcontract.EmptyBudgetPolicyBody(7),
			want: true,
		},
		{
			// A REAL cap the node rail cannot enforce: rolling_30d maps to no
			// node window, so it composes to Capped=false exactly like the
			// row above. Reporting it as an explicit none would tell the
			// admin their budget is deliberately absent.
			name: "a real rolling_30d cap maps to no node window but is NOT a none",
			body: orgcontract.BudgetPolicyBody{
				Version: 7, Period: "rolling_30d",
				Caps: []orgcontract.BudgetPolicyCap{{
					Period: "rolling_30d", CapUSD: 500,
					Enforcement: "hard", ResolvedScope: "member:u1",
				}},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff, posture := Compose(Thresholds{}, tc.body, caps)
			if posture.Capped {
				t.Fatalf("Capped = true; this case must compose to no ceiling (eff=%+v)", eff)
			}
			if posture.ResolvedScopeNone != tc.want {
				t.Fatalf("ResolvedScopeNone = %v, want %v", posture.ResolvedScopeNone, tc.want)
			}
			if got := posture.Row().ResolvedScopeNone; got != tc.want {
				t.Fatalf("Row().ResolvedScopeNone = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolvedScopeNoneIsNeverSetWithoutAVerifiedBody: the fail-closed and
// fail-open pre-composition rows return BEFORE the bit is decided, and they
// must never claim the org signed anything.
func TestResolvedScopeNoneIsNeverSetWithoutAVerifiedBody(t *testing.T) {
	t.Parallel()

	for _, caps := range []Capabilities{
		{FromOrg: true, RequireOrgBudget: true, HaveBody: false, FetchState: orgcontract.BudgetFetchUnverified, GuardMode: "enforce"},
		{FromOrg: false, HaveBody: false, FetchState: orgcontract.BudgetFetchDisabled, GuardMode: "enforce"},
		{FromOrg: false, HaveBody: true, FetchState: orgcontract.BudgetFetchOK, GuardMode: "enforce"},
	} {
		_, posture := Compose(Thresholds{}, orgcontract.BudgetPolicyBody{}, caps)
		if posture.ResolvedScopeNone {
			t.Errorf("caps %+v reported ResolvedScopeNone with no applied body", caps)
		}
	}
}

package orgbudget

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Bundle BUD-N composition tests. Two things are being pinned:
//
//  1. the four baseline outcomes, each against BOTH tenancies, because the
//     ruling is that a stale / absent / unverified baseline degrades to LOCAL
//     enforcement and NEVER to a refusal — on a managed node too; and
//  2. that a per-subject cap composes into its own table without touching the
//     node's four window ceilings.

const testNowRFC = "2026-09-15T12:00:00Z"

func testNow(t *testing.T) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, testNowRFC)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return at
}

// monthlyCapWithBaseline builds a whole-caller monthly cap carrying a
// cross-machine measurement.
func monthlyCapWithBaseline(spentUSD float64, asOf string, excludes bool) orgcontract.BudgetPolicyCap {
	return orgcontract.BudgetPolicyCap{
		Period:      orgcontract.BudgetPolicyPeriodCalendarMonth,
		CapUSD:      100,
		Enforcement: orgcontract.BudgetPolicyEnforcementHard,
		SpentUSD:    spentUSD, SpentAsOf: asOf, SpentExcludesMachine: excludes,
	}
}

func TestComposeBaseline_Table(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	fresh := now.Add(-3 * time.Minute).UTC().Format(time.RFC3339)
	old := now.Add(-40 * time.Minute).UTC().Format(time.RFC3339)

	cases := []struct {
		name          string
		cap           orgcontract.BudgetPolicyCap
		authoritative bool
		wantBaseline  float64
		wantState     string
	}{
		{
			name: "fresh machine-excluded baseline applies on an individual node",
			cap:  monthlyCapWithBaseline(60, fresh, true),
			// Lowering-only: the org's $100 cap is adopted because the node set
			// no monthly ceiling of its own, and its baseline rides with it.
			wantBaseline: 60, wantState: orgcontract.BudgetBaselineApplied,
		},
		{
			name: "fresh machine-excluded baseline applies on a managed node",
			cap:  monthlyCapWithBaseline(60, fresh, true), authoritative: true,
			wantBaseline: 60, wantState: orgcontract.BudgetBaselineApplied,
		},
		{
			name: "a measurement older than the window is refused, not fatal",
			cap:  monthlyCapWithBaseline(60, old, true), authoritative: true,
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineStale,
		},
		{
			name: "an undated measurement is stale",
			cap:  monthlyCapWithBaseline(60, "", true),
			// No date, no proof of currency. Same outcome as an old one, and
			// deliberately NOT the "empty means a pre-field server" rule the
			// DOCUMENT's issued_at uses — a pre-field server sends no spend at
			// all and lands on `absent`.
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineStale,
		},
		{
			name:         "an unparsable measurement time is stale",
			cap:          monthlyCapWithBaseline(60, "yesterday", true),
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineStale,
		},
		{
			name: "a baseline the server could not machine-exclude is refused",
			cap:  monthlyCapWithBaseline(60, fresh, false), authoritative: true,
			// It would double-count this node's own rows. Refusing it is the
			// difference between enforcing a fleet cap and enforcing an
			// arbitrary inflation of it.
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineUnverified,
		},
		{
			name: "a cap with no measurement reports absent",
			cap: orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapUSD: 100,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			},
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineAbsent,
		},
		{
			name: "a negative measurement never becomes a credit",
			cap:  monthlyCapWithBaseline(-40, fresh, true),
			// It falls on the `absent` row (no positive numbers), and even if
			// it did not, baselineAmounts floors it: a baseline that LOWERED
			// effective spend would let a bad number raise a ceiling.
			wantBaseline: 0, wantState: orgcontract.BudgetBaselineAbsent,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eff, posture := Compose(
				Thresholds{},
				orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{tc.cap}},
				Capabilities{
					FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
					GuardMode: "enforce", OrgAuthoritative: tc.authoritative,
					RequireOrgBudget: tc.authoritative,
					Now:              now, BaselineMaxAge: BaselineMaxAge(120 * time.Second),
				})
			if eff.Baseline.MonthlyUSD != tc.wantBaseline {
				t.Errorf("Baseline.MonthlyUSD = %v, want %v", eff.Baseline.MonthlyUSD, tc.wantBaseline)
			}
			if posture.OrgBaseline != tc.wantState {
				t.Errorf("posture.OrgBaseline = %q, want %q", posture.OrgBaseline, tc.wantState)
			}
			// THE RULING, asserted on every row: a refused baseline never
			// refuses the run. The cap itself is still in force.
			if eff.MonthlyUSD != 100 {
				t.Errorf("MonthlyUSD = %v, want the org cap 100 in force regardless of the baseline", eff.MonthlyUSD)
			}
			if eff.BudgetRequired {
				t.Errorf("BudgetRequired = true — a baseline problem must never fail closed")
			}
		})
	}
}

// TestComposeBaseline_TravelsOnlyWithAnAdoptedCap pins that a baseline follows
// the same rule the timezone and the enforcement mode do. An org cap that LOST
// to a tighter local ceiling governs nothing, and adding its fleet-wide spend
// to the developer's own ceiling would tighten a number the org never reached.
func TestComposeBaseline_TravelsOnlyWithAnAdoptedCap(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	fresh := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	eff, posture := Compose(
		Thresholds{MonthlyUSD: 10}, // the developer's own, TIGHTER ceiling
		orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{
			monthlyCapWithBaseline(60, fresh, true),
		}},
		Capabilities{
			FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
			GuardMode: "enforce", Now: now,
		})
	if eff.MonthlyUSD != 10 {
		t.Fatalf("MonthlyUSD = %v, want the tighter local 10", eff.MonthlyUSD)
	}
	if eff.Baseline.MonthlyUSD != 0 {
		t.Errorf("Baseline.MonthlyUSD = %v, want 0 — the org cap was not adopted", eff.Baseline.MonthlyUSD)
	}
	if posture.OrgBaseline != orgcontract.BudgetBaselineAbsent {
		t.Errorf("posture.OrgBaseline = %q, want absent (no cap of the org's governs)", posture.OrgBaseline)
	}
}

// TestComposeBaseline_WorstStateIsReported: a body whose caps disagree reports
// the WORSE outcome, because "one of your caps is measured on this machine
// only" is the fact an admin needs to see.
func TestComposeBaseline_WorstStateIsReported(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	fresh := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	stale := now.Add(-time.Hour).UTC().Format(time.RFC3339)
	body := orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{
		monthlyCapWithBaseline(60, fresh, true),
		{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 20,
			SpentUSD: 5, SpentAsOf: stale, SpentExcludesMachine: true,
		},
	}}
	eff, posture := Compose(Thresholds{}, body, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
		GuardMode: "enforce", Now: now,
	})
	if posture.OrgBaseline != orgcontract.BudgetBaselineStale {
		t.Errorf("posture.OrgBaseline = %q, want stale (the worse of the two)", posture.OrgBaseline)
	}
	// The FRESH one is still applied: reporting the worst state does not
	// discard a good measurement.
	if eff.Baseline.MonthlyUSD != 60 {
		t.Errorf("Baseline.MonthlyUSD = %v, want the fresh 60 still applied", eff.Baseline.MonthlyUSD)
	}
	if eff.Baseline.DailyUSD != 0 {
		t.Errorf("Baseline.DailyUSD = %v, want 0 (stale)", eff.Baseline.DailyUSD)
	}
}

// TestComposeBaseline_UnattributedIsReportedButApplied pins the deliberate
// choice: a baseline that counted rows the server could not attribute to a
// machine is still APPLIED — but FLAG-ONLY (adversarial review of BUD-N, P1-2).
// The amounts travel, the old bool still reports the caveat, and the enum says
// out loud that this number may warn and may not deny.
func TestComposeBaseline_UnattributedIsReportedButApplied(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	cap := monthlyCapWithBaseline(60, now.Add(-time.Minute).UTC().Format(time.RFC3339), true)
	cap.SpentIncludesUnattributed = true
	eff, posture := Compose(Thresholds{}, orgcontract.BudgetPolicyBody{
		Version: 1, Caps: []orgcontract.BudgetPolicyCap{cap},
	}, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
		GuardMode: "enforce", Now: now,
	})
	if eff.Baseline.MonthlyUSD != 60 {
		t.Errorf("Baseline.MonthlyUSD = %v, want 60", eff.Baseline.MonthlyUSD)
	}
	if !posture.OrgBaselineUnattributed {
		t.Errorf("posture.OrgBaselineUnattributed = false, want true")
	}
	if !eff.Baseline.FlagOnly {
		t.Errorf("Baseline.FlagOnly = false, want true — an unattributed baseline must not be able to deny")
	}
	if posture.Row().OrgBaselineUnattributed != true ||
		posture.Row().OrgBaseline != orgcontract.BudgetBaselineAppliedFlagOnly {
		t.Errorf("Row() did not carry the baseline posture: %+v", posture.Row())
	}
}

// TestComposeSubjectCaps pins the subject table: what composes, what is
// ignored, and that none of it touches the node's own window ceilings.
func TestComposeSubjectCaps(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	fresh := now.Add(-time.Minute).UTC().Format(time.RFC3339)

	body := orgcontract.BudgetPolicyBody{Version: 4, Caps: []orgcontract.BudgetPolicyCap{
		{ // a tool cap in dollars, hard, with a baseline
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 3,
			Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			Subject:     &orgcontract.BudgetSubject{Kind: "Tool", ID: " Claude-Code "},
			SpentUSD:    1.25, SpentAsOf: fresh, SpentExcludesMachine: true,
		},
		{ // a model cap in tokens, soft
			Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapTokens: 1_000_000,
			Enforcement: orgcontract.BudgetPolicyEnforcementSoft,
			Subject:     &orgcontract.BudgetSubject{Kind: "model", ID: "GPT-5"},
		},
		{ // an unknown subject kind is ignored, never widened
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 1,
			Subject: &orgcontract.BudgetSubject{Kind: "project", ID: "acme"},
		},
		{ // a period the node has no window for governs nothing
			Period: orgcontract.BudgetPolicyPeriodRolling30d, CapUSD: 1,
			Subject: &orgcontract.BudgetSubject{Kind: "tool", ID: "codex"},
		},
		{ // a subject cap with no ceiling in either unit is inert
			Period:  orgcontract.BudgetPolicyPeriodCalendarDay,
			Subject: &orgcontract.BudgetSubject{Kind: "tool", ID: "cline"},
		},
	}}

	eff, posture := Compose(Thresholds{DailyUSD: 50}, body, Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
		GuardMode: "enforce", OrgAuthoritative: true, RequireOrgBudget: true, Now: now,
	})

	if len(eff.Subjects) != 2 {
		t.Fatalf("Subjects = %+v, want exactly the two recognised caps", eff.Subjects)
	}
	tool := eff.Subjects[0]
	if tool.Kind != orgcontract.BudgetSubjectTool || tool.ID != "claude-code" ||
		tool.Window != "daily" || tool.CapUSD != 3 || !tool.Hard || tool.BaselineUSD != 1.25 {
		t.Errorf("tool cap = %+v", tool)
	}
	model := eff.Subjects[1]
	if model.Kind != orgcontract.BudgetSubjectModel || model.ID != "gpt-5" ||
		model.Window != "monthly" || model.CapTokens != 1_000_000 || model.Hard {
		t.Errorf("model cap = %+v", model)
	}
	// The node's OWN ceilings are untouched: a per-tool cap is not a daily cap.
	if eff.DailyUSD != 50 {
		t.Errorf("DailyUSD = %v, want the node's own 50 — a subject cap must not move a window ceiling", eff.DailyUSD)
	}
	// An org-authoritative HARD tool cap grants that row's provenance; the soft
	// model cap grants none.
	if !eff.Protection.ToolUSD || eff.Protection.ToolTokens || eff.Protection.ModelUSD || eff.Protection.ModelTokens {
		t.Errorf("Protection = %+v, want ToolUSD only", eff.Protection)
	}
	if posture.OrgBaseline != orgcontract.BudgetBaselineAbsent && posture.OrgBaseline != orgcontract.BudgetBaselineApplied {
		t.Errorf("posture.OrgBaseline = %q, want a classified state", posture.OrgBaseline)
	}
}

// TestComposeSubjectCaps_NotAdoptedWithoutABody pins that the two early-return
// paths carry neither a subject cap nor a baseline: a fail-open node and a
// fail-closed managed node both have nothing composed.
func TestComposeSubjectCaps_NotAdoptedWithoutABody(t *testing.T) {
	t.Parallel()
	body := orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{{
		Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 3,
		Subject: &orgcontract.BudgetSubject{Kind: "tool", ID: "claude-code"},
	}}}
	for _, tc := range []struct {
		name string
		caps Capabilities
		want bool // BudgetRequired
	}{
		{name: "fail open: no verified body", caps: Capabilities{FromOrg: true, HaveBody: false}},
		{name: "opted out", caps: Capabilities{FromOrg: false, HaveBody: true}},
		{
			name: "fail closed: managed with no body",
			caps: Capabilities{FromOrg: true, HaveBody: false, RequireOrgBudget: true, OrgAuthoritative: true},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eff, posture := Compose(Thresholds{}, body, tc.caps)
			if len(eff.Subjects) != 0 || eff.Baseline.Any() {
				t.Errorf("composed subjects/baseline without applying a body: %+v / %+v", eff.Subjects, eff.Baseline)
			}
			if posture.OrgBaseline != orgcontract.BudgetBaselineAbsent {
				t.Errorf("posture.OrgBaseline = %q, want absent", posture.OrgBaseline)
			}
			if eff.BudgetRequired != tc.want {
				t.Errorf("BudgetRequired = %v, want %v", eff.BudgetRequired, tc.want)
			}
		})
	}
}

// TestBaselineMaxAge pins the window's derivation from the node's own cadence.
// A 15-minute estate (the live one, SF-19) must not reject every measurement,
// which a fixed window would.
func TestBaselineMaxAge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		interval time.Duration
		want     time.Duration
	}{
		{interval: 0, want: 2*DefaultPushInterval + time.Minute},
		{interval: -time.Second, want: 2*DefaultPushInterval + time.Minute},
		{interval: 120 * time.Second, want: 5 * time.Minute},
		{interval: 15 * time.Minute, want: 31 * time.Minute},
	}
	for _, tc := range cases {
		if got := BaselineMaxAge(tc.interval); got != tc.want {
			t.Errorf("BaselineMaxAge(%s) = %s, want %s", tc.interval, got, tc.want)
		}
	}
}

// TestSubjectCapHardnessIsTheOrgsAlone is the P1-1 table: a lowering-only node
// running [guard.budget].hard = true must NOT turn an org cap the admin wrote
// as `soft` into a deny. Subject hardness is the organization's, per cap — the
// same rule internal/policy exempts B-626..B-629 from the blanket hard upgrade.
func TestSubjectCapHardnessIsTheOrgsAlone(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	cases := []struct {
		name          string
		localHard     bool
		enforcement   string
		authoritative bool
		wantHard      bool
	}{
		{
			name:      "local hard + org soft on a lowering-only node stays a nudge",
			localHard: true, enforcement: orgcontract.BudgetPolicyEnforcementSoft,
		},
		{
			name:      "local hard + org hard denies",
			localHard: true, enforcement: orgcontract.BudgetPolicyEnforcementHard, wantHard: true,
		},
		{
			name:        "local soft + org hard denies",
			enforcement: orgcontract.BudgetPolicyEnforcementHard, wantHard: true,
		},
		{
			name:      "local hard + org report stays a nudge",
			localHard: true, enforcement: orgcontract.BudgetPolicyEnforcementReport,
		},
		{
			name:      "authoritative org soft stays a nudge even with local hard",
			localHard: true, enforcement: orgcontract.BudgetPolicyEnforcementSoft, authoritative: true,
		},
		{
			name:        "authoritative org hard denies",
			enforcement: orgcontract.BudgetPolicyEnforcementHard, authoritative: true, wantHard: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{{
				Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 5,
				Enforcement: tc.enforcement,
				Subject:     &orgcontract.BudgetSubject{Kind: "tool", ID: "codex"},
			}}}
			eff, _ := Compose(Thresholds{Hard: tc.localHard}, body, Capabilities{
				FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
				GuardMode: "enforce", OrgAuthoritative: tc.authoritative, Now: now,
			})
			if len(eff.Subjects) != 1 {
				t.Fatalf("Subjects = %+v, want one", eff.Subjects)
			}
			if eff.Subjects[0].Hard != tc.wantHard {
				t.Errorf("SubjectCap.Hard = %v, want %v", eff.Subjects[0].Hard, tc.wantHard)
			}
		})
	}
}

// TestComposeBaseline_FlagOnlyTable is the P1-2 table: an applied baseline that
// counted unattributed rows is FLAG-ONLY on both the node-wide windows and the
// per-subject caps, and every other outcome is unchanged.
func TestComposeBaseline_FlagOnlyTable(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	fresh := now.Add(-time.Minute).UTC().Format(time.RFC3339)
	staleAt := now.Add(-40 * time.Minute).UTC().Format(time.RFC3339)

	cases := []struct {
		name            string
		asOf            string
		excludes        bool
		unattributed    bool
		wantState       string
		wantAmount      float64
		wantFlagOnly    bool
		wantSubjFlagged bool
	}{
		{
			name: "attributed baseline applies in full", asOf: fresh, excludes: true,
			wantState: orgcontract.BudgetBaselineApplied, wantAmount: 60,
		},
		{
			name: "unattributed baseline applies flag-only", asOf: fresh, excludes: true, unattributed: true,
			wantState: orgcontract.BudgetBaselineAppliedFlagOnly, wantAmount: 60,
			wantFlagOnly: true, wantSubjFlagged: true,
		},
		{
			name: "stale beats unattributed", asOf: staleAt, excludes: true, unattributed: true,
			wantState: orgcontract.BudgetBaselineStale,
		},
		{
			name: "unverified beats unattributed", asOf: fresh, unattributed: true,
			wantState: orgcontract.BudgetBaselineUnverified,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			window := monthlyCapWithBaseline(60, tc.asOf, tc.excludes)
			window.SpentIncludesUnattributed = tc.unattributed
			subject := orgcontract.BudgetPolicyCap{
				Period: orgcontract.BudgetPolicyPeriodCalendarMonth, CapUSD: 9,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
				Subject:     &orgcontract.BudgetSubject{Kind: "tool", ID: "codex"},
				SpentUSD:    3, SpentAsOf: tc.asOf, SpentExcludesMachine: tc.excludes,
				SpentIncludesUnattributed: tc.unattributed,
			}
			eff, posture := Compose(Thresholds{}, orgcontract.BudgetPolicyBody{
				Version: 1, Caps: []orgcontract.BudgetPolicyCap{window, subject},
			}, Capabilities{
				FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
				GuardMode: "enforce", Now: now,
			})
			if posture.OrgBaseline != tc.wantState {
				t.Errorf("OrgBaseline = %q, want %q", posture.OrgBaseline, tc.wantState)
			}
			if eff.Baseline.MonthlyUSD != tc.wantAmount {
				t.Errorf("Baseline.MonthlyUSD = %v, want %v", eff.Baseline.MonthlyUSD, tc.wantAmount)
			}
			if eff.Baseline.FlagOnly != tc.wantFlagOnly {
				t.Errorf("Baseline.FlagOnly = %v, want %v", eff.Baseline.FlagOnly, tc.wantFlagOnly)
			}
			if len(eff.Subjects) != 1 {
				t.Fatalf("Subjects = %+v, want one", eff.Subjects)
			}
			if eff.Subjects[0].BaselineFlagOnly != tc.wantSubjFlagged {
				t.Errorf("SubjectCap.BaselineFlagOnly = %v, want %v",
					eff.Subjects[0].BaselineFlagOnly, tc.wantSubjFlagged)
			}
		})
	}
}

// TestComposeSubjectCap_ResolvesIdentity is the P1-3 alias pair: the org typed
// the family id and the node captured the dated one, so the cap is composed
// onto the identity the resolver folds BOTH onto. Without it the two never
// compare equal and an authored cap governs nothing.
func TestComposeSubjectCap_ResolvesIdentity(t *testing.T) {
	t.Parallel()
	now := testNow(t)
	// The stand-in for the price table's ladder: a dated id resolves to its
	// family, and a tool id is left alone.
	resolve := func(kind, id string) string {
		if kind == orgcontract.BudgetSubjectModel && len(id) > len("claude-sonnet-5") &&
			id[:len("claude-sonnet-5")] == "claude-sonnet-5" {
			return "claude-sonnet-5"
		}
		return id
	}
	body := orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{
		{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 5,
			Subject: &orgcontract.BudgetSubject{Kind: "model", ID: "Claude-Sonnet-5-20260501"},
		},
		{
			Period: orgcontract.BudgetPolicyPeriodCalendarDay, CapUSD: 5,
			Subject: &orgcontract.BudgetSubject{Kind: "tool", ID: "Codex"},
		},
	}}
	caps := Capabilities{
		FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
		GuardMode: "enforce", Now: now,
	}

	// Without a resolver the dated id stays itself — the pre-fix behaviour, kept
	// as the honest fallback for a node with no price table.
	plain, _ := Compose(Thresholds{}, body, caps)
	if plain.Subjects[0].ID != "claude-sonnet-5-20260501" {
		t.Errorf("unresolved model id = %q, want the contract's own normalisation", plain.Subjects[0].ID)
	}

	caps.ResolveSubjectID = resolve
	eff, _ := Compose(Thresholds{}, body, caps)
	if eff.Subjects[0].ID != "claude-sonnet-5" {
		t.Errorf("resolved model id = %q, want claude-sonnet-5", eff.Subjects[0].ID)
	}
	if eff.Subjects[1].ID != "codex" {
		t.Errorf("tool id = %q, want codex — a tool has no alias ladder", eff.Subjects[1].ID)
	}

	// A resolver that answers "" is IGNORED: an emptied id would widen a cap
	// that named one thing into a cap that matches nothing.
	caps.ResolveSubjectID = func(string, string) string { return "" }
	blank, _ := Compose(Thresholds{}, body, caps)
	if blank.Subjects[0].ID != "claude-sonnet-5-20260501" {
		t.Errorf("empty resolver answer was adopted: %q", blank.Subjects[0].ID)
	}
}

// TestComposeBaseline_IdleOtherMachineStaysAppliedWhileReMeasured is the
// regression for the ETag P1, walked at the layer where the damage showed.
//
// THE SCENARIO. A developer runs a laptop and a devbox on one org cap. The
// devbox spends $12.34 and goes idle. The laptop polls every 120 s; the server
// re-measures the same $12.34 every time and re-stamps the measurement. Six
// polls later — well past BaselineMaxAge (2x120s + 60s = 5 min) — the cap must
// STILL be `applied`, because the number is still being confirmed.
//
// THE BUG IT PINS. While orgcontract.BudgetPolicyDigest blanked SpentAsOf, that
// re-measurement never reached the node: identical amounts digested identically,
// the server answered 304, the node kept poll #1's stamp, and at T0+5min this
// cap flipped to `stale`. A stale baseline composes to ZERO, so the node went on
// enforcing the org's $100 cap against its own local spend alone and silently
// allowed $12.34 more than the org can see. The second half of this test is that
// FROZEN stamp, kept as the failing shape so the two are readable side by side.
func TestComposeBaseline_IdleOtherMachineStaysAppliedWhileReMeasured(t *testing.T) {
	t.Parallel()
	const (
		pushInterval = 120 * time.Second
		idleSpend    = 12.34
	)
	start := testNow(t)
	maxAge := BaselineMaxAge(pushInterval)

	classify := func(t *testing.T, asOf string, now time.Time) (float64, string) {
		t.Helper()
		eff, posture := Compose(
			Thresholds{},
			orgcontract.BudgetPolicyBody{Version: 1, Caps: []orgcontract.BudgetPolicyCap{
				monthlyCapWithBaseline(idleSpend, asOf, true),
			}},
			Capabilities{
				FromOrg: true, HaveBody: true, FetchState: orgcontract.BudgetFetchOK,
				GuardMode: "enforce",
				Now:       now, BaselineMaxAge: maxAge,
			})
		return eff.Baseline.MonthlyUSD, posture.OrgBaseline
	}

	t.Run("a re-measured baseline stays applied indefinitely", func(t *testing.T) {
		t.Parallel()
		const polls = 6
		if span := polls * pushInterval; span <= maxAge {
			t.Fatalf("the scenario spans only %v; it must run PAST BaselineMaxAge (%v) to mean anything", span, maxAge)
		}
		for poll := 0; poll <= polls; poll++ {
			now := start.Add(time.Duration(poll) * pushInterval)
			// What the server sends on THIS poll: the same amount, measured now
			// and truncated to the minute exactly as attachBudgetBaselines does.
			asOf := now.UTC().Truncate(time.Minute).Format(time.RFC3339)
			baseline, state := classify(t, asOf, now)
			if state != orgcontract.BudgetBaselineApplied {
				t.Fatalf("poll %d (t+%v): OrgBaseline = %q, want applied — a re-confirmed measurement must not age out",
					poll, now.Sub(start), state)
			}
			if baseline != idleSpend {
				t.Fatalf("poll %d: baseline = %v, want the other machine's %v still composing", poll, baseline, idleSpend)
			}
		}
	})

	t.Run("a frozen stamp is what under-counted", func(t *testing.T) {
		t.Parallel()
		frozen := start.UTC().Truncate(time.Minute).Format(time.RFC3339)
		// Inside the window it is still applied...
		if _, state := classify(t, frozen, start.Add(pushInterval)); state != orgcontract.BudgetBaselineApplied {
			t.Fatalf("at t+%v the frozen stamp is still inside the window; state = %q", pushInterval, state)
		}
		// ...and past it the org's $12.34 silently stops counting.
		baseline, state := classify(t, frozen, start.Add(maxAge).Add(time.Second))
		if state != orgcontract.BudgetBaselineStale {
			t.Fatalf("OrgBaseline = %q, want stale past BaselineMaxAge", state)
		}
		if baseline != 0 {
			t.Fatalf("baseline = %v, want 0 — a stale measurement composes to zero", baseline)
		}
	})
}

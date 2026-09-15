package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// budgetOutcome builds a verified-body fetch outcome carrying one monthly
// token cap.
func budgetOutcome(capTokens int64, enforcement string) orgclient.BudgetFetchOutcome {
	return orgclient.BudgetFetchOutcome{
		State:    orgcontract.BudgetFetchOK,
		HaveBody: true,
		Body: orgcontract.BudgetPolicyBody{
			Version: 41, ResolvedScope: "team:eng", CapTokens: capTokens,
			Period: orgcontract.BudgetPolicyPeriodCalendarMonth, Enforcement: enforcement,
			Caps: []orgcontract.BudgetPolicyCap{{
				Period:    orgcontract.BudgetPolicyPeriodCalendarMonth,
				CapTokens: capTokens, Enforcement: enforcement, ResolvedScope: "team:eng",
			}},
		},
	}
}

// localBudget is a node [guard.budget] block with a monthly token ceiling and
// the from_org opt-in as given.
func localBudget(monthlyTokens int64, fromOrg bool) config.GuardBudgetConfig {
	return config.GuardBudgetConfig{
		MonthlyTokens: monthlyTokens,
		FromOrg:       fromOrg,
		Window:        config.GuardBudgetWindowConfig{Util5hWarn: 0.8, Util5hDeny: 0.95},
	}
}

func TestOrgBudgetWireRefusesStaleEnrollmentOutcome(t *testing.T) {
	t.Parallel()
	_, dbPath := writeManagedBudgetLaunchFixture(t, false, "enforce")
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(context.Background(), st)
	if err != nil || !active {
		t.Fatalf("current budget identity: active=%v err=%v", active, err)
	}
	cfg := config.Default().Guard
	cfg.Enabled, cfg.Mode = true, "enforce"
	gd, err := guard.New(guard.Options{Config: cfg, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	monthlyTokens := int64(100)
	gd.SetBudgetLookup(func(string) (guard.BudgetSnapshot, bool) {
		return guard.BudgetSnapshot{MonthlyTokens: monthlyTokens}, true
	})
	h := newOrgBudgetHandle(gd, config.GuardBudgetConfig{FromOrg: true},
		func() bool { return true }, st, slog.Default())

	stale := budgetOutcome(100, orgcontract.BudgetPolicyEnforcementHard)
	stale.Binding = "replaced-enrollment"
	h.apply(stale)
	if got := gd.EffectiveBudget(); got.MonthlyTokens != 0 {
		t.Fatalf("stale numeric cap reached proxy engine: %+v", got)
	}
	in := guard.InterventionBudgetInput{
		SourceReady: true, BudgetBinding: identity.Binding,
		Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}
	if got := gd.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-625" {
		t.Fatalf("stale outcome did not fail closed for current member: %+v", got)
	}

	current := budgetOutcome(100, orgcontract.BudgetPolicyEnforcementHard)
	current.Binding = identity.Binding
	h.apply(current)
	if got := gd.EffectiveBudget(); got.MonthlyTokens != 100 {
		t.Fatalf("current numeric cap was not applied: %+v", got)
	}
	if got := gd.CheckInterventionBudget(in); !got.Deny || got.RuleID != "B-623" {
		t.Fatalf("current cap decision = %+v, want B-623", got)
	}

	monthlyTokens = 99
	rewriteBudgetLaunchEnrolment(t, dbPath, func(enr *store.Enrolment) {
		enr.UserID = "replacement-member"
		enr.EnrolledAt = "2026-09-14T02:00:00Z"
	})
	proxyDecision := gd.ScanProxyRequest("openai", []byte(`{"model":"test"}`), "", in.Now)
	if !proxyDecision.Deny || proxyDecision.DenyRuleID != "B-625" {
		t.Fatalf("external re-enrollment left old proxy cap active: %+v", proxyDecision)
	}
}

// TestOrgBudgetWireBranchesOnCapabilityNotSource walks the three-way §3.3c
// rule THROUGH the boundary, so a regression in the capability resolution (not
// just in the pure composer) is caught here.
func TestOrgBudgetWireBranchesOnCapabilityNotSource(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		local         config.GuardBudgetConfig
		authoritative bool
		outcome       orgclient.BudgetFetchOutcome
		wantMonthly   int64
		wantSource    string
		wantFetch     string
		wantLastOK    bool
	}{
		{
			name:    "from_org off applies nothing",
			local:   localBudget(5_000_000, false),
			outcome: budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard),
			// The org cap is IGNORED, and the posture says the node never opted in.
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceLocal,
			wantFetch: orgcontract.BudgetFetchOK,
		},
		{
			name:        "individual node lowers",
			local:       localBudget(5_000_000, true),
			outcome:     budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard),
			wantMonthly: 2_000_000, wantSource: orgcontract.BudgetSourceOrgLowered,
			wantFetch: orgcontract.BudgetFetchOK, wantLastOK: true,
		},
		{
			name:        "individual node never raises",
			local:       localBudget(5_000_000, true),
			outcome:     budgetOutcome(8_000_000, orgcontract.BudgetPolicyEnforcementHard),
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceOrgLowered,
			wantFetch: orgcontract.BudgetFetchOK, wantLastOK: true,
		},
		{
			name:          "managed node holding enforce.budget is authoritative",
			local:         localBudget(5_000_000, true),
			authoritative: true,
			outcome:       budgetOutcome(8_000_000, orgcontract.BudgetPolicyEnforcementHard),
			wantMonthly:   8_000_000, wantSource: orgcontract.BudgetSourceOrgAuthoritative,
			wantFetch: orgcontract.BudgetFetchOK, wantLastOK: true,
		},
		{
			name:  "an unreachable org keeps the local numbers and says so",
			local: localBudget(5_000_000, true),
			outcome: orgclient.BudgetFetchOutcome{
				State: orgcontract.BudgetFetchUnreachable,
			},
			wantMonthly: 5_000_000, wantSource: orgcontract.BudgetSourceLocal,
			wantFetch: orgcontract.BudgetFetchUnreachable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g, gerr := guard.New(guard.Options{
				Config: config.GuardConfig{
					Enabled: true, Mode: "enforce", Budget: tc.local,
					Rules: config.GuardRulesConfig{},
				},
				ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
			})
			if gerr != nil {
				t.Fatalf("guard.New: %v", gerr)
			}
			h := newOrgBudgetHandle(g, tc.local,
				func() bool { return tc.authoritative }, nil, slog.Default())
			h.onBudgetFetch(tc.outcome)

			if got := g.EffectiveBudget().MonthlyTokens; got != tc.wantMonthly {
				t.Errorf("the LIVE guard's monthly token ceiling = %d, want %d", got, tc.wantMonthly)
			}

			row, ok := h.postureProvider()()
			if !ok {
				t.Fatal("no posture published")
			}
			if row.Source != tc.wantSource {
				t.Errorf("source = %q, want %q", row.Source, tc.wantSource)
			}
			if row.FetchState != tc.wantFetch {
				t.Errorf("fetch_state = %q, want %q", row.FetchState, tc.wantFetch)
			}
			if row.LastFetchOK != tc.wantLastOK {
				t.Errorf("last_fetch_ok = %v, want %v", row.LastFetchOK, tc.wantLastOK)
			}
			if row.FromOrg != tc.local.FromOrg {
				t.Errorf("from_org = %v, want %v", row.FromOrg, tc.local.FromOrg)
			}
			if row.Coverage != orgcontract.BudgetCoverageProxyOnly {
				t.Errorf("coverage = %q, want %q", row.Coverage, orgcontract.BudgetCoverageProxyOnly)
			}
		})
	}
}

func TestOrgBudgetWireCarriesManagedProtectionIntoGuard(t *testing.T) {
	t.Parallel()
	local := localBudget(5_000_000, true)
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{
			Enabled: true, Mode: "enforce", Budget: local,
			Rules: config.GuardRulesConfig{Disable: []string{"B-623"}},
		},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	h := newOrgBudgetHandle(g, local, func() bool { return true }, nil, slog.Default())
	h.onBudgetFetch(budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard))
	g.SetBudgetLookup(func(string) (guard.BudgetSnapshot, bool) {
		return guard.BudgetSnapshot{MonthlyTokens: 2_000_001}, true
	})
	approvalCalls := 0
	g.SetApprovalLookup(func(string, string, string) bool {
		approvalCalls++
		return true
	})

	res := g.ScanProxyRequest("openai", []byte(`{"model":"test"}`), "s1", time.Now().UTC())
	if !res.Deny || res.DenyRuleID != "B-623" {
		t.Fatalf("managed budget result = %+v, want protected B-623 denial", res)
	}
	if approvalCalls != 0 {
		t.Errorf("managed protected budget consulted approvals %d times", approvalCalls)
	}
}

// TestOrgBudgetWireComposesAgainstTheNodesOWNNumbers is the ratchet guard: the
// left operand of every composition is the CONFIGURED block, never the
// previously-composed one. Composing against the previous effective value
// would make each cycle re-lower an already-lowered cap, and a withdrawn org
// cap could never be released.
func TestOrgBudgetWireComposesAgainstTheNodesOWNNumbers(t *testing.T) {
	t.Parallel()

	h := newOrgBudgetHandle(nil, localBudget(5_000_000, true), nil, nil, slog.Default())

	h.onBudgetFetch(budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard))
	if got := withThresholds(h.local, thresholdsOf(h.local)).MonthlyTokens; got != 5_000_000 {
		t.Fatalf("the handle's LOCAL block was mutated: %d, want the configured 5000000", got)
	}

	// The org withdraws the budget entirely.
	h.onBudgetFetch(orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchNoBudget})
	row, _ := h.postureProvider()()
	if row.Source != orgcontract.BudgetSourceLocal || row.FetchState != orgcontract.BudgetFetchNoBudget {
		t.Errorf("after withdrawal: source=%q fetch_state=%q, want local/no_budget", row.Source, row.FetchState)
	}
}

// TestOrgBudgetWirePublishesAPreFetchPosture: a push that happens before the
// first budget poll must still report something. "Not reported" and "not
// covered" are different facts and must not collapse into one wire state.
func TestOrgBudgetWirePublishesAPreFetchPosture(t *testing.T) {
	t.Parallel()

	optedIn := newOrgBudgetHandle(nil, localBudget(0, true), nil, nil, slog.Default())
	// Prime is what publishes the pre-fetch posture now (finding H3c): a
	// posture built before the governance identity loader exists would report
	// every managed node as un-required, so the wire stays silent until the
	// daemon primes it.
	optedIn.Prime(orgclient.BudgetFetchOutcome{})
	row, ok := optedIn.postureProvider()()
	if !ok {
		t.Fatal("an opted-in node published no posture before its first poll")
	}
	if row.FetchState != orgcontract.BudgetFetchUnreachable || row.LastFetchOK {
		t.Errorf("pre-fetch posture = %+v, want unreachable + last_fetch_ok=false — claiming ok before a successful poll would lie in the dangerous direction", row)
	}

	off := newOrgBudgetHandle(nil, localBudget(0, false), nil, nil, slog.Default())
	off.Prime(orgclient.BudgetFetchOutcome{})
	row, _ = off.postureProvider()()
	if row.FetchState != orgcontract.BudgetFetchDisabled || row.FromOrg {
		t.Errorf("opt-out posture = %+v, want disabled + from_org=false", row)
	}
}

// TestWithThresholdsCarriesTheWindowBlock: an org budget governs CEILINGS. The
// [guard.budget.window] provider-utilization guardrails are a different rule
// category with their own explicit deny thresholds and must survive untouched.
func TestWithThresholdsCarriesTheWindowBlock(t *testing.T) {
	t.Parallel()

	base := localBudget(5_000_000, true)
	out := withThresholds(base, thresholdsOf(base))
	if out.Window != base.Window {
		t.Errorf("window block = %+v, want %+v", out.Window, base.Window)
	}
	if out.FromOrg != base.FromOrg {
		t.Errorf("from_org = %v, want %v — the opt-in is node config, not a composed number", out.FromOrg, base.FromOrg)
	}
}

// TestBudgetWindowCalendarFollowsTheOrgCap is MEDIUM-2's boundary half (review
// fix round 2): a calendar_day org cap authored in America/Los_Angeles must
// make the node's spend lookup count the PDT day — the same day the dashboard
// percentage and the alert ladder count.
//
// Before the fix the lookup's dayStart was now.UTC().Truncate(24h)
// unconditionally, so at 23:30 PDT the node was 6.5 hours into a day the
// Budgets page had not started: a developer could be refused against a window
// the admin's screen showed as nearly empty.
func TestBudgetWindowCalendarFollowsTheOrgCap(t *testing.T) {
	t.Parallel()

	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Skipf("tzdata unavailable on this platform: %v", err)
	}
	// 2026-09-07 23:30 PDT == 2026-09-08 06:30 UTC. The UTC day has already
	// rolled over; the LA day has not.
	now := time.Date(2026, 9, 7, 23, 30, 0, 0, la).UTC()

	// Nothing published: UTC, byte-identical to the pre-fix behaviour.
	if day, _, month := budgetWindowStarts(now, guard.BudgetCalendars{}); !day.Equal(time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)) ||
		!month.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("with no org calendar published: day=%s month=%s, want the UTC day/month", day, month)
	}

	local := config.GuardBudgetConfig{FromOrg: true}
	gd, err := guard.New(guard.Options{Config: config.GuardConfig{Enabled: true, Mode: "enforce", Budget: local}, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var calendars guard.BudgetCalendars
	gd.SetBudgetAccountingLookup(func(_ string, accounting guard.BudgetAccountingContext) (guard.BudgetSnapshot, bool) {
		calendars = accounting.Calendars
		return guard.BudgetSnapshot{}, true
	})
	h := newOrgBudgetHandle(gd, local, func() bool { return true }, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	h.apply(orgclient.BudgetFetchOutcome{
		State: orgcontract.BudgetFetchOK, HaveBody: true,
		Body: orgcontract.BudgetPolicyBody{
			Version: 12, ResolvedScope: "team:eng",
			Caps: []orgcontract.BudgetPolicyCap{{
				Period:      orgcontract.BudgetPolicyPeriodCalendarDay,
				Timezone:    "America/Los_Angeles",
				CapTokens:   1_000_000,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			}},
		},
	})

	gd.ScanProxyRequest("openai", []byte(`{"model":"test"}`), "calendar", now)
	dayStart, weekStart, monthStart := budgetWindowStarts(now, calendars)
	wantDay := time.Date(2026, 9, 7, 0, 0, 0, 0, la)
	if !dayStart.Equal(wantDay) {
		t.Errorf("dayStart = %s, want %s (LA midnight) — the node must bucket the budget's own calendar day",
			dayStart.UTC(), wantDay.UTC())
	}
	// The org authored no MONTHLY cap, so that window keeps the UTC calendar.
	if want := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC); !monthStart.Equal(want) {
		t.Errorf("monthStart = %s, want %s — an unauthored window keeps its own calendar", monthStart, want)
	}
	// weekly is a ROLLING window and has no calendar at all.
	if want := now.Add(-7 * 24 * time.Hour); !weekStart.Equal(want) {
		t.Errorf("weekStart = %s, want %s (rolling 7 days)", weekStart, want)
	}
}

// TestOrgBudgetWireFailsClosedOnAManagedNode walks ruling R2 THROUGH the
// boundary: the governance predicate is read once and feeds BOTH capabilities,
// the composed posture reaches the wire row, and the LIVE guard actually
// refuses a proxied request.
//
// It is a separate function from the table above because that table asserts
// coverage=proxy_only for every row, and the whole point of this state is that
// it is not.
func TestOrgBudgetWireFailsClosedOnAManagedNode(t *testing.T) {
	t.Parallel()

	newGuard := func(t *testing.T, local config.GuardBudgetConfig) *guard.Guard {
		t.Helper()
		g, err := guard.New(guard.Options{
			Config: config.GuardConfig{
				Enabled: true, Mode: "enforce", Budget: local,
				Rules: config.GuardRulesConfig{},
			},
			ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
		})
		if err != nil {
			t.Fatalf("guard.New: %v", err)
		}
		return g
	}

	t.Run("managed + no verified body -> budget_required on the wire", func(t *testing.T) {
		t.Parallel()
		local := localBudget(5_000_000, true)
		g := newGuard(t, local)
		h := newOrgBudgetHandle(g, local, func() bool { return true }, nil, slog.Default())
		h.onBudgetFetch(orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified})

		row, ok := h.postureProvider()()
		if !ok {
			t.Fatal("no posture published")
		}
		if row.Coverage != orgcontract.BudgetCoverageBudgetRequired {
			t.Errorf("coverage = %q, want %q", row.Coverage, orgcontract.BudgetCoverageBudgetRequired)
		}
		if row.FetchState != orgcontract.BudgetFetchUnverified {
			t.Errorf("fetch_state = %q, want the fetch's own unverified — the diagnosis must survive the block",
				row.FetchState)
		}
		if !row.Hard || !row.Capped || row.LastFetchOK {
			t.Errorf("posture = %+v, want hard+capped and last_fetch_ok=false", row)
		}
	})

	t.Run("an INDIVIDUAL node in the same state is untouched", func(t *testing.T) {
		t.Parallel()
		local := localBudget(5_000_000, true)
		g := newGuard(t, local)
		h := newOrgBudgetHandle(g, local, func() bool { return false }, nil, slog.Default())
		h.onBudgetFetch(orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified})

		row, _ := h.postureProvider()()
		if row.Coverage != orgcontract.BudgetCoverageProxyOnly {
			t.Errorf("coverage = %q, want %q — the fail-closed path must need the grant",
				row.Coverage, orgcontract.BudgetCoverageProxyOnly)
		}
		if row.Hard {
			t.Error("an individual node's hard flag was raised by an absent org body")
		}
	})

	t.Run("a managed node with a verified body does NOT block", func(t *testing.T) {
		t.Parallel()
		local := localBudget(5_000_000, true)
		g := newGuard(t, local)
		h := newOrgBudgetHandle(g, local, func() bool { return true }, nil, slog.Default())
		h.onBudgetFetch(budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard))

		row, _ := h.postureProvider()()
		if row.Coverage != orgcontract.BudgetCoverageProxyOnly {
			t.Errorf("coverage = %q, want %q", row.Coverage, orgcontract.BudgetCoverageProxyOnly)
		}
		if row.Source != orgcontract.BudgetSourceOrgAuthoritative {
			t.Errorf("source = %q, want org_authoritative", row.Source)
		}
	})

	t.Run("a nil guard still publishes the blocking posture", func(t *testing.T) {
		t.Parallel()
		h := newOrgBudgetHandle(nil, localBudget(0, true), func() bool { return true }, nil, slog.Default())
		h.Prime(orgclient.BudgetFetchOutcome{})
		row, ok := h.postureProvider()()
		if !ok {
			t.Fatal("no posture published")
		}
		if row.Coverage != orgcontract.BudgetCoverageBudgetRequired {
			t.Errorf("coverage = %q, want %q even with no guard to enforce it",
				row.Coverage, orgcontract.BudgetCoverageBudgetRequired)
		}
		if row.Mode != "off" {
			t.Errorf("mode = %q, want off — there is no enforcement point at all", row.Mode)
		}
	})
}

// TestShareModeLine is SF-12: the status line must read the SAME predicate the
// push seam does, and must name which input lifted it.
func TestShareModeLine(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                    string
		full, admin, enterprise bool
		wantContains            string
		wantDefault             bool
	}{
		{
			name: "nothing set: metadata-only, the default", wantDefault: true,
		},
		{
			name: "full_content", full: true,
			wantContains: "[org_client.share].full_content is true",
		},
		{
			name: "admin_managed — the input the old line ignored", admin: true,
			wantContains: "[org_client.share].admin_managed is true",
		},
		{
			name: "the enterprise enrolment grant — no TOML key records it", enterprise: true,
			wantContains: "managed enrolment grant",
		},
		{
			name: "full_content wins when several apply: it is the switch the operator can turn off",
			full: true, admin: true, enterprise: true,
			wantContains: "[org_client.share].full_content is true",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := shareModeLine(tc.full, tc.admin, tc.enterprise)
			if tc.wantDefault {
				if !strings.Contains(got, "metadata-only") {
					t.Fatalf("line = %q, want the metadata-only default", got)
				}
				return
			}
			if !strings.Contains(got, "FULL CONTENT") {
				t.Errorf("line = %q, want it to say FULL CONTENT", got)
			}
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("line = %q, want it to name %q", got, tc.wantContains)
			}
		})
	}
}

// TestShareModeRulesAreOrderedAndNamed pins the table itself: the fallback is
// LAST (it matches everything, so any other position makes the rows below it
// unreachable) and every row carries a name for the reader.
func TestShareModeRulesAreOrderedAndNamed(t *testing.T) {
	t.Parallel()
	want := []string{"full_content", "admin_managed", "enterprise_grant", "metadata_only"}
	if len(shareModeRules) != len(want) {
		t.Fatalf("shareModeRules has %d rows, want %d", len(shareModeRules), len(want))
	}
	for i, name := range want {
		if shareModeRules[i].name != name {
			t.Errorf("row %d = %q, want %q", i, shareModeRules[i].name, name)
		}
	}
	if !shareModeRules[len(shareModeRules)-1].lifted(false, false, false) {
		t.Error("the last row must be the total fallback")
	}
}

// TestEnrolledFeedLineAgreesWithTheGuardsPricingLine is the W2-6 pair: an
// enrolled node with from_org OFF applies NEITHER the public feed nor the
// org's rates, and both surfaces must say so.
func TestEnrolledFeedLineAgreesWithTheGuardsPricingLine(t *testing.T) {
	t.Parallel()

	on := enrolledFeedLine(true)
	if !strings.Contains(on, "prices come from the org rail") {
		t.Errorf("org-rail line = %q", on)
	}
	off := enrolledFeedLine(false)
	if !strings.Contains(off, "[guard.budget].from_org is off") {
		t.Errorf("opted-out line = %q, want it to name the switch the guard's pricing line names", off)
	}
	if strings.Contains(off, "prices come from the org rail") {
		t.Errorf("opted-out line = %q, must not claim the org rail applies", off)
	}
}

// TestOrgBudgetWirePublishesNothingBeforePrime is finding H3c: the capability
// this handle reports is resolved through the governance identity loader,
// which `observer start` installs AFTER it builds the wire. A posture
// published at construction answers "is this node required to hold an org
// budget?" with false for every node — so the wire must publish nothing at all
// until Prime is called.
//
// "Not reported" and "not covered" are different facts; this is the one place
// the first is the honest one.
func TestOrgBudgetWirePublishesNothingBeforePrime(t *testing.T) {
	t.Parallel()

	h := newOrgBudgetHandle(nil, localBudget(0, true), func() bool { return true }, nil, slog.Default())
	if _, ok := h.postureProvider()(); ok {
		t.Fatal("a posture was published before Prime — with no identity loader it would report a managed node as un-required")
	}

	h.Prime(orgclient.BudgetFetchOutcome{})
	row, ok := h.postureProvider()()
	if !ok {
		t.Fatal("Prime published no posture")
	}
	if row.Coverage != orgcontract.BudgetCoverageBudgetRequired {
		t.Errorf("coverage = %q, want %q — Prime with nothing stored must ARM the block, not wait a push interval",
			row.Coverage, orgcontract.BudgetCoverageBudgetRequired)
	}
}

// TestOrgBudgetWirePrimeRestoresTheLastVerifiedBody is finding H3's restart
// half: a managed node that had a verified body before the restart must come
// back ENFORCING it, not blocking and not uncapped.
//
// The state Prime reports is deliberately `unreachable` + HaveBody: nothing
// has been fetched by THIS process, and that is the same pair a live outage
// produces — a restart during an outage should look like the outage.
func TestOrgBudgetWirePrimeRestoresTheLastVerifiedBody(t *testing.T) {
	t.Parallel()

	local := localBudget(5_000_000, true)
	h := newOrgBudgetHandle(nil, local, func() bool { return true }, nil, slog.Default())
	restored := budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard)
	restored.State = orgcontract.BudgetFetchUnreachable
	h.Prime(restored)

	row, ok := h.postureProvider()()
	if !ok {
		t.Fatal("Prime published no posture")
	}
	if row.Coverage == orgcontract.BudgetCoverageBudgetRequired {
		t.Fatal("a restored verified body still armed the block — the restart window is not closed")
	}
	if !row.Capped || row.LastFetchOK {
		t.Errorf("posture = %+v, want capped with last_fetch_ok=false (restored, not re-fetched)", row)
	}
	if row.Source != orgcontract.BudgetSourceOrgAuthoritative {
		t.Errorf("source = %q, want org_authoritative — the restored body is the org's", row.Source)
	}
}

// TestOrgBudgetWireArmsAndDisarmsAcrossASimulatedRestart walks the whole H3
// cycle on ONE handle pair: armed with nothing stored, disarmed once a body is
// restored, and armed again when the org explicitly withdraws the budget.
func TestOrgBudgetWireArmsAndDisarmsAcrossASimulatedRestart(t *testing.T) {
	t.Parallel()

	local := localBudget(5_000_000, true)
	managed := func() bool { return true }

	// Boot 1: nothing persisted yet.
	first := newOrgBudgetHandle(nil, local, managed, nil, slog.Default())
	first.Prime(orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchUnreachable})
	if row, _ := first.postureProvider()(); row.Coverage != orgcontract.BudgetCoverageBudgetRequired {
		t.Fatalf("cold boot coverage = %q, want the block armed", row.Coverage)
	}
	// It fetches successfully.
	first.onBudgetFetch(budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard))
	if row, _ := first.postureProvider()(); row.Coverage != orgcontract.BudgetCoverageProxyOnly {
		t.Fatalf("after a verified fetch coverage = %q, want proxy_only", row.Coverage)
	}

	// Boot 2: the daemon restarts and restores that body from the store.
	restored := budgetOutcome(2_000_000, orgcontract.BudgetPolicyEnforcementHard)
	restored.State = orgcontract.BudgetFetchUnreachable
	second := newOrgBudgetHandle(nil, local, managed, nil, slog.Default())
	second.Prime(restored)
	if row, _ := second.postureProvider()(); row.Coverage == orgcontract.BudgetCoverageBudgetRequired {
		t.Fatal("the restart re-armed the block despite a persisted verified body")
	}

	// The org then withdraws the budget through an unsigned 404: the node
	// drops the body and, being required to hold one, arms again.
	second.onBudgetFetch(orgclient.BudgetFetchOutcome{State: orgcontract.BudgetFetchNoBudget})
	if row, _ := second.postureProvider()(); row.Coverage != orgcontract.BudgetCoverageBudgetRequired {
		t.Fatalf("after an unsigned withdrawal coverage = %q, want the block armed", row.Coverage)
	}
}

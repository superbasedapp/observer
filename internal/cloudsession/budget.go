package cloudsession

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// budget.go is the sandbox's SOFT budget stop (lane CA-C2, plan section 7.3,
// reference conclusion 5): there is no proxy in a vendor-hosted sandbox, so no
// pre-call token gate exists. What the sandbox can do is stop at prompt submit
// when the org's own measurement of the member's spend, carried in the signed
// budget document the policy file holds, is already over a cap. Every cap is
// soft here whatever its org enforcement says, and the number is a snapshot
// taken when `init` ran, so it is honored only while it still describes the
// current period (budgetWindows) and is otherwise ignored, never extrapolated.

// BudgetOutcome is the soft budget check's answer.
type BudgetOutcome string

// The budget outcomes.
const (
	// BudgetNone: no budget document rides with the policy.
	BudgetNone BudgetOutcome = "none"
	// BudgetUnder: every evaluable cap is under its limit.
	BudgetUnder BudgetOutcome = "under"
	// BudgetOver: a cap is at or over its limit; the prompt stops.
	BudgetOver BudgetOutcome = "over"
	// BudgetStale: caps exist but none could be evaluated now (snapshot
	// out of its period, undated, subject-narrowed or report-only).
	BudgetStale BudgetOutcome = "stale"
)

// BudgetDecision is the outcome with what the developer is shown.
type BudgetDecision struct {
	Outcome BudgetOutcome
	// Reason is the developer-facing sentence on a stop.
	Reason string
	// Skipped names every cap that was not evaluated and why.
	Skipped []string
}

// Stop reports whether the prompt stops.
func (d BudgetDecision) Stop() bool { return d.Outcome == BudgetOver }

// budgetWindow is one row of the snapshot-validity table: until when a spend
// figure measured at asOf still describes the cap's current period.
type budgetWindow struct {
	period string
	until  func(asOf time.Time, loc *time.Location) time.Time
}

// SandboxRollingSnapshotLife bounds a rolling-window figure: a rolling 30-day
// spend has no period end, so the snapshot is honored for the vendors' snapshot
// reuse span (a Claude Code environment snapshot is reused about 7 days).
const SandboxRollingSnapshotLife = 7 * 24 * time.Hour

// budgetWindows is THE validity table.
var budgetWindows = []budgetWindow{
	{orgcontract.BudgetPolicyPeriodCalendarDay, func(t time.Time, loc *time.Location) time.Time {
		l := t.In(loc)
		return time.Date(l.Year(), l.Month(), l.Day()+1, 0, 0, 0, 0, loc)
	}},
	{orgcontract.BudgetPolicyPeriodCalendarMonth, func(t time.Time, loc *time.Location) time.Time {
		l := t.In(loc)
		return time.Date(l.Year(), l.Month()+1, 1, 0, 0, 0, 0, loc)
	}},
	{orgcontract.BudgetPolicyPeriodRolling30d, func(t time.Time, _ *time.Location) time.Time {
		return t.Add(SandboxRollingSnapshotLife)
	}},
}

// capSkip is one row of the per-cap skip table: a cap matching it is not
// evaluated, with the reason recorded.
type capSkip struct {
	why  string
	when func(c orgcontract.BudgetPolicyCap, now time.Time, lookupTZ func(string) (*time.Location, error)) bool
}

// capSkips is THE skip table, walked top-down.
var capSkips = []capSkip{
	{"report-only", func(c orgcontract.BudgetPolicyCap, _ time.Time, _ func(string) (*time.Location, error)) bool {
		return c.Enforcement == orgcontract.BudgetPolicyEnforcementReport
	}},
	{"narrowed to one tool or model (not evaluated in the sandbox)", func(c orgcontract.BudgetPolicyCap, _ time.Time, _ func(string) (*time.Location, error)) bool {
		return c.Subject != nil
	}},
	{"no cap", func(c orgcontract.BudgetPolicyCap, _ time.Time, _ func(string) (*time.Location, error)) bool {
		return c.CapUSD <= 0 && c.CapTokens <= 0
	}},
	{"no dated spend figure", func(c orgcontract.BudgetPolicyCap, _ time.Time, _ func(string) (*time.Location, error)) bool {
		_, err := time.Parse(time.RFC3339, strings.TrimSpace(c.SpentAsOf))
		return err != nil
	}},
	{"spend figure from an earlier period", func(c orgcontract.BudgetPolicyCap, now time.Time, tz func(string) (*time.Location, error)) bool {
		asOf, _ := time.Parse(time.RFC3339, strings.TrimSpace(c.SpentAsOf))
		until, ok := windowEnd(c, asOf, tz)
		return !ok || !now.Before(until)
	}},
}

// windowEnd returns the end of the period the cap's spend figure describes.
func windowEnd(c orgcontract.BudgetPolicyCap, asOf time.Time, tz func(string) (*time.Location, error)) (time.Time, bool) {
	loc := time.UTC
	if name := strings.TrimSpace(c.Timezone); name != "" && tz != nil {
		l, err := tz(name)
		if err != nil {
			return time.Time{}, false
		}
		loc = l
	}
	for _, w := range budgetWindows {
		if w.period == c.Period {
			return w.until(asOf, loc), true
		}
	}
	return time.Time{}, false
}

// SoftBudgetStop evaluates the signed budget body at now. tz resolves an IANA
// zone name (time.LoadLocation in production; injected so the package stays
// free of the zone database). A nil body is BudgetNone.
func SoftBudgetStop(body *orgcontract.BudgetPolicyBody, now time.Time, tz func(string) (*time.Location, error)) BudgetDecision {
	if body == nil || body.Empty() {
		return BudgetDecision{Outcome: BudgetNone}
	}
	caps := body.Caps
	if len(caps) == 0 {
		caps = []orgcontract.BudgetPolicyCap{{
			Period: body.Period, Timezone: body.Timezone, CapTokens: body.CapTokens, CapUSD: body.CapUSD,
			Enforcement: body.Enforcement, ResolvedScope: body.ResolvedScope,
		}}
	}
	d := BudgetDecision{Outcome: BudgetStale}
	for _, c := range caps {
		c = c.RevertExpiredGrant(now)
		if why := skipCap(c, now, tz); why != "" {
			d.Skipped = append(d.Skipped, c.Period+": "+why)
			continue
		}
		if reason, over := capOver(c); over {
			return BudgetDecision{Outcome: BudgetOver, Reason: reason, Skipped: d.Skipped}
		}
		d.Outcome = BudgetUnder
	}
	return d
}

func skipCap(c orgcontract.BudgetPolicyCap, now time.Time, tz func(string) (*time.Location, error)) string {
	for _, s := range capSkips {
		if s.when(c, now, tz) {
			return s.why
		}
	}
	return ""
}

// capOver reports whether the org's spend figure has reached the cap, in
// whichever unit the org authored (dollars first, then tokens).
//
// A dollar cap is shown to the developer as the share of the cap used, never
// as dollar amounts (T-204): the sandbox does not know the org's developer
// cost display (D-013), and a share reads the same under either display. The
// amounts are never converted into tokens either (the rule of
// policy.BudgetReasonWithoutDollars). A token cap names its tokens.
func capOver(c orgcontract.BudgetPolicyCap) (string, bool) {
	scope := c.ResolvedScope
	if scope == "" {
		scope = "org"
	}
	period := strings.ReplaceAll(c.Period, "_", " ")
	if c.CapUSD > 0 && c.SpentUSD >= c.CapUSD {
		return fmt.Sprintf("Your organization's %s budget (%s) is used up: %s of the budget as of %s. This cloud session stops new prompts (a soft stop: the sandbox has no proxy). Ask your admin to raise the budget, then re-run `observer cloud-session init --guard` and commit.",
			period, scope, capShare(c.SpentUSD, c.CapUSD), c.SpentAsOf), true
	}
	if c.CapTokens > 0 && c.SpentTokens >= c.CapTokens {
		return fmt.Sprintf("Your organization's %s token budget (%s) is used up: %d of %d tokens as of %s. This cloud session stops new prompts (a soft stop: the sandbox has no proxy). Ask your admin to raise the budget, then re-run `observer cloud-session init --guard` and commit.",
			period, scope, c.SpentTokens, c.CapTokens, c.SpentAsOf), true
	}
	return "", false
}

// capShare renders spent as a whole percentage of a positive cap ("104%").
func capShare(spent, limit float64) string {
	return strconv.Itoa(int(math.Round(spent/limit*100))) + "%"
}

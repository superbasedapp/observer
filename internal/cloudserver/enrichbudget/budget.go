package enrichbudget

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/reserve"
)

// Hold arithmetic constants.
const (
	// PromptOverheadTokens is the fixed prompt every enrichment call carries
	// besides the evidence: the system prompt with the tag vocabulary and the
	// fence. S-3 measured 2,993 tokens on gpt-oss; the constant rounds up so
	// the hold stays a worst case.
	PromptOverheadTokens = 3072
	// WorstCaseTokensPerKiloByte bounds evidence tokens per 1,000 envelope
	// bytes for the HOLD. It is about 1.5 times the calibrated 323 (the
	// estimate the evidence budget is fitted against), so a tokenizer that
	// splits this session's text worse than the calibration set still lands
	// inside the hold; anything beyond it is booked as an overrun at settle,
	// never clamped.
	WorstCaseTokensPerKiloByte = 500
	// DefaultMaxOutputTokens is the output allowance a hold assumes when the
	// route declares none (a non-positive max_output_tokens): the openai
	// compatible route's 4,096 (cloud migration 0045).
	DefaultMaxOutputTokens = 4096
)

// Tier bounds. A configuration outside them is refused by Validate, so a typo
// (an extra few zeros, a zero) cannot remove a bound or block every job.
const (
	// MinEvidenceTokens is the smallest evidence budget: the ladder's floor
	// (one 128-byte prompt and the structural fields) needs several hundred.
	MinEvidenceTokens = 1000
	// MaxEvidenceTokens bounds the evidence budget. Today's builder cannot
	// produce much more than 12k evidence tokens at default settings (S-3,
	// "Ceiling"), so 32k never binds and anything above it is a typo.
	MaxEvidenceTokens = 32000
	// MaxAccountTokens bounds every token budget (a month of a heavy paid
	// account is in the tens of millions).
	MaxAccountTokens int64 = 1_000_000_000
)

// tierNamePattern is the shape of a tier name (the plans.enrichment_tier
// value that selects it).
var tierNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// Tier is one published version of an enrichment tier: the platform's
// configuration for every plan that names it.
type Tier struct {
	// Name is the tier (e.g. "free", "paid").
	Name string
	// Version is the published version (1, 2, ...); the highest is in force.
	Version int
	// RouteID is the route_registry row the tier's jobs run on. It names a
	// route; it never carries an endpoint or a credential.
	RouteID string
	// EvidenceTokens is the evidence budget: the most evidence tokens one
	// envelope may carry (cloudcontract.EstimateEvidenceTokens).
	EvidenceTokens int
	// SessionTokens is the cumulative token budget of ONE session across
	// every enrichment of it (a grown session's re-enrichment charges against
	// what the session already used).
	SessionTokens int64
	// DailyTokens and MonthlyTokens are the per-account token budgets per UTC
	// day and UTC calendar month.
	DailyTokens   int64
	MonthlyTokens int64
}

// ErrInvalidTier wraps every Validate / CheckRoute refusal.
var ErrInvalidTier = errors.New("enrichbudget: invalid tier configuration")

// tierRule is one row of tierRules: a refusal when check returns non-empty.
type tierRule struct {
	name  string
	check func(Tier) string
}

// tierRules validate a tier on its own, top-down, first refusal wins.
func tierRules() []tierRule {
	return []tierRule{
		{"name", func(t Tier) string {
			if !tierNamePattern.MatchString(t.Name) {
				return fmt.Sprintf("tier name %q must match %s", t.Name, tierNamePattern)
			}
			return ""
		}},
		{"route", func(t Tier) string {
			if t.RouteID == "" {
				return "a tier must name a route id"
			}
			return ""
		}},
		{"evidence", func(t Tier) string {
			if t.EvidenceTokens < MinEvidenceTokens || t.EvidenceTokens > MaxEvidenceTokens {
				return fmt.Sprintf("evidence budget %d must be %d-%d tokens", t.EvidenceTokens, MinEvidenceTokens, MaxEvidenceTokens)
			}
			return ""
		}},
		{"bounds", func(t Tier) string {
			for _, v := range []int64{t.SessionTokens, t.DailyTokens, t.MonthlyTokens} {
				if v <= 0 || v > MaxAccountTokens {
					return fmt.Sprintf("token budgets must be 1-%d (session %d, daily %d, monthly %d)",
						MaxAccountTokens, t.SessionTokens, t.DailyTokens, t.MonthlyTokens)
				}
			}
			return ""
		}},
		{"month_covers_day", func(t Tier) string {
			if t.MonthlyTokens < t.DailyTokens {
				return fmt.Sprintf("monthly budget %d is below the daily budget %d", t.MonthlyTokens, t.DailyTokens)
			}
			return ""
		}},
	}
}

// Validate checks a tier on its own (without its route).
func (t Tier) Validate() error {
	for _, r := range tierRules() {
		if msg := r.check(t); msg != "" {
			return fmt.Errorf("%w: %s", ErrInvalidTier, msg)
		}
	}
	return nil
}

// RouteFacts is what the store and the attestation gate know about the route
// a tier names, resolved to plain values at the boundary.
type RouteFacts struct {
	// Found reports that the route_registry row exists.
	Found bool
	// Feature is the route's feature.
	Feature string
	// Production reports the route's environment is production (the worker
	// refuses a non-production route).
	Production bool
	// Active reports route_registry.active.
	Active bool
	// Bound reports the route carries an endpoint, a provider resource
	// identity and whatever API version its dialect needs (store.RouteBound).
	Bound bool
	// Priced reports a positive per-MTok price snapshot and a stamped price
	// version.
	Priced bool
	// Attested reports a healthy attestation verdict for the route's CURRENT
	// generation from this process's attestor.
	Attested bool
	// AttestReason is the attestor's own words (shown on a refusal).
	AttestReason string
	// MaxOutputTokens is the route's output cap.
	MaxOutputTokens int
}

// routeRule is one row of routeRules.
type routeRule struct {
	name  string
	check func(t Tier, feature string, r RouteFacts) string
}

// routeRules decide whether a tier may name a route, top-down, first refusal
// wins. Binding stays an operator act on the route itself; this table only
// refuses to SELECT a route that is not ready.
func routeRules() []routeRule {
	return []routeRule{
		{"exists", func(t Tier, _ string, r RouteFacts) string {
			if !r.Found {
				return fmt.Sprintf("route %q does not exist", t.RouteID)
			}
			return ""
		}},
		{"feature", func(t Tier, feature string, r RouteFacts) string {
			if r.Feature != feature {
				return fmt.Sprintf("route %q serves %q, not %q", t.RouteID, r.Feature, feature)
			}
			return ""
		}},
		{"production", func(t Tier, _ string, r RouteFacts) string {
			if !r.Production {
				return fmt.Sprintf("route %q is not a production route", t.RouteID)
			}
			return ""
		}},
		{"active", func(t Tier, _ string, r RouteFacts) string {
			if !r.Active {
				return fmt.Sprintf("route %q is not active (bind it with --activate first)", t.RouteID)
			}
			return ""
		}},
		{"bound", func(t Tier, _ string, r RouteFacts) string {
			if !r.Bound {
				return fmt.Sprintf("route %q is not bound (run `observer-cloud route bind-*` first)", t.RouteID)
			}
			return ""
		}},
		{"priced", func(t Tier, _ string, r RouteFacts) string {
			if !r.Priced {
				return fmt.Sprintf("route %q carries no price snapshot, so its calls could not be priced", t.RouteID)
			}
			return ""
		}},
		{"attested", func(t Tier, _ string, r RouteFacts) string {
			if !r.Attested {
				return fmt.Sprintf("route %q is not attested: %s", t.RouteID, r.AttestReason)
			}
			return ""
		}},
		{"session_fits_one_call", func(t Tier, _ string, r RouteFacts) string {
			if need := WorstCaseForEvidenceBudget(t.EvidenceTokens, r.MaxOutputTokens); t.SessionTokens < need {
				return fmt.Sprintf("session budget %d is below one worst-case call at the evidence budget on this route (%d)", t.SessionTokens, need)
			}
			return ""
		}},
		{"day_fits_one_call", func(t Tier, _ string, r RouteFacts) string {
			if need := WorstCaseForEvidenceBudget(t.EvidenceTokens, r.MaxOutputTokens); t.DailyTokens < need {
				return fmt.Sprintf("daily budget %d is below one worst-case call at the evidence budget on this route (%d)", t.DailyTokens, need)
			}
			return ""
		}},
	}
}

// CheckTier is the whole publish-time decision: the tier is valid on its own
// and the route it names is ready to serve feature.
func CheckTier(t Tier, feature string, r RouteFacts) error {
	if err := t.Validate(); err != nil {
		return err
	}
	for _, rule := range routeRules() {
		if msg := rule.check(t, feature, r); msg != "" {
			return fmt.Errorf("%w: %s", ErrInvalidTier, msg)
		}
	}
	return nil
}

// WorstCaseTokens is the hold of one enrichment call: the evidence at the
// conservative worst-case ratio, the fixed prompt, and the route's whole
// output allowance. A non-positive maxOutput assumes DefaultMaxOutputTokens.
func WorstCaseTokens(evidenceBytes int64, maxOutput int) int64 {
	if evidenceBytes < 0 {
		evidenceBytes = 0
	}
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutputTokens
	}
	evidence := (evidenceBytes*WorstCaseTokensPerKiloByte + 999) / 1000
	return evidence + PromptOverheadTokens + int64(maxOutput)
}

// MaxEvidenceBytes is the largest envelope whose estimate fits an evidence
// budget of the given tokens.
func MaxEvidenceBytes(evidenceTokens int) int64 {
	if evidenceTokens <= 0 {
		return 0
	}
	return int64(evidenceTokens) * 1000 / cloudcontract.EvidenceTokensPerKiloByte
}

// WorstCaseForEvidenceBudget is the hold of a call whose envelope just fits
// the evidence budget: what one enrichment can cost at most on this route.
func WorstCaseForEvidenceBudget(evidenceTokens, maxOutput int) int64 {
	return WorstCaseTokens(MaxEvidenceBytes(evidenceTokens), maxOutput)
}

// Limit names: the store maps each to its refusal sentinel.
const (
	LimitDaily       = "tokens_daily"
	LimitMonthly     = "tokens_monthly"
	LimitConcurrency = "concurrency"
	LimitSession     = "tokens_session"
)

// Committed is what each cap's window already counts, read by the store under
// its locks: settled holds at what they booked plus open holds at their
// estimate (tokens), and the jobs in flight (count).
type Committed struct {
	Daily, Monthly, Session int64
	InFlight                int64
}

// Caps are the budgets in force for this hold: the tier's three token budgets
// and the plan's (or override's) concurrency cap.
type Caps struct {
	Daily, Monthly, Session int64
	Concurrency             int64
}

// Limits is the hold as reserve-core caps, in the store's canonical lock
// order (daily, monthly, concurrency, session). Every cap is OverCap: the
// hold's size is known before the call.
func Limits(c Caps, used Committed, hold int64) []reserve.Limit {
	tok := func(name string, capv, committed int64) reserve.Limit {
		return reserve.Limit{Name: name, Unit: reserve.UnitTokens, Cap: float64(capv), Committed: float64(committed), Estimate: float64(hold)}
	}
	return []reserve.Limit{
		tok(LimitDaily, c.Daily, used.Daily),
		tok(LimitMonthly, c.Monthly, used.Monthly),
		{Name: LimitConcurrency, Unit: reserve.UnitCount, Cap: float64(c.Concurrency), Committed: float64(used.InFlight), Estimate: 1},
		tok(LimitSession, c.Session, used.Session),
	}
}

// Admit decides a hold against every cap. A non-positive hold is refused as
// invalid input (a hold the caller could not size must never pass a cap).
func Admit(c Caps, used Committed, hold int64) reserve.Decision {
	if hold <= 0 {
		return reserve.Decision{Rule: reserve.RuleInvalid, Refused: &reserve.Breach{Name: LimitDaily, Unit: reserve.UnitTokens, Rule: reserve.RuleInvalid}}
	}
	return reserve.Admit(reserve.Request{Limits: Limits(c, used, hold)})
}

// ActualTokens is what a settled call books: prompt plus completion tokens.
// A meter that cannot say what the call cost (no prompt tokens, a negative
// count) returns -1, which the reserve core's settle books at the hold (the
// A12 rule: a broken meter costs the worst case, never zero).
func ActualTokens(promptTokens, completionTokens int64) float64 {
	if promptTokens <= 0 || completionTokens < 0 {
		return -1
	}
	return float64(promptTokens + completionTokens)
}

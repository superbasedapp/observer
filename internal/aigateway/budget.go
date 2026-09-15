package aigateway

import (
	"context"
	"math"
	"time"
)

// BudgetLevel is one tier in the hierarchical cap stack (design §2.4.3).
// A request reserves worst-case spend at EVERY applicable level before it is
// forwarded, so concurrent streams cannot collectively blow past any cap by
// racing admission.
type BudgetLevel string

const (
	// LevelKey caps one virtual key.
	LevelKey BudgetLevel = "key"
	// LevelMember caps one org member across all their keys.
	LevelMember BudgetLevel = "member"
	// LevelTeam caps one team.
	LevelTeam BudgetLevel = "team"
	// LevelOrg caps the whole org.
	LevelOrg BudgetLevel = "org"
)

// BudgetWindow is the reset cadence of a cap.
type BudgetWindow string

const (
	// WindowDaily resets each calendar day, in the cap's own timezone.
	WindowDaily BudgetWindow = "daily"
	// WindowMonthly resets each calendar month, in the cap's own timezone.
	WindowMonthly BudgetWindow = "monthly"
)

// Window key layouts. Daily buckets on the calendar date, monthly on the
// calendar month; both rendered in the cap's own zone by WindowValueFor.
const (
	windowLayoutDaily   = "2006-01-02"
	windowLayoutMonthly = "2006-01"
)

// WindowValueFor computes the ledger bucket key one SCOPE counts into: the
// calendar day or month of now as seen in the cap's own timezone.
//
// It is the whole of the "one budget, one calendar" fix on the gateway side.
// A reservation used to stamp a single UTC day / month shared by every scope
// the request touched, so a cap authored in America/Los_Angeles was enforced
// on the UTC calendar and a 23:30-local request counted against tomorrow's
// budget. The key now travels on the scope row instead, so two caps in two
// zones on the SAME request bucket differently and each is enforced on its
// own calendar (the same calendar rollup.BudgetWindowSince renders and
// orgbudget.CalendarWindowStarts anchors on the node).
//
// An empty timezone and the literal "UTC" both mean UTC, matching the
// budgets.timezone column's own absent value. zoneHonoured reports whether the
// requested zone was actually used: a zone this build cannot load NEVER panics
// and never invents a calendar, it falls back CLOSED to UTC and says so, so a
// caller can flag the scope rather than silently moving a window.
//
// A window kind that is not monthly buckets daily, the same default the
// committed-spend query applies.
func WindowValueFor(now time.Time, window BudgetWindow, timezone string) (value string, zoneHonoured bool) {
	layout := windowLayoutDaily
	if window == WindowMonthly {
		layout = windowLayoutMonthly
	}
	if timezone == "" || timezone == "UTC" {
		return now.UTC().Format(layout), true
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil || loc == nil {
		return now.UTC().Format(layout), false
	}
	return now.In(loc).Format(layout), true
}

// BudgetScope identifies one cap subject: a level, the id at that level, and
// the window it resets on. The org level's ID is the org id; the member
// level's is the user id; and so on.
//
// The scope deliberately carries no timezone: only the CAP knows its calendar,
// and the caller that builds scopes (the gateway handler) has not read the cap
// yet. The reservation store resolves the zone when it loads the cap row and
// stamps the resulting WindowValueFor key onto the scope row.
type BudgetScope struct {
	Level  BudgetLevel
	ID     string
	Window BudgetWindow
}

// WorstCaseCostUSD prices the most a request could cost before it is
// forwarded, from the model policy's max_tokens cap (design §2.4.3). Input is
// billed at the estimated prompt size; output at the FULL max_tokens ceiling,
// because a stream admitted under budget may legitimately run to that ceiling
// (§2.7 bounded overrun). Cache tokens are ignored in the worst case — they
// only ever reduce real cost. The result is an ESTIMATE (Sol S12).
func WorstCaseCostUSD(rc RateCard, model string, estInputTokens, maxOutputTokens int) float64 {
	rate, ok := rc.Rate(model)
	if !ok {
		return 0
	}
	if estInputTokens < 0 {
		estInputTokens = 0
	}
	if maxOutputTokens < 0 {
		maxOutputTokens = 0
	}
	usd := float64(estInputTokens)/1e6*rate.InPerMTok + float64(maxOutputTokens)/1e6*rate.OutPerMTok
	if math.IsNaN(usd) || math.IsInf(usd, 0) {
		return 0
	}
	return usd
}

// WorstCaseTokens is the token-denominated sibling of WorstCaseCostUSD: the
// most billable tokens a request could consume before it is forwarded. Input
// is the estimated prompt size; output is the FULL max_tokens ceiling, for the
// same reason the USD worst case uses it (a stream admitted under budget may
// legitimately run to that ceiling, §2.7 bounded overrun).
//
// It consults NO rate card. That is the whole point of a token-denominated
// cap (plan §3.2): a model with no rate-card entry cannot be budget-PRICED,
// but it can always be budget-COUNTED, so a token cap bounds it honestly
// where a USD cap could only refuse it.
func WorstCaseTokens(estInputTokens, maxOutputTokens int) int64 {
	if estInputTokens < 0 {
		estInputTokens = 0
	}
	if maxOutputTokens < 0 {
		maxOutputTokens = 0
	}
	return int64(estInputTokens) + int64(maxOutputTokens)
}

// BudgetUnit names the denomination a cap, a reservation or a denial is
// expressed in. A cap row may carry BOTH; when it does, the unit that will
// exhaust FIRST decides -- the identical rule the org alert ladder fires on
// (rollup.LeadingBudgetUsage), so a deny and a dashboard percentage can never
// name different units for the same breach.
type BudgetUnit string

const (
	// UnitUSD is a dollar-denominated cap, priced from the rate card.
	UnitUSD BudgetUnit = "usd"
	// UnitTokens is a token-denominated cap, counted with no rate card.
	UnitTokens BudgetUnit = "tokens"
)

// BudgetWarning is a SOFT cap that a request exceeded without being denied
// (plan §3.2: soft = admit, stamp a warning header, write the audit row). It
// carries no content: a level, the scope id at that level, the unit that was
// exceeded and how far past the cap the reservation lands.
type BudgetWarning struct {
	Level   BudgetLevel
	ScopeID string
	Unit    BudgetUnit
	// Pct is (committed + worst case) / cap, so a value > 1 is the overrun.
	Pct float64
}

// RefundUSD is the amount to return to every reserved level at settlement:
// the reserved worst case minus the actual observed cost. It is clamped at
// zero — a stream that ran OVER its worst-case reservation (only possible via
// a rate-card change mid-stream) never produces a negative refund that would
// credit budget back; the overrun is simply accepted (§2.7) and the next
// request is denied at admission.
func RefundUSD(reservedUSD, actualUSD float64) float64 {
	r := reservedUSD - actualUSD
	if r < 0 || math.IsNaN(r) || math.IsInf(r, 0) {
		return 0
	}
	return r
}

// ReservationRequest is the atomic worst-case reservation the BudgetStore must
// admit-or-deny across every scope in one transaction (Sol S1). RequestID is
// the gateway-issued idempotency key echoed through the node proxy (§2.4
// dedup); a retried Reserve with the same RequestID must not double-reserve.
type ReservationRequest struct {
	RequestID    string
	OrgID        string
	UserID       string
	Model        string
	Owner        EconomicOwner
	WorstCaseUSD float64
	// WorstCaseTokens is the same reservation in the token denomination, for
	// the scopes whose cap is token-denominated. Both units ride ONE ledger
	// row (plan R2d), so a dual-unit cap needs no second reservation.
	WorstCaseTokens int64
	// ModelUnpriced reports that the rate card could NOT price this model. It
	// travels with the request rather than being pre-checked by the caller
	// because only the store knows which UNITS the in-scope caps are written
	// in: an unpriced model is refused when some in-scope cap is
	// USD-denominated (it would reserve $0 headroom -- the original G4 hole)
	// and admitted under a purely token-denominated cap, which needs no price
	// (plan §3.2). That is a capability branch on the CAP, not on the model.
	//
	// The flag is stated NEGATIVELY on purpose: the zero value must mean
	// "priced", i.e. today's behaviour, so an existing caller that does not
	// set it is unaffected (CLAUDE.md rule #6, additive not invasive).
	ModelUnpriced bool
	Scopes        []BudgetScope
	Now           time.Time
}

// ReservationOutcome is the verdict. On denial it names the first level that
// failed and that level's remaining headroom, so the deny body can tell the
// agent exactly which cap it hit.
type ReservationOutcome struct {
	Admitted      bool
	DeniedLevel   BudgetLevel
	DeniedScopeID string
	RemainingUSD  float64
	CapUSD        float64
	// DeniedUnit names WHICH denomination was exhausted, so the deny body can
	// say "tokens" rather than implying a dollar figure that was never the
	// binding constraint. Empty on an admission.
	DeniedUnit BudgetUnit
	// RemainingTokens / CapTokens are the token-denominated counterparts of
	// RemainingUSD / CapUSD, populated for the denied scope.
	RemainingTokens int64
	CapTokens       int64
	// Unpriced is set (with Admitted false) when the model has no rate-card
	// entry AND some in-scope cap is USD-denominated, so worst-case pricing
	// would reserve $0 headroom (G4). The handler maps this to the existing
	// 403 model_unpriced refusal. A purely token-denominated cap never sets
	// it: a token cap bounds an unpriced model perfectly well.
	Unpriced bool
	// Warnings are SOFT caps this reservation exceeded without being denied.
	// The request is admitted; the handler stamps a warning header and the
	// audit row records the breach.
	Warnings []BudgetWarning
	// Replayed is set (with Admitted false) when RequestID already names a
	// SETTLED reservation — the original inference completed and its cost is
	// booked, so re-admitting would forward a second REAL upstream call that
	// Settle (WHERE settled=0) could never book: unlimited un-budgeted
	// inference (F3). The handler maps this to a 409 replayed_request refusal
	// (no forward, audited). Distinct from a budget denial (Admitted false,
	// Replayed false) and from an idempotent in-flight retry (Admitted true).
	Replayed bool
	// InFlight is set (with Admitted false) when RequestID already names an
	// UNSETTLED reservation that has ALREADY been forwarded to the upstream
	// (forwarded_at != ''). Re-admitting would trigger a SECOND real upstream
	// inference that the idempotent Settle (WHERE settled=0) books only once —
	// the provider may bill twice while the ledger under-counts (G5). The
	// handler maps this to a 409 in_flight refusal (no forward, audited). An
	// unsettled duplicate that has NOT yet been forwarded (a genuine
	// pre-forward crash retry) stays Admitted instead.
	InFlight bool
}

// SettleRequest finalizes a reservation with the actual observed usage and
// cost. It MUST be idempotent (Sol S6): a settle already applied for RequestID
// is a no-op, so a retried stream-end or a reconciliation sweep cannot
// double-count. Marker records how the row closed ("" normal, "aborted",
// "reconciled").
type SettleRequest struct {
	RequestID string
	ActualUSD float64
	// ActualTokens is the observed billable token count, settled into the
	// same ledger row as ActualUSD so a token cap's committed spend converges
	// from worst case to actual exactly as the USD one does.
	ActualTokens int64
	Usage        Usage
	Marker       string
	Now          time.Time
}

// Settlement markers.
const (
	MarkerNormal      = ""
	MarkerAborted     = "aborted"
	MarkerReconciled  = "reconciled"
	MarkerStreamError = "stream_error"
	// MarkerRevoked marks a stream the gateway ABORTED mid-flight because the
	// presenting virtual key was revoked with strict=true while the stream was
	// open (design §2.3 HG8; gap register G1-RESIDUALS "strict-revocation
	// in-flight abort"). A non-strict revocation lets the stream complete.
	MarkerRevoked = "revoked_strict"
)

// ReconcileRequest asks the store to close reservation rows left open by a
// crash: any reservation older than OlderThan that never settled is settled at
// its reserved worst case with MarkerReconciled, so a crash can never
// UNDER-count spend (design §2.7). Now is the sweep time.
type ReconcileRequest struct {
	OlderThan time.Time
	Now       time.Time
}

// BudgetStore is the durable reservation ledger seam. Its three methods carry
// the spend-authority guarantees the design pins:
//
//   - Reserve is atomic across all scopes and writes a DURABLE row before the
//     request is forwarded (not a best-effort detached insert).
//   - Settle is idempotent.
//   - ReconcileStale is the startup sweep.
//
// The implementation lives in gwstore (SQLite, one write transaction per
// Reserve); the core only computes amounts and shapes the verdict.
type BudgetStore interface {
	// Reserve admits or denies RequestID atomically across every scope,
	// inserting a durable reservation row on admission.
	Reserve(ctx context.Context, req ReservationRequest) (ReservationOutcome, error)
	// MarkForwarded stamps RequestID's reservation as forwarded (idempotent:
	// it sets forwarded_at only where it is still unset). The handler calls it
	// immediately before dialing the upstream so a later unsettled duplicate is
	// refused 409 in_flight rather than re-dialed (G5).
	MarkForwarded(ctx context.Context, requestID string, now time.Time) error
	// Settle finalizes a reservation idempotently.
	Settle(ctx context.Context, req SettleRequest) error
	// ReconcileStale closes crash-orphaned reservations at worst-case and
	// returns how many it settled.
	ReconcileStale(ctx context.Context, req ReconcileRequest) (int, error)
}

// DenyReason is the machine-readable code in a budget-denied response body.
type DenyReason string

// ReasonBudgetExceeded is the deny code for a hard-cap hit.
const ReasonBudgetExceeded DenyReason = "budget_exceeded"

// DenyBody is the structured 402-style payload the node proxy translates into
// an agent-legible message (design §2.4.3 — written FOR the agent, same
// philosophy as the guard deny reason). It carries no secret and no content.
type DenyBody struct {
	Error        string     `json:"error"`
	Reason       DenyReason `json:"reason"`
	Level        string     `json:"level,omitempty"`
	ScopeID      string     `json:"scope_id,omitempty"`
	RemainingUSD float64    `json:"remaining_usd"`
	CapUSD       float64    `json:"cap_usd"`
	// Unit names the denomination that was exhausted ("usd" or "tokens"), and
	// the token pair carries the numbers for a token-denominated cap. A v1
	// consumer that only reads remaining_usd/cap_usd still parses this body;
	// for a token cap those two are 0, which is honest (there was no dollar
	// cap) rather than fabricated.
	Unit            string `json:"unit,omitempty"`
	RemainingTokens int64  `json:"remaining_tokens,omitempty"`
	CapTokens       int64  `json:"cap_tokens,omitempty"`
	// Estimated is always true: budget math is priced from the versioned rate
	// card, never invoice-grade (Sol S12).
	Estimated bool `json:"estimated"`
}

// NewBudgetDenyBody builds the deny payload from a denied outcome. The message
// is deliberately concrete ("daily org budget exhausted") so the coding agent
// surfaces something actionable rather than a bare 402.
func NewBudgetDenyBody(o ReservationOutcome) DenyBody {
	unit := o.DeniedUnit
	if unit == "" {
		unit = UnitUSD
	}
	noun := "spend"
	if unit == UnitTokens {
		noun = "token"
	}
	msg := "request denied: a " + noun + " cap was reached"
	if o.DeniedLevel != "" {
		msg = "request denied: the " + string(o.DeniedLevel) + " " + noun + " cap was reached (estimated)"
	}
	return DenyBody{
		Error:           msg,
		Reason:          ReasonBudgetExceeded,
		Level:           string(o.DeniedLevel),
		ScopeID:         o.DeniedScopeID,
		RemainingUSD:    o.RemainingUSD,
		CapUSD:          o.CapUSD,
		Unit:            string(unit),
		RemainingTokens: o.RemainingTokens,
		CapTokens:       o.CapTokens,
		Estimated:       true,
	}
}

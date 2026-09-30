package reprice

import (
	"math"
	"sort"
	"strings"
	"time"
)

// RuleVersion names the rule set a run was planned under. It is recorded on
// every run row so a later reader can tell which skip rules applied. Bump it
// whenever a rule in [skipRules] or [revertRules] is added, removed or
// reordered.
const RuleVersion = 1

// Epsilon is the absolute USD difference below which a re-priced figure is
// treated as unchanged. Float round-trips through SQLite REAL and PostgreSQL
// double precision are exact, so this only absorbs summation-order noise.
const Epsilon = 1e-9

// Tokens is the priced bundle of one stored row, in the cost engine's own
// vocabulary (cost.TokenBundle), restated here so this package never imports
// the engine.
type Tokens struct {
	Input             int64
	Output            int64
	CacheRead         int64
	CacheCreation     int64
	CacheCreation1h   int64
	Reasoning         int64
	WebSearchRequests int64
	// Fast is the row's fast / priority tier flag, when the store kept it.
	Fast bool
}

// Row is one stored spend row with its provenance already resolved at the
// boundary.
type Row struct {
	// Table is the store's table name ("api_turns", "summary_calls",
	// "token_usage"). Carried through to the decision; no rule reads it.
	Table string
	// ID is the row's key in its table.
	ID int64
	// Model is the stored model id.
	Model string
	// Timestamp is the row's own event time, as stored (RFC3339 / RFC3339Nano).
	Timestamp string
	// Tokens is the bundle the price is applied to.
	Tokens Tokens
	// Stored is the stored cost. nil means the row was captured with no price
	// (SQL NULL) - an unknown cost, not a free one.
	Stored *float64
	// SourceReported is true when the stored figure is the capture source's
	// OWN stated cost (a vendor-billed figure a tool records, a native
	// telemetry cost, a gateway's settled ledger figure). Such a figure is
	// never replaced. Resolved at the boundary from capability flags and the
	// row's provenance columns - never from a tool name inside this package.
	SourceReported bool
	// FastUnknown is true when this copy of the row does not carry the fast
	// tier flag (the org's copy: the flag is node-local). A model with a fast
	// tier is then skipped rather than priced at the standard rate.
	FastUnknown bool
}

// Quote is one price answer from the injected [PriceFunc].
type Quote struct {
	// USD is the row's cost at the price in force at its timestamp.
	USD float64
	// OK is false when no rate exists for the model at that time.
	OK bool
	// FastTier is true when the model carries a fast / priority premium at
	// that time (a FastMultiplier). Consulted only for a FastUnknown row.
	FastTier bool
	// Source names where the rate came from ("org", "feed", "seed", "local",
	// ...) for display. Informational; no rule reads it.
	Source string
}

// PriceFunc prices one bundle for a model at an instant. It is the one I/O
// seam of the planner: the node injects its process cost engine's ComputeAt
// (internal/orgpricing.Mode precedence), the org server an engine built from
// the seed and org_model_prices.
type PriceFunc func(model string, at time.Time, t Tokens) Quote

// Action is what a decision does to a row.
type Action string

// Actions.
const (
	ActionUpdate Action = "update"
	ActionSkip   Action = "skip"
)

// Reason explains a decision. An update carries ReasonRepriced or
// ReasonFilled; a skip carries the name of the rule that stopped it.
type Reason string

// Reasons. The skip reasons are the names of [skipRules], in order.
const (
	ReasonRepriced       Reason = "repriced"
	ReasonFilled         Reason = "filled"
	ReasonSourceReported Reason = "source_reported"
	ReasonNoModel        Reason = "no_model"
	ReasonNoTimestamp    Reason = "no_timestamp"
	ReasonNoPrice        Reason = "no_price"
	ReasonInvalidPrice   Reason = "invalid_price"
	ReasonFastUnknown    Reason = "fast_tier_unknown"
	ReasonUnchanged      Reason = "unchanged"
)

// Decision is the planner's verdict on one row.
type Decision struct {
	Table     string
	ID        int64
	Model     string
	Timestamp string
	// Old is the stored cost (nil = captured unpriced).
	Old *float64
	// New is the re-priced cost; nil on a skip.
	New    *float64
	Action Action
	Reason Reason
	// PriceSource is Quote.Source for a priced row, "" otherwise.
	PriceSource string
}

// Delta is New - Old for an update, treating an unpriced Old as 0 (the
// figure every stored-cost SUM already counted it as). 0 on a skip.
func (d Decision) Delta() float64 {
	if d.Action != ActionUpdate || d.New == nil {
		return 0
	}
	return *d.New - value(d.Old)
}

func value(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// ruleInput is what a skip rule sees: the row, its parsed time and the quote
// (the quote is only fetched once the rules that need no price have passed).
type ruleInput struct {
	row    Row
	at     time.Time
	atOK   bool
	quote  Quote
	quoted bool
}

// skipRule is one row of the ordered skip table.
type skipRule struct {
	reason Reason
	// needsQuote marks the rules evaluated only after the price is fetched.
	needsQuote bool
	when       func(in ruleInput) bool
}

// skipRules is THE ordered rule set. First match wins; a row no rule matches
// is re-priced. Order matters: the rules that need no price run first, so a
// source-reported row never costs a price lookup, and "unchanged" runs last so
// it only ever compares two real prices.
var skipRules = []skipRule{
	{reason: ReasonSourceReported, when: func(in ruleInput) bool { return in.row.SourceReported }},
	{reason: ReasonNoModel, when: func(in ruleInput) bool { return strings.TrimSpace(in.row.Model) == "" }},
	{reason: ReasonNoTimestamp, when: func(in ruleInput) bool { return !in.atOK }},
	{reason: ReasonNoPrice, needsQuote: true, when: func(in ruleInput) bool { return !in.quote.OK }},
	{reason: ReasonInvalidPrice, needsQuote: true, when: func(in ruleInput) bool {
		u := in.quote.USD
		return math.IsNaN(u) || math.IsInf(u, 0) || u < 0
	}},
	{reason: ReasonFastUnknown, needsQuote: true, when: func(in ruleInput) bool {
		return in.row.FastUnknown && in.quote.FastTier
	}},
	{reason: ReasonUnchanged, needsQuote: true, when: func(in ruleInput) bool {
		return in.row.Stored != nil && math.Abs(in.quote.USD-*in.row.Stored) <= Epsilon
	}},
}

// ParseTimestamp parses a stored row timestamp. It accepts RFC3339 with or
// without fractional seconds (Go's RFC3339Nano parser accepts both) and the
// space-separated SQLite datetime form, all read as UTC when no zone is given.
func ParseTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// Evaluate runs one row through [skipRules] and returns its decision.
func Evaluate(r Row, price PriceFunc) Decision {
	d := Decision{Table: r.Table, ID: r.ID, Model: r.Model, Timestamp: r.Timestamp, Old: copyPtr(r.Stored), Action: ActionSkip}
	in := ruleInput{row: r}
	in.at, in.atOK = ParseTimestamp(r.Timestamp)
	for _, rule := range skipRules {
		if rule.needsQuote && !in.quoted {
			if price != nil {
				in.quote = price(r.Model, in.at, r.Tokens)
			}
			in.quoted = true
		}
		if rule.when(in) {
			d.Reason = rule.reason
			if in.quoted && in.quote.OK {
				d.PriceSource = in.quote.Source
			}
			return d
		}
	}
	usd := in.quote.USD
	d.New = &usd
	d.Action = ActionUpdate
	d.PriceSource = in.quote.Source
	d.Reason = ReasonRepriced
	if r.Stored == nil {
		d.Reason = ReasonFilled
	}
	return d
}

func copyPtr(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// ModelSummary is one model's share of a plan.
type ModelSummary struct {
	Model   string  `json:"model"`
	Changed int     `json:"changed"`
	OldUSD  float64 `json:"old_usd"`
	NewUSD  float64 `json:"new_usd"`
}

// DeltaUSD is NewUSD - OldUSD.
func (m ModelSummary) DeltaUSD() float64 { return m.NewUSD - m.OldUSD }

// TableSummary is one table's share of a plan.
type TableSummary struct {
	Table   string  `json:"table"`
	Scanned int     `json:"scanned"`
	Changed int     `json:"changed"`
	OldUSD  float64 `json:"old_usd"`
	NewUSD  float64 `json:"new_usd"`
}

// Summary is the aggregate of a plan: what a dry run shows and what a run row
// records.
type Summary struct {
	Scanned int `json:"scanned"`
	Changed int `json:"changed"`
	// Filled counts the changed rows that were captured with no price and now
	// have one.
	Filled int `json:"filled"`
	// OldUSD / NewUSD sum the changed rows only (an unpriced old = 0).
	OldUSD  float64        `json:"old_usd"`
	NewUSD  float64        `json:"new_usd"`
	Skipped map[Reason]int `json:"skipped"`
	Tables  []TableSummary `json:"tables"`
	Models  []ModelSummary `json:"models"`
}

// DeltaUSD is NewUSD - OldUSD.
func (s Summary) DeltaUSD() float64 { return s.NewUSD - s.OldUSD }

// Planner accumulates decisions over a stream of rows, keeping only the
// updates (a full re-price scans every row but changes few), and summarises.
// The zero value is not usable; build one with [NewPlanner].
type Planner struct {
	price   PriceFunc
	updates []Decision
	sum     Summary
	tables  map[string]*TableSummary
	models  map[string]*ModelSummary
}

// NewPlanner returns a planner pricing through price.
func NewPlanner(price PriceFunc) *Planner {
	return &Planner{
		price:  price,
		sum:    Summary{Skipped: map[Reason]int{}},
		tables: map[string]*TableSummary{},
		models: map[string]*ModelSummary{},
	}
}

// Add evaluates one row, records it and returns its decision.
func (p *Planner) Add(r Row) Decision {
	d := Evaluate(r, p.price)
	p.sum.Scanned++
	ts := p.tables[r.Table]
	if ts == nil {
		ts = &TableSummary{Table: r.Table}
		p.tables[r.Table] = ts
	}
	ts.Scanned++
	if d.Action != ActionUpdate {
		p.sum.Skipped[d.Reason]++
		return d
	}
	p.updates = append(p.updates, d)
	p.sum.Changed++
	if d.Reason == ReasonFilled {
		p.sum.Filled++
	}
	oldV, newV := value(d.Old), value(d.New)
	p.sum.OldUSD += oldV
	p.sum.NewUSD += newV
	ts.Changed++
	ts.OldUSD += oldV
	ts.NewUSD += newV
	ms := p.models[r.Model]
	if ms == nil {
		ms = &ModelSummary{Model: r.Model}
		p.models[r.Model] = ms
	}
	ms.Changed++
	ms.OldUSD += oldV
	ms.NewUSD += newV
	return d
}

// Updates returns the update decisions recorded so far, in Add order.
func (p *Planner) Updates() []Decision { return p.updates }

// Summary returns the aggregate. Tables are sorted by name; models by the
// magnitude of their delta, largest first, then by name.
func (p *Planner) Summary() Summary {
	s := p.sum
	s.Skipped = make(map[Reason]int, len(p.sum.Skipped))
	for k, v := range p.sum.Skipped {
		s.Skipped[k] = v
	}
	s.Tables = make([]TableSummary, 0, len(p.tables))
	for _, t := range p.tables {
		s.Tables = append(s.Tables, *t)
	}
	sort.Slice(s.Tables, func(i, j int) bool { return s.Tables[i].Table < s.Tables[j].Table })
	s.Models = make([]ModelSummary, 0, len(p.models))
	for _, m := range p.models {
		s.Models = append(s.Models, *m)
	}
	sort.Slice(s.Models, func(i, j int) bool {
		a, b := math.Abs(s.Models[i].DeltaUSD()), math.Abs(s.Models[j].DeltaUSD())
		if a != b {
			return a > b
		}
		return s.Models[i].Model < s.Models[j].Model
	})
	return s
}

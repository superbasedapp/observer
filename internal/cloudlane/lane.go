package cloudlane

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// LocationUnknown is the bucket for a session whose execution_location is
// NULL: nothing stamped where it ran. It is a bucket name, not a vocabulary
// value (models.KnownExecutionLocation rejects it).
const LocationUnknown = "unknown"

// locationOrder is the fixed bucket order of a Lane: this machine first,
// then off-machine compute, then the honest unknown.
var locationOrder = []string{
	models.ExecutionLocal,
	models.ExecutionVendorCloud,
	models.ExecutionCustomerWorker,
	LocationUnknown,
}

// offMachine names the buckets whose sessions did not run on this machine.
var offMachine = map[string]bool{
	models.ExecutionVendorCloud:    true,
	models.ExecutionCustomerWorker: true,
}

// Coverage is how complete one figure is. The values match the shared
// design system's CoverageStatus (shared/primitives/copyModel.ts), so the
// web renders them with CoverageBadge directly.
type Coverage string

// Coverage states.
const (
	// CoverageFull means every session in the bucket contributed the figure.
	CoverageFull Coverage = "full"
	// CoveragePartial means some sessions contributed and some did not.
	CoveragePartial Coverage = "partial"
	// CoverageNone means the figure exists for no session although it could.
	CoverageNone Coverage = "none"
	// CoverageUnknown means nothing reported the figure: it is not a zero.
	CoverageUnknown Coverage = "unknown"
)

// Session is one project session in the window with its stamped location
// ("" when the column is NULL).
type Session struct {
	ID       string
	Location string
}

// Turn is one priced, de-duplicated turn (the cost engine's per-turn
// pipeline has already run). SessionID may be "" for a proxy turn with no
// session; such a turn lands in the unknown bucket.
type Turn struct {
	SessionID     string
	Input         int64
	Output        int64
	CacheRead     int64
	CacheCreation int64
	Reasoning     int64
	CostUSD       float64
	// Priced is false when the turn had no recorded cost and no pricing entry.
	Priced bool
	// Source is the capture path ("proxy" = api_turns, "jsonl" = token_usage).
	Source string
}

// LedgerEntry is one cloud_usage_ledger row scoped to a session.
type LedgerEntry struct {
	ID                int64
	SupersedesID      int64
	SessionID         string
	Connector         string
	Unit              string
	ValueType         string
	MeasurementSource string
	MonetaryStatus    string
	Value             float64
	ReportedAt        time.Time
}

// Account is one linked cloud connector account, without its e-mail or
// secrets: only what the coverage badge needs.
type Account struct {
	Connector      string `json:"connector"`
	Provider       string `json:"provider"`
	CoverageState  string `json:"coverage_state,omitempty"`
	LastErrorClass string `json:"last_error_class,omitempty"`
}

// Input is everything Build reads.
type Input struct {
	Sessions []Session
	Turns    []Turn
	Ledger   []LedgerEntry
	Accounts []Account
}

// Tokens are a bucket's token sums over the turns that reported them.
type Tokens struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
	Reasoning  int64 `json:"reasoning,omitempty"`
	Total      int64 `json:"total"`
}

// Provenance counts the turns each capture path contributed to a bucket.
type Provenance struct {
	Source string `json:"source"`
	Turns  int    `json:"turns"`
}

// Rollup names how a ledger group's entries became one figure.
type Rollup string

// Rollup rules.
const (
	// RollupSum adds the entries (delta and interval figures are additive).
	RollupSum Rollup = "sum"
	// RollupLatestPerSession keeps each session's newest report, then adds
	// across sessions (a cumulative counter or a run snapshot).
	RollupLatestPerSession Rollup = "latest_per_session"
	// RollupLatest keeps only the newest report (a gauge is never added).
	RollupLatest Rollup = "latest"
)

// ledgerRollups is the per-value-type rule table (CA-D11). A value type not
// listed falls back to RollupLatest, the one rule that can never add two
// reports of the same thing.
var ledgerRollups = map[string]Rollup{
	models.UsageValueDelta:      RollupSum,
	models.UsageValueInterval:   RollupSum,
	models.UsageValueCumulative: RollupLatestPerSession,
	models.UsageValueSnapshot:   RollupLatestPerSession,
	models.UsageValueGauge:      RollupLatest,
}

// LedgerFigure is one provider usage figure in its native unit.
type LedgerFigure struct {
	Connector         string   `json:"connector"`
	Unit              string   `json:"unit"`
	ValueType         string   `json:"value_type"`
	MeasurementSource string   `json:"measurement_source"`
	MonetaryStatus    string   `json:"monetary_status"`
	Rollup            Rollup   `json:"rollup"`
	Value             float64  `json:"value"`
	Entries           int      `json:"entries"`
	Sessions          int      `json:"sessions"`
	Coverage          Coverage `json:"coverage"`
}

// Bucket is one execution location's slice of a project.
type Bucket struct {
	Location string `json:"location"`
	Sessions int    `json:"sessions"`
	// SessionsWithTokens counts sessions with at least one token turn.
	SessionsWithTokens int `json:"sessions_with_tokens"`
	// Tokens is nil when no turn in the bucket reported tokens.
	Tokens        *Tokens  `json:"tokens,omitempty"`
	TokenCoverage Coverage `json:"token_coverage"`
	// CostUSD is nil when no turn in the bucket was priced.
	CostUSD *float64 `json:"cost_usd,omitempty"`
	// SessionsWithTurns counts sessions with at least one turn. A session
	// with none contributes no dollars, so the cost figure cannot be full.
	SessionsWithTurns int            `json:"sessions_with_turns"`
	Turns             int            `json:"turns"`
	UnpricedTurns     int            `json:"unpriced_turns,omitempty"`
	CostCoverage      Coverage       `json:"cost_coverage"`
	Provenance        []Provenance   `json:"provenance,omitempty"`
	Ledger            []LedgerFigure `json:"ledger,omitempty"`
}

// Lane is a project's where-it-ran summary.
type Lane struct {
	Buckets []Bucket `json:"buckets"`
	// OffMachineSessions counts vendor_cloud plus customer_worker sessions.
	OffMachineSessions int `json:"off_machine_sessions"`
	// UnknownSessions counts sessions nothing stamped a location on.
	UnknownSessions int       `json:"unknown_sessions"`
	Accounts        []Account `json:"accounts,omitempty"`
}

// bucketOf maps a stored location to its bucket name.
func bucketOf(loc string) string {
	if models.KnownExecutionLocation(loc) {
		return loc
	}
	return LocationUnknown
}

// Build buckets in by execution location. A bucket appears only when it has
// a session, a turn or a ledger entry. Buckets come back in locationOrder.
func Build(in Input) Lane {
	type acc struct {
		b          Bucket
		withTokens map[string]bool
		withTurns  map[string]bool
		tok        Tokens
		hasTok     bool
		cost       float64
		priced     int
		prov       map[string]int
		ledger     []LedgerEntry
	}
	accs := map[string]*acc{}
	get := func(name string) *acc {
		a, ok := accs[name]
		if !ok {
			a = &acc{b: Bucket{Location: name}, withTokens: map[string]bool{}, withTurns: map[string]bool{}, prov: map[string]int{}}
			accs[name] = a
		}
		return a
	}

	locOf := make(map[string]string, len(in.Sessions))
	for _, s := range in.Sessions {
		name := bucketOf(s.Location)
		if _, dup := locOf[s.ID]; dup {
			continue
		}
		locOf[s.ID] = name
		get(name).b.Sessions++
	}

	for _, t := range in.Turns {
		name, ok := locOf[t.SessionID]
		if !ok {
			name = LocationUnknown
		}
		a := get(name)
		a.b.Turns++
		if ok {
			a.withTurns[t.SessionID] = true
		}
		total := t.Input + t.Output + t.CacheRead + t.CacheCreation + t.Reasoning
		if total > 0 {
			a.hasTok = true
			a.tok.Input += t.Input
			a.tok.Output += t.Output
			a.tok.CacheRead += t.CacheRead
			a.tok.CacheWrite += t.CacheCreation
			a.tok.Reasoning += t.Reasoning
			a.tok.Total += total
			if ok {
				a.withTokens[t.SessionID] = true
			}
		}
		if t.Priced {
			a.priced++
			a.cost += t.CostUSD
		} else {
			a.b.UnpricedTurns++
		}
		src := t.Source
		if src == "" {
			src = "unknown"
		}
		a.prov[src]++
	}

	superseded := map[int64]bool{}
	for _, e := range in.Ledger {
		if e.SupersedesID != 0 {
			superseded[e.SupersedesID] = true
		}
	}
	for _, e := range in.Ledger {
		if superseded[e.ID] {
			continue
		}
		name, ok := locOf[e.SessionID]
		if !ok {
			continue // a figure for a session outside this project and window
		}
		a := get(name)
		a.ledger = append(a.ledger, e)
	}

	lane := Lane{Buckets: []Bucket{}}
	for _, name := range locationOrder {
		a, ok := accs[name]
		if !ok {
			continue
		}
		b := a.b
		b.SessionsWithTokens = len(a.withTokens)
		if a.hasTok {
			t := a.tok
			b.Tokens = &t
		}
		b.TokenCoverage = tokenCoverage(b.Sessions, b.SessionsWithTokens, a.hasTok)
		if a.priced > 0 {
			c := a.cost
			b.CostUSD = &c
		}
		b.SessionsWithTurns = len(a.withTurns)
		b.CostCoverage = costCoverage(b.Turns, b.UnpricedTurns, b.Sessions, b.SessionsWithTurns)
		for src, n := range a.prov {
			b.Provenance = append(b.Provenance, Provenance{Source: src, Turns: n})
		}
		sort.Slice(b.Provenance, func(i, j int) bool {
			if b.Provenance[i].Turns != b.Provenance[j].Turns {
				return b.Provenance[i].Turns > b.Provenance[j].Turns
			}
			return b.Provenance[i].Source < b.Provenance[j].Source
		})
		b.Ledger = rollupLedger(a.ledger, b.Sessions)
		lane.Buckets = append(lane.Buckets, b)
		if offMachine[name] {
			lane.OffMachineSessions += b.Sessions
		}
		if name == LocationUnknown {
			lane.UnknownSessions += b.Sessions
		}
	}

	lane.Accounts = append([]Account(nil), in.Accounts...)
	sort.Slice(lane.Accounts, func(i, j int) bool {
		if lane.Accounts[i].Connector != lane.Accounts[j].Connector {
			return lane.Accounts[i].Connector < lane.Accounts[j].Connector
		}
		return lane.Accounts[i].Provider < lane.Accounts[j].Provider
	})
	return lane
}

// countCoverage is the shared covered-of-total rule: nothing covered is
// UNKNOWN (the figure was not reported), never "none" and never a zero.
func countCoverage(covered, total int) Coverage {
	switch {
	case total <= 0 || covered <= 0:
		return CoverageUnknown
	case covered >= total:
		return CoverageFull
	default:
		return CoveragePartial
	}
}

// tokenCoverage says how many of a bucket's sessions reported tokens. A
// bucket holding only session-less turns that reported tokens is full.
func tokenCoverage(sessions, withTokens int, hasTokens bool) Coverage {
	if sessions == 0 {
		if hasTokens {
			return CoverageFull
		}
		return CoverageUnknown
	}
	return countCoverage(withTokens, sessions)
}

// costCoverage says how complete a bucket's dollar figure is: every turn
// priced AND every session contributing at least one turn is full. A session
// with no turns at all leaves the figure partial (its cost is unknown, not
// zero), as does an unpriced turn; nothing priced is unknown.
func costCoverage(turns, unpriced, sessions, withTurns int) Coverage {
	c := countCoverage(turns-unpriced, turns)
	if c == CoverageFull && sessions > 0 && withTurns < sessions {
		return CoveragePartial
	}
	return c
}

// ledgerKey groups entries that may be rolled up together: one connector,
// one native unit, one value type, one measurement source and one monetary
// status. Anything that differs in one of these is a different figure.
type ledgerKey struct {
	connector, unit, valueType, source, monetary string
}

// rollupLedger turns a bucket's ledger entries into figures, one per
// ledgerKey, by the ledgerRollups rule of each key's value type.
func rollupLedger(entries []LedgerEntry, bucketSessions int) []LedgerFigure {
	if len(entries) == 0 {
		return nil
	}
	groups := map[ledgerKey][]LedgerEntry{}
	for _, e := range entries {
		k := ledgerKey{e.Connector, e.Unit, e.ValueType, e.MeasurementSource, e.MonetaryStatus}
		groups[k] = append(groups[k], e)
	}
	out := make([]LedgerFigure, 0, len(groups))
	for k, es := range groups {
		rule, ok := ledgerRollups[k.valueType]
		if !ok {
			rule = RollupLatest
		}
		sessions := map[string]bool{}
		for _, e := range es {
			sessions[e.SessionID] = true
		}
		out = append(out, LedgerFigure{
			Connector:         k.connector,
			Unit:              k.unit,
			ValueType:         k.valueType,
			MeasurementSource: k.source,
			MonetaryStatus:    k.monetary,
			Rollup:            rule,
			Value:             rollupValue(rule, es),
			Entries:           len(es),
			Sessions:          len(sessions),
			Coverage:          countCoverage(len(sessions), bucketSessions),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		for _, c := range [][2]string{
			{a.Connector, b.Connector},
			{a.Unit, b.Unit},
			{a.ValueType, b.ValueType},
			{a.MeasurementSource, b.MeasurementSource},
			{a.MonetaryStatus, b.MonetaryStatus},
		} {
			if c[0] != c[1] {
				return c[0] < c[1]
			}
		}
		return false
	})
	return out
}

// newer orders two reports: later ReportedAt first, then the higher row id.
func newer(a, b LedgerEntry) bool {
	if !a.ReportedAt.Equal(b.ReportedAt) {
		return a.ReportedAt.After(b.ReportedAt)
	}
	return a.ID > b.ID
}

// rollupValue applies one rule to one group's entries.
func rollupValue(rule Rollup, es []LedgerEntry) float64 {
	switch rule {
	case RollupSum:
		var v float64
		for _, e := range es {
			v += e.Value
		}
		return v
	case RollupLatestPerSession:
		latest := map[string]LedgerEntry{}
		for _, e := range es {
			if cur, ok := latest[e.SessionID]; !ok || newer(e, cur) {
				latest[e.SessionID] = e
			}
		}
		var v float64
		for _, e := range latest {
			v += e.Value
		}
		return v
	default:
		best := es[0]
		for _, e := range es[1:] {
			if newer(e, best) {
				best = e
			}
		}
		return best.Value
	}
}

package predict

import (
	"math"
	"sort"
	"time"
)

// projection.go is the run-out projection of a usage limit (the provider's
// 5-hour and weekly subscription windows) and of a spend budget (the node's
// own [guard.budget] caps and the org budget the node composed). Pure: the
// caller loads the reading, the budget and the captured usage through their
// owning seams and hands plain values in; nothing here reads a database, the
// network or the clock (Now is an input).
//
// Honesty rules the math enforces, each with a test row:
//   - a reading whose window already reset is never projected from; only
//     the captured usage of the current window is reported, and only when
//     the window start can be inferred (a fixed-cadence window);
//   - under an hour of window, or nothing used, means no rate (NoteNotEnoughData),
//     never a made-up one;
//   - every derived figure that rests on an assumption carries an estimate
//     flag or a note code; the English lives in the dashboard's vocabulary.

// UsageRow is one (session, model) aggregate of the usage this node captured
// in a time range, over the deduplicated api_turns and token_usage substrate
// (a turn both captured counts once). Input is stored net of cache reads, and
// a transcript row's Output net of its Reasoning, so the classes add up.
type UsageRow struct {
	SessionID  string
	Model      string
	Project    string
	Input      int64
	CacheRead  int64
	CacheWrite int64
	Output     int64
	Reasoning  int64
	CostUSD    float64
	Turns      int
}

// TokenDef names which token classes a token figure counts.
type TokenDef string

const (
	// TokensAll counts every class the provider processes: input, cache
	// reads, cache writes, output and reasoning. A subscription window
	// meters processed work, so the limit projection counts everything.
	TokensAll TokenDef = "all"
	// TokensInputOutput counts input and output only: the definition the
	// guard and the org enforce a token budget with (docs/budgets.md "Token
	// vs USD cap units"), so a budget's tokens agree with its enforcement.
	TokensInputOutput TokenDef = "input_output"
)

// tokenDefs is the class table: which classes each definition adds.
var tokenDefs = map[TokenDef]func(r UsageRow) int64{
	TokensAll: func(r UsageRow) int64 {
		return r.Input + r.CacheRead + r.CacheWrite + r.Output + r.Reasoning
	},
	TokensInputOutput: func(r UsageRow) int64 { return r.Input + r.Output },
}

func (d TokenDef) of(r UsageRow) int64 {
	if f, ok := tokenDefs[d]; ok {
		return f(r)
	}
	return tokenDefs[TokensAll](r)
}

// UsageTotals is the captured usage of a window.
type UsageTotals struct {
	Tokens     int64   `json:"tokens"`
	Input      int64   `json:"input"`
	CacheRead  int64   `json:"cache_read"`
	CacheWrite int64   `json:"cache_write"`
	Output     int64   `json:"output"`
	Reasoning  int64   `json:"reasoning"`
	CostUSD    float64 `json:"cost_usd"`
	Turns      int     `json:"turns"`
	Sessions   int     `json:"sessions"`
	// Unpriced is true when some captured tokens carry no recorded cost,
	// so CostUSD is a lower bound.
	Unpriced bool `json:"unpriced,omitempty"`
}

// Summarize totals rows under a token definition.
func Summarize(rows []UsageRow, def TokenDef) UsageTotals {
	var t UsageTotals
	seen := map[string]bool{}
	for _, r := range rows {
		t.Tokens += def.of(r)
		t.Input += r.Input
		t.CacheRead += r.CacheRead
		t.CacheWrite += r.CacheWrite
		t.Output += r.Output
		t.Reasoning += r.Reasoning
		t.CostUSD += r.CostUSD
		t.Turns += r.Turns
		if r.CostUSD == 0 && def.of(r) > 0 {
			t.Unpriced = true
		}
		if !seen[r.SessionID] {
			seen[r.SessionID] = true
			t.Sessions++
		}
	}
	t.CostUSD = round6(t.CostUSD)
	return t
}

// MessageCost is the next-message band of the cost predictor, the unit
// "how many more prompts" is counted in. AllTokens is the band's billed
// tokens (turns x (prefix + fresh input + output)); NewTokens its genuinely
// new half (turns x (fresh input + output)).
type MessageCost struct {
	Has    bool
	Priced bool
	Low    MessageBand
	Mid    MessageBand
	High   MessageBand
}

// MessageBand is one column of MessageCost.
type MessageBand struct {
	USD       float64
	AllTokens float64
	NewTokens float64
}

// MessageCostOf maps an estimate onto the band the projection counts in.
func MessageCostOf(e EstimateResult) MessageCost {
	if !e.HasShape {
		return MessageCost{}
	}
	band := func(b Band) MessageBand {
		p := float64(e.PrefixTokens)
		fresh := b.Turns * float64(b.FreshInput+b.Output)
		return MessageBand{USD: b.MessageUSD, AllTokens: b.Turns*p + fresh, NewTokens: fresh}
	}
	return MessageCost{Has: true, Priced: e.HasEstimate, Low: band(e.Low), Mid: band(e.Mid), High: band(e.High)}
}

// ProjectionState is the closed state vocabulary of a projection.
type ProjectionState string

const (
	// StateLive: a current reading (limit) or a budget in force; the full
	// projection is computed.
	StateLive ProjectionState = "live"
	// StateResetInferred: the reading's window already reset, and the
	// window has a fixed cadence, so the current window's start is inferred
	// and only the captured usage since then is reported (no percent).
	StateResetInferred ProjectionState = "reset_inferred"
	// StateReset: the reading's window already reset and the current window
	// cannot be placed (a window that starts on first use). Nothing is
	// projected.
	StateReset ProjectionState = "reset"
	// StateNoResetTime: the reading carries no reset time, so the window
	// cannot be placed. Only the reading is echoed.
	StateNoResetTime ProjectionState = "no_reset_time"
	// StateRolling: a rolling budget window (no fixed reset).
	StateRolling ProjectionState = "rolling"
	// StateSession: a per-session budget cap (no time window).
	StateSession ProjectionState = "session"
)

// ProjectionNote is the closed note vocabulary; the dashboard words each.
type ProjectionNote string

const (
	NoteNotEnoughData     ProjectionNote = "not_enough_data"
	NoteCapacityTooSmall  ProjectionNote = "capacity_too_small"
	NoteCarriedForward    ProjectionNote = "carried_forward"
	NoteLocalOnly         ProjectionNote = "local_only"
	NoteReadingStale      ProjectionNote = "reading_stale"
	NoteWindowReset       ProjectionNote = "window_reset"
	NoteWindowInferred    ProjectionNote = "window_inferred"
	NoteUnpriced          ProjectionNote = "unpriced_usage"
	NoteTimezoneAssumed   ProjectionNote = "timezone_assumed_utc"
	NoteOtherMachines     ProjectionNote = "other_machines"
	NoteExhausted         ProjectionNote = "exhausted"
	NoteNoMessageEstimate ProjectionNote = "no_message_estimate"
)

// Burn is the window's consumption rate, from the usage inside it.
type Burn struct {
	// FracPerHour / FracPerDay are shares of the limit or cap.
	FracPerHour   float64 `json:"frac_per_hour"`
	FracPerDay    float64 `json:"frac_per_day"`
	TokensPerHour float64 `json:"tokens_per_hour"`
	TokensPerDay  float64 `json:"tokens_per_day"`
	USDPerHour    float64 `json:"usd_per_hour"`
	USDPerDay     float64 `json:"usd_per_day"`
	// BasisHours is the elapsed window the rate is averaged over.
	BasisHours float64 `json:"basis_hours"`
}

// Pace compares the share used with the share of the window elapsed.
type Pace struct {
	ElapsedFrac float64 `json:"elapsed_frac"`
	UsedFrac    float64 `json:"used_frac"`
	// Delta is UsedFrac - ElapsedFrac: above zero is burning faster than an
	// even spread over the window.
	Delta float64 `json:"delta"`
	// Verdict is "ahead" (faster than even), "on_pace" or "behind".
	Verdict string `json:"verdict"`
}

// RunOut is the projection at the current rate.
type RunOut struct {
	// Exhausted: the limit or cap is already used up.
	Exhausted bool `json:"exhausted,omitempty"`
	// RunsOutAtUnix is when it runs out at the current rate, set only when
	// that is before the reset (or there is no reset).
	RunsOutAtUnix *int64 `json:"runs_out_at_unix,omitempty"`
	// LastsUntilReset: at the current rate it lasts until the reset, with
	// ProjectedLeftAtResetFrac left.
	LastsUntilReset          bool     `json:"lasts_until_reset,omitempty"`
	ProjectedLeftAtResetFrac *float64 `json:"projected_left_at_reset_frac,omitempty"`
	// Safe* is what can be spent per hour / day and still last until the
	// reset: what is left spread evenly over the time to the reset.
	SafePerHourFrac   *float64 `json:"safe_per_hour_frac,omitempty"`
	SafePerDayFrac    *float64 `json:"safe_per_day_frac,omitempty"`
	SafePerHourTokens *float64 `json:"safe_per_hour_tokens,omitempty"`
	SafePerDayTokens  *float64 `json:"safe_per_day_tokens,omitempty"`
	SafePerHourUSD    *float64 `json:"safe_per_hour_usd,omitempty"`
	SafePerDayUSD     *float64 `json:"safe_per_day_usd,omitempty"`
}

// SessionStats is how the window's sessions shared it.
type SessionStats struct {
	Count      int      `json:"count"`
	ThisTokens int64    `json:"this_tokens"`
	ThisUSD    float64  `json:"this_usd"`
	ThisShare  *float64 `json:"this_share,omitempty"`
	AvgTokens  float64  `json:"avg_tokens"`
	AvgUSD     float64  `json:"avg_usd"`
}

// PromptsLeft is how many more next-messages fit in what is left, at the
// predictor's high / typical / low message (Low counts high-cost messages).
type PromptsLeft struct {
	Low  float64 `json:"low"`
	Mid  float64 `json:"mid"`
	High float64 `json:"high"`
	// Basis is "usd" or "tokens": the unit the division ran in.
	Basis string `json:"basis"`
}

// Trend compares this window's burn with the previous window's.
type Trend struct {
	PrevStartUnix int64   `json:"prev_start_unix"`
	PrevEndUnix   int64   `json:"prev_end_unix"`
	PrevTokens    int64   `json:"prev_tokens"`
	PrevUSD       float64 `json:"prev_usd"`
	PrevSessions  int     `json:"prev_sessions"`
	// RateChange is (this window's tokens per hour) / (the previous
	// window's) - 1; nil when either side has nothing to compare.
	RateChange *float64 `json:"rate_change,omitempty"`
}

// Mix is the window's token composition, as shares of the counted tokens.
type Mix struct {
	Input      float64 `json:"input"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
	Output     float64 `json:"output"`
	Reasoning  float64 `json:"reasoning"`
}

// Contributor is one model or project's share of the window.
type Contributor struct {
	Name   string  `json:"name"`
	Tokens int64   `json:"tokens"`
	USD    float64 `json:"usd"`
	Share  float64 `json:"share"`
}

// Projection is the full stat set of one limit window or budget.
type Projection struct {
	Kind  string          `json:"kind"` // "limit" | "budget"
	Key   string          `json:"key"`
	State ProjectionState `json:"state"`
	// Unit is "fraction" for a limit, "usd" or "tokens" for a budget.
	Unit     string   `json:"unit"`
	TokenDef TokenDef `json:"token_def"`
	Source   string   `json:"source,omitempty"`
	// Origin / Scope / Enforcement / Subject describe a budget.
	Origin      string `json:"origin,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Enforcement string `json:"enforcement,omitempty"`
	Subject     string `json:"subject,omitempty"`

	ObservedAtUnix  *int64   `json:"observed_at_unix,omitempty"`
	ReadingAgeSec   *int64   `json:"reading_age_sec,omitempty"`
	WindowStartUnix *int64   `json:"window_start_unix,omitempty"`
	ResetsAtUnix    *int64   `json:"resets_at_unix,omitempty"`
	WindowInferred  bool     `json:"window_inferred,omitempty"`
	LengthSec       int64    `json:"length_sec,omitempty"`
	ElapsedFrac     *float64 `json:"elapsed_frac,omitempty"`
	SecondsToReset  *int64   `json:"seconds_to_reset,omitempty"`

	// UsedFrac is the reading (limit) or spent / cap (budget). UsedFracEst
	// is the share the projection runs on: the reading carried forward by
	// the usage captured since it (UsedFracIsEstimate), else the reading.
	UsedFrac           *float64 `json:"used_frac,omitempty"`
	UsedFracEst        *float64 `json:"used_frac_est,omitempty"`
	UsedFracIsEstimate bool     `json:"used_frac_is_estimate,omitempty"`
	LeftFrac           *float64 `json:"left_frac,omitempty"`
	// Cap / Spent are a budget's own numbers in Unit.
	Cap   float64 `json:"cap,omitempty"`
	Spent float64 `json:"spent,omitempty"`

	// Used is the usage this node captured in the window.
	Used UsageTotals `json:"used"`
	// Capacity*Est is the whole limit in tokens / dollars, estimated as the
	// captured usage divided by the share used (limits only).
	CapacityTokensEst *float64 `json:"capacity_tokens_est,omitempty"`
	CapacityUSDEst    *float64 `json:"capacity_usd_est,omitempty"`
	// Left* is what is left in tokens and dollars; the *IsEstimate flags
	// mark a figure derived from the captured usage rather than the cap.
	LeftTokens           *float64 `json:"left_tokens,omitempty"`
	LeftUSD              *float64 `json:"left_usd,omitempty"`
	LeftTokensIsEstimate bool     `json:"left_tokens_is_estimate,omitempty"`
	LeftUSDIsEstimate    bool     `json:"left_usd_is_estimate,omitempty"`

	Burn            *Burn         `json:"burn,omitempty"`
	Pace            *Pace         `json:"pace,omitempty"`
	RunOut          *RunOut       `json:"run_out,omitempty"`
	Sessions        *SessionStats `json:"sessions,omitempty"`
	MoreSessionsEst *float64      `json:"more_sessions_est,omitempty"`
	MorePrompts     *PromptsLeft  `json:"more_prompts,omitempty"`
	Trend           *Trend        `json:"trend,omitempty"`
	Mix             *Mix          `json:"mix,omitempty"`
	TopModels       []Contributor `json:"top_models,omitempty"`
	TopProjects     []Contributor `json:"top_projects,omitempty"`
	// FiveHourWindowsLeft is how many full 5-hour windows fit before a weekly
	// reset (weekly limit only).
	FiveHourWindowsLeft *int `json:"five_hour_windows_left,omitempty"`
	// Confidence is "low", "medium" or "high" (the confidence rule table).
	Confidence string           `json:"confidence,omitempty"`
	Notes      []ProjectionNote `json:"notes,omitempty"`
}

// --- Limit windows -------------------------------------------------------------

// LimitKind is one row of the limit-window table.
type LimitKind struct {
	Key    string
	Length time.Duration
	// FixedCadence: the window restarts on a fixed schedule (the weekly
	// cap), so after a reset the current window's start can be inferred.
	// A window that starts on first use (the 5-hour window) cannot.
	FixedCadence bool
	// MinUsedFrac is the smallest share used a capacity estimate trusts.
	MinUsedFrac float64
}

// LimitKinds is the limit-window table, weekly first (the order surfaces
// show them in).
var LimitKinds = []LimitKind{
	{Key: "weekly", Length: 7 * 24 * time.Hour, FixedCadence: true, MinUsedFrac: 0.01},
	{Key: "5h", Length: 5 * time.Hour, FixedCadence: false, MinUsedFrac: 0.01},
}

// LimitKindFor returns the table row of a window key.
func LimitKindFor(key string) (LimitKind, bool) {
	for _, k := range LimitKinds {
		if k.Key == key {
			return k, true
		}
	}
	return LimitKind{}, false
}

// LimitReading is one observation of one window.
type LimitReading struct {
	Key        string
	UsedFrac   *float64
	ResetsAt   time.Time // zero = unknown
	Length     time.Duration
	ObservedAt time.Time // zero = unknown
	Source     string
}

// Bounds is where a window sits in time and which usage ranges the caller
// loads for it.
type Bounds struct {
	State    ProjectionState
	Start    time.Time
	Reset    time.Time
	Length   time.Duration
	Inferred bool
	// SinceReading: load the usage since the reading (it was observed
	// inside the window, so it can be carried forward).
	SinceReading bool
	// PrevStart / PrevEnd is the previous window of the same length (zero
	// when there is none to compare).
	PrevStart time.Time
	PrevEnd   time.Time
}

// boundsRule is one row of the limit-window state table, walked top-down.
type boundsRule struct {
	state ProjectionState
	match func(r LimitReading, k LimitKind, now time.Time) bool
}

var limitBoundsRules = []boundsRule{
	{StateNoResetTime, func(r LimitReading, _ LimitKind, _ time.Time) bool { return r.ResetsAt.IsZero() }},
	{StateLive, func(r LimitReading, _ LimitKind, now time.Time) bool { return r.ResetsAt.After(now) }},
	{StateResetInferred, func(_ LimitReading, k LimitKind, _ time.Time) bool { return k.FixedCadence }},
	{StateReset, func(LimitReading, LimitKind, time.Time) bool { return true }},
}

// LimitBounds places a reading's window in time.
func LimitBounds(r LimitReading, now time.Time) Bounds {
	k, _ := LimitKindFor(r.Key)
	length := r.Length
	if length <= 0 {
		length = k.Length
	}
	b := Bounds{Length: length}
	for _, rule := range limitBoundsRules {
		if rule.match(r, k, now) {
			b.State = rule.state
			break
		}
	}
	if length <= 0 {
		if b.State == StateLive || b.State == StateResetInferred {
			b.State = StateNoResetTime
		}
		return b
	}
	switch b.State {
	case StateLive:
		b.Reset = r.ResetsAt
		b.Start = r.ResetsAt.Add(-length)
		b.SinceReading = !r.ObservedAt.IsZero() && r.ObservedAt.After(b.Start) && now.Sub(r.ObservedAt) >= carryForwardAfter
	case StateResetInferred:
		// The window restarts every `length` from the last known reset.
		n := now.Sub(r.ResetsAt) / length
		b.Start = r.ResetsAt.Add(n * length)
		b.Reset = b.Start.Add(length)
		b.Inferred = true
	default:
		return b
	}
	b.PrevStart, b.PrevEnd = b.Start.Add(-length), b.Start
	return b
}

// carryForwardAfter is how old a reading must be before the projection
// carries it forward with the usage captured since.
const carryForwardAfter = 10 * time.Minute

// staleAfter is the reading age past which a note says so.
const staleAfter = 6 * time.Hour

// minBasis is the least elapsed window a rate is averaged over.
const minBasis = time.Hour

// LimitInput is everything ProjectLimit reads. Window, SinceReading and
// Previous are the usage the caller loaded for LimitBounds' ranges.
type LimitInput struct {
	Now          time.Time
	Reading      LimitReading
	SessionID    string
	Window       []UsageRow
	SinceReading []UsageRow
	Previous     []UsageRow
	Message      MessageCost
}

// ProjectLimit computes the stat set of one limit window.
func ProjectLimit(in LimitInput) Projection {
	r := in.Reading
	b := LimitBounds(r, in.Now)
	p := Projection{Kind: "limit", Key: r.Key, State: b.State, Unit: "fraction", TokenDef: TokensAll, Source: r.Source, UsedFrac: r.UsedFrac}
	if !r.ObservedAt.IsZero() {
		u := r.ObservedAt.Unix()
		p.ObservedAtUnix = &u
		age := int64(in.Now.Sub(r.ObservedAt).Seconds())
		p.ReadingAgeSec = &age
		if in.Now.Sub(r.ObservedAt) > staleAfter {
			p.addNote(NoteReadingStale)
		}
	}
	if !r.ResetsAt.IsZero() {
		u := r.ResetsAt.Unix()
		p.ResetsAtUnix = &u
	}
	switch b.State {
	case StateNoResetTime:
		return p
	case StateReset:
		p.addNote(NoteWindowReset)
		return p
	}
	p.placeWindow(b, in.Now)
	if b.State == StateResetInferred {
		// The reading measured a window that is over: no percent for the
		// current one, only what this node captured since it started.
		p.ResetsAtUnix = unixPtr(b.Reset)
		p.UsedFrac = nil
		p.addNote(NoteWindowReset)
		p.addNote(NoteWindowInferred)
		p.WindowInferred = true
	}

	p.Used = Summarize(in.Window, TokensAll)
	if p.Used.Unpriced {
		p.addNote(NoteUnpriced)
	}
	p.fillShared(in.Window, in.Previous, b, in.SessionID, in.Now, TokensAll)
	p.fiveHourWindows(b, in.Now)

	elapsed := in.Now.Sub(b.Start)
	if b.State == StateResetInferred || r.UsedFrac == nil {
		p.burnFromUsage(elapsed)
		p.Confidence = confidenceOf(p, elapsed, b.Length)
		return p
	}

	// Live reading: capacity, carry-forward, burn, run-out.
	k, _ := LimitKindFor(r.Key)
	used := *r.UsedFrac
	since := Summarize(in.SinceReading, TokensAll)
	atReadingTokens := p.Used.Tokens - since.Tokens
	atReadingUSD := p.Used.CostUSD - since.CostUSD
	usedEst := used
	if used >= k.MinUsedFrac && atReadingTokens > 0 {
		capT := float64(atReadingTokens) / used
		p.CapacityTokensEst = f64(math.Round(capT))
		if atReadingUSD > 0 && !p.Used.Unpriced {
			p.CapacityUSDEst = f64(round6(atReadingUSD / used))
		}
		if b.SinceReading && since.Tokens > 0 {
			usedEst = used + float64(since.Tokens)/capT
			p.UsedFracIsEstimate = true
			p.addNote(NoteCarriedForward)
		}
		p.addNote(NoteLocalOnly)
	} else if used > 0 && used < k.MinUsedFrac {
		p.addNote(NoteCapacityTooSmall)
	}
	p.UsedFracEst = f64(usedEst)
	left := math.Max(0, 1-usedEst)
	p.LeftFrac = f64(left)
	if p.CapacityTokensEst != nil {
		p.LeftTokens = f64(math.Round(*p.CapacityTokensEst * left))
		p.LeftTokensIsEstimate = true
	}
	if p.CapacityUSDEst != nil {
		p.LeftUSD = f64(round6(*p.CapacityUSDEst * left))
		p.LeftUSDIsEstimate = true
	}

	p.pace(usedEst, b, in.Now)
	switch {
	case usedEst >= 1:
		p.RunOut = &RunOut{Exhausted: true}
		p.addNote(NoteExhausted)
	case elapsed < minBasis || usedEst <= 0:
		p.addNote(NoteNotEnoughData)
	default:
		hours := elapsed.Hours()
		p.Burn = &Burn{
			FracPerHour: usedEst / hours, FracPerDay: usedEst / hours * 24,
			TokensPerHour: float64(p.Used.Tokens) / hours, TokensPerDay: float64(p.Used.Tokens) / hours * 24,
			USDPerHour: p.Used.CostUSD / hours, USDPerDay: p.Used.CostUSD / hours * 24,
			BasisHours: round1(hours),
		}
		p.RunOut = runOut(usedEst, p.Burn.FracPerHour, b.Reset, in.Now, p.CapacityTokensEst, p.CapacityUSDEst)
	}
	p.leftInUnits(in.Message, TokensAll)
	p.Confidence = confidenceOf(p, elapsed, b.Length)
	return p
}

// --- Budgets ---------------------------------------------------------------------

// BudgetWindow is one budget in force with the spend its owner measured.
type BudgetWindow struct {
	// Key is "session", "daily", "weekly" or "monthly".
	Key string
	// Origin is "node" (the node's own [guard.budget]) or "org".
	Origin      string
	Unit        string // "usd" | "tokens"
	Cap         float64
	Spent       float64
	Start       time.Time // zero for a session cap
	Reset       time.Time // zero for a rolling window or a session cap
	Rolling     bool
	Length      time.Duration // a rolling window's length
	Scope       string
	Enforcement string
	Subject     string
	// TimezoneAssumed: the period's timezone is not known, UTC is assumed.
	TimezoneAssumed bool
	// OtherMachines: the spend includes other machines of the same
	// developer, which the captured usage here does not.
	OtherMachines bool
}

// BudgetBounds returns the usage ranges the caller loads for a budget:
// the window [start, now) and the previous window of the same kind.
func BudgetBounds(w BudgetWindow, now time.Time) Bounds {
	b := Bounds{Start: w.Start, Reset: w.Reset, Length: w.Length}
	switch {
	case w.Key == "session" || w.Start.IsZero():
		b.State = StateSession
		return b
	case w.Rolling:
		b.State = StateRolling
		if b.Length <= 0 {
			b.Length = now.Sub(w.Start)
		}
	default:
		b.State = StateLive
		b.Length = w.Reset.Sub(w.Start)
	}
	if b.Length > 0 {
		b.PrevStart, b.PrevEnd = w.Start.Add(-b.Length), w.Start
	}
	return b
}

// BudgetInput is everything ProjectBudget reads. Rows is the usage since the
// budget's start (the session's own usage for a session cap); Previous the
// previous window's.
type BudgetInput struct {
	Now       time.Time
	Window    BudgetWindow
	SessionID string
	Rows      []UsageRow
	Previous  []UsageRow
	Message   MessageCost
}

// ProjectBudget computes the stat set of one budget: the cap-only half
// (budgetCore, shared with the org Budgets page through ProjectBudgetCap)
// with the node's captured usage layered on top: the token and dollar burn
// of that usage, sessions, trend, token mix, top contributors, the other
// unit's estimate, prompts left and the confidence level.
func ProjectBudget(in BudgetInput) Projection {
	w := in.Window
	used := Summarize(in.Rows, TokensInputOutput)
	usdPerTok := 0.0
	if used.Tokens > 0 && used.CostUSD > 0 && !used.Unpriced {
		usdPerTok = used.CostUSD / float64(used.Tokens)
	}
	p, hours := budgetCore(in.Now, w, usdPerTok, used.Unpriced)
	if w.Cap <= 0 {
		return p
	}
	p.Used = used
	b := BudgetBounds(w, in.Now)
	if b.State != StateSession {
		p.fillShared(in.Rows, in.Previous, b, in.SessionID, in.Now, TokensInputOutput)
	}
	if p.Burn != nil && hours > 0 {
		// The node's token and dollar rates are its captured usage's, on the
		// same basis hours as the share of the cap.
		p.Burn.TokensPerHour, p.Burn.TokensPerDay = float64(used.Tokens)/hours, float64(used.Tokens)/hours*24
		p.Burn.USDPerHour, p.Burn.USDPerDay = used.CostUSD/hours, used.CostUSD/hours*24
	}
	p.leftInUnits(in.Message, TokensInputOutput)
	p.Confidence = confidenceOf(p, in.Now.Sub(w.Start), b.Length)
	return p
}

// budgetCapacities is the cap in tokens and dollars: exact in its own unit,
// through the captured dollars per token in the other.
func budgetCapacities(w BudgetWindow, usdPerTok float64) (tokens, usd *float64) {
	if w.Unit == "tokens" {
		tokens = f64(w.Cap)
		if usdPerTok > 0 {
			usd = f64(w.Cap * usdPerTok)
		}
		return tokens, usd
	}
	usd = f64(w.Cap)
	if usdPerTok > 0 {
		tokens = f64(w.Cap / usdPerTok)
	}
	return tokens, usd
}

// --- Shared math -----------------------------------------------------------------

func (p *Projection) addNote(n ProjectionNote) {
	for _, have := range p.Notes {
		if have == n {
			return
		}
	}
	p.Notes = append(p.Notes, n)
}

// placeWindow fills the window's start, reset, elapsed share and time left.
func (p *Projection) placeWindow(b Bounds, now time.Time) {
	p.WindowStartUnix = unixPtr(b.Start)
	if !b.Reset.IsZero() {
		p.ResetsAtUnix = unixPtr(b.Reset)
		s := int64(math.Max(0, b.Reset.Sub(now).Seconds()))
		p.SecondsToReset = &s
	}
	if b.Length > 0 {
		p.LengthSec = int64(b.Length.Seconds())
		e := now.Sub(b.Start).Seconds() / b.Length.Seconds()
		p.ElapsedFrac = f64(math.Min(1, math.Max(0, e)))
	}
}

// fillShared fills the sessions, trend, mix and top contributors.
func (p *Projection) fillShared(rows, prev []UsageRow, b Bounds, sessionID string, now time.Time, def TokenDef) {
	t := p.Used
	if t.Sessions > 0 {
		ss := &SessionStats{Count: t.Sessions, AvgTokens: float64(t.Tokens) / float64(t.Sessions), AvgUSD: round6(t.CostUSD / float64(t.Sessions))}
		for _, r := range rows {
			if r.SessionID == sessionID {
				ss.ThisTokens += def.of(r)
				ss.ThisUSD += r.CostUSD
			}
		}
		ss.ThisUSD = round6(ss.ThisUSD)
		if t.CostUSD > 0 && !t.Unpriced {
			ss.ThisShare = f64(ss.ThisUSD / t.CostUSD)
		} else if t.Tokens > 0 {
			ss.ThisShare = f64(float64(ss.ThisTokens) / float64(t.Tokens))
		}
		p.Sessions = ss
	}
	if t.Tokens > 0 {
		den := float64(t.Input + t.CacheRead + t.CacheWrite + t.Output + t.Reasoning)
		if den > 0 {
			p.Mix = &Mix{
				Input: float64(t.Input) / den, CacheRead: float64(t.CacheRead) / den, CacheWrite: float64(t.CacheWrite) / den,
				Output: float64(t.Output) / den, Reasoning: float64(t.Reasoning) / den,
			}
		}
	}
	p.TopModels = topContributors(rows, def, func(r UsageRow) string { return r.Model })
	p.TopProjects = topContributors(rows, def, func(r UsageRow) string { return r.Project })
	if !b.PrevStart.IsZero() && b.PrevEnd.After(b.PrevStart) {
		pt := Summarize(prev, def)
		tr := &Trend{PrevStartUnix: b.PrevStart.Unix(), PrevEndUnix: b.PrevEnd.Unix(), PrevTokens: pt.Tokens, PrevUSD: pt.CostUSD, PrevSessions: pt.Sessions}
		elapsed := now.Sub(b.Start)
		if pt.Tokens > 0 && t.Tokens > 0 && elapsed >= minBasis {
			cur := float64(t.Tokens) / elapsed.Hours()
			was := float64(pt.Tokens) / b.PrevEnd.Sub(b.PrevStart).Hours()
			tr.RateChange = f64(cur/was - 1)
		}
		p.Trend = tr
	}
}

// burnFromUsage is the rate of a window without a share reading: tokens and
// dollars per hour only.
func (p *Projection) burnFromUsage(elapsed time.Duration) {
	if elapsed < minBasis || p.Used.Tokens <= 0 {
		p.addNote(NoteNotEnoughData)
		return
	}
	h := elapsed.Hours()
	p.Burn = &Burn{
		TokensPerHour: float64(p.Used.Tokens) / h, TokensPerDay: float64(p.Used.Tokens) / h * 24,
		USDPerHour: p.Used.CostUSD / h, USDPerDay: p.Used.CostUSD / h * 24, BasisHours: round1(h),
	}
}

// paceBand is the half-width of "on pace", as a share of the window.
const paceBand = 0.05

// pace compares used with elapsed.
func (p *Projection) pace(used float64, b Bounds, now time.Time) {
	if b.Length <= 0 {
		return
	}
	e := math.Min(1, math.Max(0, now.Sub(b.Start).Seconds()/b.Length.Seconds()))
	d := used - e
	v := "on_pace"
	switch {
	case d > paceBand:
		v = "ahead"
	case d < -paceBand:
		v = "behind"
	}
	p.Pace = &Pace{ElapsedFrac: e, UsedFrac: used, Delta: d, Verdict: v}
}

// runOut projects a share used at a per-hour rate to the reset.
func runOut(used, perHour float64, reset, now time.Time, capT, capU *float64) *RunOut {
	ro := &RunOut{}
	left := math.Max(0, 1-used)
	if perHour > 0 {
		hoursLeft := left / perHour
		at := now.Add(time.Duration(hoursLeft * float64(time.Hour)))
		if reset.IsZero() || at.Before(reset) {
			u := at.Unix()
			ro.RunsOutAtUnix = &u
		} else {
			ro.LastsUntilReset = true
			ro.ProjectedLeftAtResetFrac = f64(math.Max(0, 1-(used+perHour*reset.Sub(now).Hours())))
		}
	}
	if !reset.IsZero() {
		h := reset.Sub(now).Hours()
		if h > 0 {
			ph := left / h
			ro.SafePerHourFrac = f64(ph)
			ro.SafePerDayFrac = f64(math.Min(left, ph*24))
			if capT != nil {
				ro.SafePerHourTokens = f64(math.Round(ph * *capT))
				ro.SafePerDayTokens = f64(math.Round(*ro.SafePerDayFrac * *capT))
			}
			if capU != nil {
				ro.SafePerHourUSD = f64(round6(ph * *capU))
				ro.SafePerDayUSD = f64(round6(*ro.SafePerDayFrac * *capU))
			}
		}
	}
	return ro
}

// leftInUnits fills "more sessions" and "more prompts" from what is left.
func (p *Projection) leftInUnits(m MessageCost, def TokenDef) {
	if s := p.Sessions; s != nil && s.Count > 0 {
		switch {
		case p.LeftUSD != nil && s.AvgUSD > 0:
			p.MoreSessionsEst = f64(round1(*p.LeftUSD / s.AvgUSD))
		case p.LeftTokens != nil && s.AvgTokens > 0:
			p.MoreSessionsEst = f64(round1(*p.LeftTokens / s.AvgTokens))
		}
	}
	if !m.Has {
		if p.LeftUSD != nil || p.LeftTokens != nil {
			p.addNote(NoteNoMessageEstimate)
		}
		return
	}
	tok := func(b MessageBand) float64 {
		if def == TokensInputOutput {
			return b.NewTokens
		}
		return b.AllTokens
	}
	div := func(left, per float64) float64 {
		if per <= 0 {
			return 0
		}
		return round1(left / per)
	}
	switch {
	case p.LeftUSD != nil && m.Priced && m.Mid.USD > 0:
		l := *p.LeftUSD
		p.MorePrompts = &PromptsLeft{Low: div(l, m.High.USD), Mid: div(l, m.Mid.USD), High: div(l, m.Low.USD), Basis: "usd"}
	case p.LeftTokens != nil && tok(m.Mid) > 0:
		l := *p.LeftTokens
		p.MorePrompts = &PromptsLeft{Low: div(l, tok(m.High)), Mid: div(l, tok(m.Mid)), High: div(l, tok(m.Low)), Basis: "tokens"}
	}
}

// fiveHourWindows counts the full 5-hour windows left before a weekly reset.
func (p *Projection) fiveHourWindows(b Bounds, now time.Time) {
	if p.Key != "weekly" || b.Reset.IsZero() {
		return
	}
	n := int(math.Max(0, math.Floor(b.Reset.Sub(now).Hours()/5)))
	p.FiveHourWindowsLeft = &n
}

// topN is how many contributors a projection lists.
const topN = 3

// topContributors ranks rows by dollars (tokens when no dollars) per key.
func topContributors(rows []UsageRow, def TokenDef, key func(UsageRow) string) []Contributor {
	agg := map[string]*Contributor{}
	var totT int64
	var totU float64
	for _, r := range rows {
		k := key(r)
		if k == "" {
			k = "unknown"
		}
		c, ok := agg[k]
		if !ok {
			c = &Contributor{Name: k}
			agg[k] = c
		}
		t := def.of(r)
		c.Tokens += t
		c.USD += r.CostUSD
		totT += t
		totU += r.CostUSD
	}
	if len(agg) < 2 {
		return nil // one contributor is no ranking
	}
	out := make([]Contributor, 0, len(agg))
	byUSD := totU > 0
	for _, c := range agg {
		c.USD = round6(c.USD)
		if byUSD {
			c.Share = c.USD / totU
		} else if totT > 0 {
			c.Share = float64(c.Tokens) / float64(totT)
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Share != out[j].Share {
			return out[i].Share > out[j].Share
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// confidenceRule is one row of the confidence table, walked top-down.
type confidenceRule struct {
	level string
	match func(f confFacts) bool
}

type confFacts struct {
	hasBurn     bool
	turns       int
	sessions    int
	elapsedFrac float64
	ageHours    float64
	carried     bool
}

var confidenceRules = []confidenceRule{
	{"", func(f confFacts) bool { return !f.hasBurn }},
	{"low", func(f confFacts) bool { return f.turns < 10 || f.elapsedFrac < 0.05 }},
	{"medium", func(f confFacts) bool {
		return f.elapsedFrac < 0.25 || f.ageHours > staleAfter.Hours() || f.sessions < 2 || f.carried
	}},
	{"high", func(confFacts) bool { return true }},
}

func confidenceOf(p Projection, elapsed, length time.Duration) string {
	f := confFacts{hasBurn: p.Burn != nil, turns: p.Used.Turns, sessions: p.Used.Sessions, carried: p.UsedFracIsEstimate}
	if length > 0 {
		f.elapsedFrac = elapsed.Seconds() / length.Seconds()
	} else {
		f.elapsedFrac = 1
	}
	if p.ReadingAgeSec != nil {
		f.ageHours = float64(*p.ReadingAgeSec) / 3600
	}
	for _, r := range confidenceRules {
		if r.match(f) {
			return r.level
		}
	}
	return ""
}

func f64(v float64) *float64 { return &v }

func unixPtr(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	u := t.Unix()
	return &u
}

func round6(x float64) float64 { return math.Round(x*1e6) / 1e6 }

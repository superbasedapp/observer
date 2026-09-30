package sessiongauge

import (
	"regexp"
	"strconv"
)

// Turn is one COUNTED turn row of a session: a row the one session rule
// (sessionmsg.DeriveVerdicts) keeps, a proxy row carrying its transcript
// twin's visible output. Only the fields the gauges read are carried.
type Turn struct {
	// Timestamp is the row's stored timestamp text. Rows are compared by
	// plain text order, the order both engines' substrates already use.
	Timestamp string
	// Model is the row's model after the per-session default (a blank model
	// takes sessions.model), as both engines' loaders already apply it.
	Model     string
	Input     int64
	Output    int64
	CacheRead int64
}

// LatestPrefix is the running cache prefix "now": the newest non-zero
// cache_read over the turns. On a timestamp tie the larger prefix wins (the
// cache prefix grows monotonically across a session, so the larger is the
// later state). 0 when no turn carried a cached prefix (an uncached provider,
// or nothing observed yet). Order-independent by construction.
func LatestPrefix(turns []Turn) int64 {
	var bestTS string
	var best int64
	for _, t := range turns {
		if t.CacheRead <= 0 {
			continue
		}
		if t.Timestamp > bestTS || (t.Timestamp == bestTS && t.CacheRead > best) {
			bestTS, best = t.Timestamp, t.CacheRead
		}
	}
	return best
}

// Observed reports whether any turn carried usage at all (input or output),
// the predictor's has_shape: it separates "nothing observed yet" from
// "observed turns on an uncached provider" when LatestPrefix is 0.
func Observed(turns []Turn) bool {
	for _, t := range turns {
		if t.Input != 0 || t.Output != 0 {
			return true
		}
	}
	return false
}

// DominantModel is the model with the largest input+output volume over the
// turns (ties by model name), "" when no turn carries a model: the fallback
// for a session whose sessions.model is empty.
func DominantModel(turns []Turn) string {
	vol := map[string]int64{}
	for _, t := range turns {
		if t.Model != "" {
			vol[t.Model] += t.Input + t.Output
		}
	}
	best, bestVol := "", int64(-1)
	for m, v := range vol {
		if v > bestVol || (v == bestVol && m < best) {
			best, bestVol = m, v
		}
	}
	return best
}

// Budget sources, the vocabulary of ContextGauge.BudgetSource.
const (
	// BudgetReported is the session's own reported context budget (the
	// carried prompt-context token counts some tools record per request).
	BudgetReported = "reported"
	// BudgetModelWindow is the model's context window from the pricing
	// catalog (the signed feed's economics.context_window_tokens).
	BudgetModelWindow = "model_window"
)

// ContextInput is everything the context gauge reads. Both engines fill it
// from their own stores; the arithmetic is Context's alone.
type ContextInput struct {
	// Turns are the session's counted turn rows (see Turn).
	Turns []Turn
	// SessionModel is sessions.model ("" when the session row carries
	// none; DominantModel(Turns) is then the session's model).
	SessionModel string
	// ReportedBudget is the session's own reported context budget in tokens
	// (the node's sum of prompt_context counts); 0 = none reported.
	ReportedBudget int64
	// Windows is the caller's pricing catalog's model context windows (see
	// ModelWindows); nil or empty = every model's window is unknown.
	Windows Windows
}

// model is the session's model: sessions.model, else the dominant turn model.
func (in ContextInput) model() string {
	if in.SessionModel != "" {
		return in.SessionModel
	}
	return DominantModel(in.Turns)
}

// ContextGauge is the context-window gauge. A zero UsedTokens with Observed
// false is "nothing observed yet"; with Observed true it is "observed turns,
// but none carried a cached prefix". Ratio is nil whenever either side of the
// fraction is unknown - a surface renders that as unknown, never 0%.
type ContextGauge struct {
	// UsedTokens is the running cache prefix (LatestPrefix).
	UsedTokens int64 `json:"used_tokens"`
	// Observed is Observed(Turns).
	Observed bool `json:"observed"`
	// Model is the model the catalog window was looked up for (the
	// session's model); empty when no model is known.
	Model string `json:"model,omitempty"`
	// BudgetTokens / BudgetSource are the ceiling and where it came from;
	// both empty when no ceiling is known.
	BudgetTokens int64  `json:"budget_tokens,omitempty"`
	BudgetSource string `json:"budget_source,omitempty"`
	// Ratio is UsedTokens / BudgetTokens in 0..1; nil when unknown.
	Ratio *float64 `json:"ratio,omitempty"`
	// OverWindow is true when the prefix EXCEEDS the catalog's model window:
	// the catalog number is evidently not this session's real ceiling (a
	// larger-context variant of the model), so the ratio is left unknown
	// rather than pinned at a false 100%.
	OverWindow bool `json:"over_window,omitempty"`
}

// budgetRule is one rung of the ceiling ladder: the first rung with a
// positive value wins. clip says how a prefix larger than the ceiling is
// read: a REPORTED budget is the session's own number and is clipped to a
// full ring (the node gauge's behaviour since it shipped); a catalog window a
// real prefix exceeds is simply wrong for this session and yields unknown.
type budgetRule struct {
	source string
	value  func(ContextInput) int64
	clip   bool
}

// budgetLadder is the ordered ceiling table, walked top-down.
var budgetLadder = []budgetRule{
	{source: BudgetReported, value: func(in ContextInput) int64 { return in.ReportedBudget }, clip: true},
	{source: BudgetModelWindow, value: func(in ContextInput) int64 { return in.Windows.WindowFor(in.model()) }, clip: false},
}

// Context derives the context-window gauge from in.
func Context(in ContextInput) ContextGauge {
	g := ContextGauge{UsedTokens: LatestPrefix(in.Turns), Observed: Observed(in.Turns), Model: in.model()}
	for _, rule := range budgetLadder {
		budget := rule.value(in)
		if budget <= 0 {
			continue
		}
		g.BudgetTokens, g.BudgetSource = budget, rule.source
		if g.UsedTokens <= 0 {
			return g
		}
		ratio := float64(g.UsedTokens) / float64(budget)
		if ratio > 1 {
			if !rule.clip {
				g.OverWindow = true
				return g
			}
			ratio = 1
		}
		g.Ratio = &ratio
		return g
	}
	return g
}

// promptContextTokensRe extracts the token count from a prompt_context
// action's target ("Rules - 15580 tokens, 61924 chars"). The format is
// adapter-controlled (cursor.promptSectionEvent) and stable.
var promptContextTokensRe = regexp.MustCompile(`(\d+)\s+tokens`)

// ReportedBudget sums the carried context budget from a session's
// prompt_context action targets (a tool's per-section prompt-token counts).
// These tokens are part of a turn's input but never billed on their own, so
// the sum is only ever an estimate of carried context and must NOT feed cost.
// A target without a count contributes nothing; 0 when none carries one.
func ReportedBudget(targets []string) int64 {
	var total int64
	for _, target := range targets {
		m := promptContextTokensRe.FindStringSubmatch(target)
		if m == nil {
			continue
		}
		if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			total += v
		}
	}
	return total
}

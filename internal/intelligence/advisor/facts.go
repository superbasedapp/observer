package advisor

import "time"

// Facts is the one seam between data loading and detection: a read-only
// bundle the engine loads once per run. Detectors receive it plus
// Thresholds and stay pure.
type Facts struct {
	WindowDays int
	Now        time.Time
	Sessions   []SessionFacts
	Price      PriceFn
	// LCThreshold returns the model's long-context threshold in tokens
	// (0 = the model has no LC tier). Backed by the pricing table.
	LCThreshold func(model string) int64

	// Phase-2 fact groups.
	CacheEvents   map[string][]CacheEventFact // session_id → cachetrack verdicts
	Failures      []FailureFact               // failure_context rollup (window)
	MCPCalls      int                         // mcp_audit calls in window
	MCPDenied     int                         // subset with response_ok = 0
	MCPConfigured bool                        // [intelligence.mcp] enabled (injected)
	Scores        []SessionScores             // scoring-engine persisted metrics, started_at ASC

	// X3.1 fact groups (security/routing usability arc). The mode
	// strings and the shadow signal are INJECTED by callers (the
	// MCPConfigured pattern — the advisor never reads config files or
	// re-derives the §R22 gate); the guard counts load here.
	GuardMode            string        // effective [guard] mode ("off" when disabled)
	GuardHighSevEvents   int           // guard_events at high/critical severity in window
	GuardActiveApprovals int           // unexpired guard_approvals rows
	RoutingMode          string        // effective [routing] mode ("off" when disabled)
	RoutingShadow        *ShadowSignal // §R22 gate read; nil = not computed / no advise history
}

// ShadowSignal is the injected §R22 advise-shadow gate read — the
// routing_evidence_ready detector's input. Callers map it from
// store.AdviseShadowSignal (which composes BuildAdviseShadowReport,
// the ONE owner of the gate) so the advisor can never drift from the
// Shadow card's verdict.
type ShadowSignal struct {
	AdviseDecisions int
	WouldReroute    int
	WouldSaveUSD    float64
	QualityFlags    int
	MinDecisions    int
	Ready           bool
}

// CacheEventFact is one cachetrack verdict (cache_events row) — the advisor
// consumes cachetrack's attribution, never re-derives it (one owner per
// table).
type CacheEventFact struct {
	Kind          string
	Cause         string
	TokensRead    int64
	TokensWritten int64
	CostDeltaUSD  float64
}

// FailureFact is one (project, command) failure group from failure_context.
type FailureFact struct {
	Project   string
	Command   string
	Fails     int
	Retries   int
	Recovered bool // any failure in the group eventually succeeded
}

// ActionMix is a session's action-type histogram (Phase-2 loaders).
type ActionMix struct {
	Total      int
	Reads      int // read_file + search_text + search_files
	Edits      int // edit_file + write_file
	EffortHigh int // actions stamped effort_level xhigh|max
}

// SessionFacts is one session's ordered per-turn token rows after the
// proxy∪JSONL shape dedup (see load.go).
type SessionFacts struct {
	ID          string
	Tool        string
	Model       string // session-level model (fallback when a row's is empty)
	ProjectRoot string
	Rows        []TurnFact
	// ContextWindow is the model's context window from the Tokenomics
	// data (Options.ContextWindow); zero = not known there.
	ContextWindow int64
	// Phase-2 enrichment.
	Mix             ActionMix
	CompressionOrig int64 // Σ api_turns.compression_original_bytes
	CompressionOut  int64 // Σ api_turns.compression_compressed_bytes
	// HandoffTarget is true when this session is the stamped target
	// of a session handoff (handoffs.target_session_id). Its first
	// turn / first cache event is a large cold rehydration write BY
	// DESIGN, so the balloon + cache-write-waste detectors exempt
	// that leading row. Loaded read-only from the node-local
	// handoffs table (see loadPhase2). This is the retroactive belt
	// that covers non-proxied handoff targets whose live
	// cachetrack handoff_rehydration flag never fired.
	HandoffTarget bool
}

// HasProxy reports whether any row came from the proxy path.
func (s *SessionFacts) HasProxy() bool {
	for _, r := range s.Rows {
		if r.Source == "proxy" {
			return true
		}
	}
	return false
}

// totals sums the session's token bundle (gross, all rows).
func (s *SessionFacts) totals() (in, out, cr, cc, cc1, reasoning int64, anyFast bool) {
	for _, r := range s.Rows {
		in += r.Input
		out += r.Output
		cr += r.CacheRead
		cc += r.CacheCreation
		cc1 += r.CacheCreation1h
		reasoning += r.Reasoning
		anyFast = anyFast || r.Fast
	}
	return
}

// TurnFact is one captured turn's token shape. Window() is the prompt
// window the balloon economics run on.
type TurnFact struct {
	TS              time.Time
	Model           string
	Input           int64
	Output          int64
	CacheRead       int64
	CacheCreation   int64
	CacheCreation1h int64
	Reasoning       int64
	Fast            bool
	Source          string // "proxy" | "jsonl"
}

// Window is the prompt window: everything the provider processed on the
// input side this turn.
func (t TurnFact) Window() int64 {
	return t.Input + t.CacheRead + t.CacheCreation
}

// rowModel resolves a row's model with the session-level fallback.
func rowModel(s *SessionFacts, r TurnFact) string {
	if r.Model != "" {
		return r.Model
	}
	return s.Model
}

// segments splits a session's rows at idle gaps > gapMinutes. The first
// segment anchors the per-turn cost baseline (calibration T4/T6: resumed
// sessions re-anchor); the gap boundaries are also where A5 re-cache
// detection looks.
func segments(rows []TurnFact, gapMinutes float64) [][]TurnFact {
	if len(rows) == 0 {
		return nil
	}
	var out [][]TurnFact
	start := 0
	for i := 1; i < len(rows); i++ {
		if rows[i].TS.Sub(rows[i-1].TS).Minutes() > gapMinutes {
			out = append(out, rows[start:i])
			start = i
		}
	}
	return append(out, rows[start:])
}

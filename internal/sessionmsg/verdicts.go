package sessionmsg

// Verdicts is Derive's dedup decision for every INPUT proxy and token row,
// index-aligned with the caller's own DeriveInput.ProxyRows / TokenRows (not
// Derive's internal canonical order).
//
// It exists for surfaces that aggregate spend across many sessions in SQL
// (the org's windowed rollups) or over pre-loaded row sets (the node's cost
// engine) and so cannot fold Derive's Rows themselves. Such a surface stores
// or applies these verdicts per row and then sums rows the ordinary way; the
// result equals SumContributions(Derive(in)) for the same input by
// construction, because both read the same dedupPlan:
//
//   - a token row contributes iff TokenCounted is true, with its own figures;
//   - a proxy row contributes iff ProxyCounted is true (false only when the
//     session-cumulative reconciliation dropped it), with Output =
//     ProxyOutput and Reasoning = ProxyReasoning in place of its stored
//     output (a twinned proxy row's gross output is split into its
//     transcript twin's visible output and reasoning) and every other field
//     as stored.
//
// TestDeriveVerdicts_SumEqualsDerive pins that equality on randomized input.
type Verdicts struct {
	// TokenCounted[i] is false when TokenRows[i] is a second capture of
	// spend already counted: a paired output-only shadow row, a row whose
	// source_event_id is one of the session's proxy request ids, a proxy
	// row's shape-matched twin, or a row the session-cumulative
	// reconciliation dropped wholesale.
	TokenCounted []bool
	// TokenShadow[i] is true when TokenRows[i] is not counted BECAUSE it is
	// a paired output-only shadow row - a duplicate the transcript made of
	// itself, which a transcript-only read must also drop (every other
	// reason names a proxy row the transcript-only read never sees).
	TokenShadow []bool
	// ProxyCounted[i] is false only when the session-cumulative
	// reconciliation dropped ProxyRows[i] (the session's running-total token
	// row captured more of the session than the proxy did).
	ProxyCounted []bool
	// ProxyPartner[i] is the index in TokenRows of the transcript row that
	// captured the SAME turn as ProxyRows[i] - its shape twin, else the
	// first row whose source_event_id is the proxy row's request id - or -1.
	// It is attribution, not dedup: a caller that splits a session's spend
	// by a transcript-only property (the sidechain flag) reads it from the
	// partner, because api_turns carries no such column.
	ProxyPartner []int
	// ProxyOutput[i] / ProxyReasoning[i] are the Output / Reasoning of
	// ProxyRows[i]'s contribution.
	ProxyOutput    []int64
	ProxyReasoning []int64
	// ProxyInheritedFast[i] is true when ProxyRows[i]'s twin is fast (the
	// Contribution's InheritedFast): a caller that prices contributions
	// re-prices such a row at the fast tier when it is not fast itself.
	ProxyInheritedFast []bool
}

// ProxyAdjusted reports whether proxy row i's contribution differs from its
// stored figures: a twinned row whose twin carries reasoning, or a row the
// session-cumulative reconciliation dropped.
func (v Verdicts) ProxyAdjusted(i int, storedOutput int64) bool {
	return !v.ProxyCounted[i] || v.ProxyOutput[i] != storedOutput || v.ProxyReasoning[i] != 0
}

// DeriveVerdicts returns Derive's per-row dedup decisions for one session's
// rows. ActionRows, Mode and DefaultModel do not affect them (they shape the
// message rows, never which spend rows count).
func DeriveVerdicts(in DeriveInput) Verdicts {
	plan := planDedup(in)
	v := Verdicts{
		TokenCounted:   make([]bool, len(in.TokenRows)),
		TokenShadow:    make([]bool, len(in.TokenRows)),
		ProxyCounted:   make([]bool, len(in.ProxyRows)),
		ProxyPartner:   make([]int, len(in.ProxyRows)),
		ProxyOutput:    make([]int64, len(in.ProxyRows)),
		ProxyReasoning: make([]int64, len(in.ProxyRows)),

		ProxyInheritedFast: make([]bool, len(in.ProxyRows)),
	}
	for i, src := range plan.tokenIn {
		v.TokenCounted[src] = !plan.tokenDropped(i)
		v.TokenShadow[src] = plan.shadowExcluded[i]
	}
	// firstByEventID maps a source_event_id to its first canonical token row,
	// for ProxyPartner's id-match fallback.
	firstByEventID := map[string]int{}
	for i, t := range plan.tokens {
		if _, seen := firstByEventID[t.SourceEventID]; t.SourceEventID != "" && !seen {
			firstByEventID[t.SourceEventID] = i
		}
	}
	for i, src := range plan.proxyIn {
		_, _, reasoning, output, twinFast := resolveProxyRowKey(plan.proxies[i], plan.tokens, plan.twinOf, i, RollupTurn)
		v.ProxyCounted[src] = !plan.proxyDropped[i]
		v.ProxyOutput[src] = output
		v.ProxyReasoning[src] = reasoning
		v.ProxyInheritedFast[src] = twinFast
		partner := plan.twinOf[i]
		if partner < 0 {
			if ti, ok := firstByEventID[plan.proxies[i].RequestID]; ok && plan.proxies[i].RequestID != "" {
				partner = ti
			}
		}
		v.ProxyPartner[src] = -1
		if partner >= 0 {
			v.ProxyPartner[src] = plan.tokenIn[partner]
		}
	}
	return v
}

// Caps is the per-session capability triple Derive dispatches on, resolved
// by the caller from internal/integration's TokenTier for the session's tool
// (never a tool name): see DeriveInput's fields of the same names.
type Caps struct {
	ShadowCapable     bool
	ReasoningDisjoint bool
	SessionCumulative bool
}

// SessionVerdicts is DeriveVerdicts over one session's rows after the
// per-session defaults every loader of a session applies: a row with a blank
// model takes the session's model (sessions.model), and every token row
// carries the session's tool. The node session detail and the org loaders do
// this in SQL (a COALESCE onto sessions.model); the Go-side callers that load
// rows across many sessions at once (the node cost engine, the Model Value
// Report, the advisor, the predictor) call this so the rows Derive sees are
// the same on every surface. caps is the session tool's capability triple,
// resolved by the caller. The slices are modified in place (Model / Tool
// only).
func SessionVerdicts(proxies []ProxyRow, tokens []TokenRow, sessionModel, sessionTool string, caps Caps) Verdicts {
	for i := range proxies {
		if proxies[i].Model == "" {
			proxies[i].Model = sessionModel
		}
	}
	for i := range tokens {
		if tokens[i].Model == "" {
			tokens[i].Model = sessionModel
		}
		tokens[i].Tool = sessionTool
	}
	return DeriveVerdicts(DeriveInput{
		ProxyRows:         proxies,
		TokenRows:         tokens,
		Mode:              RollupTurn,
		ShadowCapable:     caps.ShadowCapable,
		ReasoningDisjoint: caps.ReasoningDisjoint,
		SessionCumulative: caps.SessionCumulative,
		DefaultModel:      sessionModel,
	})
}

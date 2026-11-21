package cloudlane

import (
	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// CA-D12 token precedence for project figures (cloud-agents lane CA-C1,
// decision CA-D21). A cloud session can be seen by more than one rail: the
// agent's own transcript captured inside the sandbox (Rail S), the vendor's
// run total pulled by a connector (Rail P), vendor telemetry (Rail T), an
// organization daily report. Each lands its own token rows on the same
// session, so a plain sum would count the same work twice. Per session, only
// the rows of the best tier present survive; the rest are kept as evidence
// (counted, never summed).
//
// The fold runs ONLY over sessions that ran off this machine. A local
// session's rows are the cost engine's already de-duplicated per-turn rows and
// pass through untouched, so a node with no cloud sessions sees byte-identical
// figures.

// tokenSourceTier maps a token_usage.source value to its CA-D12 tier. It is
// the inverse of the connector mapping (internal/cloudagents MapTokens). A
// source not listed here (proxy, hook, log_delta, a capture path added later)
// is a per-turn capture and ranks with the in-sandbox transcript: an unknown
// source is never dropped in favour of a coarser one.
var tokenSourceTier = map[string]cloudagents.TokenSourceKind{
	models.TokenSourceJSONL:          cloudagents.TokenFromSandboxTranscript,
	models.TokenSourceProxy:          cloudagents.TokenFromSandboxTranscript,
	models.TokenSourceSessionSummary: cloudagents.TokenFromProviderRunTotal,
	models.TokenSourceOTel:           cloudagents.TokenFromOTelProvisional,
	models.TokenSourceEstimated:      cloudagents.TokenFromOrgDailyReport,
}

// TierOf returns the CA-D12 tier of a token_usage.source value ("" and any
// unlisted value rank as the in-sandbox transcript, the per-turn tier).
func TierOf(source string) cloudagents.TokenSourceKind {
	if k, ok := tokenSourceTier[source]; ok {
		return k
	}
	return cloudagents.TokenFromSandboxTranscript
}

// FoldTurn is the slice of one priced turn the precedence fold reads.
type FoldTurn struct {
	SessionID string
	// TokenSource is the token_usage.source of the row ("" for a proxy turn
	// or a row whose source was not looked up).
	TokenSource string
}

// SupersededTurns returns, per turn (same index as turns), whether a better
// CA-D12 tier on the same session replaces it. offMachine reports whether a
// session ran off this machine; only those sessions are folded, and a
// session-less turn is never dropped.
func SupersededTurns(turns []FoldTurn, offMachine func(sessionID string) bool) []bool {
	out := make([]bool, len(turns))
	if offMachine == nil {
		return out
	}
	present := map[string][]cloudagents.TokenSourceKind{}
	for _, t := range turns {
		if t.SessionID == "" || !offMachine(t.SessionID) {
			continue
		}
		present[t.SessionID] = append(present[t.SessionID], TierOf(t.TokenSource))
	}
	best := make(map[string]cloudagents.TokenSourceKind, len(present))
	for sid, kinds := range present {
		if k, ok := cloudagents.PreferredTokenSource(kinds); ok {
			best[sid] = k
		}
	}
	for i, t := range turns {
		b, ok := best[t.SessionID]
		if !ok {
			continue
		}
		out[i] = cloudagents.TokenSupersedes(b, TierOf(t.TokenSource))
	}
	return out
}

// OffMachine reports whether a stored execution_location is off this
// machine (a vendor sandbox or a customer-run worker).
func OffMachine(location string) bool { return offMachine[location] }

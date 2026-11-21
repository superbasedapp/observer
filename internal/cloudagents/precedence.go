package cloudagents

// CA-D12: duplicates across capture rails are resolved by table-driven
// precedence per figure, never by ad hoc checks.

// TokenSourceKind names where a session's token figure came from.
type TokenSourceKind string

const (
	// TokenFromSandboxTranscript: the agent's own transcript, captured by
	// Observer inside the vendor sandbox (Rail S).
	TokenFromSandboxTranscript TokenSourceKind = "in_sandbox_transcript"
	// TokenFromProviderRunTotal: the vendor's finalized run or session total
	// (Rail P).
	TokenFromProviderRunTotal TokenSourceKind = "provider_run_total"
	// TokenFromOTelProvisional: vendor-native telemetry (Rail T), provisional.
	TokenFromOTelProvisional TokenSourceKind = "otel_provisional"
	// TokenFromOrgDailyReport: an organization daily report.
	TokenFromOrgDailyReport TokenSourceKind = "org_daily_report"
)

// tokenPrecedence is the CA-D12 order for a session's token total, best
// first.
var tokenPrecedence = []TokenSourceKind{
	TokenFromSandboxTranscript,
	TokenFromProviderRunTotal,
	TokenFromOTelProvisional,
	TokenFromOrgDailyReport,
}

// TokenPrecedence returns the order (a copy), best first.
func TokenPrecedence() []TokenSourceKind {
	return append([]TokenSourceKind(nil), tokenPrecedence...)
}

func tokenRank(k TokenSourceKind) int {
	for i, s := range tokenPrecedence {
		if s == k {
			return i
		}
	}
	return len(tokenPrecedence)
}

// PreferredTokenSource returns the source whose figure a session shows
// when several rails reported one, and false when none is known. The losers
// are kept as evidence, never summed with the winner.
func PreferredTokenSource(present []TokenSourceKind) (TokenSourceKind, bool) {
	best, rank := TokenSourceKind(""), len(tokenPrecedence)
	for _, p := range present {
		if r := tokenRank(p); r < rank {
			best, rank = p, r
		}
	}
	return best, rank < len(tokenPrecedence)
}

// TokenSupersedes reports whether a figure from next replaces one from
// prev for the same session (strictly better precedence).
func TokenSupersedes(next, prev TokenSourceKind) bool {
	return tokenRank(next) < tokenRank(prev)
}

// SessionMatch says how a pulled task found the session row it lands on.
type SessionMatch string

const (
	// MatchVendorRef: another rail already created the session and stamped
	// the task's vendor reference; the task merges into that row.
	MatchVendorRef SessionMatch = "vendor_session_ref"
	// MatchNativeID: the task's native id is the row id (CA-D2), whether the
	// row exists yet or not; (tool, id) is the merge key.
	MatchNativeID SessionMatch = "native_id"
)

// sessionRule is one row of the session-merge precedence table.
type sessionRule struct {
	match SessionMatch
	find  func(t Task, byRef func(ref string) (string, bool)) (string, bool)
}

var sessionRules = []sessionRule{
	{MatchVendorRef, func(t Task, byRef func(string) (string, bool)) (string, bool) {
		if t.VendorRef == "" || byRef == nil {
			return "", false
		}
		id, ok := byRef(t.VendorRef)
		return id, ok && id != ""
	}},
	{MatchNativeID, func(t Task, _ func(string) (string, bool)) (string, bool) {
		return t.ID, t.ID != ""
	}},
}

// ResolveSessionID returns the sessions.id a pulled task lands on and the
// rule that chose it. byRef looks a vendor reference up among the tool's
// existing sessions (store.SessionIDByVendorRef).
func ResolveSessionID(t Task, byRef func(ref string) (string, bool)) (string, SessionMatch) {
	for _, r := range sessionRules {
		if id, ok := r.find(t, byRef); ok {
			return id, r.match
		}
	}
	return "", ""
}

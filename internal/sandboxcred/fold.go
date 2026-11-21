package sandboxcred

// fold.go is the session fold for an injected local run's model turns
// (tracker row F-003, finding F-N3-1, ledger row OSH-R-150). A local run's
// host helper stamps the run on every request through its model-proxy
// forward (lane N3), and the proxy files a stamped request under the run's
// own namespace (rsbx-<run>-<id>). A hosted run's pulled transcripts land
// in that namespace too, so its turns pair with them. A local run's
// transcript and relayed hooks stay on the tool's native session id, so
// its turns are folded back onto that id, but only when every row below
// holds; any failing row keeps the turn in the run's namespace (today's
// behaviour, so a box can never bind its spend to a session that is not
// its own, nor to a session that existed before the run, such as the
// developer's unsandboxed session of the same project).

// FoldCode names a fold outcome.
type FoldCode string

// The closed FoldCode vocabulary.
const (
	// FoldNative: the turn lands on the session the request names.
	FoldNative FoldCode = "native"
	// The rows that keep the turn in the run's namespace.
	FoldNoRecord      FoldCode = "no_record"
	FoldHostedLane    FoldCode = "hosted_lane"
	FoldNotLive       FoldCode = "not_live"
	FoldHelperGone    FoldCode = "helper_gone"
	FoldNotRelayed    FoldCode = "not_relayed"
	FoldNoSession     FoldCode = "no_session"
	FoldNotRunSession FoldCode = "not_run_session"
	FoldResumed       FoldCode = "resumed_session"
)

// FoldFacts are what the caller read for one stamped request: the run's
// injection record, its helper's liveness, the request's relay token and
// the session it names, and whether the run's own relayed hooks claim that
// session (the relay daemon's claim table, its one owner).
type FoldFacts struct {
	// Found: an injection record exists for the run.
	Found bool
	// Lane is the record's lane (written by the host side; the request
	// cannot choose it).
	Lane Lane
	// Live: the record is not past its end and the run's relay record
	// exists.
	Live bool
	// HelperLive: the run's host helper still holds its liveness lock.
	HelperLive bool
	// Token is the relay token the request carries; TokenHash the
	// record's.
	Token, TokenHash string
	// Session is the session id the request names (the proxy's own
	// extraction, before any run namespace).
	Session string
	// ClaimedByRun: the run's own relayed hooks already speak for
	// Session, so no other live run does.
	ClaimedByRun bool
	// FreshClaim: when the run first claimed Session the node recorded no
	// session of that id, so the run started it. A session recorded before
	// (a host session of the same project the run resumed, which the relay
	// lets it speak for) is not fresh (audit FU3-A1).
	FreshClaim bool
}

// FoldDecision is a fold outcome: Session is where the turn lands ("" keeps
// it in the run's namespace) and Code the row that decided. Mismatch marks
// the one row worth an audit line: the request named a session the run's
// hooks do not speak for.
type FoldDecision struct {
	Session  string
	Code     FoldCode
	Mismatch bool
}

// foldRule is one row: when keeps holds, the turn stays in the run's
// namespace with code.
type foldRule struct {
	name     string
	keeps    func(FoldFacts) bool
	code     FoldCode
	mismatch bool
}

// foldRules are walked top-down; every row must pass for the turn to land
// on the session the request names. The order puts the facts the host side
// wrote first, so a request with a forged token never reaches the session
// rows.
var foldRules = []foldRule{
	{"no record", func(f FoldFacts) bool { return !f.Found }, FoldNoRecord, false},
	{"hosted lane", func(f FoldFacts) bool { return f.Lane != LaneLocal }, FoldHostedLane, false},
	{"not live", func(f FoldFacts) bool { return !f.Live }, FoldNotLive, false},
	{"helper gone", func(f FoldFacts) bool { return !f.HelperLive }, FoldHelperGone, false},
	{"not relayed", func(f FoldFacts) bool { return !equalHash(f.Token, f.TokenHash) }, FoldNotRelayed, false},
	{"no session", func(f FoldFacts) bool { return f.Session == "" }, FoldNoSession, false},
	{"not the run's session", func(f FoldFacts) bool { return !f.ClaimedByRun }, FoldNotRunSession, true},
	{"a session the run resumed", func(f FoldFacts) bool { return !f.FreshClaim }, FoldResumed, false},
}

// DecideFold walks the table for one stamped request.
func DecideFold(f FoldFacts) FoldDecision {
	for _, rule := range foldRules {
		if rule.keeps(f) {
			return FoldDecision{Code: rule.code, Mismatch: rule.mismatch}
		}
	}
	return FoldDecision{Session: f.Session, Code: FoldNative}
}

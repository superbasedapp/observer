package store

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// NodeSessionVerdicts runs the ONE proxy-vs-transcript dedup rule,
// sessionmsg.DeriveVerdicts, over one session's already-loaded rows, shaped
// exactly the way the node's session detail header hands them to Derive
// (internal/intelligence/dashboard's loadMessageProxyRows /
// loadMessageTokenRows): a blank row model falls back to the session's
// model, every token row carries the session's tool, and output-only
// shadow pairing and the session-cumulative reconciliation are enabled from
// the tool's registry capabilities (NodeSessionCaps), never a tool name. The rows are mutated
// only in their Model / Tool fields; verdicts come back index-aligned with
// the caller's slices.
//
// Every store-side surface that sums a session's api_turns ∪ token_usage
// (the predictor substrate, the Model Value Report loader) calls this
// rather than restating a request-id / shape predicate, so a session's
// figures there agree with its detail header.
func NodeSessionVerdicts(tool, sessionModel string, proxies []sessionmsg.ProxyRow, tokens []sessionmsg.TokenRow) sessionmsg.Verdicts {
	return sessionmsg.SessionVerdicts(proxies, tokens, sessionModel, tool, NodeSessionCaps(tool))
}

// NodeSessionCaps resolves the capability triple sessionmsg.Derive dispatches
// on (output-only shadow pairing, disjoint reasoning, session-cumulative
// reconciliation) from the session tool's integration registry row - never
// its name. An unknown tool resolves to the zero Caps. Every node caller
// that builds a sessionmsg.DeriveInput takes its flags from here, so the
// session header, the Messages tab and the stored verdicts cannot disagree
// about which rules apply to a session.
func NodeSessionCaps(tool string) sessionmsg.Caps {
	return spendverdict.CapsFor(tool)
}

// RefreshSpendVerdicts brings the stored dedup verdicts (agent migration 143)
// up to date for every session whose rows changed since it was last derived -
// the one writer is internal/spendverdict.Refresh. The daemon calls it on a
// ticker; a windowed reader calls it before reading.
func (s *Store) RefreshSpendVerdicts(ctx context.Context, opts spendverdict.Options) (int, error) {
	return spendverdict.Refresh(ctx, s.db, opts)
}

// spendVerdictReadBound caps the refresh a latency-bounded windowed read runs
// first (the guard's budget lookup has a 3 s deadline): the daemon's ticker
// keeps the queue short, so this is normally a single empty probe, and after
// a one-time rule backfill the read proceeds on the verdicts derived so far.
const spendVerdictReadBound = time.Second

// refreshSpendVerdictsBounded runs RefreshSpendVerdicts under
// spendVerdictReadBound before a windowed read. A failure leaves the previous
// verdicts in place: only a session changed since its last derivation can be
// off, and the next read retries.
func (s *Store) refreshSpendVerdictsBounded(ctx context.Context) {
	_, _ = spendverdict.Refresh(ctx, s.db, spendverdict.Options{MaxDuration: spendVerdictReadBound})
}

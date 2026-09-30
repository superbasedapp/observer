package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// SpendTurn is one row a session's spend counts under the ONE session rule
// (internal/sessionmsg.Derive, over spendverdict.LoadSession's rows): a proxy
// (api_turns) row, carrying its transcript twin's visible output and
// reasoning when it has one, or a transcript (token_usage) row that is not a
// second capture of a turn already counted. Summing a session's SpendTurns
// gives exactly its session header's token figures, and pricing each one
// (recorded cost when positive, else the table at Ts) its header cost.
//
// It is the substrate of every node drill-down BELOW a session - the linked
// sub-agent children, the legacy same-session sidechain windows, the fork /
// sub-agent lineage children and the task attribution - so a drill-down row
// and the header of the session it summarizes cannot disagree (lane
// R2-ONERULE). Those surfaces used to sum token_usage alone: a proxied turn
// the transcript missed was absent, and a Copilot-family output-only shadow
// row was counted twice.
type SpendTurn struct {
	Ts    time.Time
	Model string
	// Proxy is true for an api_turns row.
	Proxy bool
	// Sidechain is the row's migration-087 is_sidechain flag; a proxy row
	// (api_turns has no such column) takes its transcript partner's - the
	// twin or request-id row that captured the same turn - else false.
	Sidechain          bool
	InputTokens        int64
	OutputTokens       int64
	CacheReadTokens    int64
	CacheWriteTokens   int64
	CacheWrite1hTokens int64
	ReasoningTokens    int64
	WebSearchRequests  int64
	// Fast is the row's served tier, including a fast tier a proxy row
	// inherits from its fast transcript twin.
	Fast bool
	// RecordedCostUSD is the capture path's own cost, 0 when none was
	// recorded - and 0 for a proxy row lifted to its twin's fast tier, whose
	// recorded figure was priced at the standard wire tier and no longer
	// stands (the session header re-prices such a row too).
	RecordedCostUSD float64
}

// LoadSessionSpendTurns returns sessionID's counted spend rows in time order
// (see SpendTurn).
func (s *Store) LoadSessionSpendTurns(ctx context.Context, sessionID string) ([]SpendTurn, error) {
	rows, err := spendverdict.LoadSession(ctx, s.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionSpendTurns: %w", err)
	}
	return spendTurnsOf(rows), nil
}

// LoadSessionsSpendTurns is LoadSessionSpendTurns for many sessions, in a
// fixed number of queries per 900 ids (spendverdict.LoadSessions). Every id
// gets an entry.
func (s *Store) LoadSessionsSpendTurns(ctx context.Context, sessionIDs []string) (map[string][]SpendTurn, error) {
	all, err := spendverdict.LoadSessions(ctx, s.db, sessionIDs)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSessionsSpendTurns: %w", err)
	}
	out := make(map[string][]SpendTurn, len(all))
	for id, rows := range all {
		out[id] = spendTurnsOf(rows)
	}
	return out, nil
}

// spendTurnsOf applies sessionmsg.DeriveVerdicts to one session's rows and
// returns the counted ones in time order.
func spendTurnsOf(rows spendverdict.SessionRows) []SpendTurn {
	v := rows.Verdicts()
	type keyed struct {
		ts string
		t  SpendTurn
	}
	all := make([]keyed, 0, len(rows.Proxies)+len(rows.Tokens))
	for i, p := range rows.Proxies {
		if !v.ProxyCounted[i] {
			continue
		}
		lift := v.ProxyInheritedFast[i] && !p.Fast
		t := SpendTurn{
			Model: p.Model, Proxy: true,
			InputTokens: p.Input, OutputTokens: v.ProxyOutput[i], CacheReadTokens: p.CacheRead,
			CacheWriteTokens: p.CacheCreation, CacheWrite1hTokens: p.CacheCreation1h,
			ReasoningTokens: v.ProxyReasoning[i], WebSearchRequests: p.WebSearchRequests,
			Fast: p.Fast || lift, RecordedCostUSD: p.CostUSD,
		}
		if lift {
			t.RecordedCostUSD = 0
		}
		if partner := v.ProxyPartner[i]; partner >= 0 {
			t.Sidechain = rows.TokenSidechain[partner]
		}
		all = append(all, keyed{p.Timestamp, t})
	}
	for i, tk := range rows.Tokens {
		if !v.TokenCounted[i] {
			continue
		}
		all = append(all, keyed{tk.Timestamp, SpendTurn{
			Model: tk.Model, Sidechain: rows.TokenSidechain[i],
			InputTokens: tk.Input, OutputTokens: tk.Output, CacheReadTokens: tk.CacheRead,
			CacheWriteTokens: tk.CacheCreation, CacheWrite1hTokens: tk.CacheCreation1h,
			ReasoningTokens: tk.Reasoning, WebSearchRequests: tk.WebSearchRequests,
			Fast: tk.Fast, RecordedCostUSD: tk.CostUSD,
		}})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].ts < all[j].ts })
	out := make([]SpendTurn, 0, len(all))
	for _, k := range all {
		t := k.t
		if at, ok := parseDBTime(k.ts); ok {
			t.Ts = at
		}
		out = append(out, t)
	}
	return out
}

// SpendTurnTotals is the token sum of a SpendTurn slice.
type SpendTurnTotals struct {
	InputTokens, OutputTokens, CacheReadTokens, CacheWriteTokens int64
	RecordedCostUSD                                              float64
}

// SumSpendTurns totals turns.
func SumSpendTurns(turns []SpendTurn) SpendTurnTotals {
	var t SpendTurnTotals
	for _, r := range turns {
		t.InputTokens += r.InputTokens
		t.OutputTokens += r.OutputTokens
		t.CacheReadTokens += r.CacheReadTokens
		t.CacheWriteTokens += r.CacheWriteTokens
		t.RecordedCostUSD += r.RecordedCostUSD
	}
	return t
}

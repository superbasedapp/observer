package dashboard

import (
	"context"
	"database/sql"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// spendTurn is one row of the node's deduped spend substrate: a proxy
// (api_turns) or transcript (token_usage) row that survived the ONE session
// dedup rule, sessionmsg.DeriveVerdicts, applied through the node's stored
// verdicts (internal/spendverdict) by cost.Engine.TurnRows. A twinned proxy row
// carries its transcript twin's visible output + reasoning split.
//
// The Analysis tab, the monthly report, the budget card, the experiments
// report, the live rollup and the statusline all read spend through this
// one substrate (lane R2-PARITY-2). They used to run their own SQL
// (`proxy_turn_ids ... NOT IN`), which only dropped a transcript row whose
// source_event_id equalled an api_turns.request_id ANYWHERE in the window:
// every Codex / OpenCode / OpenClaw twin (disjoint id schemes) was counted
// twice, a request id held by another session could erase this session's
// row, and Copilot-family output-only shadow rows were never paired - so
// those surfaces disagreed with the Sessions list and the session detail
// header for the same data.
type spendTurn struct {
	SessionID string
	Model     string
	Tool      string
	// ProjectPath is the resolved projects.root_path ("" when the row could
	// not be attributed to a project).
	ProjectPath string
	At          time.Time
	Bundle      cost.TokenBundle
	// Recorded is the capture path's own recorded cost (>0), else 0.
	Recorded float64
	// CostUSD is the engine's price: Recorded when set, else the pricing
	// table's rate at At; 0 when neither exists (Priced false).
	CostUSD float64
	Priced  bool
}

// spendTurns loads the deduped spend rows for [since, until) (a zero until
// is open-ended) scoped by the dashboard's global tool / project filters.
// sessionIDs, when non-empty, scopes to those sessions.
func (s *Server) spendTurns(ctx context.Context, since, until time.Time, tool, project string, sessionIDs []string) ([]spendTurn, error) {
	return loadSpendTurns(ctx, s.db(), s.opts.CostEngine, since, until, tool, project, sessionIDs)
}

// turnRowLister is the one cost-engine capability loadSpendTurns needs
// (*cost.Engine implements it).
type turnRowLister interface {
	TurnRows(ctx context.Context, db *sql.DB, opts cost.Options) ([]cost.TurnRow, error)
}

// loadSpendTurns is spendTurns for a caller holding its own DB and engine
// (ComputeExperimentReport, which the CLI also runs). A session-id scope is
// chunked under the engine's bind-variable ceiling; a session lands in one
// chunk only, so nothing is double-counted.
//
// Summary-call rows (the observer's own rolling-summary Haiku calls) are
// excluded: none of these surfaces ever counted them, and dedup parity must
// not also change what they measure.
func loadSpendTurns(ctx context.Context, db *sql.DB, engine turnRowLister, since, until time.Time, tool, project string, sessionIDs []string) ([]spendTurn, error) {
	opts := cost.Options{Since: since, Until: until, Source: cost.SourceAuto, Tool: tool, ProjectRoot: project}
	var rows []cost.TurnRow
	if len(sessionIDs) == 0 {
		r, err := engine.TurnRows(ctx, db, opts)
		if err != nil {
			return nil, err
		}
		rows = r
	}
	for start := 0; start < len(sessionIDs); start += cost.MaxSessionIDsPerScope {
		end := start + cost.MaxSessionIDsPerScope
		if end > len(sessionIDs) {
			end = len(sessionIDs)
		}
		chunk := opts
		chunk.SessionIDs = sessionIDs[start:end]
		r, err := engine.TurnRows(ctx, db, chunk)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	out := make([]spendTurn, 0, len(rows))
	for _, r := range rows {
		if r.Source == "summary_calls" {
			continue
		}
		t := spendTurn{
			SessionID: r.SessionID, Model: r.Model, Tool: r.Tool, ProjectPath: r.ProjectPath, At: r.At,
			Bundle: r.Tokens, Recorded: r.RecordedUSD, Priced: r.Priced,
		}
		if r.Priced {
			t.CostUSD = r.CostUSD
		}
		out = append(out, t)
	}
	return out, nil
}

// turnCostAndStandard returns a turn's actual cost and what it would have
// cost at standard (non-long-context) rates - the pair the Analysis tab
// compares to flag a long-context turn. A recorded cost is ground truth and
// has no table counterfactual here (both equal it); an unpriced turn is 0/0.
func (s *Server) turnCostAndStandard(t spendTurn) (rowCost, rowStdCost float64) {
	if t.Recorded > 0 {
		return t.CostUSD, t.CostUSD
	}
	if p, ok := s.opts.CostEngine.LookupAt(t.Model, t.At); ok {
		return t.CostUSD, cost.Compute(stripLongContext(p), t.Bundle)
	}
	return 0, 0
}

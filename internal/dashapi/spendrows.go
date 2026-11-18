package dashapi

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
type SpendTurn struct {
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
	// Source is the capture path whose row survived dedup ("proxy" |
	// "jsonl"), from cost.TurnRow.Source. Additive: lets a surface tell a
	// proxy-recorded cost from a transcript- or table-priced estimate.
	Source string
}

// spendScope is the dashboard's global tool / project / model filter as the
// spend substrate applies it (the zero value is unscoped). Tool and project
// are session grain; model is turn grain (cost.Options.Model): under a model
// filter the substrate holds only that model's turns.
type SpendScope struct {
	Tool, Project, Model string
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
func LoadSpendTurns(ctx context.Context, db *sql.DB, engine turnRowLister, since, until time.Time, scope SpendScope, sessionIDs []string) ([]SpendTurn, error) {
	opts := cost.Options{Since: since, Until: until, Source: cost.SourceAuto, Tool: scope.Tool, ProjectRoot: scope.Project, Model: scope.Model}
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
	out := make([]SpendTurn, 0, len(rows))
	for _, r := range rows {
		if r.Source == "summary_calls" {
			continue
		}
		t := SpendTurn{
			SessionID: r.SessionID, Model: r.Model, Tool: r.Tool, ProjectPath: r.ProjectPath, At: r.At,
			Bundle: r.Tokens, Recorded: r.RecordedUSD, Priced: r.Priced, Source: r.Source,
		}
		if r.Priced {
			t.CostUSD = r.CostUSD
		}
		out = append(out, t)
	}
	return out, nil
}

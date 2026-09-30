package repricesvc

import (
	"github.com/marmutapp/superbased-observer/internal/reprice"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The JSON wire shapes of the node dashboard's /api/reprice/* routes and of
// `observer reprice --json` (one owner, so the CLI and the card never
// disagree). Field names follow the G-REPRICE node dashboard contract.

// SummaryView is a plan's aggregate.
type SummaryView struct {
	Scanned  int                    `json:"scanned"`
	Changed  int                    `json:"changed"`
	Filled   int                    `json:"filled"`
	OldUSD   float64                `json:"old_usd"`
	NewUSD   float64                `json:"new_usd"`
	DeltaUSD float64                `json:"delta_usd"`
	Skipped  map[string]int         `json:"skipped"`
	Tables   []reprice.TableSummary `json:"tables"`
	Models   []reprice.ModelSummary `json:"models"`
}

// PlanView is a dry run on the wire.
type PlanView struct {
	Since       string      `json:"since"`
	Until       string      `json:"until"`
	Model       string      `json:"model"`
	Pricing     PricingInfo `json:"pricing"`
	Digest      string      `json:"digest"`
	RuleVersion int         `json:"rule_version"`
	Summary     SummaryView `json:"summary"`
	Org         OrgNote     `json:"org"`
}

// View renders the plan for the wire. Maps and slices are never null.
func (p Plan) View() PlanView {
	sv := SummaryView{
		Scanned: p.Summary.Scanned, Changed: p.Summary.Changed, Filled: p.Summary.Filled,
		OldUSD: p.Summary.OldUSD, NewUSD: p.Summary.NewUSD, DeltaUSD: p.Summary.DeltaUSD(),
		Skipped: map[string]int{},
		Tables:  append([]reprice.TableSummary{}, p.Summary.Tables...),
		Models:  append([]reprice.ModelSummary{}, p.Summary.Models...),
	}
	for k, v := range p.Summary.Skipped {
		sv.Skipped[string(k)] = v
	}
	return PlanView{
		Since: p.Since, Until: p.Until, Model: p.Model, Pricing: p.Pricing,
		Digest: p.Digest, RuleVersion: p.RuleVersion, Summary: sv, Org: p.Org,
	}
}

// RunView is one run on the wire.
type RunView struct {
	ID             int64          `json:"id"`
	Kind           string         `json:"kind"`
	CreatedAt      string         `json:"created_at"`
	Actor          string         `json:"actor"`
	Since          string         `json:"since"`
	Until          string         `json:"until"`
	Model          string         `json:"model"`
	RuleVersion    int            `json:"rule_version"`
	PricingSource  string         `json:"pricing_source"`
	PricingVersion int64          `json:"pricing_version"`
	Scanned        int            `json:"scanned"`
	Changed        int            `json:"changed"`
	Filled         int            `json:"filled"`
	CASMissed      int            `json:"cas_missed"`
	OldUSD         float64        `json:"old_usd"`
	NewUSD         float64        `json:"new_usd"`
	DeltaUSD       float64        `json:"delta_usd"`
	RevertsRun     int64          `json:"reverts_run"`
	RevertedByRun  int64          `json:"reverted_by_run"`
	Status         string         `json:"status"`
	Skipped        map[string]int `json:"skipped,omitempty"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// ViewRun renders one store run for the wire.
func ViewRun(r store.RepriceRun) RunView {
	return RunView{
		ID: r.ID, Kind: r.Kind, CreatedAt: r.CreatedAt, Actor: r.Actor,
		Since: r.Since, Until: r.Until, Model: r.Model, RuleVersion: r.RuleVersion,
		PricingSource: r.PricingSource, PricingVersion: r.PricingVersion,
		Scanned: r.Scanned, Changed: r.Changed, Filled: r.Filled, CASMissed: r.CASMissed,
		OldUSD: r.OldUSD, NewUSD: r.NewUSD, DeltaUSD: r.DeltaUSD,
		RevertsRun: r.RevertsRun, RevertedByRun: r.RevertedByRun, Status: r.Status,
		Skipped: r.Summary.Skipped, Warnings: r.Warnings,
	}
}

// ViewRuns renders a run list (never null).
func ViewRuns(rs []store.RepriceRun) []RunView {
	out := make([]RunView, 0, len(rs))
	for _, r := range rs {
		out = append(out, ViewRun(r))
	}
	return out
}

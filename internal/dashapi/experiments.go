package dashapi

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// ExperimentArmReport is one arm's aggregate evidence.
type ExperimentArmReport struct {
	Arm                   string  `json:"arm"`
	Profile               string  `json:"profile"`
	Sessions              int     `json:"sessions"`
	TotalCostUSD          float64 `json:"total_cost_usd"`
	MeanCostUSD           float64 `json:"mean_cost_usd"`
	SDCostUSD             float64 `json:"sd_cost_usd"`
	CVPct                 float64 `json:"cv_pct"`
	Turns                 int64   `json:"turns"`
	MeanTurns             float64 `json:"mean_turns"`
	CacheReadTokens       int64   `json:"cache_read_tokens"`
	CacheWriteTokens      int64   `json:"cache_write_tokens"`
	CompressionSavedBytes int64   `json:"compression_saved_bytes"`
	// CompressionEvictedBytes is byte volume removed by lossy-eviction
	// mechanisms (drops). It has ALREADY been subtracted out of
	// CompressionSavedBytes so that field reports genuine, retrievable
	// compression only; evicted content is recoverable via
	// search_past_outputs markers, not a saving.
	CompressionEvictedBytes int64            `json:"compression_evicted_bytes"`
	CacheEventsByCause      map[string]int64 `json:"cache_events_by_cause"`
}

// ExperimentReport is the full evidence bundle for one experiment.
type ExperimentReport struct {
	Experiment config.ExperimentConfig `json:"experiment"`
	Running    bool                    `json:"running"`
	WindowFrom string                  `json:"window_from"`
	WindowTo   string                  `json:"window_to"`
	Control    ExperimentArmReport     `json:"control"`
	Candidate  ExperimentArmReport     `json:"candidate"`
	// DeltaCostPct is candidate-vs-control on per-session means
	// (negative = candidate cheaper). Zero when either arm is empty.
	DeltaCostPct  float64 `json:"delta_cost_pct"`
	DeltaTurnsPct float64 `json:"delta_turns_pct"`
}

// ComputeExperimentReport recomputes arm membership by hash and
// aggregates the §2.4 evidence per arm. Shared by the dashboard
// handler and `observer experiment report` so the two surfaces can
// never disagree.
//
//nolint:gocyclo // one sequential aggregation pass per evidence dimension; splitting would scatter the §2.4 report shape (P6 arc).
func ComputeExperimentReport(ctx context.Context, db *sql.DB, engine costLookup, exp config.ExperimentConfig) (*ExperimentReport, error) {
	now := time.Now().UTC()
	start, end, err := config.ExperimentWindow(exp, now)
	if err != nil {
		return nil, err
	}
	rep := &ExperimentReport{
		Experiment: exp,
		Running:    exp.Running(),
		WindowFrom: start.Format(time.RFC3339),
		WindowTo:   end.Format(time.RFC3339),
		Control:    ExperimentArmReport{Arm: "control", Profile: exp.Control, CacheEventsByCause: map[string]int64{}},
		Candidate:  ExperimentArmReport{Arm: "candidate", Profile: exp.Candidate, CacheEventsByCause: map[string]int64{}},
	}
	if db == nil {
		return rep, nil
	}

	// Population: sessions that STARTED inside the window and belong
	// to the class. Sessions started before the experiment resolved
	// their profile under the pre-experiment assignment - counting
	// them would attribute old-assignment traffic to an arm.
	startArg := start.Format(time.RFC3339Nano)
	endArg := end.Add(time.Second).Format(time.RFC3339Nano)
	var rows *sql.Rows
	if toolName, ok := strings.CutPrefix(exp.Class, "tool:"); ok {
		rows, err = db.QueryContext(ctx,
			`SELECT id FROM sessions WHERE tool = ? AND started_at >= ? AND started_at <= ?`,
			toolName, startArg, endArg)
	} else {
		rows, err = db.QueryContext(ctx,
			`SELECT DISTINCT s.id FROM sessions s
			 JOIN api_turns t ON t.session_id = s.id AND t.provider = ?
			 WHERE s.started_at >= ? AND s.started_at <= ?`,
			exp.Class, startArg, endArg)
	}
	if err != nil {
		return nil, err
	}
	armOf := map[string]string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && id != "" {
			_, arm := config.ExperimentArm(exp, id)
			armOf[id] = arm
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// Per-session rollups over the window, over the node's deduped spend
	// substrate (LoadSpendTurns: the one session dedup rule,
	// sessionmsg.DeriveVerdicts, applied by the cost engine) scoped to the
	// arm population, so an arm's cost agrees with the Sessions list and the
	// session detail header. The window's upper bound stays inclusive of the
	// experiment's end second (the population query's `<= end+1s`).
	type sess struct {
		cost  float64
		turns int64
	}
	perSession := map[string]*sess{}
	armIDs := make([]string, 0, len(armOf))
	for id := range armOf {
		armIDs = append(armIDs, id)
	}
	sort.Strings(armIDs)
	var turns []SpendTurn
	if len(armIDs) > 0 && engine != nil {
		turns, err = LoadSpendTurns(ctx, db, engine, start, end.Add(time.Second+time.Nanosecond), SpendScope{}, armIDs)
		if err != nil {
			return nil, err
		}
	}
	for _, t := range turns {
		sid, bundle := t.SessionID, t.Bundle
		arm, ok := armOf[sid]
		if !ok {
			continue
		}
		ar := rep.armFor(arm)
		ps := perSession[sid]
		if ps == nil {
			ps = &sess{}
			perSession[sid] = ps
		}
		// The engine's price: recorded cost wins; otherwise the rate in
		// force on the row's own timestamp.
		rowCost := t.CostUSD
		ps.cost += rowCost
		ps.turns++
		ar.Turns++
		ar.TotalCostUSD += rowCost
		ar.CacheReadTokens += bundle.CacheRead
		ar.CacheWriteTokens += bundle.CacheCreation + bundle.CacheCreation1h
	}
	// Compression telemetry is a property of the proxy rows alone (never
	// deduped away), summed per arm straight off api_turns.
	comprows, err := db.QueryContext(ctx,
		`SELECT COALESCE(session_id, ''),
		        COALESCE(SUM(COALESCE(compression_original_bytes, 0) - COALESCE(compression_compressed_bytes, 0)), 0)
		   FROM api_turns
		  WHERE timestamp >= ? AND timestamp <= ?
		    AND (error_class IS NULL OR error_class = '')
		  GROUP BY session_id`, startArg, endArg)
	if err != nil {
		return nil, err
	}
	for comprows.Next() {
		var sid string
		var saved int64
		if comprows.Scan(&sid, &saved) != nil {
			continue
		}
		if arm, ok := armOf[sid]; ok {
			rep.armFor(arm).CompressionSavedBytes += saved
		}
	}
	err = comprows.Err()
	comprows.Close()
	if err != nil {
		return nil, err
	}

	// Lossy-eviction (drop) bytes inflate comp_saved because dropping
	// content shrinks compression_compressed_bytes. Subtract them per arm
	// (attributed by session) so CompressionSavedBytes reports genuine,
	// retrievable compression only, and surface the evicted volume
	// additively. Same window as the combined CTE; lossy set drawn from
	// the ONE classifier owner (LossyEvictionMechanismList).
	if lossy := LossyEvictionMechanismList(); len(lossy) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(lossy)), ",")
		evArgs := make([]any, 0, len(lossy)+2)
		for _, m := range lossy {
			evArgs = append(evArgs, m)
		}
		evArgs = append(evArgs, startArg, endArg)
		evrows, everr := db.QueryContext(ctx,
			//nolint:gosec // G202: IN placeholder list is code constants; values bound via args.
			`SELECT COALESCE(at.session_id, ''), COALESCE(SUM(ce.original_bytes), 0)
			 FROM compression_events ce
			 JOIN api_turns at ON at.id = ce.api_turn_id
			 WHERE ce.mechanism IN (`+placeholders+`)
			   AND ce.timestamp >= ? AND ce.timestamp <= ?
			 GROUP BY at.session_id`,
			evArgs...)
		if everr == nil {
			for evrows.Next() {
				var sid string
				var evicted int64
				if evrows.Scan(&sid, &evicted) == nil {
					if arm, ok := armOf[sid]; ok {
						ar := rep.armFor(arm)
						ar.CompressionEvictedBytes += evicted
						ar.CompressionSavedBytes -= evicted
					}
				}
			}
			_ = evrows.Err()
			evrows.Close()
		}
		// Clamp saved bytes to non-negative after eviction subtraction.
		for _, arm := range []string{"control", "candidate"} {
			if ar := rep.armFor(arm); ar.CompressionSavedBytes < 0 {
				ar.CompressionSavedBytes = 0
			}
		}
	}

	// Cache events by cause, window-scoped, attributed by session arm.
	erows, err := db.QueryContext(ctx,
		`SELECT COALESCE(session_id, ''), COALESCE(cause, '(none)'), COUNT(*)
		 FROM cache_events WHERE timestamp >= ? AND timestamp <= ?
		 GROUP BY session_id, cause`, startArg, endArg)
	if err == nil {
		for erows.Next() {
			var sid, cause string
			var n int64
			if erows.Scan(&sid, &cause, &n) == nil {
				if arm, ok := armOf[sid]; ok {
					rep.armFor(arm).CacheEventsByCause[cause] += n
				}
			}
		}
		_ = erows.Err()
		erows.Close()
	}

	// Per-arm session stats (mean / sd / CV over per-session cost).
	costsByArm := map[string][]float64{}
	turnsByArm := map[string]int64{}
	for sid, ps := range perSession {
		arm := armOf[sid]
		costsByArm[arm] = append(costsByArm[arm], ps.cost)
		turnsByArm[arm] += ps.turns
	}
	for _, arm := range []string{"control", "candidate"} {
		ar := rep.armFor(arm)
		costs := costsByArm[arm]
		ar.Sessions = len(costs)
		if len(costs) == 0 {
			continue
		}
		var sum float64
		for _, c := range costs {
			sum += c
		}
		ar.MeanCostUSD = sum / float64(len(costs))
		ar.MeanTurns = float64(turnsByArm[arm]) / float64(len(costs))
		if len(costs) >= 2 {
			var ss float64
			for _, c := range costs {
				d := c - ar.MeanCostUSD
				ss += d * d
			}
			ar.SDCostUSD = math.Sqrt(ss / float64(len(costs)-1))
			if ar.MeanCostUSD > 0 {
				ar.CVPct = ar.SDCostUSD / ar.MeanCostUSD * 100
			}
		}
	}
	if rep.Control.MeanCostUSD > 0 && rep.Candidate.Sessions > 0 {
		rep.DeltaCostPct = (rep.Candidate.MeanCostUSD - rep.Control.MeanCostUSD) / rep.Control.MeanCostUSD * 100
	}
	if rep.Control.MeanTurns > 0 && rep.Candidate.Sessions > 0 {
		rep.DeltaTurnsPct = (rep.Candidate.MeanTurns - rep.Control.MeanTurns) / rep.Control.MeanTurns * 100
	}
	return rep, nil
}

// armFor maps an arm label to its report slot.
func (r *ExperimentReport) armFor(arm string) *ExperimentArmReport {
	if arm == "candidate" {
		return &r.Candidate
	}
	return &r.Control
}

// costLookup is the cost-engine capability the report needs. Interface so
// the CLI can pass its own engine instance. TurnRows supplies the deduped,
// date-effectively priced spend rows (the same substrate every spend surface
// reads); Lookup/LookupAt stay for callers that price a what-if.
type costLookup interface {
	Lookup(model string) (cost.Pricing, bool)
	LookupAt(model string, at time.Time) (cost.Pricing, bool)
	turnRowLister
}

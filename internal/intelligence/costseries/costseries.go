package costseries

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

// Query scopes a series: the resolved bucket spec, the engine window and
// the dashboard's global filters.
type Query struct {
	// Spec is the resolved granularity, zone and window.
	Spec timebucket.Spec
	// Days, Since and Until are the cost engine's window (cost.Options):
	// Since overrides Days; a zero Until means no upper bound.
	Days         int
	Since, Until time.Time
	// Tool, Project and Model are the dashboard's global filters
	// (sessions.tool, projects.root_path, the row's own model).
	Tool, Project, Model string
}

// Bucket is one slot of the zero-filled axis. Row is the engine's grouped
// row for the bucket; an empty bucket carries a zero Row with Key set and
// HasData false.
type Bucket struct {
	Key     string
	T       time.Time
	Row     cost.Row
	HasData bool
}

// ModelPoint is one (bucket, model) row of TokensByModel.
type ModelPoint struct {
	Bucket string
	T      time.Time
	Model  string
	Row    cost.Row
}

// maxRows is the engine row cap: one row per bucket (or per bucket and
// model), and the bucket count is capped (sub-day) or data-bounded
// (day/week), so this never truncates a real window.
const maxRows = 1 << 20

// TotalTokens is the dashboard's token figure for a bundle: input + output
// + cache read + cache write (CacheCreation1h is a subset of
// CacheCreation; reasoning is inside output).
func TotalTokens(b cost.TokenBundle) int64 {
	return b.Input + b.Output + b.CacheRead + b.CacheCreation
}

func (q Query) options(group cost.GroupBy) cost.Options {
	return cost.Options{
		Days: q.Days, Since: q.Since, Until: q.Until,
		GroupBy:     group,
		Source:      cost.SourceAuto,
		Limit:       maxRows,
		BucketKey:   timebucket.StoredKeyer(q.Spec),
		Tool:        q.Tool,
		ProjectRoot: q.Project,
		Model:       q.Model,
	}
}

// Cost returns one Bucket per slot of q's zero-filled grid, oldest first,
// with the engine's tokens, cost, turn count and compression stats per
// bucket (cost.GroupByDay keyed by the timebucket keyer).
func Cost(ctx context.Context, eng *cost.Engine, db *sql.DB, q Query) ([]Bucket, error) {
	if eng == nil {
		return nil, fmt.Errorf("costseries.Cost: no cost engine")
	}
	summary, err := eng.Summary(ctx, db, q.options(cost.GroupByDay))
	if err != nil {
		return nil, fmt.Errorf("costseries.Cost: %w", err)
	}
	byKey := make(map[string]cost.Row, len(summary.Rows))
	starts := make(map[string]time.Time, len(summary.Rows))
	for _, row := range summary.Rows {
		byKey[row.Key] = row
		starts[row.Key] = timebucket.KeyStart(q.Spec, row.Key)
	}
	slots := timebucket.Slots(q.Spec, starts)
	out := make([]Bucket, 0, len(slots))
	for _, sl := range slots {
		row, ok := byKey[sl.Key]
		if !ok {
			row = cost.Row{Key: sl.Key}
		}
		out = append(out, Bucket{Key: sl.Key, T: sl.T, Row: row, HasData: ok})
	}
	return out, nil
}

// TokensByModel returns one point per (bucket, model) pair that has data,
// sorted by bucket start then model (a stable stacking order), plus the
// zero-filled grid of every bucket in the window so an empty bucket still
// takes its slot on the axis (cost.GroupByDayModel).
func TokensByModel(ctx context.Context, eng *cost.Engine, db *sql.DB, q Query) ([]ModelPoint, []timebucket.GridSlot, error) {
	if eng == nil {
		return nil, nil, fmt.Errorf("costseries.TokensByModel: no cost engine")
	}
	summary, err := eng.Summary(ctx, db, q.options(cost.GroupByDayModel))
	if err != nil {
		return nil, nil, fmt.Errorf("costseries.TokensByModel: %w", err)
	}
	points := make([]ModelPoint, 0, len(summary.Rows))
	starts := map[string]time.Time{}
	for _, row := range summary.Rows {
		bucket, model := cost.SplitDayModelKey(row.Key)
		st, ok := starts[bucket]
		if !ok {
			st = timebucket.KeyStart(q.Spec, bucket)
			starts[bucket] = st
		}
		points = append(points, ModelPoint{Bucket: bucket, T: st, Model: model, Row: row})
	}
	// The engine sorts by cost DESC; re-sort chronologically, then by
	// model, so an axis reads left to right.
	sort.SliceStable(points, func(i, j int) bool {
		if !points[i].T.Equal(points[j].T) {
			return points[i].T.Before(points[j].T)
		}
		if points[i].Bucket != points[j].Bucket {
			return points[i].Bucket < points[j].Bucket
		}
		return points[i].Model < points[j].Model
	})
	return points, timebucket.Slots(q.Spec, starts), nil
}

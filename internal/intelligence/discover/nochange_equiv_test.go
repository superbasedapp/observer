package discover

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// referenceNoChangeRerunCounts is the PRE-2026-09-27 correlated-subquery
// form of noChangeRerunCounts, kept verbatim as the oracle the rewritten
// running-count query must match byte for byte (optimization review
// 2026-09-27). It is test-only: never call it from production code — on a
// large corpus it is per-session quadratic.
func referenceNoChangeRerunCounts(ctx context.Context, database *sql.DB, projectRoot string, since time.Time) (map[noChangeKey]int, error) {
	q := `WITH runs AS (
		SELECT a.session_id, a.target, a.project_id, a.timestamp,
		       LAG(a.timestamp) OVER (PARTITION BY a.session_id, a.target, a.project_id ORDER BY a.timestamp) AS prev_ts
		FROM actions a
		WHERE a.action_type = 'run_command' AND a.target != ''`
	var args []any
	if !since.IsZero() {
		q += " AND a.timestamp >= ?"
		args = append(args, since.UTC().Format(time.RFC3339Nano))
	}
	q += `
	)
	SELECT r.target, COALESCE(p.root_path, '') AS project_root,
	       SUM(CASE WHEN NOT EXISTS (
	         SELECT 1 FROM actions e
	         WHERE e.session_id = r.session_id
	           AND e.action_type IN ('edit_file', 'write_file')
	           AND e.timestamp > r.prev_ts
	           AND e.timestamp < r.timestamp
	       ) THEN 1 ELSE 0 END) AS no_change_count
	FROM runs r
	LEFT JOIN projects p ON p.id = r.project_id
	WHERE r.prev_ts IS NOT NULL`
	if projectRoot != "" {
		q += " AND p.root_path = ?"
		args = append(args, projectRoot)
	}
	q += ` GROUP BY r.target, r.project_id`
	rows, err := database.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[noChangeKey]int{}
	for rows.Next() {
		var key noChangeKey
		var count int
		if err := rows.Scan(&key.command, &key.project, &count); err != nil {
			return nil, err
		}
		out[key] = count
	}
	return out, rows.Err()
}

// TestNoChangeRerunCountsMatchesReference fuzzes a corpus built to hit
// every edge of the rewrite: timestamp ties between a run and an edit, two
// runs of the same command at the same instant, edits that are
// read_file-adjacent noise, several projects sharing one session, empty
// command targets, and a window lower bound that falls between runs. The
// rewritten single-pass query must return exactly the reference map for
// every seed, window and project scope.
func TestNoChangeRerunCountsMatchesReference(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 6; seed++ {
		seed := seed
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			database := openDB(t)
			rootA, rootB := t.TempDir(), t.TempDir()
			roots := []string{rootA, rootB}
			rng := rand.New(rand.NewSource(seed))
			base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			types := []string{
				models.ActionRunCommand, models.ActionRunCommand, models.ActionRunCommand,
				models.ActionEditFile, models.ActionWriteFile, models.ActionReadFile,
			}
			targets := []string{"go test ./...", "make lint", "npm run build", ""}
			var events []models.ToolEvent
			for i := 0; i < 400; i++ {
				at := types[rng.Intn(len(types))]
				target := targets[rng.Intn(len(targets))]
				if at != models.ActionRunCommand {
					target = fmt.Sprintf("f%d.go", rng.Intn(3))
				}
				// A small discrete time grid forces many exact ties.
				ts := base.Add(time.Duration(rng.Intn(60)) * time.Minute)
				events = append(events, models.ToolEvent{
					SourceFile:    fmt.Sprintf("src-%d", seed),
					SourceEventID: fmt.Sprintf("e%d", i),
					SessionID:     fmt.Sprintf("s%d", rng.Intn(3)),
					ProjectRoot:   roots[rng.Intn(len(roots))],
					Tool:          models.ToolClaudeCode,
					Timestamp:     ts,
					ActionType:    at,
					Target:        target,
					Success:       rng.Intn(4) != 0,
				})
			}
			ingest(t, database, rootA, events)

			d := New(database)
			for _, since := range []time.Time{{}, base.Add(20 * time.Minute), base.Add(45 * time.Minute)} {
				for _, root := range []string{"", rootA, rootB} {
					want, err := referenceNoChangeRerunCounts(ctx, database, root, since)
					if err != nil {
						t.Fatalf("reference: %v", err)
					}
					got, err := d.noChangeRerunCounts(ctx, root, since)
					if err != nil {
						t.Fatalf("noChangeRerunCounts: %v", err)
					}
					if len(want) == 0 {
						t.Fatalf("seed %d since %v root %q: reference produced no groups - the fixture no longer exercises the query", seed, since, root)
					}
					if len(got) != len(want) {
						t.Fatalf("seed %d since %v root %q: %d groups, want %d\n got=%v\nwant=%v", seed, since, root, len(got), len(want), got, want)
					}
					for k, w := range want {
						if g, ok := got[k]; !ok || g != w {
							t.Errorf("seed %d since %v root %q key %+v: got %d (present=%v), want %d", seed, since, root, k, g, ok, w)
						}
					}
				}
			}
		})
	}
}

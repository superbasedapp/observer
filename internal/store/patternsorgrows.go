package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// patternsorgrows.go is the W3.3 org-wire seam for Discovery/Patterns (see
// docs/plans/org-parity-full-depth-plan-2026-08-24.md §4 "W3.3"). It OWNS the
// project_patterns table reference for the org-push path — orgpush.go
// deliberately never names that table (module-boundary discipline: one owner
// per table/read seam; the privacy sentinel in tests/invariant/privacy_test.go
// also gains a pin naming it, see the W3.3 report's teams-hardening snippet).
//
// Design choice — reads ONLY the persisted project_patterns table, not a live
// re-aggregation over actions:
//
// The node has two read paths for patterns: (1) the persisted
// project_patterns table, populated only by a manual/cron `observer patterns
// derive` run (cmd/observer/patterns.go → patterns.Deriver.Derive), and (2)
// the MCP get_project_patterns tool's live top-N GROUP BY over actions for
// hot_files/common_commands specifically (internal/mcp/tools_extra.go),
// which exists BECAUSE project_patterns can be empty/stale on a node that
// never ran the derive step. This seam mirrors path (1) only — the
// dashboard's own handlePatterns (internal/intelligence/dashboard/dashboard.go)
// does the same, and replicating the Deriver's hotFiles()/commonCommands()
// SQL here would require its unexported fileActionTypes/commandActionTypes/
// tooltax internals. The honest consequence: a node that has never run
// `observer patterns derive` (or whose derive run is stale — the Deriver
// DELETEs and reinserts per project on each run, so the table is inherently
// freshness-bounded by that cadence, needing no additional time-window filter
// here) contributes nothing to this wire until it does.
//
// Cap: projectPatternCapPerGroup rows per (project, kind), applied in Go via
// an ORDER BY + counter map — NOT a SQL window function (ROW_NUMBER() OVER),
// following internal/store/processorgrows.go's documented convention that
// this package avoids that construct even though other packages in the
// codebase use it.
const projectPatternCapPerGroup = 50

// SelectProjectPatternRows recomputes the W3.3 Discovery/Patterns wire rows
// from every project's persisted project_patterns table. One row per
// (project, kind, value), capped at projectPatternCapPerGroup per
// (project, kind), ordered by confidence then observation_count.
func (s *Store) SelectProjectPatternRows(ctx context.Context) ([]orgcontract.ProjectPatternRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT p.root_path_hash, p.root_path,
		        pp.pattern_type, pp.pattern_data,
		        COALESCE(pp.observation_count, 0), COALESCE(pp.confidence, 0),
		        COALESCE(pp.source_tools, ''), COALESCE(pp.last_reinforced_at, '')
		   FROM project_patterns pp
		   JOIN projects p ON p.id = pp.project_id
		  WHERE p.root_path_hash != ''
		  ORDER BY p.id, pp.pattern_type, pp.confidence DESC, pp.observation_count DESC, pp.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("store.SelectProjectPatternRows: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	out := []orgcontract.ProjectPatternRow{}
	for rows.Next() {
		var rootHash, rootPath, kind, data, sourceTools, lastSeen string
		var observationCount int64
		var confidence float64
		if err := rows.Scan(&rootHash, &rootPath, &kind, &data, &observationCount, &confidence, &sourceTools, &lastSeen); err != nil {
			return nil, fmt.Errorf("store.SelectProjectPatternRows: scan: %w", err)
		}

		groupKey := rootHash + "\x00" + kind
		if counts[groupKey] >= projectPatternCapPerGroup {
			continue
		}
		counts[groupKey]++

		out = append(out, orgcontract.ProjectPatternRow{
			ProjectRootHash:  rootHash,
			ProjectRoot:      rootPath,
			Kind:             kind,
			Value:            projectPatternValue(kind, data),
			ObservationCount: observationCount,
			Confidence:       confidence,
			SourceTools:      sourceTools,
			LastSeen:         lastSeen,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectProjectPatternRows: %w", err)
	}
	return out, nil
}

// projectPatternValue extracts the ProjectPatternRow.Value for a pattern_data
// JSON blob, per kind — see internal/orgcontract/patterns.go's Value doc
// comment for the extraction rule. Falls back to the raw JSON blob if the
// expected field is missing or the JSON fails to decode (defensive: an
// unexpected shape should still ship something rather than silently drop the
// row).
func projectPatternValue(kind, dataJSON string) string {
	switch kind {
	case "hot_file":
		var v struct {
			FilePath string `json:"file_path"`
		}
		if err := json.Unmarshal([]byte(dataJSON), &v); err == nil && v.FilePath != "" {
			return v.FilePath
		}
	case "common_command":
		var v struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal([]byte(dataJSON), &v); err == nil && v.Command != "" {
			return v.Command
		}
	}
	return dataJSON
}

// probeProjectPatterns is the Track R2 change-detection probe for the
// project_patterns wire. It lives here — with the wire's own SQL — so
// orgsnapgate.go and orgpush.go stay free of the table names.
//
// PROBE: (MAX(id), COUNT(*)) over project_patterns plus MAX(projects.id).
//
// WHY THE COUNT IS AFFORDABLE HERE — AND NECESSARY: `observer patterns derive`
// DELETEs and reinserts a project's rows wholesale, so a derive run that
// produces FEWER patterns than the last one can leave MAX(id) looking
// plausible only if the reinsert happens to be smaller; the row count is what
// makes a shrinking derive visible. project_patterns is a derived, capped table
// (projectPatternCapPerGroup rows per project × kind), not an event log, so the
// count is an index-only scan over thousands of rows at most — unlike the
// event-log families, where the same COUNT would be the cost the gate exists to
// avoid. `projects` is in the probe because the wire JOINs it for
// root_path_hash, and it is smaller still.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: an in-place confidence /
// observation_count UPDATE that neither inserts nor deletes a row would not
// move either component; snapGate's maxSkipAge recomputes within the hour.
func (s *Store) probeProjectPatterns(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'pp' || (SELECT COALESCE(MAX(id), 0) || '/' || COUNT(*) FROM project_patterns) ||
		       ':pj' || (SELECT COALESCE(MAX(id), 0) FROM projects)`)
}

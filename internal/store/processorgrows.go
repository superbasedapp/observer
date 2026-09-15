package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// W2.2 session-scoped process rows (org-parity plan §4 W2.2,
// docs/plans/org-parity-full-depth-plan-2026-08-24.md). This file — NOT
// orgpush.go — owns the process_runs / process_events read (the privacy
// sentinel forbids the process_* table names from ever appearing in
// orgpush.go; the push path composes these rows via a function call, exactly
// like SelectProcessSummaries in processsummary.go).
//
// Unlike processsummary.go's Arc 4 aggregate, this is a RAW per-run read: it
// ships under admin_managed / full_content (ShareOptions.shipsRawContent())
// so the org session detail can render the same process tree the node's own
// System tab shows, scoped to one session. It still never reads
// process_network_bodies and never reads process_events.target*/details_json
// — only a per-run COUNT(*) of events crosses.

// sessionProcessWindowDays bounds the read to sessions active in the recent
// window; the server upserts by natural key (org_id, session_id, run_key), so
// re-pushing a window is idempotent.
const sessionProcessWindowDays = 7

// sessionProcessRunCap is the per-session cap on how many process runs this
// query returns. Sessions that spawn far more than this (a runaway shell
// loop, a noisy watch script) would otherwise dominate the push payload for
// one session; 200 comfortably covers ordinary interactive + sub-agent
// process fan-out while bounding worst case. The cap keeps the MOST RECENT
// runs (by started_at) per session, enforced IN SQL via ROW_NUMBER() OVER
// (PARTITION BY session_id ORDER BY started_at DESC) filtered rn <= this cap
// — exactly like sessionNetworkEventCap in networkorgrows.go — so the
// discarded runs never reach the per-run event count or the Go scan.
const sessionProcessRunCap = 200

// sessionProcessMetricSampleCap and sessionProcessMetricSamplesMaxBytes bound
// the high-volume metric_samples_json ring on the wire. The node stores a
// capped in-row JSON array of recent {t,cpu,ws,rb,wb,…} sparkline samples
// (migration 045); a runaway or long-lived run can still leave it far larger
// than the rest of the row, so the wire keeps only the most-recent
// sessionProcessMetricSampleCap samples and, if the trimmed array still
// exceeds sessionProcessMetricSamplesMaxBytes, drops it entirely (the process
// tree / metadata is worth far more per byte than the trend chart). This
// per-row bound is deterministic and independent of the whole-envelope budget
// the push loop enforces in orgpush.go — that second guard drops the samples
// across ALL process rows when the composed slice would still overrun the
// remaining snapshot budget. 60 samples matches the node's own display window;
// 8 KiB comfortably holds them while refusing a pathological blob.
const (
	sessionProcessMetricSampleCap       = 60
	sessionProcessMetricSamplesMaxBytes = 8 << 10
)

// sessionProcessRowsQuery is the SelectSessionProcessRows read, held as a
// const so processorgrows_test.go can assert its EXPLAIN QUERY PLAN against
// the exact string production runs (a copy in the test would silently drift
// away from the query whose plan it claims to pin).
//
// The per-session cap is enforced IN SQL via ROW_NUMBER() rather than in Go,
// and the per-run event count is a CORRELATED subquery rather than a
// pre-aggregated LEFT JOIN. Both changes exist to stop work the cap was going
// to throw away:
//
//   - the count now fires only for runs that survive rn <= cap, as a covering-
//     index seek on idx_process_events_run (migration 090). The previous
//     LEFT JOIN (SELECT ... GROUP BY process_run_id) materialized an aggregate
//     over the ENTIRE process_events table on every push tick — no index led
//     with process_run_id, so it was a full scan plus a temp-b-tree GROUP BY
//     whose cost was independent of how few runs the window held.
//   - idx_process_runs_session_started_desc (migration 090) serves the
//     window's PARTITION BY session_id ORDER BY started_at DESC with no sort.
//     idx_process_runs_session is ASC on both columns and cannot: the required
//     order is MIXED, and reverse-scanning it yields session_id DESC. Without
//     the DESC index the plan externally sorted the whole window before the
//     cap could discard from it.
//
// A temp b-tree remains on the outer ORDER BY (SQLite cannot carry sort order
// out of a co-routine CTE), but it sorts only the post-cap survivors —
// bounded by cap x sessions, not by the window. Together these were the
// 11.9%-of-daemon-CPU finding of the 2026-08-26 audit.
//
// Selection is arithmetically identical to the Go-side cap it replaces: the
// sessionProcessRunCap most recent runs per session by started_at DESC,
// output ordered session_id then started_at DESC. Placeholders are (since,
// cap) in that order.
const sessionProcessRowsQuery = `
		WITH ranked AS (
			SELECT pr.id, pr.session_id, pr.process_key, pr.parent_process_key, pr.pid, pr.ppid,
			       pr.tool, pr.action_id, pr.turn_index,
			       pr.exe_path, pr.exe_basename, pr.exe_hash, pr.cwd, pr.argv_preview, pr.argv_argc,
			       pr.attribution_source, pr.attribution_confidence,
			       pr.started_at, pr.exited_at, pr.exit_code, pr.exit_signal, pr.duration_ms,
			       pr.cpu_user_ms, pr.cpu_system_ms, pr.max_rss_bytes, pr.working_set_bytes,
			       pr.thread_count, pr.read_bytes, pr.write_bytes, pr.metric_samples_json,
			       ROW_NUMBER() OVER (PARTITION BY pr.session_id ORDER BY pr.started_at DESC) AS rn
			FROM process_runs pr
			WHERE pr.session_id IS NOT NULL AND pr.session_id != '' AND pr.started_at >= ?
		)
		SELECT r.session_id, r.process_key, r.parent_process_key, r.pid, r.ppid,
		       r.tool, r.action_id, r.turn_index,
		       r.exe_path, r.exe_basename, r.exe_hash, r.cwd, r.argv_preview, r.argv_argc,
		       r.attribution_source, r.attribution_confidence,
		       r.started_at, r.exited_at, r.exit_code, r.exit_signal, r.duration_ms,
		       r.cpu_user_ms, r.cpu_system_ms, r.max_rss_bytes, r.working_set_bytes,
		       r.thread_count, r.read_bytes, r.write_bytes, r.metric_samples_json,
		       (SELECT COUNT(*) FROM process_events pe WHERE pe.process_run_id = r.id),
		       (SELECT a.message_id FROM actions a WHERE a.id = r.action_id)
		FROM ranked r
		WHERE r.rn <= ?
		ORDER BY r.session_id, r.started_at DESC`

// SelectSessionProcessRows reads process_runs (+ a process_events count per
// run) for every session with process activity in the trailing window,
// capped to the sessionProcessRunCap most recent runs per session.
func (s *Store) SelectSessionProcessRows(ctx context.Context) ([]orgcontract.SessionProcessRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sessionProcessWindowDays)
	rows, err := s.db.QueryContext(ctx, sessionProcessRowsQuery, timestamp(since), sessionProcessRunCap)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessRows: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.SessionProcessRow{}
	for rows.Next() {
		var (
			r                      orgcontract.SessionProcessRow
			parentKey              sql.NullString
			ppid                   sql.NullInt64
			tool                   sql.NullString
			actionID, turnIndex    sql.NullInt64
			exePath, exeBasename   sql.NullString
			exeHash, cwd           sql.NullString
			argvPreview            sql.NullString
			argvArgc               sql.NullInt64
			exitedAt               sql.NullString
			exitCode, exitSignal   sql.NullInt64
			durationMs             sql.NullInt64
			cpuUserMs, cpuSystemMs sql.NullInt64
			maxRSSBytes            sql.NullInt64
			workingSetBytes        sql.NullInt64
			threadCount            sql.NullInt64
			readBytes, writeBytes  sql.NullInt64
			metricSamplesJSON      sql.NullString
			messageID              sql.NullString
		)
		if err := rows.Scan(
			&r.SessionID, &r.RunKey, &parentKey, &r.PID, &ppid,
			&tool, &actionID, &turnIndex,
			&exePath, &exeBasename, &exeHash, &cwd, &argvPreview, &argvArgc,
			&r.AttributionSource, &r.AttributionConfidence,
			&r.StartedAt, &exitedAt, &exitCode, &exitSignal, &durationMs,
			&cpuUserMs, &cpuSystemMs, &maxRSSBytes, &workingSetBytes,
			&threadCount, &readBytes, &writeBytes, &metricSamplesJSON,
			&r.EventCount, &messageID,
		); err != nil {
			return nil, fmt.Errorf("store.SelectSessionProcessRows: scan: %w", err)
		}

		r.ParentRunKey = parentKey.String
		r.PPID = ppid.Int64
		r.Tool = tool.String
		r.ActionID = actionID.Int64
		r.TurnIndex = turnIndex.Int64
		r.MessageID = messageID.String
		r.ExePath = exePath.String
		r.ExeBasename = exeBasename.String
		r.ExeHash = exeHash.String
		r.CWD = cwd.String
		r.ArgvPreview = argvPreview.String
		r.ArgvArgc = argvArgc.Int64
		r.EndedAt = exitedAt.String
		r.Exited = exitedAt.Valid
		r.ExitCode = exitCode.Int64
		r.ExitSignal = exitSignal.Int64
		r.DurationMs = durationMs.Int64
		r.CPUUserMs = cpuUserMs.Int64
		r.CPUSystemMs = cpuSystemMs.Int64
		r.MaxRSSBytes = maxRSSBytes.Int64
		r.WorkingSetBytes = workingSetBytes.Int64
		r.ThreadCount = threadCount.Int64
		r.ReadBytes = readBytes.Int64
		r.WriteBytes = writeBytes.Int64
		r.MetricSamplesJSON = capMetricSamples(metricSamplesJSON.String)

		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionProcessRows: %w", err)
	}
	return out, nil
}

// capMetricSamples bounds the high-volume metric_samples_json ring for the
// wire. It parses the node's stored JSON array of samples, keeps only the most
// recent sessionProcessMetricSampleCap of them (the tail is the freshest — the
// node appends chronologically), and re-serializes. If the input is not a JSON
// array (garbage, or a shape the node never wrote) or the trimmed result still
// exceeds sessionProcessMetricSamplesMaxBytes, it drops the ring entirely
// (returns ""). Dropping is never data loss: metric_samples_json is a display-
// only sparkline the server upserts by natural key, recomposed on the next
// push tick, and every consumer treats an empty ring as "no trend captured".
func capMetricSamples(raw string) string {
	if raw == "" {
		return ""
	}
	var samples []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &samples); err != nil {
		// Not a JSON array we recognize — refuse to ship an opaque blob.
		return ""
	}
	if len(samples) > sessionProcessMetricSampleCap {
		samples = samples[len(samples)-sessionProcessMetricSampleCap:]
	}
	trimmed, err := json.Marshal(samples)
	if err != nil || len(trimmed) > sessionProcessMetricSamplesMaxBytes {
		return ""
	}
	return string(trimmed)
}

// probeProcessRuns is the Track R2 change-detection probe SHARED by both wires
// fed from the process tables: session_process (this file) and process_summary
// (processsummary.go). It lives here — with the other process_* SQL — so
// orgsnapgate.go and orgpush.go stay free of the table names the privacy
// sentinel forbids there.
//
// PROBE: the pair (MAX(process_runs.id), MAX(process_events.id)) — two
// index-endpoint seeks on AUTOINCREMENT primary keys, O(1). Both tables are in
// the probe because this wire ships a per-run EVENT COUNT as well as the run
// row, so a run that only gains events must still be seen as dirty.
//
// WHY A WINDOWED COUNT IS NOT USED: process_runs has no index on started_at, so
// mirroring the wire's own `WHERE started_at >= ?` window in the probe would
// cost a full table scan every tick — the very cost this gate exists to remove.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: process_runs is UPSERTED by
// process_key, so an exit-code / exited_at / duration backfill onto an EXISTING
// run — and the correlator's session/tool/action attribution UPDATEs — advance
// no id. On an active node new runs and events arrive continuously and the
// probe fires anyway; on an idle node the last run's exit lands within
// snapGate's maxSkipAge (an hour), which is well inside the org rollups'
// day-scale windows.
func (s *Store) probeProcessRuns(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `
		SELECT 'pr' || (SELECT COALESCE(MAX(id), 0) FROM process_runs) ||
		       ':pe' || (SELECT COALESCE(MAX(id), 0) FROM process_events)`)
}

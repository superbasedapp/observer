// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// hookactivitysummary.go composes the per-session hook liveness wire
// (surface-gap review 2026-10-25, OBS-7; operator decision DEC-5; lane
// w5-wire). This file, NOT orgpush.go, owns the hook_activity READ for the
// wire, exactly as toolaccountsummary.go owns the tool_account_observations
// read: the privacy sentinel forbids that table name in orgpush.go, so the
// push path composes this through a FUNCTION CALL.
//
// internal/store/hookactivity.go stays the table's one WRITER
// (UpsertHookActivity, fed by the daemon's hook spool drainer) and its
// node-side reader. This file only reads, for the wire.
//
// THE CONTENT GATE LIVES HERE, ONCE. SelectSessionHookActivity takes a
// shipsContent bool that the ONE call site in orgpush.go supplies as
// share.shipsRawContent(). When it is false every env class outside the
// closed coarse vocabulary (hookliveness.MetadataClass; today the
// CLAUDE_CONFIG_DIR path hash) is dropped from the row before it is
// returned, so a metadata-tier node ships "ANTHROPIC_BASE_URL: loopback" and
// never a path hash. The test is on the CLASS, not on a variable name, so a
// future content-level probe is withheld by default.
//
// WINDOW + IDEMPOTENCY. The recompute is bounded to rows whose last
// invocation falls in the trailing sessionHookActivityWindowDays window, and
// the server upserts on the node's own PRIMARY KEY (session_id, tool, event)
// scoped by org and pushing user, so re-pushing a window is idempotent and a
// growing count overwrites the older one.

// sessionHookActivityWindowDays bounds the recompute, matching
// sessionToolAccountWindowDays: a row whose last invocation is older than a
// week has already shipped with its final count.
const sessionHookActivityWindowDays = 7

// SelectSessionHookActivity returns every hook_activity row whose last
// invocation is inside the trailing window, in primary key order (session
// id, tool, event), with content-level env classes dropped unless
// shipsContent.
func (s *Store) SelectSessionHookActivity(ctx context.Context, shipsContent bool) ([]orgcontract.HookActivitySessionRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sessionHookActivityWindowDays).Format(hookActivityTimeLayout)
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, tool, event, count, first_at, last_at, env_classes
		  FROM hook_activity
		 WHERE last_at >= ?
		 ORDER BY session_id, tool, event`, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionHookActivity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []orgcontract.HookActivitySessionRow{}
	for rows.Next() {
		var r orgcontract.HookActivitySessionRow
		var env string
		if err := rows.Scan(&r.SessionID, &r.Tool, &r.Event, &r.Count, &r.FirstAt, &r.LastAt, &env); err != nil {
			return nil, fmt.Errorf("store.SelectSessionHookActivity: scan: %w", err)
		}
		r.EnvClasses = wireEnvClasses(env, shipsContent)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSessionHookActivity: %w", err)
	}
	return out, nil
}

// wireEnvClasses decodes a stored env_classes object and keeps the entries
// the posture allows: every entry when shipsContent, otherwise only the
// closed coarse classes. nil when nothing remains (omitempty drops it). An
// undecodable value ships nothing rather than a guess.
func wireEnvClasses(stored string, shipsContent bool) map[string]string {
	if stored == "" {
		return nil
	}
	var all map[string]string
	if err := json.Unmarshal([]byte(stored), &all); err != nil {
		return nil
	}
	out := make(map[string]string, len(all))
	for name, class := range all {
		if shipsContent || hookliveness.MetadataClass(class) {
			out[name] = class
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// probeHookActivity is the Track R2 change-detection probe for the
// session_hook_activity wire family (orgsnapgate.go). It lives HERE, with
// the table's wire reader, so orgsnapgate.go and orgpush.go stay free of the
// hook_activity name.
//
// PROBE: MAX(last_at), one seek on idx_hook_activity_last_at. Every drained
// invocation that is the newest so far advances it, and the upsert moves
// last_at forward on the row it touches.
//
// RESIDUAL, BOUNDED BY THE FRESHNESS FLOOR: a late spool record whose
// invocation is older than the current maximum only raises a count, and a
// retention prune is a delete; neither moves MAX(last_at). snapGate's
// maxSkipAge recomputes within the hour, like probeToolAccounts' residual.
func (s *Store) probeHookActivity(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'ha' || COALESCE(MAX(last_at), '') FROM hook_activity`)
}

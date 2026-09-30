package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
)

// LoadModelValueFacts is the store seam for the Model Value Report and
// the routing replay surfaces (model-routing spec §R17/§R18): it loads
// the deduped proxy∪JSONL turn substrate plus the normalized action
// stream into a modelvalue.Facts bundle. modelvalue itself imports no
// SQL — this file owns the queries; the boundary resolutions (command
// class, phase hint, subagent name) happen here so no content leaves
// the seam (§24.3).
//
// Dedup is the one session rule, sessionmsg.DeriveVerdicts (via
// NodeSessionVerdicts), applied per session over the window's rows: every
// api_turns row counts, a twinned one with its transcript twin's visible
// output / reasoning split (and its fast tier when the twin is fast); a
// token_usage row counts unless Derive claims it as a proxy twin, a
// request-id duplicate, or a paired output-only shadow row. It replaced a
// set-membership rule on (request_id) and a RAW-output shape key (lane
// R2-PARITY-2) that missed every reasoning-split twin and dropped every
// same-shape transcript row rather than one per proxy row.
//
// Price and Tiers are left nil — callers inject them (PriceFn from
// cost.Engine.ComputeBreakdown; nil Tiers means the shipped seed table).
func (s *Store) LoadModelValueFacts(ctx context.Context, opts modelvalue.LoadOptions) (*modelvalue.Facts, error) {
	now := opts.EffectiveNow()
	windowDays := opts.EffectiveWindowDays()
	since := now.AddDate(0, 0, -windowDays).UTC().Format(time.RFC3339)

	f := &modelvalue.Facts{WindowDays: windowDays, GeneratedAt: now}

	dd := newMVDedup()

	// Queries are assembled here (the only dynamic part is the optional
	// project predicate, always parameter-bound) and executed by the
	// per-arm loaders — the advisor-loader structure.
	//
	// No ORDER BY on any of the three: api_turns/token_usage/actions
	// are large tables with no index covering (session_id, timestamp),
	// so a DB-side sort here would spill a temp B-tree (P1-C). Ordering
	// is load-bearing but produced downstream instead — report.go's
	// indexFacts sorts turns globally by (session, timestamp) and
	// actions per session by timestamp (both stably) before any
	// classification runs, so a pre-sorted arm here would already have
	// been redundant.
	proxyQ := `
		SELECT at.session_id, COALESCE(s.tool, ''), COALESCE(s.model, ''), COALESCE(s.project_id, 0), COALESCE(p.root_path, ''),
		       at.timestamp, COALESCE(at.model, ''), COALESCE(at.request_id, ''),
		       COALESCE(at.input_tokens, 0), COALESCE(at.output_tokens, 0),
		       COALESCE(at.cache_read_tokens, 0), COALESCE(at.cache_creation_tokens, 0),
		       COALESCE(at.cache_creation_1h_tokens, 0), COALESCE(at.web_search_requests, 0),
		       COALESCE(at.fast, 0), COALESCE(at.cost_usd, 0),
		       COALESCE(at.message_count, 0), COALESCE(at.tool_use_count, 0),
		       COALESCE(at.time_to_first_token_ms, 0), COALESCE(at.total_response_ms, 0),
		       COALESCE(at.http_status, 0), COALESCE(at.error_class, ''),
		       COALESCE(at.stop_reason, '')
		FROM api_turns at
		JOIN sessions s ON s.id = at.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE at.timestamp >= ?` + mvScope(opts)
	jsonlQ := `
		SELECT tu.session_id, COALESCE(s.tool, ''), COALESCE(s.model, ''), COALESCE(s.project_id, 0), COALESCE(p.root_path, ''),
		       tu.timestamp, COALESCE(tu.model, ''), COALESCE(tu.source_event_id, ''),
		       COALESCE(tu.input_tokens, 0), COALESCE(tu.output_tokens, 0),
		       COALESCE(tu.cache_read_tokens, 0), COALESCE(tu.cache_creation_tokens, 0),
		       COALESCE(tu.cache_creation_1h_tokens, 0), COALESCE(tu.web_search_requests, 0),
		       COALESCE(tu.reasoning_tokens, 0), COALESCE(tu.fast, 0),
		       COALESCE(tu.message_id, ''), COALESCE(tu.turn_id, ''),
		       COALESCE(tu.estimated_cost_usd, 0), COALESCE(tu.source_file_hash, '')
		FROM token_usage tu
		JOIN sessions s ON s.id = tu.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE tu.timestamp >= ?` + mvScope(opts)
	actionsQ := `
		SELECT a.session_id, a.timestamp, a.action_type,
		       COALESCE(a.success, 1), COALESCE(a.is_sidechain, 0),
		       COALESCE(a.duration_ms, 0),
		       CASE WHEN a.action_type IN (?, ?, ?) THEN COALESCE(a.target, '') ELSE '' END
		FROM actions a
		JOIN sessions s ON s.id = a.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE a.timestamp >= ?` + mvScope(opts)

	if err := s.loadModelValueProxyTurns(ctx, proxyQ, since, opts, f, dd); err != nil {
		return nil, fmt.Errorf("store.LoadModelValueFacts: proxy rows: %w", err)
	}
	if err := s.loadModelValueJSONLTurns(ctx, jsonlQ, since, opts, dd); err != nil {
		return nil, fmt.Errorf("store.LoadModelValueFacts: jsonl rows: %w", err)
	}
	dd.apply(f)
	if err := s.loadModelValueActions(ctx, actionsQ, since, opts, f); err != nil {
		return nil, fmt.Errorf("store.LoadModelValueFacts: actions: %w", err)
	}
	return f, nil
}

// mvScope appends the optional project predicate; mvScopeArgs binds it.
func mvScope(opts modelvalue.LoadOptions) string {
	if opts.ProjectRoot != "" {
		return " AND p.root_path = ?"
	}
	return ""
}

func mvScopeArgs(since string, opts modelvalue.LoadOptions) []any {
	args := []any{since}
	if opts.ProjectRoot != "" {
		args = append(args, opts.ProjectRoot)
	}
	return args
}

func (s *Store) loadModelValueProxyTurns(
	ctx context.Context, q, since string, opts modelvalue.LoadOptions,
	f *modelvalue.Facts, dd *mvDedup,
) error {
	rows, err := s.db.QueryContext(ctx, q, mvScopeArgs(since, opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			sid, tool, smodel, root, ts, model, reqID, errClass, stop string
			projectID, in, out, cr, cc, cc1, ws                       int64
			fast                                                      int64
			costUSD                                                   float64
			msgCount, toolCount                                       int
			ttft, totalMS                                             int64
			httpStatus                                                int
		)
		if err := rows.Scan(&sid, &tool, &smodel, &projectID, &root, &ts, &model, &reqID,
			&in, &out, &cr, &cc, &cc1, &ws, &fast, &costUSD,
			&msgCount, &toolCount, &ttft, &totalMS, &httpStatus, &errClass, &stop); err != nil {
			return err
		}
		t := parseStamp(ts)
		if t.IsZero() {
			continue
		}
		f.Turns = append(f.Turns, modelvalue.TurnRow{
			SessionID: sid, ProjectID: projectID, ProjectRoot: root,
			Timestamp: t, Model: model,
			Input: in, Output: out, CacheRead: cr, CacheCreation: cc,
			CacheCreation1h: cc1, WebSearchRequests: ws, Fast: fast != 0,
			MessageCount: msgCount, ToolUseCount: toolCount,
			TTFTMs: ttft, TotalMs: totalMS, HasLatency: totalMS > 0,
			HTTPStatus: httpStatus, ErrorClass: errClass,
			HasStatus:     httpStatus > 0 || errClass != "",
			StoredCostUSD: costUSD,
		})
		dd.addProxy(sid, tool, smodel, len(f.Turns)-1, sessionmsg.ProxyRow{
			RequestID: reqID, Timestamp: ts, Model: model,
			Input: in, Output: out, CacheRead: cr, CacheCreation: cc,
			CacheCreation1h: cc1, WebSearchRequests: ws, CostUSD: costUSD, Fast: fast != 0,
			TTFBMs: ttft, TotalMs: totalMS, StopReason: stop,
		})
	}
	return rows.Err()
}

func (s *Store) loadModelValueJSONLTurns(
	ctx context.Context, q, since string, opts modelvalue.LoadOptions, dd *mvDedup,
) error {
	rows, err := s.db.QueryContext(ctx, q, mvScopeArgs(since, opts)...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			sid, tool, smodel, root, ts, model, eventID string
			projectID, in, out, cr, cc, cc1, ws         int64
			reasoning, fast                             int64
			messageID, turnID, fileHash                 string
			costUSD                                     float64
		)
		if err := rows.Scan(&sid, &tool, &smodel, &projectID, &root, &ts, &model, &eventID,
			&in, &out, &cr, &cc, &cc1, &ws, &reasoning, &fast,
			&messageID, &turnID, &costUSD, &fileHash); err != nil {
			return err
		}
		t := parseStamp(ts)
		if t.IsZero() {
			continue
		}
		dd.addToken(sid, tool, smodel, modelvalue.TurnRow{
			SessionID: sid, ProjectID: projectID, ProjectRoot: root,
			Timestamp: t, Model: model,
			Input: in, Output: out, CacheRead: cr, CacheCreation: cc,
			CacheCreation1h: cc1, WebSearchRequests: ws, Reasoning: reasoning,
			Fast: fast != 0,
			// JSONL rows carry no latency or HTTP status — the
			// capability flags stay false so the report grades only
			// what was observed.
		}, sessionmsg.TokenRow{
			SourceEventID: eventID, MessageID: messageID, TurnID: turnID,
			Timestamp: ts, Model: model,
			Input: in, Output: out, CacheRead: cr, CacheCreation: cc,
			CacheCreation1h: cc1, Reasoning: reasoning, WebSearchRequests: ws,
			CostUSD: costUSD, Fast: fast != 0, SourceFileHash: fileHash,
		})
	}
	return rows.Err()
}

// mvDedup gathers the window's proxy and transcript rows per session so
// LoadModelValueFacts can apply the one session dedup rule
// (NodeSessionVerdicts) before a transcript row becomes a turn.
type mvDedup struct {
	sessions map[string]*mvSession
	order    []string
}

type mvSession struct {
	tool, model string
	proxyIdx    []int // indexes into Facts.Turns
	proxies     []sessionmsg.ProxyRow
	tokenTurns  []modelvalue.TurnRow
	tokens      []sessionmsg.TokenRow
}

func newMVDedup() *mvDedup { return &mvDedup{sessions: map[string]*mvSession{}} }

func (d *mvDedup) session(sid, tool, model string) *mvSession {
	ss := d.sessions[sid]
	if ss == nil {
		ss = &mvSession{tool: tool, model: model}
		d.sessions[sid] = ss
		d.order = append(d.order, sid)
	}
	return ss
}

func (d *mvDedup) addProxy(sid, tool, model string, turnIdx int, p sessionmsg.ProxyRow) {
	ss := d.session(sid, tool, model)
	ss.proxyIdx = append(ss.proxyIdx, turnIdx)
	ss.proxies = append(ss.proxies, p)
}

func (d *mvDedup) addToken(sid, tool, model string, turn modelvalue.TurnRow, t sessionmsg.TokenRow) {
	ss := d.session(sid, tool, model)
	ss.tokenTurns = append(ss.tokenTurns, turn)
	ss.tokens = append(ss.tokens, t)
}

// apply runs the verdicts per session: twinned proxy turns take their
// twin's output / reasoning split (and fast tier), and every transcript row
// Derive counts is appended as a turn, in load order.
func (d *mvDedup) apply(f *modelvalue.Facts) {
	for _, sid := range d.order {
		ss := d.sessions[sid]
		if len(ss.tokens) == 0 {
			continue
		}
		v := NodeSessionVerdicts(ss.tool, ss.model, ss.proxies, ss.tokens)
		for j, ti := range ss.proxyIdx {
			f.Turns[ti].Output = v.ProxyOutput[j]
			f.Turns[ti].Reasoning = v.ProxyReasoning[j]
			f.Turns[ti].Fast = f.Turns[ti].Fast || v.ProxyInheritedFast[j]
		}
		for j, turn := range ss.tokenTurns {
			if v.TokenCounted[j] {
				f.Turns = append(f.Turns, turn)
			}
		}
	}
}

// loadModelValueActions loads the normalized action stream with all
// content resolved away at this boundary: run_command targets become a
// CommandClass, permission-mode targets a PhaseHint, subagent_start
// targets the persona name. The target column never leaves this
// function for any other action type.
func (s *Store) loadModelValueActions(
	ctx context.Context, q, since string, opts modelvalue.LoadOptions, f *modelvalue.Facts,
) error {
	args := []any{models.ActionRunCommand, models.ActionPermissionMode, models.ActionSubagentStart}
	args = append(args, mvScopeArgs(since, opts)...)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			sid, ts, actionType, target string
			success, sidechain          int64
			durationMS                  int64
		)
		if err := rows.Scan(&sid, &ts, &actionType, &success, &sidechain, &durationMS, &target); err != nil {
			return err
		}
		t := parseStamp(ts)
		if t.IsZero() {
			continue
		}
		row := modelvalue.ActionRow{
			SessionID: sid, Timestamp: t, Type: actionType,
			Success: success != 0, IsSidechain: sidechain != 0, DurationMs: durationMS,
		}
		switch actionType {
		case models.ActionRunCommand:
			row.CommandClass = routing.ResolveCommandClass(target)
		case models.ActionPermissionMode:
			row.PhaseHint = target
		case models.ActionSubagentStart:
			row.SubagentName = target
		}
		f.Actions = append(f.Actions, row)
	}
	return rows.Err()
}

package advisor

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
)

// minSessionRows is the floor below which a session doesn't enter Facts at
// all — no detector has anything to say about a 4-row session.
const minSessionRows = 5

// LoadFacts builds the Facts bundle for one engine run. The substrate is
// the deduped proxy∪JSONL union (calibration §1: an api_turns-only loader
// yields zero suggestions on a watcher-dominated corpus). WHICH rows survive
// is the one session rule, sessionmsg.DeriveVerdicts, applied per session
// (sessionVerdicts) — the rule the node's session detail header, the cost
// engine and the org use: every api_turns row counts (a twinned one with its
// transcript twin's visible output / reasoning split and its fast tier), and
// a token_usage row counts unless Derive claims it as a proxy twin, a
// request-id duplicate or a paired output-only shadow row. It replaced a
// set-membership rule on request id and a RAW-output shape key (lane
// R2-PARITY-2) that missed every reasoning-split twin and dropped every
// same-shape transcript row rather than one per proxy row.
func LoadFacts(ctx context.Context, db *sql.DB, opts Options) (*Facts, error) {
	now := opts.now()
	since := now.AddDate(0, 0, -opts.WindowDays).UTC().Format(time.RFC3339)

	sessions := map[string]*SessionFacts{}
	pending := map[string]*pendingSession{}
	var pendingOrder []string
	pend := func(sid string) *pendingSession {
		ps := pending[sid]
		if ps == nil {
			ps = &pendingSession{}
			pending[sid] = ps
			pendingOrder = append(pendingOrder, sid)
		}
		return ps
	}

	// No ORDER BY: api_turns is large and un-indexed on (session_id,
	// timestamp), so a DB-side sort would spill a temp B-tree (P1-C).
	// Ordering is produced in Go below — every session's Rows is
	// re-sorted by timestamp after both arms are merged, so a
	// pre-sorted arm here would be redundant even before removal.
	proxyQ := `
		SELECT at.session_id, COALESCE(s.tool,''), COALESCE(s.model,''), COALESCE(p.root_path,''),
		       at.timestamp, COALESCE(at.model,''), COALESCE(at.request_id,''),
		       COALESCE(at.input_tokens,0), COALESCE(at.output_tokens,0),
		       COALESCE(at.cache_read_tokens,0), COALESCE(at.cache_creation_tokens,0),
		       COALESCE(at.cache_creation_1h_tokens,0), 0 AS reasoning_tokens, COALESCE(at.fast,0),
		       COALESCE(at.compression_original_bytes,0), COALESCE(at.compression_compressed_bytes,0),
		       COALESCE(at.web_search_requests,0), COALESCE(at.cost_usd,0),
		       '', '', '',
		       COALESCE(at.time_to_first_token_ms,0), COALESCE(at.total_response_ms,0), COALESCE(at.stop_reason,'')
		FROM api_turns at
		JOIN sessions s ON s.id = at.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE at.timestamp >= ?` + scopeFilter(opts)
	if err := loadRows(ctx, db, proxyQ, since, opts, func(r loadedRow) {
		s := ensureSession(sessions, r.sid, r.tool, r.smodel, r.root)
		t, ok := parseTS(r.ts)
		if !ok {
			return
		}
		s.Rows = append(s.Rows, TurnFact{TS: t, Model: r.model, Input: r.in, Output: r.out, CacheRead: r.cr, CacheCreation: r.cc, CacheCreation1h: r.cc1, Reasoning: r.reasoning, Fast: r.fast != 0, Source: "proxy"})
		s.CompressionOrig += r.compOrig
		s.CompressionOut += r.compOut
		ps := pend(r.sid)
		ps.tool, ps.model = r.tool, r.smodel
		ps.proxyIdx = append(ps.proxyIdx, len(s.Rows)-1)
		ps.proxies = append(ps.proxies, sessionmsg.ProxyRow{
			RequestID: r.eventID, Timestamp: r.ts, Model: r.model,
			Input: r.in, Output: r.out, CacheRead: r.cr, CacheCreation: r.cc,
			CacheCreation1h: r.cc1, WebSearchRequests: r.ws, CostUSD: r.cost, Fast: r.fast != 0,
			TTFBMs: r.ttfb, TotalMs: r.totalMS, StopReason: r.stop,
		})
	}); err != nil {
		return nil, fmt.Errorf("advisor.LoadFacts: proxy rows: %w", err)
	}

	// Same reasoning as proxyQ above: token_usage is large and
	// un-indexed on (session_id, timestamp); ordering is produced in Go.
	jsonlQ := `
		SELECT tu.session_id, COALESCE(s.tool,''), COALESCE(s.model,''), COALESCE(p.root_path,''),
		       tu.timestamp, COALESCE(tu.model,''), COALESCE(tu.source_event_id,''),
		       COALESCE(tu.input_tokens,0), COALESCE(tu.output_tokens,0),
		       COALESCE(tu.cache_read_tokens,0), COALESCE(tu.cache_creation_tokens,0),
		       COALESCE(tu.cache_creation_1h_tokens,0), COALESCE(tu.reasoning_tokens,0), COALESCE(tu.fast,0),
		       0, 0,
		       COALESCE(tu.web_search_requests,0), COALESCE(tu.estimated_cost_usd,0),
		       COALESCE(tu.message_id,''), COALESCE(tu.turn_id,''), COALESCE(tu.source_file_hash,''),
		       0, 0, ''
		FROM token_usage tu
		JOIN sessions s ON s.id = tu.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE tu.timestamp >= ?` + scopeFilter(opts)
	if err := loadRows(ctx, db, jsonlQ, since, opts, func(r loadedRow) {
		t, ok := parseTS(r.ts)
		if !ok {
			return
		}
		ps := pend(r.sid)
		ps.tool, ps.model = r.tool, r.smodel
		ps.root = r.root
		ps.tokenFacts = append(ps.tokenFacts, TurnFact{TS: t, Model: r.model, Input: r.in, Output: r.out, CacheRead: r.cr, CacheCreation: r.cc, CacheCreation1h: r.cc1, Reasoning: r.reasoning, Fast: r.fast != 0, Source: "jsonl"})
		ps.tokens = append(ps.tokens, sessionmsg.TokenRow{
			SourceEventID: r.eventID, MessageID: r.messageID, TurnID: r.turnID,
			Timestamp: r.ts, Model: r.model,
			Input: r.in, Output: r.out, CacheRead: r.cr, CacheCreation: r.cc,
			CacheCreation1h: r.cc1, Reasoning: r.reasoning, WebSearchRequests: r.ws,
			CostUSD: r.cost, Fast: r.fast != 0, SourceFileHash: r.fileHash,
		})
	}); err != nil {
		return nil, fmt.Errorf("advisor.LoadFacts: jsonl rows: %w", err)
	}

	for _, sid := range pendingOrder {
		ps := pending[sid]
		if len(ps.tokens) == 0 {
			continue
		}
		v := sessionVerdicts(ps.tool, ps.model, ps.proxies, ps.tokens)
		s := ensureSession(sessions, sid, ps.tool, ps.model, ps.root)
		for j, ri := range ps.proxyIdx {
			s.Rows[ri].Output = v.ProxyOutput[j]
			s.Rows[ri].Reasoning = v.ProxyReasoning[j]
			s.Rows[ri].Fast = s.Rows[ri].Fast || v.ProxyInheritedFast[j]
		}
		for j, tf := range ps.tokenFacts {
			if v.TokenCounted[j] {
				s.Rows = append(s.Rows, tf)
			}
		}
	}

	f := &Facts{WindowDays: opts.WindowDays, Now: now}
	for _, s := range sessions {
		if len(s.Rows) < minSessionRows {
			continue
		}
		// Stable: with the SQL ORDER BY removed, ties (rows sharing an
		// exact timestamp) fall back to arrival order rather than an
		// unstable-sort shuffle.
		sort.SliceStable(s.Rows, func(i, j int) bool { return s.Rows[i].TS.Before(s.Rows[j].TS) })
		f.Sessions = append(f.Sessions, *s)
	}
	sort.Slice(f.Sessions, func(i, j int) bool { return f.Sessions[i].ID < f.Sessions[j].ID })
	if err := loadPhase2(ctx, db, since, f); err != nil {
		return nil, err
	}
	return f, nil
}

// pendingSession holds one session's proxy rows (as indexes into its
// SessionFacts.Rows) and transcript rows until the dedup verdicts are known.
type pendingSession struct {
	tool, model, root string
	proxyIdx          []int
	proxies           []sessionmsg.ProxyRow
	tokenFacts        []TurnFact
	tokens            []sessionmsg.TokenRow
}

// sessionVerdicts runs sessionmsg.DeriveVerdicts over one session's rows,
// shaped the way the node's session detail header hands them to Derive
// (internal/store.NodeSessionVerdicts is the store-side twin; advisor cannot
// import internal/store): a blank row model falls back to the session's, the
// session's tool is stamped on each token row, and shadow pairing and the
// session-cumulative reconciliation follow the tool's registry capabilities,
// never its name.
func sessionVerdicts(tool, sessionModel string, proxies []sessionmsg.ProxyRow, tokens []sessionmsg.TokenRow) sessionmsg.Verdicts {
	ic, _ := integration.For(tool)
	return sessionmsg.SessionVerdicts(proxies, tokens, sessionModel, tool, sessionmsg.Caps{
		ShadowCapable:     ic.TokenTier.OutputOnlyShadow,
		ReasoningDisjoint: ic.TokenTier.ReasoningDisjoint,
		SessionCumulative: ic.TokenTier.SessionCumulative,
	})
}

// scopeFilter appends the optional project + tool predicates; scopeArgs
// (below) binds them in the same order.
func scopeFilter(opts Options) string {
	var sb strings.Builder
	if opts.ProjectRoot != "" {
		sb.WriteString(" AND p.root_path = ?")
	}
	if opts.Tool != "" {
		sb.WriteString(" AND s.tool = ?")
	}
	return sb.String()
}

func scopeArgs(opts Options) []any {
	var args []any
	if opts.ProjectRoot != "" {
		args = append(args, opts.ProjectRoot)
	}
	if opts.Tool != "" {
		args = append(args, opts.Tool)
	}
	return args
}

// loadedRow is one scanned row of either union arm (fields a given arm
// does not carry are zero).
type loadedRow struct {
	sid, tool, smodel, root, ts, model, eventID string
	in, out, cr, cc, cc1, reasoning, fast       int64
	compOrig, compOut, ws                       int64
	cost                                        float64
	messageID, turnID, fileHash                 string
	ttfb, totalMS                               int64
	stop                                        string
}

// loadRows runs one of the two union-arm queries, binding the optional
// project filter, and feeds each row to fn.
func loadRows(ctx context.Context, db *sql.DB, q, since string, opts Options, fn func(loadedRow)) error {
	args := append([]any{since}, scopeArgs(opts)...)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r loadedRow
		if err := rows.Scan(&r.sid, &r.tool, &r.smodel, &r.root, &r.ts, &r.model, &r.eventID,
			&r.in, &r.out, &r.cr, &r.cc, &r.cc1, &r.reasoning, &r.fast, &r.compOrig, &r.compOut,
			&r.ws, &r.cost, &r.messageID, &r.turnID, &r.fileHash, &r.ttfb, &r.totalMS, &r.stop); err != nil {
			return err
		}
		fn(r)
	}
	return rows.Err()
}

func ensureSession(m map[string]*SessionFacts, sid, tool, smodel, root string) *SessionFacts {
	s, ok := m[sid]
	if !ok {
		s = &SessionFacts{ID: sid, Tool: tool, Model: smodel, ProjectRoot: root}
		m[sid] = s
	}
	return s
}

func parseTS(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

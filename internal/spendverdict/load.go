package spendverdict

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
)

// Reader is the read surface LoadSession runs over: a *sql.DB, *sql.Tx or
// *sql.Conn.
type Reader interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Querier is the read/write surface the re-derive runs over: the refresh
// transaction.
type Querier interface {
	Reader
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// SessionRows is one session's spend rows, loaded exactly the way every node
// reader of a session hands them to sessionmsg.Derive: a row with a blank
// model takes the session's model, every token row carries the session's
// tool, and both slices are ordered explicitly (timestamp, then the row's
// own id key) rather than relying on Derive's defensive re-sort.
type SessionRows struct {
	// Tool and Model are the sessions row's tool and model ("" when the
	// session row does not exist yet: a proxy turn can land before the
	// watcher ingests the session).
	Tool  string
	Model string
	// Caps is the tool's capability triple (CapsFor(Tool)).
	Caps    sessionmsg.Caps
	Proxies []sessionmsg.ProxyRow
	// ProxyIDs[i] is Proxies[i]'s api_turns.id.
	ProxyIDs []int64
	Tokens   []sessionmsg.TokenRow
	// TokenIDs[i] is Tokens[i]'s token_usage.id and TokenSidechain[i] its
	// is_sidechain flag (migration 087), which the sub-agent / task
	// drill-downs split a session by.
	TokenIDs       []int64
	TokenSidechain []bool
}

// DeriveInput is the sessionmsg input for these rows (RollupTurn mode, no
// actions): the one construction every spend reader of a session uses.
func (r SessionRows) DeriveInput() sessionmsg.DeriveInput {
	return sessionmsg.DeriveInput{
		ProxyRows:         r.Proxies,
		TokenRows:         r.Tokens,
		Mode:              sessionmsg.RollupTurn,
		ShadowCapable:     r.Caps.ShadowCapable,
		ReasoningDisjoint: r.Caps.ReasoningDisjoint,
		SessionCumulative: r.Caps.SessionCumulative,
		DefaultModel:      r.Model,
	}
}

// Verdicts is sessionmsg.DeriveVerdicts over these rows, index-aligned with
// Proxies / Tokens.
func (r SessionRows) Verdicts() sessionmsg.Verdicts {
	return sessionmsg.DeriveVerdicts(r.DeriveInput())
}

// CapsFor resolves the capability triple sessionmsg.Derive dispatches on
// (output-only shadow pairing, disjoint reasoning, the session-cumulative
// reconciliation) from the tool's integration registry row - never its name.
// An unknown tool resolves to the zero Caps.
func CapsFor(tool string) sessionmsg.Caps {
	ic, _ := integration.For(tool)
	return sessionmsg.Caps{
		ShadowCapable:     ic.TokenTier.OutputOnlyShadow,
		ReasoningDisjoint: ic.TokenTier.ReasoningDisjoint,
		SessionCumulative: ic.TokenTier.SessionCumulative,
	}
}

// LoadSession loads one session's spend rows (see SessionRows).
func LoadSession(ctx context.Context, q Reader, sessionID string) (SessionRows, error) {
	all, err := LoadSessions(ctx, q, []string{sessionID})
	if err != nil {
		return SessionRows{}, err
	}
	return all[sessionID], nil
}

// maxIDsPerQuery bounds the session ids bound into one IN (...) list, well
// under SQLite's bind-variable ceiling.
const maxIDsPerQuery = 900

// LoadSessions loads the spend rows of every session in ids (see
// SessionRows), in a fixed number of queries per 900 ids - a drill-down
// over many sessions (the task report) costs the same number of round trips
// whatever its size. Every id gets an entry, a session with no rows
// included. Duplicate ids are loaded once.
func LoadSessions(ctx context.Context, q Reader, ids []string) (map[string]SessionRows, error) {
	out := make(map[string]SessionRows, len(ids))
	var uniq []string
	for _, id := range ids {
		if _, seen := out[id]; seen {
			continue
		}
		out[id] = SessionRows{Caps: CapsFor("")}
		uniq = append(uniq, id)
	}
	for start := 0; start < len(uniq); start += maxIDsPerQuery {
		end := start + maxIDsPerQuery
		if end > len(uniq) {
			end = len(uniq)
		}
		if err := loadChunk(ctx, q, uniq[start:end], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// loadChunk fills out for one chunk of ids: the sessions rows first, so a
// blank row model can take its session's model and every token row its
// session's tool.
func loadChunk(ctx context.Context, q Reader, ids []string, out map[string]SessionRows) error {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	//nolint:gosec // G202: only a ?-placeholder list is interpolated; ids bind via args.
	srows, err := q.QueryContext(ctx, `SELECT id, COALESCE(tool, ''), COALESCE(model, '') FROM sessions WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return fmt.Errorf("spendverdict.LoadSessions: sessions: %w", err)
	}
	for srows.Next() {
		var id string
		var r SessionRows
		if err := srows.Scan(&id, &r.Tool, &r.Model); err != nil {
			srows.Close()
			return fmt.Errorf("spendverdict.LoadSessions: scan session: %w", err)
		}
		r.Caps = CapsFor(r.Tool)
		out[id] = r
	}
	if err := srows.Err(); err != nil {
		srows.Close()
		return fmt.Errorf("spendverdict.LoadSessions: sessions: %w", err)
	}
	srows.Close()

	//nolint:gosec // G202: only a ?-placeholder list is interpolated; ids bind via args.
	prows, err := q.QueryContext(ctx, `
		SELECT session_id, id, COALESCE(request_id,''), timestamp, COALESCE(model,''),
		       COALESCE(input_tokens,0), COALESCE(output_tokens,0),
		       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
		       COALESCE(cache_creation_1h_tokens,0), COALESCE(web_search_requests,0),
		       COALESCE(cost_usd,0), COALESCE(fast,0),
		       COALESCE(time_to_first_token_ms,0), COALESCE(total_response_ms,0),
		       COALESCE(stop_reason,'')
		  FROM api_turns
		 WHERE session_id IN (`+ph+`)
		 ORDER BY session_id, timestamp ASC, COALESCE(request_id,'') ASC, id ASC`, args...)
	if err != nil {
		return fmt.Errorf("spendverdict.LoadSessions: proxy rows: %w", err)
	}
	for prows.Next() {
		var sid string
		var id int64
		var p sessionmsg.ProxyRow
		var fast int
		if err := prows.Scan(&sid, &id, &p.RequestID, &p.Timestamp, &p.Model, &p.Input, &p.Output,
			&p.CacheRead, &p.CacheCreation, &p.CacheCreation1h, &p.WebSearchRequests,
			&p.CostUSD, &fast, &p.TTFBMs, &p.TotalMs, &p.StopReason); err != nil {
			prows.Close()
			return fmt.Errorf("spendverdict.LoadSessions: scan proxy row: %w", err)
		}
		r := out[sid]
		if p.Model == "" {
			p.Model = r.Model
		}
		p.Fast = fast != 0
		r.Proxies = append(r.Proxies, p)
		r.ProxyIDs = append(r.ProxyIDs, id)
		out[sid] = r
	}
	if err := prows.Err(); err != nil {
		prows.Close()
		return fmt.Errorf("spendverdict.LoadSessions: proxy rows: %w", err)
	}
	prows.Close()

	//nolint:gosec // G202: only a ?-placeholder list is interpolated; ids bind via args.
	trows, err := q.QueryContext(ctx, `
		SELECT session_id, id, COALESCE(source_event_id,''), COALESCE(message_id,''), COALESCE(turn_id,''),
		       timestamp, COALESCE(model,''),
		       COALESCE(input_tokens,0), COALESCE(output_tokens,0),
		       COALESCE(cache_read_tokens,0), COALESCE(cache_creation_tokens,0),
		       COALESCE(cache_creation_1h_tokens,0), COALESCE(reasoning_tokens,0),
		       COALESCE(web_search_requests,0), COALESCE(estimated_cost_usd,0),
		       COALESCE(fast,0), COALESCE(source_file_hash,''),
		       COALESCE(gen_ms,0), COALESCE(gen_basis,''), COALESCE(is_sidechain,0)
		  FROM token_usage
		 WHERE session_id IN (`+ph+`)
		 ORDER BY session_id, timestamp ASC, COALESCE(source_event_id,'') ASC, id ASC`, args...)
	if err != nil {
		return fmt.Errorf("spendverdict.LoadSessions: token rows: %w", err)
	}
	defer trows.Close()
	for trows.Next() {
		var sid string
		var id int64
		var t sessionmsg.TokenRow
		var fast, sidechain int
		if err := trows.Scan(&sid, &id, &t.SourceEventID, &t.MessageID, &t.TurnID, &t.Timestamp, &t.Model,
			&t.Input, &t.Output, &t.CacheRead, &t.CacheCreation, &t.CacheCreation1h, &t.Reasoning,
			&t.WebSearchRequests, &t.CostUSD, &fast, &t.SourceFileHash, &t.GenMs, &t.GenBasis,
			&sidechain); err != nil {
			return fmt.Errorf("spendverdict.LoadSessions: scan token row: %w", err)
		}
		r := out[sid]
		if t.Model == "" {
			t.Model = r.Model
		}
		t.Fast = fast != 0
		t.Tool = r.Tool
		r.Tokens = append(r.Tokens, t)
		r.TokenIDs = append(r.TokenIDs, id)
		r.TokenSidechain = append(r.TokenSidechain, sidechain != 0)
		out[sid] = r
	}
	if err := trows.Err(); err != nil {
		return fmt.Errorf("spendverdict.LoadSessions: token rows: %w", err)
	}
	return nil
}

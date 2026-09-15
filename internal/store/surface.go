package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// SetSessionSurface stamps the normalized capture-surface attribution
// (migration 107: sessions.surface / sessions.surface_host) onto an
// existing session row. It is the ONE write path for those columns —
// UpsertSession never touches them, so a re-parse that carries no
// surface can never clear a captured value.
//
// SEMANTICS: FIRST-WINS-UNLESS-EMPTY, per column. The first grounded
// stamp sticks; a later parse can only FILL a column that is still
// empty, never change one that already holds a value. Both columns are
// independent — a stamp carrying only a host fills an empty
// surface_host while leaving a populated surface alone, and vice versa.
//
// Why first-wins rather than last-wins: the value is a property of the
// session's ORIGIN, decided once when the session was created, and the
// discriminators adapters read (Claude Code `entrypoint`, Codex
// `originator`/`source`, Cline `source`) sit at the head of a
// transcript. A later record in the same transcript carrying a weaker
// or differently-derived signal is not a correction — it is a
// re-derivation of the same fact from less context, and letting it win
// would make the column depend on how far a parse happened to read. A
// genuine correction is a data-repair concern (a backfill / rescan that
// clears the column first), not something a routine re-parse should be
// able to do.
//
// The returned bool honestly reports whether the UPDATE actually
// changed anything: true only when an EMPTY column became non-empty.
// An identical re-stamp, a differing later stamp, and an all-empty
// stamp all match zero rows and return false. A missing session id is a
// silent no-op — the adapter may legitimately observe a discriminator
// before the row exists on a partial parse; the next parse re-stamps.
//
// The kind is validated against models.KnownSurface: an adapter that
// leaks a raw vendor token ("codex_vscode") instead of resolving it
// through its table is a programming error and fails loudly here rather
// than persisting garbage forever. This validation stays STRICT for
// direct callers — Ingest's batch seam downgrades it to a skip so a bad
// surface cannot fail an ingest whose actions/tokens already landed
// (see store.Ingest). SurfaceHost is free-form (lowercase token by
// convention) and is not validated beyond being non-prose.
//
// NOTE: migration 107's own SQL comment describes this write as
// "COALESCE-preserving" — that wording predates the first-wins rule and
// describes only the weaker half of it (a re-parse never CLEARS a
// value). This doc comment is the authority; migrations are immutable
// once shipped and are not edited to track semantics.
func (s *Store) SetSessionSurface(ctx context.Context, sf models.SessionSurface) (bool, error) {
	if sf.SessionID == "" {
		return false, errors.New("store.SetSessionSurface: SessionID is required")
	}
	if sf.Surface != "" && !models.KnownSurface(sf.Surface) {
		return false, fmt.Errorf("store.SetSessionSurface: unknown surface kind %q (session %s) — resolve vendor tokens through the adapter's table", sf.Surface, sf.SessionID)
	}
	if sf.Surface == "" && sf.SurfaceHost == "" {
		return false, nil
	}
	if sf.Hosted {
		return s.setHostedSessionSurface(ctx, sf)
	}
	// FIRST-WINS-UNLESS-EMPTY: the stored value is preferred; the
	// incoming one is used only where the column is currently NULL/''.
	// The WHERE guard restricts the UPDATE to rows where that actually
	// fills something, so RowsAffected stays an honest "changed".
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET
		   surface = COALESCE(NULLIF(surface, ''), NULLIF(?, '')),
		   surface_host = COALESCE(NULLIF(surface_host, ''), NULLIF(?, ''))
		 WHERE id = ?
		   AND ( (? != '' AND IFNULL(surface, '') = '')
		      OR (? != '' AND IFNULL(surface_host, '') = '') )`,
		sf.Surface, sf.SurfaceHost, sf.SessionID,
		sf.Surface, sf.SurfaceHost,
	)
	if err != nil {
		return false, fmt.Errorf("store.SetSessionSurface: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// setHostedSessionSurface is the HOST-WINS branch of SetSessionSurface
// for a stamp carrying models.SessionSurface.Hosted: the value comes
// from the hosting layer's own record (an IDE orchestration store that
// names the agent session it drove), which knows the session's origin
// better than the agent's self-report can. Each non-empty incoming
// column REPLACES the stored one; an empty incoming column still
// preserves what is stored (a hosted stamp never clears), and the WHERE
// guard restricts the UPDATE to rows where at least one column actually
// differs, so an identical re-stamp — the enricher re-scanning the same
// task file every tick — reports false and writes nothing.
//
// Why replace rather than fill: the agent's self-report is TRUE but
// less specific (Claude Code under IntelliJ says `sdk`/`ts`; Qoder
// driven by Qoder Work says `cli`/`qoder`). A hosted stamp is the same
// fact seen from one layer up, not a re-derivation from less context,
// so the first-wins rationale in SetSessionSurface's doc does not
// apply to it. Two hosts never claim one session on a real box (a
// session has one orchestrator), so "last hosted wins" is the only
// tie rule needed.
//
// IRREVERSIBLE TODAY: once a hosted stamp lands, no routine parse can
// change it (first-wins blocks every self-report) and no clearing
// rescan exists — a wrong hosted stamp stays until a data-repair
// backfill is written. That is why every hosted emitter must be gated
// on a grounded "this host actually drove the session" discriminator
// (the Qoder Work import case, review fix 2026-09-03). Follow-up: a
// `observer backfill --clear-surface <session>` repair path.
func (s *Store) setHostedSessionSurface(ctx context.Context, sf models.SessionSurface) (bool, error) {
	res, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET
		   surface = COALESCE(NULLIF(?, ''), NULLIF(surface, '')),
		   surface_host = COALESCE(NULLIF(?, ''), NULLIF(surface_host, ''))
		 WHERE id = ?
		   AND ( (? != '' AND IFNULL(surface, '') != ?)
		      OR (? != '' AND IFNULL(surface_host, '') != ?) )`,
		sf.Surface, sf.SurfaceHost, sf.SessionID,
		sf.Surface, sf.Surface, sf.SurfaceHost, sf.SurfaceHost,
	)
	if err != nil {
		return false, fmt.Errorf("store.SetSessionSurface(hosted): %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// LoadSessionSurface returns the stored capture-surface attribution for
// a session. Both fields are "" when the session exists but no adapter
// has stamped a surface (the honest unknown). sql.ErrNoRows propagates
// unwrapped when the session does not exist so callers can 404.
func (s *Store) LoadSessionSurface(ctx context.Context, sessionID string) (models.SessionSurface, error) {
	out := models.SessionSurface{SessionID: sessionID}
	if sessionID == "" {
		return out, errors.New("store.LoadSessionSurface: sessionID is required")
	}
	var kind, host sql.NullString
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COALESCE(surface, ''), COALESCE(surface_host, '') FROM sessions WHERE id = ?`,
		sessionID,
	).Scan(&kind, &host); err != nil {
		return out, err // sql.ErrNoRows propagates to the caller unwrapped.
	}
	out.Surface = kind.String
	out.SurfaceHost = host.String
	return out, nil
}

// SurfaceCount is one row of the per-surface rollup: how many sessions
// (and how much metered spend) a (tool, surface, surface_host) triple
// accounts for. Sessions with no stamped surface roll up under
// Surface="" so the dashboard can render the unknown share honestly.
type SurfaceCount struct {
	Tool        string
	Surface     string
	SurfaceHost string
	Sessions    int64
	CostUSD     float64
}

// LoadSurfaceCounts returns the per-(tool, surface, host) session +
// spend rollup for the sessions whose started_at falls at/after since
// (RFC3339; "" = all time). Spend is the deduped-by-nothing SUM of
// token_usage.estimated_cost_usd per session — the same additive metric
// the cost pages use — so the split is directly comparable to them.
// Read-only; the columns are node-local so this never reaches the org
// wire.
func (s *Store) LoadSurfaceCounts(ctx context.Context, since string) ([]SurfaceCount, error) {
	q := `SELECT s.tool, COALESCE(s.surface, ''), COALESCE(s.surface_host, ''),
	             COUNT(*), COALESCE(SUM(tu.cost), 0)
	        FROM sessions s
	        LEFT JOIN (SELECT session_id, SUM(estimated_cost_usd) AS cost
	                     FROM token_usage GROUP BY session_id) tu ON tu.session_id = s.id`
	args := []any{}
	if since != "" {
		q += ` WHERE s.started_at >= ?`
		args = append(args, since)
	}
	q += ` GROUP BY s.tool, COALESCE(s.surface, ''), COALESCE(s.surface_host, '')
	       ORDER BY s.tool, COALESCE(s.surface, ''), COALESCE(s.surface_host, '')`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.LoadSurfaceCounts: %w", err)
	}
	defer rows.Close()
	var out []SurfaceCount
	for rows.Next() {
		var c SurfaceCount
		if err := rows.Scan(&c.Tool, &c.Surface, &c.SurfaceHost, &c.Sessions, &c.CostUSD); err != nil {
			return nil, fmt.Errorf("store.LoadSurfaceCounts: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.LoadSurfaceCounts: rows: %w", err)
	}
	return out, nil
}

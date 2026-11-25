package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// otelCursorKey is the schema_meta row that holds the highest api_turns id the
// OTel row tail has published. It is independent of the org push cursor
// (org_push_cursor_*) so enrolling, unenrolling, or pushing never perturbs the
// exporter's position and vice-versa.
const otelCursorKey = "otel_cursor"

// otelTailPageSize bounds a single tail query so a large backlog (e.g. the
// exporter being enabled on an established install) drains in pages rather than
// loading every historical turn into memory at once.
const otelTailPageSize = 256

// apiTurnFetcher reads up to limit api_turns rows with id > afterID in ascending
// id order. cursorLoader / cursorSaver read and persist the published-id
// high-water mark. Factoring these as function types lets the timing loop in
// tailAPITurns be exercised by testing/synctest with in-memory fakes (the
// project's established pattern — see orgclient.runLoop), while the production
// SubscribeAPITurns wires the real store methods.
type (
	apiTurnFetcher func(ctx context.Context, afterID int64, limit int) ([]models.APITurn, error)
	cursorLoader   func(ctx context.Context) (int64, error)
	cursorSaver    func(ctx context.Context, id int64) error
)

// SubscribeAPITurns returns a channel that yields every api_turns row inserted
// after the persisted otel_cursor, in ascending id order, polling every
// interval. It is the row tail behind the M4 OTel exporter (spec §2.4.3).
//
// A background goroutine polls api_turns in pages and, after publishing each
// page on the channel, advances and persists the last-published id in the
// schema_meta otel_cursor row, so a restart resumes exactly past the last
// delivered turn. Delivery is at-least-once: a crash between publishing a row
// and persisting the cursor re-delivers that row, which telemetry tolerates.
//
// The goroutine stops and closes the channel when ctx is done. Transient query
// or cursor-persist errors are logged at WARN and retried on the next tick;
// they never close the channel (P1 — a telemetry hiccup must not stop the
// tail). interval defaults to 1s when <= 0; logger must be non-nil.
func (s *Store) SubscribeAPITurns(ctx context.Context, interval time.Duration, logger *slog.Logger) <-chan models.APITurn {
	out := make(chan models.APITurn, otelTailPageSize)
	go tailAPITurns(ctx, interval, logger, out,
		s.loadOTelCursor, s.saveOTelCursor, s.fetchAPITurnsSince)
	return out
}

// tailAPITurns is the pure timing loop: it owns the ticker, the drain-in-pages
// behaviour, the cursor advance, and ctx cancellation, delegating all I/O to
// the injected closures. It closes out before returning.
func tailAPITurns(
	ctx context.Context,
	interval time.Duration,
	logger *slog.Logger,
	out chan<- models.APITurn,
	load cursorLoader,
	save cursorSaver,
	fetch apiTurnFetcher,
) {
	defer close(out)
	if interval <= 0 {
		interval = time.Second
	}

	cursor, err := load(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		// A cursor-read failure must not replay the whole history; the safe
		// fallback is to start where we are and move forward.
		logger.Warn("otel row tail: load cursor failed; resuming from 0", "err", err)
		cursor = 0
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		// Drain all currently-available rows in pages before sleeping, so a
		// startup backlog clears without waiting one interval per page.
		for {
			rows, err := fetch(ctx, cursor, otelTailPageSize)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return
				}
				logger.Warn("otel row tail: query failed; will retry", "err", err)
				break
			}
			if len(rows) == 0 {
				break
			}
			for _, r := range rows {
				select {
				case <-ctx.Done():
					return
				case out <- r:
				}
				cursor = r.ID
			}
			// Persist the advanced cursor for the rows we just published. Use a
			// cancellation-detached, time-bounded context: a row that has been
			// published must durably advance the cursor even if the consumer
			// cancels immediately after receiving it, otherwise a clean shutdown
			// would needlessly re-deliver the last page on restart.
			sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := save(sctx, cursor); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("otel row tail: persist cursor failed", "cursor", cursor, "err", err)
			}
			scancel()
			if len(rows) < otelTailPageSize {
				break
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// loadOTelCursor reads the published-id high-water mark from schema_meta.
// A missing or unparseable value is treated as 0 (start from the beginning).
func (s *Store) loadOTelCursor(ctx context.Context) (int64, error) {
	v, err := s.readMeta(ctx, otelCursorKey)
	if err != nil {
		return 0, fmt.Errorf("store.loadOTelCursor: %w", err)
	}
	if v == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, nil
	}
	return id, nil
}

// saveOTelCursor persists the published-id high-water mark to schema_meta.
func (s *Store) saveOTelCursor(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		otelCursorKey, strconv.FormatInt(id, 10))
	if err != nil {
		return fmt.Errorf("store.saveOTelCursor: %w", err)
	}
	return nil
}

// fetchAPITurnsSince reads up to limit api_turns rows with id > afterID, in
// ascending id order, fully populating models.APITurn from the api_turns row
// (no project join — the exporter resolves project_id → root via the cached
// ProjectRootByID, keeping this a pure single-table tail).
func (s *Store) fetchAPITurnsSince(ctx context.Context, afterID int64, limit int) ([]models.APITurn, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, COALESCE(session_id,''), COALESCE(project_id,0), timestamp,
		        provider, COALESCE(model,''), COALESCE(request_id,''),
		        input_tokens, output_tokens, COALESCE(cache_read_tokens,0),
		        COALESCE(cache_creation_tokens,0), COALESCE(cache_creation_1h_tokens,0),
		        COALESCE(web_search_requests,0), COALESCE(cost_usd,0),
		        COALESCE(message_count,0), COALESCE(tool_use_count,0),
		        COALESCE(system_prompt_hash,''), COALESCE(message_prefix_hash,''),
		        COALESCE(time_to_first_token_ms,0), COALESCE(total_response_ms,0),
		        COALESCE(stop_reason,''), COALESCE(http_status,0),
		        COALESCE(error_class,''), COALESCE(error_message,''),
		        COALESCE(org_id,''), COALESCE(user_email,'')
		   FROM api_turns
		  WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("store.fetchAPITurnsSince: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []models.APITurn
	for rows.Next() {
		var t models.APITurn
		var ts string // timestamps are stored as RFC3339Nano TEXT, not scannable into time.Time
		if err := rows.Scan(&t.ID, &t.SessionID, &t.ProjectID, &ts,
			&t.Provider, &t.Model, &t.RequestID, &t.InputTokens, &t.OutputTokens,
			&t.CacheReadTokens, &t.CacheCreationTokens, &t.CacheCreation1hTokens,
			&t.WebSearchRequests, &t.CostUSD, &t.MessageCount, &t.ToolUseCount,
			&t.SystemPromptHash, &t.MessagePrefixHash, &t.TimeToFirstTokenMS,
			&t.TotalResponseMS, &t.StopReason, &t.HTTPStatus, &t.ErrorClass,
			&t.ErrorMessage, &t.OrgID, &t.UserEmail); err != nil {
			return nil, fmt.Errorf("store.fetchAPITurnsSince: scan: %w", err)
		}
		t.Timestamp = parseStoredTime(ts)
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.fetchAPITurnsSince: rows: %w", err)
	}
	return out, nil
}

// ProjectRootByID resolves a project_id to its root_path. Returns "" (no error)
// when the id is unknown, so the exporter can attribute an unresolved turn
// without an empty-string crash. Used by the OTel exporter's cached resolver.
func (s *Store) ProjectRootByID(ctx context.Context, id int64) (string, error) {
	if id == 0 {
		return "", nil
	}
	var root string
	err := s.db.QueryRowContext(ctx, `SELECT root_path FROM projects WHERE id = ?`, id).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store.ProjectRootByID: %w", err)
	}
	return root, nil
}

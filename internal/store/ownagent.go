package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/ownagent"
)

// EnsureOwnAgentSession makes sure the capture session for a developer's own
// agent exists (P-228, docs/own-agents.md): tool models.ToolCustomAgent,
// surface "sdk", surface_host "agent:<agent>". The proxy calls it once per
// new session, before the session's first turn is written
// (proxy.OwnAgentSessionSink), and so does the OTLP ingest for the agent's
// own spans (PT-55, cmd/observer otlpIngest.ensureSession): both paths mint
// the session id with internal/ownagent.SessionID, so a run seen by both is
// one session, whichever path writes the row first.
//
// It reuses the two existing seams and adds no table: EnsureCaptureSession
// (insert-only, an existing row keeps its project, model and start time) and
// SetSessionSurface (first-wins-unless-empty). The session id is minted by
// internal/ownagent with a prefix no coding tool uses, so an existing row
// for it is always an earlier call for the same agent session; a row of any
// other tool under that id is refused rather than restamped.
func (s *Store) EnsureOwnAgentSession(ctx context.Context, sessionID, agent, projectRoot, model string, startedAt time.Time) error {
	if sessionID == "" || agent == "" {
		return errors.New("store.EnsureOwnAgentSession: sessionID and agent are required")
	}
	if _, err := s.EnsureCaptureSession(ctx, sessionID, models.ToolCustomAgent, projectRoot, model, startedAt); err != nil {
		return fmt.Errorf("store.EnsureOwnAgentSession: %w", err)
	}
	var tool string
	if err := s.db.QueryRowContext(ctx, `SELECT tool FROM sessions WHERE id = ?`, sessionID).Scan(&tool); err != nil {
		return fmt.Errorf("store.EnsureOwnAgentSession: read back: %w", err)
	}
	if tool != models.ToolCustomAgent {
		return fmt.Errorf("store.EnsureOwnAgentSession: session %s belongs to tool %q", sessionID, tool)
	}
	// A session whose first turn carried no model (an error turn) takes the
	// model of the first later call that names one; a stored model is never
	// replaced.
	if model != "" {
		if _, err := s.db.ExecContext(ctx,
			`UPDATE sessions SET model = ? WHERE id = ? AND tool = ? AND COALESCE(model, '') = ''`,
			model, sessionID, models.ToolCustomAgent); err != nil {
			return fmt.Errorf("store.EnsureOwnAgentSession: model: %w", err)
		}
	}
	if err := s.upgradeOwnAgentPlaceholderProject(ctx, sessionID, projectRoot); err != nil {
		return fmt.Errorf("store.EnsureOwnAgentSession: %w", err)
	}
	if _, err := s.SetSessionSurface(ctx, models.SessionSurface{
		SessionID:   sessionID,
		Surface:     ownagent.SurfaceKind,
		SurfaceHost: ownagent.SurfaceHost(agent),
	}); err != nil {
		return fmt.Errorf("store.EnsureOwnAgentSession: %w", err)
	}
	return nil
}

// OwnAgentSummary is one own agent's roll-up for the dashboard's Own agents
// view: every custom-agent session grouped by agent name.
type OwnAgentSummary struct {
	// Agent is the normalized agent name (surface_host without "agent:").
	Agent string `json:"agent"`
	// SurfaceHost is the stored host token, the value the Sessions list's
	// surface_host filter takes.
	SurfaceHost  string  `json:"surface_host"`
	Sessions     int64   `json:"sessions"`
	Turns        int64   `json:"turns"`
	InputTokens  int64   `json:"input_tokens"`
	OutputTokens int64   `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	// LastSeen is the newest turn time, else the newest session start.
	LastSeen string `json:"last_seen"`
	// Via is the source label: which capture path saw the agent
	// (OwnAgentViaProxy, OwnAgentViaOTLP or OwnAgentViaBoth). It is the
	// only thing the view shows differently for span-sourced sessions.
	Via string `json:"via"`
}

// Own-agent source labels (OwnAgentSummary.Via).
const (
	// OwnAgentViaProxy: every turn came through the proxy header path.
	OwnAgentViaProxy = "proxy"
	// OwnAgentViaOTLP: everything came from the agent's own OTLP spans
	// (turns with source SourceAgentOTel, or tool calls from the export).
	OwnAgentViaOTLP = "otlp"
	// OwnAgentViaBoth: both paths saw the agent.
	OwnAgentViaBoth = "proxy+otlp"
)

// ownAgentOTLPSourceFile is the actions.source_file the OTLP ingest stamps
// on the agent's tool calls ("otlp:<tool>", cmd/observer toolEventFromOTLP).
const ownAgentOTLPSourceFile = "otlp:" + models.ToolCustomAgent

// ownAgentVia resolves the source label from the two path counts. A
// session with neither (its only turn failed before any row) reads as the
// proxy's, the path that opened every pre-PT-55 own-agent session.
func ownAgentVia(proxyTurns, otlpRecords int64) string {
	switch {
	case proxyTurns > 0 && otlpRecords > 0:
		return OwnAgentViaBoth
	case otlpRecords > 0:
		return OwnAgentViaOTLP
	default:
		return OwnAgentViaProxy
	}
}

// ListOwnAgents returns one OwnAgentSummary per own agent, most recently
// active first. It reads sessions, api_turns and the OTLP-sourced actions
// only; the token and cost figures are the stored turns' own, whichever
// path wrote them (a call seen by both paths is one row, the proxy's).
func (s *Store) ListOwnAgents(ctx context.Context) ([]OwnAgentSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.surface_host,
		       COUNT(DISTINCT s.id),
		       COUNT(t.id),
		       COALESCE(SUM(t.input_tokens), 0),
		       COALESCE(SUM(t.output_tokens), 0),
		       COALESCE(SUM(t.cost_usd), 0),
		       COALESCE(MAX(t.timestamp), MAX(s.started_at), ''),
		       COALESCE(SUM(CASE WHEN t.id IS NOT NULL AND COALESCE(t.source, '') <> ? THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN t.source = ? THEN 1 ELSE 0 END), 0)
		         + (SELECT COUNT(*) FROM actions a JOIN sessions s2 ON s2.id = a.session_id
		             WHERE s2.tool = ? AND s2.surface_host = s.surface_host AND a.source_file = ?)
		  FROM sessions s
		  LEFT JOIN api_turns t ON t.session_id = s.id
		 WHERE s.tool = ? AND s.surface_host LIKE 'agent:%'
		 GROUP BY s.surface_host
		 ORDER BY 7 DESC, 1 ASC`,
		SourceAgentOTel, SourceAgentOTel, models.ToolCustomAgent, ownAgentOTLPSourceFile, models.ToolCustomAgent)
	if err != nil {
		return nil, fmt.Errorf("store.ListOwnAgents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OwnAgentSummary
	for rows.Next() {
		var a OwnAgentSummary
		var proxyTurns, otlpRecords int64
		if err := rows.Scan(&a.SurfaceHost, &a.Sessions, &a.Turns, &a.InputTokens, &a.OutputTokens, &a.CostUSD, &a.LastSeen,
			&proxyTurns, &otlpRecords); err != nil {
			return nil, fmt.Errorf("store.ListOwnAgents: scan: %w", err)
		}
		a.Via = ownAgentVia(proxyTurns, otlpRecords)
		name, ok := ownagent.AgentFromSurfaceHost(a.SurfaceHost)
		if !ok {
			continue
		}
		a.Agent = name
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListOwnAgents: %w", err)
	}
	return out, nil
}

// OwnAgentSpanOutcome is what UpsertOwnAgentSpanTurn did with one span turn.
type OwnAgentSpanOutcome string

// Span-turn outcomes.
const (
	// OwnAgentSpanInserted: no row had the request id; the span's row stands.
	OwnAgentSpanInserted OwnAgentSpanOutcome = "inserted"
	// OwnAgentSpanMerged: a custom-agent row for the same call existed and
	// the request-id merge ran against it (a higher-ranked proxy row is
	// left as it is).
	OwnAgentSpanMerged OwnAgentSpanOutcome = "merged"
	// OwnAgentSpanYielded: a row of ANOTHER tool or plane (or with no
	// session) holds the request id; the span never touches it and adds
	// nothing.
	OwnAgentSpanYielded OwnAgentSpanOutcome = "yielded"
	// OwnAgentSpanSuperseded: the span's row was inserted, but a row for
	// the same call landed concurrently (the proxy's, another tool's, or an
	// earlier copy of the same span), so the span removed its own row.
	OwnAgentSpanSuperseded OwnAgentSpanOutcome = "superseded"
)

// ownAgentSpanMidHook runs between UpsertOwnAgentSpanTurn's read and its
// insert. Tests only (nil in production): it forces the interleaving in
// which the proxy writes the same call in that window.
var ownAgentSpanMidHook func()

// requestIDRow is one api_turns row holding a request id, with the tool of
// its session ("" when it has none).
type requestIDRow struct {
	id     int64
	source string
	tool   string
}

// rowsForRequestID lists every api_turns row with the request id, except
// the row with id skip (0 skips nothing), oldest first.
func (s *Store) rowsForRequestID(ctx context.Context, requestID string, skip int64) ([]requestIDRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT t.id, COALESCE(t.source, ''), COALESCE(se.tool, '')
		  FROM api_turns t
		  LEFT JOIN sessions se ON se.id = t.session_id
		 WHERE t.request_id = ? AND t.id <> ?
		 ORDER BY t.id`, requestID, skip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []requestIDRow
	for rows.Next() {
		var r requestIDRow
		if err := rows.Scan(&r.id, &r.source, &r.tool); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertOwnAgentSpanTurn records one turn from a developer's own agent's
// OpenTelemetry spans (PT-55; t.Source is SourceAgentOTel, t.SessionID an
// own-agent session). It replaces the generic request-id merge for that path
// with two guarantees (sdk-2 fix round 1, M1 and L4):
//
//   - It never touches another tool's or plane's row: when any row holding
//     the request id belongs to a session of another tool (or to no
//     session, such as a Plane A span reconciled into api_turns), the span
//     yields and adds nothing. Only custom-agent rows are merged with.
//   - It never leaves two rows for one call. The proxy writes with
//     InsertAPITurn (not this merge) and deletes agent_otel rows only after
//     its own insert, on its own connection, so a proxy row can land between
//     this method's read and its insert. After inserting, the method reads
//     again and deletes its OWN row when any other row for the call now
//     exists: a non-span row, or an older span row (a concurrent redelivery
//     of the same span). The newer copy always removes itself, so the call
//     keeps exactly one row whichever side wins each race; the proxy's own
//     delete of span rows stays as the other half.
func (s *Store) UpsertOwnAgentSpanTurn(ctx context.Context, t models.APITurn) (OwnAgentSpanOutcome, error) {
	if t.RequestID == "" || t.Source != SourceAgentOTel {
		return "", errors.New("store.UpsertOwnAgentSpanTurn: a request id and source agent_otel are required")
	}
	existing, err := s.rowsForRequestID(ctx, t.RequestID, 0)
	if err != nil {
		return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: %w", err)
	}
	for _, r := range existing {
		if r.tool != models.ToolCustomAgent {
			return OwnAgentSpanYielded, nil
		}
	}
	if len(existing) > 0 {
		// A span row left beside another row for the same call (a
		// supersede that failed after its insert, sdk-2 lows N1) is removed
		// on this redelivery: the proxy's row always wins, and among span
		// copies the oldest stays.
		superseded, err := s.dropSpanDuplicates(ctx, t.RequestID, existing)
		if err != nil {
			return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: %w", err)
		}
		if superseded {
			return OwnAgentSpanSuperseded, nil
		}
		if _, _, err := s.UpsertTurnByRequestID(ctx, t); err != nil {
			return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: %w", err)
		}
		return OwnAgentSpanMerged, nil
	}
	if ownAgentSpanMidHook != nil {
		ownAgentSpanMidHook()
	}
	// The insert, its re-check and the self-delete must finish together: a
	// cancelled export request must not stop between the insert and the
	// delete and leave two rows (sdk-2 lows, N1). They run detached from
	// the caller's cancellation, under their own bound.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ownAgentSpanWriteTimeout)
	defer cancel()
	id, err := s.InsertAPITurn(wctx, t)
	if err != nil {
		return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: %w", err)
	}
	others, err := s.rowsForRequestIDRecheck(wctx, t.RequestID, id)
	if err != nil {
		// The row stays; the exporter's retry takes the merge path above,
		// which removes it when another row for the call exists.
		return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: re-check: %w", err)
	}
	for _, r := range others {
		if r.source != SourceAgentOTel || r.id < id {
			if _, err := s.db.ExecContext(wctx, `DELETE FROM api_turns WHERE id = ?`, id); err != nil {
				return "", fmt.Errorf("store.UpsertOwnAgentSpanTurn: remove own row: %w", err)
			}
			return OwnAgentSpanSuperseded, nil
		}
	}
	return OwnAgentSpanInserted, nil
}

// ownAgentSpanWriteTimeout bounds UpsertOwnAgentSpanTurn's detached insert,
// re-check and self-delete.
const ownAgentSpanWriteTimeout = 5 * time.Second

// ownAgentSpanRecheckHook, when set, runs before the post-insert re-check
// and its error replaces the re-check's result. Tests only (nil in
// production): it makes the re-check fail once after the insert.
var ownAgentSpanRecheckHook func() error

// rowsForRequestIDRecheck is rowsForRequestID behind the test hook.
func (s *Store) rowsForRequestIDRecheck(ctx context.Context, requestID string, skip int64) ([]requestIDRow, error) {
	if ownAgentSpanRecheckHook != nil {
		if err := ownAgentSpanRecheckHook(); err != nil {
			return nil, err
		}
	}
	return s.rowsForRequestID(ctx, requestID, skip)
}

// dropSpanDuplicates removes the span rows that stand beside another row
// for the same call (existing is every row holding the request id, all of
// them custom-agent rows). When a non-span row exists (the proxy's), every
// span row goes and superseded is true; otherwise every span row but the
// oldest goes.
func (s *Store) dropSpanDuplicates(ctx context.Context, requestID string, existing []requestIDRow) (superseded bool, err error) {
	var keepSpan int64
	for _, r := range existing {
		if r.source != SourceAgentOTel {
			superseded = true
		} else if keepSpan == 0 || r.id < keepSpan {
			keepSpan = r.id
		}
	}
	if superseded {
		keepSpan = 0
	}
	for _, r := range existing {
		if r.source == SourceAgentOTel && r.id != keepSpan {
			if _, err := s.db.ExecContext(ctx, `DELETE FROM api_turns WHERE id = ? AND request_id = ?`, r.id, requestID); err != nil {
				return false, fmt.Errorf("remove a duplicate span row: %w", err)
			}
		}
	}
	return superseded, nil
}

// ownAgentPlaceholderRoot is the project an own-agent session gets when no
// path knew its working directory (the proxy's fallback and the OTLP
// ingest's otlpvendor.PlaceholderProjectRoot).
const ownAgentPlaceholderRoot = "[" + models.ToolCustomAgent + "]"

// upgradeOwnAgentPlaceholderProject moves an own-agent session that sits on
// the placeholder project onto projectRoot, a real working directory a later
// caller resolved (the proxy, after the agent's spans opened the session
// first; sdk-2 fix round 1, L1). The session's actions and turns that sit on
// the placeholder move with it, in ONE transaction, so a reader never sees a
// half-moved session (sdk-2 lows, N2). Never the reverse: a placeholder
// projectRoot, or a session already on a real project, changes nothing; and
// UpsertSession never writes a placeholder over a real project, so a
// concurrent span tool-call ingest cannot move the session back.
func (s *Store) upgradeOwnAgentPlaceholderProject(ctx context.Context, sessionID, projectRoot string) error {
	if projectRoot == "" || projectRoot == ownAgentPlaceholderRoot {
		return nil
	}
	current, err := s.ProjectRootForSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if current != ownAgentPlaceholderRoot {
		return nil
	}
	// The project row is idempotent and harmless on its own, so it is made
	// before the transaction; the moves are what must be atomic.
	projectID, err := s.UpsertProject(ctx, projectRoot, "")
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("upgrade placeholder project: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var placeholderID int64
	err = tx.QueryRowContext(ctx, `
		SELECT s.project_id FROM sessions s JOIN projects p ON p.id = s.project_id
		 WHERE s.id = ? AND s.tool = ? AND p.root_path = ?`,
		sessionID, models.ToolCustomAgent, ownAgentPlaceholderRoot).Scan(&placeholderID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // moved meanwhile (by another caller); nothing to do
	}
	if err != nil {
		return fmt.Errorf("upgrade placeholder project: %w", err)
	}
	for _, q := range []string{
		`UPDATE sessions SET project_id = ? WHERE id = ? AND tool = ? AND project_id = ?`,
		`UPDATE actions SET project_id = ? WHERE session_id = ? AND tool = ? AND project_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, projectID, sessionID, models.ToolCustomAgent, placeholderID); err != nil {
			return fmt.Errorf("upgrade placeholder project: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE api_turns SET project_id = ? WHERE session_id = ? AND project_id = ?`, projectID, sessionID, placeholderID); err != nil {
		return fmt.Errorf("upgrade placeholder project: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("upgrade placeholder project: %w", err)
	}
	return nil
}

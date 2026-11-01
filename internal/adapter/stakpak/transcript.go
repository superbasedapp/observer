package stakpak

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/transcriptutil"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ReadTranscript implements handoffsvc.TranscriptReader, the session-handoff
// transcript tier (docs/session-handoff.md). Stakpak has no proxy tier and
// every checkpoint's state is the WHOLE cumulative conversation, so the
// transcript is the newest checkpoint's `state.messages` of the session:
// user prompts (harness `<local_context>` tail removed), assistant text and
// tool calls, with each tool message folded into the call it answers.
// Excerpt caps apply (the P1 default reader).
func (a *Adapter) ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.New())
}

// ReadTranscriptFull implements handoffsvc.FullTranscriptReader: the same
// normalized stream with message text and tool-result bodies emitted whole
// (excerpt caps lifted) for the full_cache carry mode and the
// get_session_message MCP pull.
func (a *Adapter) ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error) {
	return a.readTranscript(ctx, sess, sourceHints, transcriptutil.NewWithCaps(0, 0, 0))
}

// chainStep is one checkpoint on the leaf's parent chain: when it was
// written and how many messages its state held.
type chainStep struct {
	ID        string
	CreatedAt time.Time
	Count     int
}

// readTranscript resolves the store, picks the session's newest checkpoint
// (the leaf of the latest branch) and folds its messages into b. Message
// times come from the parent chain: a message's time is the created_at of the
// first checkpoint whose state holds it, and its id is that checkpoint's id —
// the same MessageID the parse stamps on the corresponding rows.
func (a *Adapter) readTranscript(ctx context.Context, sess models.Session, sourceHints []string, b *transcriptutil.Builder) ([]models.TranscriptMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sess.ID == "" {
		return nil, fmt.Errorf("stakpak.ReadTranscript: empty session id")
	}
	var lastErr error
	for _, dbPath := range a.transcriptStores(sourceHints) {
		msgs, found, err := a.readSessionFromStore(ctx, dbPath, sess.ID, b)
		if err != nil {
			lastErr = err
			continue
		}
		if found {
			return msgs, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("stakpak.ReadTranscript: %w", lastErr)
	}
	return nil, fmt.Errorf("stakpak.ReadTranscript: no transcript for session %s", sess.ID)
}

// transcriptStores lists the candidate local.db paths: a usable source hint
// first, then each watch root's store. Duplicates are dropped.
func (a *Adapter) transcriptStores(hints []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		p = resolveDBPath(p)
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, h := range hints {
		if a.IsSessionFile(h) || strings.EqualFold(filepath.Base(resolveDBPath(h)), "local.db") {
			add(h)
		}
	}
	for _, root := range a.roots {
		add(filepath.Join(root, "local.db"))
	}
	return out
}

// readSessionFromStore folds one session out of one store. found is false
// when the store has no checkpoint for the session.
func (a *Adapter) readSessionFromStore(ctx context.Context, dbPath, sessionID string, b *transcriptutil.Builder) ([]models.TranscriptMessage, bool, error) {
	db, err := openReadOnlyDB(dbPath)
	if err != nil {
		return nil, false, fmt.Errorf("open: %w", err)
	}
	defer db.Close()

	chain, err := leafChain(ctx, db, sessionID)
	if err != nil {
		return nil, false, err
	}
	if len(chain) == 0 {
		return nil, false, nil
	}
	leaf := chain[len(chain)-1]
	var state string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(state, '') FROM checkpoints WHERE id = ?`, leaf.ID).Scan(&state); err != nil {
		return nil, false, fmt.Errorf("leaf state: %w", err)
	}
	var doc stateDoc
	if err := json.Unmarshal([]byte(state), &doc); err != nil {
		return nil, false, fmt.Errorf("leaf state %s: %w", leaf.ID, err)
	}
	a.foldTranscript(b, doc.Messages, chain)
	return b.Finish(), true, nil
}

// leafChain returns the parent chain of the session's newest checkpoint,
// oldest first. The chain follows parent_id, so a session resumed at an older
// checkpoint yields only the branch that ends in the newest write.
func leafChain(ctx context.Context, db *sql.DB, sessionID string) ([]chainStep, error) {
	if ok, err := tableExists(ctx, db, "checkpoints"); err != nil || !ok {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		WITH RECURSIVE chain(id, parent_id, created_at, n, depth) AS (
			SELECT id, parent_id, COALESCE(created_at, ''),
			       CASE WHEN json_valid(state) THEN COALESCE(json_array_length(state, '$.messages'), 0) ELSE 0 END, 0
			  FROM checkpoints
			 WHERE rowid = (SELECT MAX(rowid) FROM checkpoints WHERE session_id = ?)
			UNION ALL
			SELECT c.id, c.parent_id, COALESCE(c.created_at, ''),
			       CASE WHEN json_valid(c.state) THEN COALESCE(json_array_length(c.state, '$.messages'), 0) ELSE 0 END,
			       chain.depth + 1
			  FROM checkpoints c JOIN chain ON c.id = chain.parent_id
		)
		SELECT id, created_at, n FROM chain ORDER BY depth DESC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	defer rows.Close()
	var out []chainStep
	for rows.Next() {
		var s chainStep
		var created string
		if err := rows.Scan(&s.ID, &created, &s.Count); err != nil {
			return nil, fmt.Errorf("chain scan: %w", err)
		}
		s.CreatedAt = parseTime(created)
		out = append(out, s)
	}
	return out, rows.Err()
}

// introducedBy returns the chain step that first held message idx: the first
// checkpoint whose state has more than idx messages. chain is oldest first
// and non-empty; a message past every count (a corrupt count) is attributed
// to the leaf.
func introducedBy(chain []chainStep, idx int) chainStep {
	for _, s := range chain {
		if s.Count > idx {
			return s
		}
	}
	return chain[len(chain)-1]
}

// foldTranscript feeds the leaf state's messages into the builder. The model
// is the per-message `model` when a future build records one (never today).
func (a *Adapter) foldTranscript(b *transcriptutil.Builder, msgs []rawMessage, chain []chainStep) {
	for i, m := range msgs {
		step := introducedBy(chain, i)
		ts := step.CreatedAt
		model := strings.TrimSpace(m.Model)
		switch strings.ToLower(m.Role) {
		case "user":
			text, _ := decodeContent(m.Content)
			text = strings.TrimSpace(stripLocalContext(text))
			b.SetNextID(step.ID)
			b.User(text, ts)
		case "assistant":
			text, _ := decodeContent(m.Content)
			b.SetNextID(step.ID)
			b.AssistantText(text, model, ts)
			for _, tc := range m.ToolCalls {
				b.SetNextID(step.ID)
				b.AssistantCall(tc.ID, nativeName(tc.Function.Name), string(argumentBytes(tc.Function.Arguments)), model, ts)
			}
		case "tool":
			text, _ := decodeContent(m.Content)
			b.Resolve(m.ToolCallID, text, ts)
		}
	}
}

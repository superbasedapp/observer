package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intelligence/compaction"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Observe-family hook capabilities that need no reply decision (hook-parity
// audit section 6, Lane E): compaction and task observation. A receiver
// answers the host with its dialect's allow FIRST, then hands the payload to
// recordObserveBinding, which dispatches on the binding's CAPABILITY (never
// a tool name) to the one recorder each capability has. Every path here is
// fail-open and best-effort: the reply already went out, a recorder error
// only reaches stderr, and nothing here can block or roll back the host's
// action (a task_observe hook that exited 2 would roll back the developer's
// task creation on Claude Code and Qwen Code, so these handlers never exit
// non-zero).

// observeRecorders is the capability -> recorder table (CLAUDE.md rule 5).
// A capability without a row is not recorded by this seam.
var observeRecorders = map[integration.HookCap]func(ctx context.Context, rec observeRecord) error{
	integration.HookCapCompactLifecycle: recordHookCompaction,
	integration.HookCapTaskObserve:      recordHookTaskEvent,
}

// observeRecord is one already-answered observe-family hook invocation.
type observeRecord struct {
	Tool       string
	Label      string
	Binding    integration.HookBinding
	Body       []byte
	ConfigPath string
	Now        time.Time
}

// recordObserveBinding records an observe-family hook payload for the
// binding the (tool, event) invocation resolves to. It reports whether a
// recorder ran. Call it only AFTER the host's reply went out.
func recordObserveBinding(ctx context.Context, tool, label, event string, body []byte, configPath string, stderr io.Writer) bool {
	b, ok := resolveHookInvocationBinding(tool, event)
	if !ok {
		return false
	}
	return recordObserveFor(ctx, tool, label, b, body, configPath, stderr)
}

// recordObserveFor is recordObserveBinding with the binding already
// resolved.
func recordObserveFor(ctx context.Context, tool, label string, b integration.HookBinding, body []byte, configPath string, stderr io.Writer) bool {
	run, ok := observeRecorders[b.Cap]
	if !ok {
		return false
	}
	err := run(ctx, observeRecord{Tool: tool, Label: label, Binding: b, Body: body, ConfigPath: configPath, Now: time.Now().UTC()})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s %s: %v\n", label, b.Cap, err)
	}
	return true
}

// observePayloadKeys are the field spellings the observe recorders read, in
// preference order, across every host whose compaction / task event Observer
// binds: snake_case (Claude-shaped hosts, Codex, Kimi's snake-cased runner,
// Poolside, Gemini), camelCase (Copilot CLI style), and Cursor's
// conversation_id / workspace_roots.
var (
	observeSessionKeys = []string{"session_id", "sessionId", "conversation_id"}
	observeCwdKeys     = []string{"cwd", "workspace_roots"}
	observeTriggerKeys = []string{"trigger"}
)

// observePayload is the normalized view of an observe-family payload.
type observePayload struct {
	SessionID string
	Cwd       string
	Trigger   string
	raw       map[string]json.RawMessage
}

// decodeObservePayload normalizes body. ok=false for a body that is not a
// JSON object.
func decodeObservePayload(body []byte) (observePayload, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil || m == nil {
		return observePayload{}, false
	}
	p := observePayload{raw: m}
	p.SessionID = firstStringField(m, observeSessionKeys)
	p.Cwd = firstStringField(m, observeCwdKeys)
	p.Trigger = firstStringField(m, observeTriggerKeys)
	return p, true
}

// str returns the payload's string field key ("" when absent or not a
// string).
func (p observePayload) str(key string) string {
	return firstStringField(p.raw, []string{key})
}

// firstStringField returns the first key whose value is a non-empty string,
// or the first element of a non-empty string array (Cursor's
// workspace_roots).
func firstStringField(m map[string]json.RawMessage, keys []string) string {
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			return s
		}
		var list []string
		if json.Unmarshal(raw, &list) == nil && len(list) > 0 && list[0] != "" {
			return list[0]
		}
	}
	return ""
}

// openObserveStore opens the configured database for one recorder call.
func openObserveStore(ctx context.Context, configPath string) (*store.Store, config.Config, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return nil, config.Config{}, nil, fmt.Errorf("config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return nil, config.Config{}, nil, fmt.Errorf("db: %w", err)
	}
	return hookIngestStore(database), cfg, func() { _ = database.Close() }, nil
}

// recordHookCompaction is the ONE compaction recorder every compact_lifecycle
// binding reaches (previously Claude Code only): a "pre" phase captures the
// pre-compaction snapshot, a "post" phase reconciles the most recent capture
// for the session. A host with only a pre event (Gemini PreCompress, Cursor
// preCompact, Droid PreCompact) records the capture alone.
func recordHookCompaction(ctx context.Context, rec observeRecord) error {
	p, ok := decodeObservePayload(rec.Body)
	if !ok || p.SessionID == "" {
		return fmt.Errorf("no session id in payload")
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: rec.ConfigPath})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer database.Close()
	spoolPath := ""
	if resolved, rerr := config.ResolveGlobalPath(rec.ConfigPath); rerr == nil {
		spoolPath = hookspool.Path(resolved)
	}
	return recordCompactionOrHold(ctx, database, spoolPath, hookspool.Record{
		Kind:        hookspool.KindCompaction,
		Phase:       rec.Binding.Phase,
		Tool:        rec.Tool,
		SessionID:   p.SessionID,
		ProjectRoot: hookIngestRootOf(p.Cwd),
		Trigger:     p.Trigger,
		Timestamp:   rec.Now,
	})
}

// recordCompactionOrHold lands a compaction hook now when its session row
// exists, and otherwise hands it to the daemon's lifecycle spool (T-320).
//
// A compaction can fire before the watcher has ingested its session (a
// resumed conversation that compacts at once). Its tables reference
// sessions, so writing it then failed the foreign key and the event was
// lost. The drainer lands a held record once the session exists, bounded by
// hookspool's hold caps (age, passes, records per pass).
//
// ORDER (P3-37): a session that already has a compaction record waiting on
// the spool holds this one too, behind it. Otherwise a PostCompact that fires
// once the session exists would reconcile at once while the earlier
// PreCompact is still held, and the drainer would then capture the pre
// snapshot AFTER the compaction it describes.
func recordCompactionOrHold(ctx context.Context, database *sql.DB, spoolPath string, held hookspool.Record) error {
	exists, err := store.New(database).SessionExists(ctx, held.SessionID)
	if err != nil {
		return fmt.Errorf("session lookup: %w", err)
	}
	if exists {
		pending, perr := hookspool.HoldsKind(spoolPath, hookspool.KindCompaction, held.SessionID)
		if perr != nil {
			return fmt.Errorf("spool lookup: %w", perr)
		}
		exists = !pending
	}
	if !exists {
		if err := hookspool.Append(spoolPath, held); err != nil {
			return fmt.Errorf("hold for session: %w", err)
		}
		return nil
	}
	return applyCompactionRecord(ctx, compaction.New(database), held)
}

// applyCompactionRecord lands one compaction hook: a "pre" phase captures the
// pre-compaction snapshot, a "post" phase reconciles the session's most
// recent capture. It is the ONE applier both the hook (session already
// ingested) and the daemon's lifecycle drainer (a held record whose session
// has since arrived) call, so the two paths cannot record differently.
func applyCompactionRecord(ctx context.Context, r *compaction.Recorder, rec hookspool.Record) error {
	switch rec.Phase {
	case integration.HookPhasePre:
		if _, err := r.Capture(ctx, compaction.CaptureOptions{
			SessionID:   rec.SessionID,
			ProjectRoot: rec.ProjectRoot,
			Tool:        rec.Tool,
			Timestamp:   rec.Timestamp,
			Trigger:     rec.Trigger,
		}); err != nil {
			return fmt.Errorf("capture: %w", err)
		}
	case integration.HookPhasePost:
		if err := r.Reconcile(ctx, compaction.ReconcileOptions{SessionID: rec.SessionID}); err != nil {
			return fmt.Errorf("reconcile: %w", err)
		}
	}
	return nil
}

// taskEventFields are the payload spellings of a task / todo hook event,
// per host (data, keyed on the field, never on the tool):
//
//   - Claude Code TaskCreated / TaskCompleted (code.claude.com/docs/en/hooks,
//     fetched 2026-10-03): task_id, task_title (task_subject in some
//     builds), task_description;
//   - Qwen Code TodoCreated / TodoCompleted (qwen-code 0.24.7 bundled
//     source on demo node 1, 2026-10-03): todo_id, todo_content,
//     todo_status / previous_status, phase ("validation" | "postWrite").
var (
	taskIDKeys    = []string{"task_id", "todo_id"}
	taskTitleKeys = []string{"task_title", "task_subject", "todo_content"}
)

// taskObservePhaseSkip is the one payload phase recordHookTaskEvent ignores:
// Qwen Code fires each todo event twice, first in "validation" (a hook
// there may still block the write) and then in "postWrite" (the write
// happened). Only the latter is a fact.
const taskObservePhaseSkip = "validation"

// recordHookTaskEvent records a task_observe binding as one task_event
// action row: capture only, never a decision (the reply already went out
// as the dialect's allow). The row's Target is "<phase>: <title>" so the
// session timeline reads "created: Fix the login" / "completed: ...".
func recordHookTaskEvent(ctx context.Context, rec observeRecord) error {
	ev, ok := buildHookTaskEvent(rec)
	if !ok {
		return nil
	}
	st, cfg, closeFn, err := openObserveStore(ctx, rec.ConfigPath)
	if err != nil {
		return err
	}
	defer closeFn()
	insertCtx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	if _, err := st.Ingest(insertCtx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

// buildHookTaskEvent is recordHookTaskEvent's pure half. ok=false skips the
// fire: no session id, a non-object payload, or Qwen's pre-write
// "validation" pass.
func buildHookTaskEvent(rec observeRecord) (models.ToolEvent, bool) {
	p, ok := decodeObservePayload(rec.Body)
	if !ok || p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	if p.str("phase") == taskObservePhaseSkip {
		return models.ToolEvent{}, false
	}
	verb := "created"
	if rec.Binding.Phase == integration.HookPhaseEnd {
		verb = "completed"
	}
	id := firstStringField(p.raw, taskIDKeys)
	title := strings.TrimSpace(firstStringField(p.raw, taskTitleKeys))
	target := verb
	if title != "" {
		target = verb + ": " + previewLine(title, 160)
	}
	// One row per (session, task, transition): a host that fires the same
	// transition twice for one task collapses onto the same source event id.
	key := id
	if key == "" {
		key = claudeContentHash(rec.Body)
	}
	return models.ToolEvent{
		SourceFile:    rec.Tool + ":hook",
		SourceEventID: p.SessionID + ":task_event:" + verb + ":" + key,
		SessionID:     p.SessionID,
		ProjectRoot:   p.Cwd,
		Timestamp:     rec.Now,
		Tool:          rec.Tool,
		ActionType:    models.ActionTaskEvent,
		Target:        target,
		RawToolName:   rec.Binding.NativeEvent,
		Success:       true,
	}, true
}

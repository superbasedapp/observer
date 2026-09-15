package qoder

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver (CLAUDE.md: no CGO)

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// workAppDir is Qoder Work's per-user data directory name. GROUNDED
// 2026-09-03 on a live Windows install: `%APPDATA%\com.qoder.app.stable`,
// a bundle-identifier-shaped name (distinct from `%APPDATA%\Qoder`, which
// is the Qoder IDE's Electron userData dir — the two apps ship separately,
// `%LOCALAPPDATA%\Programs\Qoder\Qoder.exe` vs
// `%LOCALAPPDATA%\Programs\Qoder IDE\Qoder IDE.exe`).
const workAppDir = "com.qoder.app.stable"

// workDBName is the Qoder Work store this adapter reads. Its `-wal` /
// `-shm` siblings are deliberately NOT session files (see classify): the
// watcher's 30s full scan re-parses main.sqlite anyway, and claiming the
// sidecars would only multiply parse_cursors rows for one store.
const workDBName = "main.sqlite"

// workFreshnessWindow is how long a Qoder Work session stays "in flight"
// for this adapter's two freshness gates. Both exist because the Work DB
// and the qodercli transcript are written by DIFFERENT processes and the
// adapter can only ever see one of them at a time:
//
//   - Hosted surface stamps are RE-EMITTED for every session touched
//     inside the window on every parse. A stamp for a session whose
//     transcript the watcher has not ingested yet updates zero rows (there
//     is no `sessions` row to stamp), so a single emission would be lost;
//     re-emitting until the window closes gives the transcript time to
//     land. The store no-ops an identical re-stamp, so the repetition is
//     free.
//   - The twin-less conversation fallback only CLAIMS a session once it
//     has been quiet for the whole window, so an in-flight run whose
//     transcript is about to appear is never claimed out from under
//     qodercli.
//
// Ten minutes is comfortably longer than the seconds-scale gap observed
// between a Work turn and its transcript write, and short enough that a
// genuinely twin-less session (an aborted run — see docs) is still picked
// up in the same working session.
const workFreshnessWindow = 10 * time.Minute

// workAppDataSpec declares Qoder Work's per-user data directory, one
// shape per OS:
//
//	<home>/AppData/Roaming/com.qoder.app.stable             (Windows — GROUNDED)
//	<home>/Library/Application Support/com.qoder.app.stable (macOS  — UNVERIFIED)
//	<home>/.config/com.qoder.app.stable                     (Linux  — UNVERIFIED)
//
// Only the Windows shape is grounded (live install 2026-09-03). The other
// two are the standard per-user data directories the app's toolkit family
// (Electron `app.getPath("userData")`, Tauri `appDataDir`) resolves an
// application-identifier name to — a convention, not an observation, hence
// UNVERIFIED. They are declared anyway because the cost of being wrong is
// one inert path on that OS, while the cost of omitting one is silent
// zero-capture on a Mac.
//
// XDGOnWindows is deliberately NOT set: nothing suggests Qoder Work
// writes <home>/.config on Windows.
var workAppDataSpec = adapter.AppDataSpec{
	Name: workAppDir,
	Shapes: adapter.ShapeWindowsRoaming |
		adapter.ShapeDarwinAppSupport |
		adapter.ShapeXDGConfig,
}

// workDBRoots returns the Qoder Work data directory under every
// cross-mount-resolved home, in the shape that belongs to each home's
// LOGICAL OS.
//
// Every shape used to be emitted under every home on the theory that a
// non-existent root is inert. It is inert to the DATA path but not to
// the operational one: on a WSL2 daemon that produced, registered and
// logged `/mnt/c/Users/<u>/Library/Application Support/
// com.qoder.app.stable` and `/mnt/c/Users/<u>/.config/
// com.qoder.app.stable` for every Windows profile on the box — paths
// that cannot exist on any host. crossmount already tags each home
// with its logical OS; adapter.AppDataRoots is the one owner of
// turning that tag into the right shape.
func workDBRoots() []string {
	var roots []string
	for _, h := range allHomesFunc() {
		roots = append(roots, adapter.AppDataRoots(h, workAppDataSpec)...)
	}
	return adapter.DedupRootsByIdentity(roots)
}

// isWorkDBPath reports whether a slash-normalized lower-cased path is the
// Qoder Work store. The file must sit DIRECTLY in a `com.qoder.app.stable`
// directory, which is what keeps the app's other stores unclaimed:
// `sessionMigration.sqlite` and `qoder-data.v1.json` are siblings with
// different names, and `main.sqlite-wal` / `-shm` fail the name test.
func isWorkDBPath(lower string) bool {
	if !strings.HasSuffix(lower, "/"+workDBName) {
		return false
	}
	return filepath.Base(filepath.Dir(lower)) == strings.ToLower(workAppDir)
}

// workMessage is one chat_session_messages row's read projection.
type workMessage struct {
	sessionID string
	messageID string
	updatedAt int64
	payload   workPayload
}

// workPayload is the decoded `payload_json` of a chat_session_messages
// row. GROUNDED 2026-09-03 against all 18 live rows.
//
// The id spaces are SHARED with the qodercli transcript, byte for byte: a
// user message's `id` is the transcript record's `uuid`, and a
// `tools[].id` is the transcript's `tool_use` block id. That is the
// strongest evidence for the §2.1 "one tool, two surfaces" call, and it is
// why the fallback emitter below reuses the transcript parser's
// SourceEventID scheme verbatim.
type workPayload struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	TurnID    string     `json:"turnId"`
	Text      string     `json:"text"`
	Timestamp string     `json:"timestamp"`
	Tools     []workTool `json:"tools"`
	// FailureReason is set on an assistant message that never produced
	// content (observed: "BYOK_PROVIDER_REQUEST_FAILED").
	FailureReason string `json:"failureReason"`
	// Subtype discriminates the non-conversational system rows
	// ("hook_activity"); role already excludes them, this is here so the
	// shape is documented rather than silently dropped.
	Subtype string `json:"subtype"`
}

// workTool is one entry of an assistant payload's `tools` array — a
// COMPLETE tool-call record (request, verdict and response in one object),
// unlike the transcript's split tool_use / tool_result pair.
type workTool struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Input       json.RawMessage `json:"input"`
	Status      string          `json:"status"`
	StartedAt   string          `json:"startedAt"`
	CompletedAt string          `json:"completedAt"`
	DurationMs  int64           `json:"durationMs"`
	Response    json.RawMessage `json:"response"`
}

// workSession is a chat_sessions row's read projection. Deliberately
// narrow: `model` is NEVER read (it holds `byok:<credential-profile-uuid>`
// or the tier alias `auto`, neither of which is a model name), and the
// account / credential columns are never named in a query at all.
type workSession struct {
	cwd       string
	gitBranch string
	// imported marks a session Qoder Work IMPORTED from another product
	// rather than drove itself. Grounded live 2026-09-03 (review fix):
	// the Work app imports Qoder IDE ("quest") tasks — the IDE original
	// stays at projects/<slug>/transcript/<task>.session.execution.jsonl
	// and the import is written as a NEW flat <uuid>.jsonl carrying
	// `toolu_migrated_call` markers, joined by sessionMigration.sqlite's
	// migration_ledger (source_ref = the task id, target_session_id =
	// the uuid). On the Work side such a session carries
	// extra_json.importedFrom (= "quest") and a NULL execution_kind,
	// and its messages are all source='cli-import'. The conversation
	// was NOT hosted by Work, so stamping it desktop/qoder-work (a
	// host-wins, irreversible write) would mislabel a copy of an IDE
	// task; both the stamp and the twin-less fallback skip it.
	imported bool
}

// parseWorkDB parses Qoder Work's main.sqlite.
//
// fromOffset is a Unix-MILLISECOND watermark on
// chat_session_messages.updated_at, not a byte offset (see
// CursorSemanticsFor). The read deliberately reaches BACK one
// workFreshnessWindow behind the watermark so recent rows are revisited:
// every event id is deterministic and every store write on this path is
// an idempotent upsert or an identical-value no-op, so re-reading is free
// and it is what makes the two freshness gates work at all.
func (a *Adapter) parseWorkDB(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	staged, err := stageMirrorIfForeign(path)
	if err != nil {
		return res, fmt.Errorf("qoder.parseWorkDB: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(staged))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return res, fmt.Errorf("qoder.parseWorkDB: open: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Tolerate a fresh install / a schema the app has not migrated yet
	// rather than erroring the whole poll tick.
	for _, tbl := range []string{"chat_session_messages", "chat_sessions"} {
		ok, err := workTableExists(ctx, db, tbl)
		if err != nil {
			return res, fmt.Errorf("qoder.parseWorkDB: %w", err)
		}
		if !ok {
			return res, nil
		}
	}

	since := fromOffset - workFreshnessWindow.Milliseconds()
	if since < 0 {
		since = 0
	}
	msgs, maxUpdated, err := readWorkMessages(ctx, db, since, &res)
	if err != nil {
		return res, fmt.Errorf("qoder.parseWorkDB: %w", err)
	}
	if maxUpdated > res.NewOffset {
		res.NewOffset = maxUpdated
	}
	if len(msgs) == 0 {
		return res, nil
	}

	bySession, order, sessionMax := groupWorkMessages(msgs)
	meta, err := readWorkSessions(ctx, db, order)
	if err != nil {
		return res, fmt.Errorf("qoder.parseWorkDB: %w", err)
	}

	st := &parseState{
		adapter:       a,
		path:          path,
		rootCache:     map[string]string{},
		remoteCache:   map[string]string{},
		identityCache: map[string]git.Identity{},
		pendingCall:   map[string]int{},
	}
	cutoff := a.clock().Add(-workFreshnessWindow).UnixMilli()
	for _, sessionID := range order {
		if meta[sessionID].imported {
			// An import of another product's conversation (see
			// workSession.imported): Work never hosted it, so no hosted
			// stamp and no fallback rows — the original is captured
			// from its own store under its own surface.
			continue
		}
		// The hosted stamp is the PRIMARY product of this parser and is
		// emitted for every session Work itself drove in the read
		// window, in flight or not.
		if s := surfaceFor(layoutWorkDB, sessionID); s.Surface != "" {
			res.SessionSurfaces = append(res.SessionSurfaces, s)
		}
		if sessionMax[sessionID] >= cutoff {
			// Still in flight: keep this file on the poll loop so the
			// stamp is re-emitted once the transcript has landed, and
			// do not consider claiming the conversation yet.
			res.RetrySuggested = true
			continue
		}
		if a.hasCLITwin(sessionID) {
			continue
		}
		st.emitWorkConversation(&res, sessionID, meta[sessionID], bySession[sessionID])
	}
	st.applyIdentities(&res)
	return res, nil
}

// groupWorkMessages buckets messages by session, preserving first-seen
// session order (the query is ordered by session then sequence) and
// recording each session's newest updated_at.
func groupWorkMessages(msgs []workMessage) (bySession map[string][]workMessage, order []string, sessionMax map[string]int64) {
	bySession = map[string][]workMessage{}
	sessionMax = map[string]int64{}
	for _, m := range msgs {
		if _, seen := bySession[m.sessionID]; !seen {
			order = append(order, m.sessionID)
		}
		bySession[m.sessionID] = append(bySession[m.sessionID], m)
		if m.updatedAt > sessionMax[m.sessionID] {
			sessionMax[m.sessionID] = m.updatedAt
		}
	}
	return bySession, order, sessionMax
}

// readWorkMessages pulls every chat_session_messages row newer than
// `since`, ordered by session then sequence. Malformed payload JSON is a
// per-row warning, never a parse failure.
//
// The column list is an explicit ALLOW-LIST of what the emitter actually
// uses. `feedback` (a user's thumbs up/down note), `source` and `status`
// are NOT read — the per-tool `status` inside the payload is the verdict
// that matters, and ownership is decided by the twin check rather than by
// the `source` provenance label. No query in this package ever names
// byok_model_credentials, mcp_oauth_credentials or account_profiles.
func readWorkMessages(ctx context.Context, db *sql.DB, since int64, res *adapter.ParseResult) ([]workMessage, int64, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT session_id, message_id, updated_at, payload_json
		   FROM chat_session_messages
		  WHERE updated_at > ?
		  ORDER BY session_id ASC, sequence ASC`, since)
	if err != nil {
		return nil, 0, fmt.Errorf("readWorkMessages: query: %w", err)
	}
	defer rows.Close()

	var out []workMessage
	var maxUpdated int64
	for rows.Next() {
		var (
			m       workMessage
			payload string
		)
		if err := rows.Scan(&m.sessionID, &m.messageID, &m.updatedAt, &payload); err != nil {
			return nil, maxUpdated, fmt.Errorf("readWorkMessages: scan: %w", err)
		}
		if m.updatedAt > maxUpdated {
			maxUpdated = m.updatedAt
		}
		if err := json.Unmarshal([]byte(payload), &m.payload); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("qoder-work: message %s/%s: malformed payload_json: %v", m.sessionID, m.messageID, err))
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, maxUpdated, fmt.Errorf("readWorkMessages: iterate: %w", err)
	}
	return out, maxUpdated, nil
}

// workSessionChunk caps how many session ids go into one IN(...) list.
const workSessionChunk = 200

// readWorkSessions loads cwd + git_branch for the given session ids. A
// session id with no chat_sessions row simply yields no metadata (the
// caller then resolves an empty project root, which is the honest answer).
func readWorkSessions(ctx context.Context, db *sql.DB, ids []string) (map[string]workSession, error) {
	out := map[string]workSession{}
	for start := 0; start < len(ids); start += workSessionChunk {
		end := start + workSessionChunk
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		args := make([]any, 0, len(chunk))
		placeholders := make([]string, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
			placeholders = append(placeholders, "?")
		}
		// The only interpolated text is a comma-joined run of literal
		// "?" placeholders sized to len(chunk); every session id travels
		// as a bound argument. There is no other way to write a
		// variable-length IN list in database/sql.
		// execution_kind + extra_json are read ONLY for the import
		// discriminator (workSession.imported); extra_json is decoded
		// into a one-field struct so nothing else in it is retained.
		q := `SELECT session_id, cwd, git_branch, execution_kind, extra_json FROM chat_sessions WHERE session_id IN (` + //nolint:gosec // G202: placeholders only, ids are bound args
			strings.Join(placeholders, ",") + `)`
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("readWorkSessions: query: %w", err)
		}
		for rows.Next() {
			var (
				id       string
				cwd      sql.NullString
				branch   sql.NullString
				execKind sql.NullString
				extra    sql.NullString
			)
			if err := rows.Scan(&id, &cwd, &branch, &execKind, &extra); err != nil {
				rows.Close()
				return nil, fmt.Errorf("readWorkSessions: scan: %w", err)
			}
			out[id] = workSession{
				cwd:       cwd.String,
				gitBranch: branch.String,
				imported:  workSessionImported(execKind, extra.String),
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("readWorkSessions: iterate: %w", err)
		}
	}
	return out, nil
}

// workSessionImported is the import discriminator (workSession.imported):
// extra_json.importedFrom names the source product on every imported
// session observed live, and execution_kind is NULL on exactly those
// rows (every Work-driven session carries "local"). Either signal alone
// is enough — a session Work did not execute is not a session Work
// hosted.
func workSessionImported(executionKind sql.NullString, extraJSON string) bool {
	if !executionKind.Valid || strings.TrimSpace(executionKind.String) == "" {
		return true
	}
	if strings.TrimSpace(extraJSON) == "" {
		return false
	}
	var extra struct {
		ImportedFrom string `json:"importedFrom"`
	}
	if err := json.Unmarshal([]byte(extraJSON), &extra); err != nil {
		return false
	}
	return extra.ImportedFrom != ""
}

// hasCLITwin reports whether the qodercli transcript store already holds a
// session with this id — i.e. whether internal/adapter/qoder's own
// transcript parser is (or will be) the canonical owner of the rows.
//
// THE OWNERSHIP RULE (the kiro-crew precedent, docs/kiro-crew-adapter.md):
// the CLI transcript is the RICHER record — it carries the split
// tool_use/tool_result pair, per-record cwd + gitBranch, isSidechain, the
// upstream message id and the attachment/runtime-config envelope, none of
// which the Work projection has — so it OWNS the conversation. Qoder Work
// contributes only the hosted surface stamp for a session with a twin.
// A twin-less session is the one case where the Work store is the ONLY
// record of the conversation, and there the fallback emits it in full.
//
// The check is a filesystem stat, not a DB read: no cross-store lock, no
// second cursor, and it stays correct if the transcript is deleted.
//
// A session id containing glob metacharacters is treated as HAVING a twin
// (i.e. never claimed). Every observed id is a uuid; refusing to expand a
// pattern is the conservative direction — a missed session is recoverable
// by a later parse, a duplicated one is not.
func (a *Adapter) hasCLITwin(sessionID string) bool {
	if sessionID == "" || strings.ContainsAny(sessionID, `*?[\`) {
		return true
	}
	for _, root := range a.roots {
		if filepath.Base(root) != projectsDir {
			continue
		}
		for _, pattern := range []string{
			filepath.Join(root, "*", sessionID+".jsonl"),
			filepath.Join(root, "*", transcriptDir, sessionID+".jsonl"),
		} {
			if m, err := filepath.Glob(pattern); err == nil && len(m) > 0 {
				return true
			}
		}
	}
	return false
}

// emitWorkConversation emits the conversation rows for a Work session with
// NO qodercli twin. Kept deliberately thin — it is the fallback, not the
// primary path.
//
// SourceEventIDs reuse the transcript parser's scheme
// ("session_start:<sid>" / "prompt:<uuid>" / "tool:<call id>") because the
// id spaces are byte-identical across the two stores (see workPayload).
// The store's dedup key is (source_file, source_event_id) and the two
// stores are different files, so a transcript that appears LATER would
// still double-count; the freshness gate is what makes that unlikely, and
// the shared scheme is what would make a future repair a join rather than
// a guess. Documented in docs/qoder-adapter.md "Known limitation".
//
// NEVER emitted here: token events (chat_session_context_usage reports
// `tokenCountsAvailable:false` with every count zero — it is a
// context-window occupancy gauge, not usage) and a model string
// (`byok:<uuid>` is a credential-profile id, `auto` a tier alias).
func (st *parseState) emitWorkConversation(res *adapter.ParseResult, sessionID string, meta workSession, msgs []workMessage) {
	root, remote := st.projectRoot(meta.cwd)
	started := false
	for _, m := range msgs {
		ts := parseTimestamp(m.payload.Timestamp)
		base := models.ToolEvent{
			SourceFile:  st.path,
			SessionID:   sessionID,
			ProjectRoot: root,
			GitBranch:   meta.gitBranch,
			GitRemote:   remote,
			Timestamp:   ts,
			Tool:        models.ToolQoder,
			Success:     true,
		}
		switch m.payload.Role {
		case "user":
			text := strings.TrimSpace(m.payload.Text)
			if text == "" {
				continue
			}
			if !started {
				started = true
				start := base
				start.SourceEventID = "session_start:" + sessionID
				start.ActionType = models.ActionSessionStart
				start.Target = "startup"
				start.RawToolName = "qoder.session_start"
				res.ToolEvents = append(res.ToolEvents, start)
			}
			scrubbed := st.adapter.scrubber.String(text)
			ev := base
			ev.SourceEventID = "prompt:" + m.payload.ID
			ev.ActionType = models.ActionUserPrompt
			ev.Target = truncate(scrubbed, 200)
			ev.RawToolName = "qoder.user_prompt"
			ev.RawToolInput = scrubbed
			res.ToolEvents = append(res.ToolEvents, ev)
		case "assistant":
			if text := strings.TrimSpace(m.payload.Text); text != "" {
				scrubbed := st.adapter.scrubber.String(text)
				ev := base
				ev.SourceEventID = "assistant:" + assistantEventKey(m.payload)
				ev.ActionType = models.ActionAssistantMessage
				ev.Target = truncate(scrubbed, 200)
				ev.RawToolName = "qoder.assistant_text"
				ev.ToolOutput = st.adapter.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes))
				res.ToolEvents = append(res.ToolEvents, ev)
			}
			for _, tool := range m.payload.Tools {
				res.ToolEvents = append(res.ToolEvents, st.workToolEvent(base, tool))
			}
		default:
			// role "system" is a hook-activity projection
			// (subtype "hook_activity", empty text, a `parts[].hook`
			// record of the plugin hook qodercli fired). It describes
			// the harness, not the conversation — skipped.
		}
	}
}

// workToolEvent builds one ToolEvent from a Work `tools[]` entry.
func (st *parseState) workToolEvent(base models.ToolEvent, tool workTool) models.ToolEvent {
	action := mapToolName(tool.Name)
	ev := base
	ev.SourceEventID = "tool:" + tool.ID
	ev.ActionType = action
	ev.Target = st.adapter.scrubber.String(targetFromInput(tool.Input, tool.Name))
	ev.RawToolName = tool.Name
	ev.RawToolInput = st.adapter.scrubber.RawJSON(tool.Input)
	ev.ContentBytes = authoredBytes(action, tool.Input)
	ev.DurationMs = tool.DurationMs
	if ts := parseTimestamp(tool.StartedAt); !ts.IsZero() {
		ev.Timestamp = ts
	}
	// The tool record carries its own verdict, so — unlike the split
	// transcript pair — there is never a pending outcome to reconcile.
	ev.Success = tool.Status == "completed"
	if out := toolResultText(tool.Response); out != "" {
		scrubbed := st.adapter.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
		ev.ToolOutput = scrubbed
		if !ev.Success {
			ev.ErrorMessage = truncate(scrubbed, 500)
		}
	}
	return ev
}

// assistantEventKey returns the id half of an assistant message's event
// id. The stored message_id is "assistant:<turnId>"; stripping the prefix
// keeps the emitted SourceEventID from reading "assistant:assistant:…".
func assistantEventKey(p workPayload) string {
	if id := strings.TrimPrefix(p.ID, "assistant:"); id != "" {
		return id
	}
	if p.TurnID != "" {
		return p.TurnID
	}
	return p.ID
}

// workTableExists reports whether a table is present, via sqlite_master.
func workTableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var found string
	err := db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&found)
	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("workTableExists(%s): %w", name, err)
	default:
		return true, nil
	}
}

// isForeignMountPath reports whether path lives under a crossmount-
// detected non-native home. Both bridge directions are covered.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

// stageMirrorIfForeign copies a Work DB that lives on a foreign mount
// (a Windows profile seen from WSL2 over DrvFs, or the reverse) into a
// local staging dir before opening it. SQLite over DrvFs fails with
// `disk I/O error (10)`; the same mirror trick kirocli/opencode/zcode use.
// A native path is returned unchanged.
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "qoderwork-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("qoder.stageMirror: mkdir %s: %w", mirrorDir, err)
	}
	dstDB := filepath.Join(mirrorDir, workDBName)
	if mirrorUpToDate(srcDB, dstDB) {
		return dstDB, nil
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := srcDB + suffix
		dst := dstDB + suffix
		data, err := os.ReadFile(src) //nolint:gosec // src derives from validated watch roots
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(dst)
				continue
			}
			return "", fmt.Errorf("qoder.stageMirror: read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("qoder.stageMirror: write %s: %w", dst, err)
		}
	}
	return dstDB, nil
}

// mirrorUpToDate reports whether the mirrored DB is at least as fresh as
// the source, comparing (size, mtime) on the main file and the -wal
// sibling. Returns false on any stat error so a fresh copy is attempted.
func mirrorUpToDate(srcDB, dstDB string) bool {
	for _, suffix := range []string{"", "-wal"} {
		src, srcErr := os.Stat(srcDB + suffix)
		dst, dstErr := os.Stat(dstDB + suffix)
		if srcErr != nil {
			// Absent source sibling: the mirror must not claim to be
			// current if it still holds a stale copy of it.
			if dstErr == nil {
				return false
			}
			continue
		}
		if dstErr != nil || src.Size() != dst.Size() || src.ModTime().After(dst.ModTime()) {
			return false
		}
	}
	return true
}

// allHomesFunc is the test seam over crossmount.AllHomes, matching the
// kirocli / kirocrew precedent.
var allHomesFunc = crossmount.AllHomes

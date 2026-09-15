package openclaw

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// OpenClaw 2.0 (~2026-08-30) moved live sessions and their transcripts
// out of `agents/<agentId>/sessions/*.jsonl` and into ONE SQLite store
// per agent:
//
//	~/.openclaw/agents/<agentId>/agent/openclaw-agent.sqlite
//
// The legacy `sessions/` tree survives as an archive that
// `openclaw doctor --fix` imports into the store. Everything in this
// file exists so an upgraded install keeps capturing without the
// adapter silently zeroing, and so a session that exists in BOTH
// layouts is ingested ONCE. See docs/openclaw-adapter.md.
const (
	agentDBBase = "openclaw-agent.sqlite"
	agentDBWAL  = "openclaw-agent.sqlite-wal"
	agentDBSHM  = "openclaw-agent.sqlite-shm"
)

// agentHeaderScanLimit bounds the per-session lookback used to recover
// a session's cwd from its `session` header entry when the current
// delta does not contain that header. The header is the FIRST entry of
// a transcript by construction, so a handful of rows is enough.
const agentHeaderScanLimit = 8

// allHomesFunc is the test seam over crossmount.AllHomes, used by the
// foreign-mount detection below. Same shape as kirocli/clinecli.
var allHomesFunc = crossmount.AllHomes

// isAgentDBPath reports whether path names an OpenClaw 2.0 per-agent
// store — `.../agents/<agentId>/agent/openclaw-agent.sqlite`, or its
// `-wal` sidecar. Separators and case are normalised first (the
// kirocli.classifyLayout pattern) so a Windows-shaped path examined on
// Linux still yields the right basename. Root-gating still happens in
// IsSessionFile; this only recognises the shape.
func isAgentDBPath(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	base := norm
	if i := strings.LastIndex(norm, "/"); i >= 0 {
		base = norm[i+1:]
	}
	if base != agentDBBase && base != agentDBWAL {
		return false
	}
	// Belt-and-braces: the file must sit in the agent's own `agent`
	// directory under an `agents/<id>/` tree, so a stray
	// openclaw-agent.sqlite elsewhere cannot claim the dispatch.
	return strings.HasSuffix(norm, "/agent/"+base) && strings.Contains(norm, "/agents/")
}

// resolveAgentDB maps a WAL/SHM sidecar trigger onto the main database
// file. fsnotify usually reports the `-wal` write, never the main file,
// so the sidecar is a TRIGGER only — parsing always opens
// openclaw-agent.sqlite itself. Mirrors resolveRunsDB.
func resolveAgentDB(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == agentDBWAL || base == agentDBSHM {
		return filepath.Join(filepath.Dir(path), agentDBBase)
	}
	return path
}

// legacySourceFile maps a 2.0 store path + session id onto the
// CANONICAL pre-2.0 message-log path for that session:
//
//	<...>/agents/<agentId>/agent/openclaw-agent.sqlite
//	                    ↓
//	<...>/agents/<agentId>/sessions/<sessionId>.jsonl
//
// That path — not the DB path — is what every event parsed out of the
// store carries as SourceFile. It is the dedup key: `openclaw doctor
// --fix` imports the legacy `sessions/` tree into the store, so a
// session observer already ingested from its `.jsonl` would otherwise
// be ingested a SECOND time under a different source_file. Because the
// SQLite path reuses the same entry handler, and therefore derives the
// same SourceEventID from the same entry id, the re-read collides on
// the store's UNIQUE(source_file, source_event_id) index instead.
//
// It also keeps the sibling lookups working: the sessions.json index
// (applySessionAlias) and the `<id>.trajectory.jsonl` bootstrap
// preamble both resolve relative to this path's directory, which is
// exactly where they live when the legacy tree is still present. When
// it is not, both lookups simply miss and fall back, as they already do
// for a rotated-away sibling.
//
// The DB path is returned unchanged when the layout does not match, so
// a future relocation degrades to self-keyed events rather than
// mis-aliased ones.
func legacySourceFile(dbPath, sessionID string) string {
	if strings.TrimSpace(sessionID) == "" {
		return dbPath
	}
	agentDir := filepath.Dir(dbPath)
	if !strings.EqualFold(filepath.Base(agentDir), "agent") {
		return dbPath
	}
	return filepath.Join(filepath.Dir(agentDir), "sessions", sessionID+".jsonl")
}

// epochMillisCutoff separates a seconds-scale epoch value from a
// millis-scale one. 1e11 seconds is the year 5138 and 1e11 millis is
// 1973-03-03, so every plausible timestamp below the cutoff is seconds
// and every one above it is milliseconds.
const epochMillisCutoff = int64(1e11)

// epochToTime converts an integer epoch column (or entry_json field) to
// UTC. The 2.0 schema is grounded on column NAMES, not units, so both
// scales are accepted; non-positive values yield the zero time.
func epochToTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	if v < epochMillisCutoff {
		return time.Unix(v, 0).UTC()
	}
	return time.UnixMilli(v).UTC()
}

// sessionEntry is the subset of `session_nodes.entry_json` (OpenClaw's
// SessionEntry) this adapter reads: the provider/model fallbacks used
// when session_windows carries neither.
//
// The entry ALSO carries session-level counters (inputTokens,
// outputTokens, totalTokens, contextTokens). They are deliberately NOT
// read: per-call usage already arrives on the `message` transcript
// entries, and adding a session-level total on top would double-count
// every turn.
type sessionEntry struct {
	SessionID        string `json:"sessionId"`
	Provider         string `json:"provider"`
	ProviderOverride string `json:"providerOverride"`
	ModelOverride    string `json:"modelOverride"`
}

// parseAgentDB reads new `transcript_events` rows out of an OpenClaw
// 2.0 per-agent store and folds them through the SAME entry handler the
// pre-2.0 message log uses.
//
// The offset is a row watermark, not a byte offset (declared as
// adapter.CursorWatermark in cursorsemantics.go).
func (a *Adapter) parseAgentDB(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	dbPath := resolveAgentDB(path)
	src, err := stageMirrorIfForeign(dbPath)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: stage agent DB mirror: %w", err)
	}
	// Read-only WITHOUT immutable=1: the OpenClaw gateway holds the
	// database open and its newest turns live in the WAL, which an
	// immutable open would not see.
	db, err := openReadOnlyDB(src)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("openclaw.ParseSessionFile: open agent DB: %w", err)
	}
	defer db.Close()

	res := adapter.ParseResult{NewOffset: fromOffset}
	if !agentTableExists(ctx, db, "transcript_events") {
		// A store that predates (or postdates) this table is not an
		// error — the adapter's other layouts still carry the install.
		return res, nil
	}
	byRowID := transcriptRowIDUsable(ctx, db)
	latest, err := latestTranscriptWatermark(ctx, db, byRowID)
	if err != nil {
		return res, fmt.Errorf("openclaw.ParseSessionFile: transcript watermark: %w", err)
	}
	res.NewOffset = latest
	if latest <= fromOffset {
		return res, nil
	}

	rows, err := queryTranscriptDelta(ctx, db, byRowID, fromOffset)
	if err != nil {
		return res, fmt.Errorf("openclaw.ParseSessionFile: query transcript_events: %w", err)
	}
	defer rows.Close()

	// One scope per session_id: the store interleaves every session of
	// the agent in one rowid sequence, and pending tool calls / model
	// state must not leak across them.
	scopes := map[string]*transcriptScope{}
	for rows.Next() {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		var (
			rowID     sql.NullInt64
			sessionID sql.NullString
			seq       sql.NullInt64
			eventJSON sql.NullString
			createdAt sql.NullInt64
		)
		if err := rows.Scan(&rowID, &sessionID, &seq, &eventJSON, &createdAt); err != nil {
			return res, fmt.Errorf("openclaw.ParseSessionFile: scan transcript_events: %w", err)
		}
		sid := strings.TrimSpace(sessionID.String)
		body := strings.TrimSpace(eventJSON.String)
		if sid == "" || body == "" {
			continue
		}
		var line jsonlLine
		if err := json.Unmarshal([]byte(body), &line); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("session %s seq %d: malformed event_json: %v", sid, seq.Int64, err))
			continue
		}
		sc, ok := scopes[sid]
		if !ok {
			sc = a.newAgentScope(ctx, db, dbPath, sid)
			scopes[sid] = sc
		}
		ts := parseTimestamp(line.Timestamp)
		if ts.IsZero() {
			ts = epochToTime(createdAt.Int64)
		}
		a.handleTranscriptEntry(sc, line, int(seq.Int64), ts, &res)
	}
	return res, rows.Err()
}

// newAgentScope builds the parse scope for one session_id in the store.
func (a *Adapter) newAgentScope(ctx context.Context, db *sql.DB, dbPath, sessionID string) *transcriptScope {
	sourceFile := legacySourceFile(dbPath, sessionID)
	state := sessionContext{SessionID: sessionID, ProjectRoot: "[openclaw]"}
	rootCache := map[string]projectGitInfo{}

	// When the pre-2.0 tree is still on disk its sessions.json remains
	// the canonical owner of the session KEY, exactly as on the JSONL
	// path — so both layouts land one run on one observer session.
	applySessionAlias(sourceFile, &state, sessionID)

	provider, model := agentSessionModel(ctx, db, sessionID)
	if state.Provider == "" {
		state.Provider = provider
	}
	if state.Model == "" {
		state.Model = model
	}
	// A delta that does not contain the session header still needs the
	// project root; recover it from the header row in the store. A
	// header inside the delta overwrites this with the same value.
	if state.ProjectRoot == "" || state.ProjectRoot == "[openclaw]" {
		if cwd := agentSessionCwd(ctx, db, sessionID); cwd != "" {
			state.ProjectRoot = cwd
		}
	}
	if state.ProjectRoot != "" && state.ProjectRoot != "[openclaw]" {
		state.ProjectRoot, state.ProjectRemote = a.resolveProjectRoot(state.ProjectRoot, rootCache)
	}

	tracePrefix := ""
	tracePrefixLoaded := false
	return &transcriptScope{
		sourceFile:        sourceFile,
		state:             state,
		pending:           map[string]int{},
		rootCache:         rootCache,
		seenSystemPrompts: map[string]bool{},
		cacheAcc:          cacheobs.New(MaxBlocksPerSession),
		bootstrapPrefix: func() string {
			if !tracePrefixLoaded {
				tracePrefixLoaded = true
				tracePrefix = bootstrapPrefixFromTrace(sourceFile)
			}
			return tracePrefix
		},
	}
}

// agentSessionModel resolves the session's provider/model from
// session_windows, falling back to session_nodes.entry_json. Both
// lookups are tolerant: a missing table, a missing column or a NULL all
// degrade to "no grounded value" rather than an error, and a `message`
// entry's own provider/model always wins over either.
func agentSessionModel(ctx context.Context, db *sql.DB, sessionID string) (provider, model string) {
	if agentTableExists(ctx, db, "session_windows") {
		var p, m sql.NullString
		err := db.QueryRowContext(ctx,
			`SELECT model_provider, model FROM session_windows WHERE session_id = ? LIMIT 1`,
			sessionID).Scan(&p, &m)
		if err == nil {
			provider = strings.TrimSpace(p.String)
			model = strings.TrimSpace(m.String)
		}
	}
	if provider != "" && model != "" {
		return provider, model
	}
	if !agentTableExists(ctx, db, "session_nodes") {
		return provider, model
	}
	var entry sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT entry_json FROM session_nodes WHERE current_session_id = ? LIMIT 1`,
		sessionID).Scan(&entry); err != nil {
		return provider, model
	}
	var e sessionEntry
	if json.Unmarshal([]byte(entry.String), &e) != nil {
		return provider, model
	}
	if provider == "" {
		provider = firstNonEmpty(e.ProviderOverride, e.Provider)
	}
	if model == "" {
		model = strings.TrimSpace(e.ModelOverride)
	}
	return provider, model
}

// agentSessionCwd recovers a session's working directory from its
// `session` header entry. The header is the first entry of a transcript,
// so the scan is bounded to agentHeaderScanLimit rows.
func agentSessionCwd(ctx context.Context, db *sql.DB, sessionID string) string {
	rows, err := db.QueryContext(ctx,
		`SELECT event_json FROM transcript_events WHERE session_id = ? ORDER BY seq ASC LIMIT ?`,
		sessionID, agentHeaderScanLimit)
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var body sql.NullString
		if err := rows.Scan(&body); err != nil {
			return ""
		}
		var line jsonlLine
		if json.Unmarshal([]byte(body.String), &line) != nil {
			continue
		}
		if line.Type == "session" && strings.TrimSpace(line.Cwd) != "" {
			return line.Cwd
		}
	}
	return ""
}

// transcriptRowIDUsable probes whether transcript_events exposes an
// implicit rowid. A WITHOUT ROWID table errors on `SELECT rowid`; an
// empty ordinary table returns sql.ErrNoRows, which is still usable.
func transcriptRowIDUsable(ctx context.Context, db *sql.DB) bool {
	var n sql.NullInt64
	err := db.QueryRowContext(ctx, `SELECT rowid FROM transcript_events LIMIT 1`).Scan(&n)
	return err == nil || errors.Is(err, sql.ErrNoRows)
}

// latestTranscriptWatermark returns the highest watermark value in the
// store — MAX(rowid), or MAX(created_at) when rowid is unavailable.
//
// The two live in different offset spaces. Switching rowid → created_at
// (the only direction a schema change can take us, since rowid is the
// default) makes a stored rowid watermark tiny next to epoch values, so
// the next parse re-reads the whole transcript and every row collides on
// UNIQUE(source_file, source_event_id) — a re-read, never a loss. The
// reverse switch would strand the offset, and is documented rather than
// guarded because SQLite cannot add an implicit rowid to an existing
// WITHOUT ROWID table.
func latestTranscriptWatermark(ctx context.Context, db *sql.DB, byRowID bool) (int64, error) {
	q := `SELECT COALESCE(MAX(rowid), 0) FROM transcript_events`
	if !byRowID {
		q = `SELECT COALESCE(MAX(created_at), 0) FROM transcript_events`
	}
	var latest int64
	if err := db.QueryRowContext(ctx, q).Scan(&latest); err != nil {
		return 0, err
	}
	return latest, nil
}

// queryTranscriptDelta returns every transcript row past the watermark,
// in insertion order. Both variants project the same five columns so
// the caller's scan is uniform.
//
// The two comparisons are deliberately DIFFERENT, because the two
// watermarks have different uniqueness guarantees:
//
//   - rowid is unique per row, so `>` is exact: the row AT the watermark
//     is the last row we already read, and nothing else can share its
//     value.
//   - created_at is an epoch MILLISECOND, and OpenClaw writes several
//     transcript rows per model turn — a burst routinely shares one
//     millisecond. With `>`, every row that shared the previous
//     MAX(created_at) but landed AFTER the watermark was taken would be
//     skipped forever: a silent, permanent loss of real events. So this
//     variant uses `>=` and re-reads the boundary millisecond, which is
//     safe because the store's UNIQUE(source_file, source_event_id)
//     index collapses the rows we already have. Over-reading one
//     millisecond is cheap; losing a turn is not.
//
// The caller's `latest <= fromOffset` early return is what stops `>=`
// from re-reading the boundary on every idle tick: with no new rows the
// watermark has not moved and the query never runs.
func queryTranscriptDelta(ctx context.Context, db *sql.DB, byRowID bool, fromOffset int64) (*sql.Rows, error) {
	if byRowID {
		return db.QueryContext(ctx, `
			SELECT rowid, session_id, seq, event_json, created_at
			  FROM transcript_events
			 WHERE rowid > ?
			 ORDER BY rowid ASC`, fromOffset)
	}
	return db.QueryContext(ctx, `
		SELECT 0 AS rowid, session_id, seq, event_json, created_at
		  FROM transcript_events
		 WHERE COALESCE(created_at, 0) >= ?
		 ORDER BY COALESCE(created_at, 0) ASC, session_id ASC, seq ASC`, fromOffset)
}

// agentTableExists reports whether a table is present. The 2.0 schema is
// grounded on its column LISTS, not on which tables a given build ships,
// so every optional read is gated through here (the opencode/kilocode
// pattern).
func agentTableExists(ctx context.Context, db *sql.DB, name string) bool {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

// stageMirrorIfForeign returns srcDB unchanged when it's native. For a
// foreign-mount source (e.g. /mnt/c/Users/<u>/.openclaw/agents/main/
// agent/openclaw-agent.sqlite read by a WSL2 observer) it stages a local
// mirror — copying the SQLite trio (main + -wal + -shm) into a
// per-source cache dir and returning the mirrored path.
// modernc.org/sqlite hits SQLITE_IOERR against /mnt/c paths while the
// OpenClaw gateway holds the WAL open; the mirror avoids the DrvFs
// bridge by reading bytes once via os.ReadFile (which DOES work) then
// opening the in-tmp copy. Same pattern kirocli / clinecli / opencode
// adopt. Native paths pass through with no overhead.
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "openclaw-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("openclaw.stageMirror: mkdir %s: %w", mirrorDir, err)
	}
	dstDB := filepath.Join(mirrorDir, agentDBBase)
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
			return "", fmt.Errorf("openclaw.stageMirror: read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("openclaw.stageMirror: write %s: %w", dst, err)
		}
	}
	return dstDB, nil
}

// mirrorUpToDate reports whether the mirror trio is at least as fresh as
// the source. Uses (size, mtime) per sibling; the size guard catches an
// in-flight truncate/realloc that mtime alone misses. Returns false on
// any stat error so a fresh copy gets attempted.
func mirrorUpToDate(srcDB, dstDB string) bool {
	if !filesMatch(srcDB, dstDB) {
		return false
	}
	if sw, err := os.Stat(srcDB + "-wal"); err == nil {
		if !filesMatchInfo(sw, dstDB+"-wal") {
			return false
		}
	}
	return true
}

func filesMatch(src, dst string) bool {
	s, err := os.Stat(src)
	if err != nil {
		return false
	}
	return filesMatchInfo(s, dst)
}

func filesMatchInfo(srcInfo os.FileInfo, dst string) bool {
	d, err := os.Stat(dst)
	if err != nil {
		return false
	}
	if srcInfo.Size() != d.Size() {
		return false
	}
	return !srcInfo.ModTime().After(d.ModTime())
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

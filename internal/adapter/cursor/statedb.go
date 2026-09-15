package cursor

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// This file adds a third Cursor session-file shape alongside the
// per-conversation agent-transcript JSONL (matchesSessionShape) and
// per-conversation store.db (matchesStoreDBShape): Cursor's GLOBAL
// state database, `<home>/.../Cursor/User/globalStorage/state.vscdb`.
//
// Every other Cursor artefact this adapter reads is scoped to one
// conversation that is attached to a project folder — a transcript
// only exists under `.cursor/projects/<slug>/agent-transcripts/`, a
// store.db only under `.cursor/chats/<ws-hash>/`. An "empty window"
// chat (Cursor opened with no folder — or before a folder is ever
// opened for that window) has neither: Cursor persists it ONLY as
// key/value rows inside the single shared state.vscdb SQLite file
// every window and every project reads/writes. Without this reader
// those conversations are invisible to observer — no session row,
// no activity row, nothing.
//
// state.vscdb is a plain (undocumented, no vendor spec) SQLite file
// with two tables this reader touches:
//
//   - ItemTable(key TEXT UNIQUE, value BLOB) — general VS-Code-family
//     key/value settings store. The one key read here is
//     `composer.composerHeaders`, an index Cursor's own UI uses to
//     group conversations under a project; it maps composerId ->
//     workspaceIdentifier.uri.fsPath (absent for an ephemeral / no-
//     folder chat — exactly the gap case).
//   - cursorDiskKV(key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB) —
//     the conversation data itself: `composerData:<composerId>` (one
//     row per conversation: name, model, mode, createdAt, ...) and
//     `bubbleId:<composerId>:<bubbleId>` (one row per message: type
//     1=user / 2=assistant, text, createdAt). This table also holds
//     thousands of unrelated keys (checkpoints, MRU, other
//     extensions' state) which is why every query below filters by
//     key prefix rather than scanning the whole table.
//
// `agentKv:*` keys exist in some Cursor builds but their shape is not
// documented anywhere and was not confirmed against a live capture —
// this reader deliberately does not touch them. Likewise bubble
// `codeBlocks` / `toolResults` / `richText` fields are read by
// nothing here: only `type` + `text` (the two fields with a stable,
// confirmed meaning) are parsed. A wrong guess at an unconfirmed shape
// risks writing a garbage row into the actions table forever; missing
// a row is recoverable (a future release can add the field), a bad
// row is not.
//
// Cursor NEVER writes token/cost data anywhere in state.vscdb — the
// composerData/bubbleId rows carry no usage fields. Cost/model
// accuracy for these conversations still depends entirely on the live
// hook (BuildStopTokenEvent); this reader only closes the "the
// conversation happened at all" gap.

// matchesStateDBShape returns true when path is Cursor's global state
// database: `<...>/Cursor/User/globalStorage/state.vscdb`. Excludes
// the `-wal` / `-shm` fsnotify sidecars and any `.backup*` copies
// Cursor itself writes alongside it — the suffix check is exact.
// The `/cursor/user/globalstorage/` segment excludes the same
// filename under a sibling VS-Code-family app (Code, Antigravity, ...)
// that happens to live under a watched cross-mount home.
func matchesStateDBShape(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	return strings.HasSuffix(norm, "/state.vscdb") &&
		strings.Contains(norm, "/cursor/user/globalstorage/")
}

// cursorGlobalStorageDir resolves the per-home Cursor globalStorage
// directory that holds state.vscdb. Mirrors
// internal/adapter/cline/adapter.go::vsCodeGlobalStorage with the app
// name swapped from "Code" to "Cursor" — Cursor is itself a VS Code
// fork and keeps the same per-OS globalStorage layout. Returns "" for
// an unrecognized h.OS so callers can skip it without special-casing.
func cursorGlobalStorageDir(h crossmount.HomeRoot) string {
	switch h.OS {
	case crossmount.OSWindows:
		if h.Origin == "native" && runtime.GOOS == "windows" {
			if appData := os.Getenv("APPDATA"); appData != "" {
				return filepath.Join(appData, "Cursor", "User", "globalStorage")
			}
		}
		return filepath.Join(h.Path, "AppData", "Roaming", "Cursor", "User", "globalStorage")
	case crossmount.OSDarwin:
		return filepath.Join(h.Path, "Library", "Application Support", "Cursor", "User", "globalStorage")
	case crossmount.OSLinux:
		return filepath.Join(h.Path, ".config", "Cursor", "User", "globalStorage")
	}
	return ""
}

// stateDBWatermarkSQL selects the current watermark: MAX(rowid) among
// the two key families this reader tracks. `ON CONFLICT REPLACE` on
// cursorDiskKV.key is a delete+insert in SQLite, so updating an
// existing composerData/bubbleId row still advances its rowid — the
// table only ever holds one row per key, but rowid keeps climbing.
// That makes MAX(rowid) a cheap, natively-indexed, monotonic proxy for
// "anything conversation-shaped changed", without parsing every row's
// JSON body just to compute a MAX(createdAt). Filtering by key prefix
// means unrelated ItemTable-style churn elsewhere in the same shared
// file (settings, MRU lists, other extensions' state) never advances
// the watermark and never triggers a scan.
const stateDBWatermarkSQL = `
	SELECT COALESCE(MAX(rowid), 0) FROM cursorDiskKV
	WHERE key LIKE 'composerData:%' OR key LIKE 'bubbleId:%'`

// stateDBDeltaSQL selects every composerData/bubbleId row whose rowid
// advanced past the last-seen watermark, oldest first.
const stateDBDeltaSQL = `
	SELECT rowid, key, value FROM cursorDiskKV
	WHERE rowid > ? AND (key LIKE 'composerData:%' OR key LIKE 'bubbleId:%')
	ORDER BY rowid ASC`

// parseStateDBFile handles Cursor's global state.vscdb. Unlike
// parseStoreDBFile (byte-offset-via-file-size), the cursor here is a
// MAX(rowid) watermark — see stateDBWatermarkSQL's doc and
// CursorSemanticsFor (cursorsemantics.go), which declares this shape
// CursorWatermark so the watcher's byte-offset heuristics don't
// misfire against it.
//
// The DB is opened strictly read-only + immutable: this file is
// Cursor's live, shared, frequently-written state store and observer
// must never hold a write lock against it or risk corrupting it.
//
// Dedup: a composerId whose conversation is already captured through
// the live hook or a sibling on-disk transcript/store.db is skipped
// entirely (stateDBAlreadyCaptured) — those paths already cover it in
// more detail (full tool_use activity, token usage) than this reader
// ever can. What's left after that filter is, by construction, almost
// entirely the case this reader exists for: conversations with no
// project folder attached, which have no transcript/store.db to be
// covered by in the first place.
func (a *Adapter) parseStateDBFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseStateDBFile: stat: %w", err)
	}
	if fi.Size() == 0 {
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}

	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1&_pragma=busy_timeout(2000)", sqlitedsn.Escape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseStateDBFile: open: %w", err)
	}
	defer db.Close()

	var latest int64
	if err := db.QueryRowContext(ctx, stateDBWatermarkSQL).Scan(&latest); err != nil {
		// Most likely cause: cursorDiskKV doesn't exist yet (fresh
		// Cursor install with no chats at all) or an unexpected schema.
		// Fail open — no progress, no hard error — the file stays on
		// the watch list and the next fsnotify/poll tick retries.
		return adapter.ParseResult{
			NewOffset: fromOffset,
			Warnings:  []string{fmt.Sprintf("cursor: state.vscdb watermark query failed for %s: %v", path, err)},
		}, nil
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	rows, err := db.QueryContext(ctx, stateDBDeltaSQL, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseStateDBFile: query: %w", err)
	}
	type kv struct {
		key   string
		value []byte
	}
	var delta []kv
	for rows.Next() {
		if ctx.Err() != nil {
			rows.Close()
			return adapter.ParseResult{}, ctx.Err()
		}
		var rowid int64
		var key string
		var value []byte
		if scanErr := rows.Scan(&rowid, &key, &value); scanErr != nil {
			continue
		}
		delta = append(delta, kv{key: key, value: value})
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("cursor: state.vscdb row scan error for %s: %v", path, rowsErr))
	}
	if len(delta) == 0 {
		return res, nil
	}

	roots := cursorWorkspaceRoots(db)
	ts := fi.ModTime().UTC()

	sessions := map[string][]byte{}
	type bubbleKey struct {
		composerID, bubbleID string
		value                []byte
	}
	var bubbles []bubbleKey
	for _, e := range delta {
		switch {
		case strings.HasPrefix(e.key, "composerData:"):
			if cid := strings.TrimPrefix(e.key, "composerData:"); cid != "" {
				sessions[cid] = e.value
			}
		case strings.HasPrefix(e.key, "bubbleId:"):
			rest := strings.TrimPrefix(e.key, "bubbleId:")
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
				bubbles = append(bubbles, bubbleKey{composerID: parts[0], bubbleID: parts[1], value: e.value})
			}
		}
	}

	covered := map[string]bool{}
	coveredElsewhere := func(cid string) bool {
		if v, ok := covered[cid]; ok {
			return v
		}
		c := a.stateDBAlreadyCaptured(ctx, cid)
		covered[cid] = c
		return c
	}

	for cid, val := range sessions {
		if coveredElsewhere(cid) {
			continue
		}
		if ev, ok := a.composerSessionEvent(val, cid, path, roots[cid], ts); ok {
			res.ToolEvents = append(res.ToolEvents, ev)
		}
	}
	for _, b := range bubbles {
		if coveredElsewhere(b.composerID) {
			continue
		}
		if ev, ok := a.bubbleEvent(b.value, b.composerID, b.bubbleID, path, roots[b.composerID], ts); ok {
			res.ToolEvents = append(res.ToolEvents, ev)
		}
	}

	return res, nil
}

// stateDBAlreadyCaptured reports whether composerID's conversation is
// already tracked through the live hook or a sibling on-disk
// transcript/store.db, making state.vscdb-derived rows pure
// duplication. This is the gate that keeps this reader's actual
// contribution scoped to the gap it was built for: a project-attached
// conversation always has both a transcript AND (once the user sends
// a message) a live hook stream; an empty-window / no-folder
// conversation has neither, so it always passes this check and its
// rows are the only record it exists at all.
func (a *Adapter) stateDBAlreadyCaptured(ctx context.Context, composerID string) bool {
	if composerID == "" {
		return true
	}
	if a.hookCheck != nil {
		if hooked, err := a.hookCheck(ctx, composerID); err == nil && hooked {
			return true
		}
	}
	return cursorSiblingExists(composerID)
}

// cursorSiblingExists globs every cross-mount home for an existing
// agent-transcript or store.db belonging to composerID — the marker
// that this conversation is (or was) attached to a real project
// folder and is already captured by the richer transcript/store.db
// paths.
func cursorSiblingExists(composerID string) bool {
	return cursorTranscriptSiblingExists(composerID) || cursorAgentStoreExists(composerID)
}

// cursorTranscriptSiblingExists reports whether an IDE agent-transcript
// exists for composerID under any cross-mount home.
func cursorTranscriptSiblingExists(composerID string) bool {
	return cursorSiblingGlob(composerID, func(home string) string {
		return filepath.Join(home, ".cursor", "projects", "*", "agent-transcripts", composerID, composerID+".jsonl")
	})
}

// cursorAgentStoreExists reports whether a `cursor-agent` CLI store
// (`.cursor/chats/<ws-hash>/<conv>/store.db`) exists for composerID
// under any cross-mount home.
//
// Split out of cursorSiblingExists so the surface layer can ask this
// HALF of the question on its own: a store.db is written by exactly one
// client, the CLI, so its presence is positive evidence about WHICH
// client ran the conversation — evidence the transcript / state.vscdb
// stamps do not have and must defer to (see surface.go, "CLI store
// wins").
func cursorAgentStoreExists(composerID string) bool {
	return cursorSiblingGlob(composerID, func(home string) string {
		return filepath.Join(home, ".cursor", "chats", "*", composerID, "store.db")
	})
}

// cursorSiblingGlob walks every cross-mount home, building one glob per
// home through pattern, and reports whether any matched. An empty
// composerID never matches — an unresolved conversation id must not be
// allowed to glob a whole directory.
func cursorSiblingGlob(composerID string, pattern func(home string) string) bool {
	if strings.TrimSpace(composerID) == "" {
		return false
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		if matches, err := filepath.Glob(pattern(h.Path)); err == nil && len(matches) > 0 {
			return true
		}
	}
	return false
}

// cursorWorkspaceRoots best-effort resolves composerId -> workspace
// root from ItemTable's `composer.composerHeaders` index — the same
// index Cursor's own UI uses to group conversations under a project.
// The exact JSON shape of this value is undocumented and has drifted
// across Cursor releases, so two candidate shapes are tried (a
// `{"allComposers":[...]}` wrapper, then a bare array) and the first
// that decodes at least one entry wins. Any failure returns an empty
// map: callers already treat "" project root as the expected outcome
// for a true empty-window session, so a decode miss here just means
// those sessions surface with no project instead of a wrong one.
//
// Entries are stat-gated: an fsPath that doesn't translate to an
// existing directory on this host is dropped rather than attributed,
// matching the "stat-gate before trusting a foreign path" convention
// resolveProjectRoot uses for the transcript-slug path.
func cursorWorkspaceRoots(db *sql.DB) map[string]string {
	out := map[string]string{}
	var raw []byte
	if err := db.QueryRow(`SELECT value FROM ItemTable WHERE key = 'composer.composerHeaders'`).Scan(&raw); err != nil || len(raw) == 0 {
		return out
	}

	type header struct {
		ComposerID          string `json:"composerId"`
		WorkspaceIdentifier *struct {
			URI *struct {
				FsPath string `json:"fsPath"`
			} `json:"uri"`
		} `json:"workspaceIdentifier"`
	}
	var wrapper struct {
		AllComposers []header `json:"allComposers"`
	}
	var headers []header
	if err := json.Unmarshal(raw, &wrapper); err == nil && len(wrapper.AllComposers) > 0 {
		headers = wrapper.AllComposers
	} else if err := json.Unmarshal(raw, &headers); err != nil {
		return out
	}

	for _, h := range headers {
		if h.ComposerID == "" || h.WorkspaceIdentifier == nil || h.WorkspaceIdentifier.URI == nil {
			continue
		}
		fsPath := strings.TrimSpace(h.WorkspaceIdentifier.URI.FsPath)
		if fsPath == "" {
			continue
		}
		translated := crossmount.TranslateForeignPath(fsPath)
		if translated == "" {
			translated = fsPath
		}
		if fi, statErr := os.Stat(translated); statErr == nil && fi.IsDir() {
			out[h.ComposerID] = translated
		}
	}
	return out
}

// composerDataDoc is the well-documented subset of a
// `composerData:<composerId>` blob this reader relies on
// (reverse-engineered from public documentation as of 2026-08 — no
// vendor spec exists). Every field is read defensively; a missing or
// mistyped field degrades the row rather than dropping it.
//
// `name` is JSON `null` on some rows (a conversation the user never
// titled): Go decodes a null into the zero string, so no tolerant type
// is needed there.
type composerDataDoc struct {
	Name        string         `json:"name"`
	CreatedAt   flexTime       `json:"createdAt"`
	UnifiedMode string         `json:"unifiedMode"`
	IsAgentic   bool           `json:"isAgentic"`
	ModelConfig modelConfigDoc `json:"modelConfig"`
}

// modelConfigDoc is the tolerant decode of `composerData.modelConfig`,
// whose SHAPE differs across Cursor store versions:
//
//	_v 14/15 (live capture 2026-09-02, all 23 rows):
//	  "modelConfig":{"modelName":"default","maxMode":false}
//	  "modelConfig":{"modelName":"default","maxMode":false,
//	                 "selectedModels":[{"modelId":"default","parameters":[]}]}
//	older builds (the shape this reader was originally written against):
//	  "modelConfig":[{"modelName":"claude-4-sonnet"}]
//
// Declaring the field as a fixed `[]struct{...}` made EVERY v14/v15
// composerData row fail json.Unmarshal, which dropped the whole
// document (name, createdAt, mode) — the reader emitted zero rows on a
// store holding hundreds. So this type accepts object OR array OR null,
// and — critically — NEVER returns an error: an unrecognized fourth
// shape degrades to an empty model instead of dropping the session row
// again.
type modelConfigDoc struct {
	// ModelName is the resolved model string, "" when none was found.
	ModelName string
}

// modelConfigEntry is one modelConfig element (the object itself in the
// v14/v15 shape, one array element in the legacy shape). `modelName`
// stays the primary source — it is what the pre-v14 reader used and
// what Cursor still writes today; `selectedModels[0].modelId` is only
// consulted when `modelName` is absent/empty.
type modelConfigEntry struct {
	ModelName      string `json:"modelName"`
	SelectedModels []struct {
		ModelID string `json:"modelId"`
	} `json:"selectedModels"`
}

// resolve returns the entry's model string under the modelName-first
// precedence documented on modelConfigEntry.
func (e modelConfigEntry) resolve() string {
	if name := strings.TrimSpace(e.ModelName); name != "" {
		return name
	}
	for _, sm := range e.SelectedModels {
		if id := strings.TrimSpace(sm.ModelID); id != "" {
			return id
		}
	}
	return ""
}

// UnmarshalJSON implements json.Unmarshaler for the object-or-array
// modelConfig shapes. It is deliberately total: every input, including
// a shape Cursor has not written yet, decodes to "no model" rather than
// an error.
func (m *modelConfigDoc) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	switch {
	case trimmed == "" || trimmed == "null":
		return nil
	case strings.HasPrefix(trimmed, "["):
		var entries []modelConfigEntry
		if err := json.Unmarshal(b, &entries); err != nil {
			return nil
		}
		for _, e := range entries {
			if name := e.resolve(); name != "" {
				m.ModelName = name
				return nil
			}
		}
	case strings.HasPrefix(trimmed, "{"):
		var entry modelConfigEntry
		if err := json.Unmarshal(b, &entry); err != nil {
			return nil
		}
		m.ModelName = entry.resolve()
	}
	return nil
}

// flexTime is the tolerant decode of the `createdAt` fields on both
// composerData and bubbleId documents. On the live v14/v15 store every
// bubble's `createdAt` is an ISO-8601 TEXT string
// ("2026-08-30T11:04:07.318Z") while older builds wrote Unix
// milliseconds as a NUMBER — the fixed `int64` declaration made all 293
// bubble rows fail json.Unmarshal, so the reader emitted no messages at
// all. Like modelConfigDoc this never errors: an unparsable value
// leaves Set false and the caller falls back to the file mtime, which
// is exactly the pre-existing "createdAt absent" behaviour.
type flexTime struct {
	// Time is the decoded timestamp (UTC); only meaningful when Set.
	Time time.Time
	// Set reports whether a usable timestamp was decoded.
	Set bool
}

// flexTimeLayouts are the string layouts tried, in order, for a TEXT
// createdAt. RFC3339Nano covers the millisecond-precision "…318Z" form
// Cursor writes; RFC3339 covers a whole-second variant.
var flexTimeLayouts = []string{time.RFC3339Nano, time.RFC3339}

// UnmarshalJSON implements json.Unmarshaler for the number-or-string
// createdAt shapes.
func (t *flexTime) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return nil
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		for _, layout := range flexTimeLayouts {
			if parsed, err := time.Parse(layout, s); err == nil {
				t.Time, t.Set = parsed.UTC(), true
				return nil
			}
		}
		// Some builds quote the epoch-ms number; accept that too rather
		// than losing the timestamp to a pair of quotes.
		if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 0 {
			t.Time, t.Set = time.UnixMilli(ms).UTC(), true
		}
		return nil
	}
	var ms int64
	if err := json.Unmarshal(b, &ms); err != nil {
		return nil
	}
	if ms > 0 {
		t.Time, t.Set = time.UnixMilli(ms).UTC(), true
	}
	return nil
}

// composerSessionEvent builds an ActionSessionStart row for a
// composerData row — the session-registration row that makes an
// otherwise-invisible empty-window conversation show up at all.
// Mirrors the JSONL-watcher convention other hook-only/inferred
// adapters use (Target = "startup"; see e.g.
// commandcode.parseState.emitSessionStart): the descriptive fields
// this format actually offers (name/model/mode) go in RawToolInput
// instead of overloading Target.
//
// SourceEventID is keyed on the composerId plus a hash of the fields
// that meaningfully identify a REVISION of the session metadata (name,
// model, mode) — not on the raw JSON body, which also carries fields
// like `context`/`status` that mutate far more often than the row's
// story changes. That keeps re-scans from minting a fresh row every
// time an unrelated field in the same blob ticks over.
func (a *Adapter) composerSessionEvent(raw []byte, composerID, sourceFile, projectRoot string, fallback time.Time) (models.ToolEvent, bool) {
	var doc composerDataDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return models.ToolEvent{}, false
	}
	ts := fallback
	if doc.CreatedAt.Set {
		ts = doc.CreatedAt.Time
	}
	model := doc.ModelConfig.ModelName
	name := strings.TrimSpace(doc.Name)
	detail := fmt.Sprintf("Cursor state.vscdb composerData: name=%q model=%q mode=%q agentic=%v",
		name, model, doc.UnifiedMode, doc.IsAgentic)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: "cursor-statedb-session:" + composerID + ":" + shortHash(name+"|"+model+"|"+doc.UnifiedMode),
		SessionID:     composerID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		Model:         model,
		Tool:          models.ToolCursor,
		ActionType:    models.ActionSessionStart,
		Target:        "startup",
		Success:       true,
		RawToolName:   "state.vscdb:composerData",
		RawToolInput:  detail,
		MessageID:     "session:" + composerID,
	}, true
}

// bubbleDoc is the well-documented subset of a
// `bubbleId:<composerId>:<bubbleId>` blob this reader relies on: Type
// 1 = user message, Type 2 = assistant message (Cursor's own
// numbering, reverse-engineered — no vendor spec exists). Every other
// field (codeBlocks, toolResults, richText, context, ...) is read by
// NEITHER this struct NOR this file: their shape is not confirmed
// against a live capture, and guessing wrong risks writing a garbage
// row rather than just missing one. See the package/adapter report
// for the follow-up.
type bubbleDoc struct {
	Type int    `json:"type"`
	Text string `json:"text"`
	// CreatedAt is an ISO-8601 string on current builds and Unix
	// milliseconds on older ones — see flexTime. Absent entirely on
	// some builds, in which case the caller falls back to file mtime.
	CreatedAt flexTime `json:"createdAt"`
}

// bubbleEvent builds an ActionUserPrompt or ActionAssistantMessage row
// for one bubble, mirroring the field placement
// buildTranscriptToolEvents / BuildTranscriptUserPromptEvent use for
// the transcript-JSONL path (200-char scrubbed preview in Target +
// PrecedingReasoning; user text in RawToolInput, assistant text in
// ToolOutput capped via contentcap).
//
// KNOWN LIMITATION: cursorDiskKV holds exactly one row per key at any
// instant (ON CONFLICT REPLACE), so this reader only ever sees
// whatever a bubble's row happens to contain at the moment of a poll.
// If Cursor's live client replaces a bubbleId row incrementally while
// an assistant response is still streaming (unconfirmed — no ground
// truth was available to verify either way), a poll that lands mid-
// stream can capture a partial-text snapshot; a later poll then sees
// the settled, complete text under a DIFFERENT content hash and emits
// a second row for the same logical message. SourceEventID is
// therefore content-hash-keyed (not stably keyed on composerId+
// bubbleId alone): the store's INSERT OR IGNORE dedup keeps a stable
// key from ever being updated with more-complete later content, so a
// stable key would risk permanently freezing a truncated snapshot
// instead of the at-worst-occasional streaming-duplicate this design
// accepts.
func (a *Adapter) bubbleEvent(raw []byte, composerID, bubbleID, sourceFile, projectRoot string, fallback time.Time) (models.ToolEvent, bool) {
	var doc bubbleDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return models.ToolEvent{}, false
	}
	text := strings.TrimSpace(doc.Text)
	if text == "" {
		return models.ToolEvent{}, false
	}
	var actionType string
	switch doc.Type {
	case 1:
		actionType = models.ActionUserPrompt
	case 2:
		actionType = models.ActionAssistantMessage
	default:
		return models.ToolEvent{}, false
	}
	ts := fallback
	if doc.CreatedAt.Set {
		ts = doc.CreatedAt.Time
	}
	body := text
	if a.scrubber != nil {
		body = a.scrubber.String(text)
	}
	preview := body
	if len(preview) > 200 {
		preview = preview[:200]
	}

	ev := models.ToolEvent{
		SourceFile:         sourceFile,
		SourceEventID:      "cursor-statedb-bubble:" + composerID + ":" + bubbleID + ":" + shortHash(text),
		SessionID:          composerID,
		MessageID:          "statedb:" + bubbleID,
		ProjectRoot:        projectRoot,
		Timestamp:          ts,
		Tool:               models.ToolCursor,
		ActionType:         actionType,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
	}
	switch doc.Type {
	case 1:
		ev.RawToolName = "state.vscdb:bubble.user"
		ev.RawToolInput = body
	case 2:
		ev.RawToolName = "state.vscdb:bubble.assistant"
		ev.ToolOutput = contentcap.Cap(body, contentcap.DefaultMaxBytes)
	}
	return ev, true
}

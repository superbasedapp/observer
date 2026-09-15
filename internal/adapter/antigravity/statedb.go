package antigravity

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// indexEntry is the per-conversation enrichment surfaced by the
// state.vscdb trajectorySummaries blob. Every field is best-effort;
// the index is rebuilt by Antigravity on crash and may lag the
// filesystem by hours.
type indexEntry struct {
	uuid         string
	title        string
	workspaceURI string
	modelHint    string
	created      time.Time
	modified     time.Time
}

// stateDBKey is the well-known ItemTable key under which the
// trajectorySummaries blob lives.
const stateDBKey = "antigravityUnifiedStateSync.trajectorySummaries"

// lookupIndexEntry returns the enrichment for conversationID, or nil
// if not found. Dispatches by layout: desktop reads state.vscdb (with
// state.vscdb.backup as a freshness comparison); CLI parses
// ~/.gemini/antigravity-cli/log/cli-*.log + ~/.gemini/config/projects/
// (CLI has no equivalent of state.vscdb). Both paths memoise into
// a.indexCache under different key prefixes so they coexist without
// collision.
func (a *Adapter) lookupIndexEntry(sessionPath, conversationID string) *indexEntry {
	switch classifyLayout(sessionPath) {
	case LayoutCLI, LayoutCLIDB:
		return a.lookupCLIIndexEntry(sessionPath, conversationID)
	case LayoutDesktop, LayoutDesktopTranscript, LayoutDesktopDB:
		// Every desktop shape sits under the same ~/.gemini parent, so
		// stateDBPathFor's walk-up resolves the same state.vscdb.
		return a.lookupDesktopIndexEntry(sessionPath, conversationID)
	}
	return nil
}

// lookupDesktopIndexEntry resolves metadata via the desktop
// Antigravity state.vscdb (and its .backup sibling).
func (a *Adapter) lookupDesktopIndexEntry(sessionPath, conversationID string) *indexEntry {
	dbPath := stateDBPathFor(sessionPath)
	if dbPath == "" {
		return nil
	}
	a.indexMu.Lock()
	defer a.indexMu.Unlock()

	freshDB, freshMtime := pickFreshIndexDB(dbPath)
	if freshDB == "" {
		return nil
	}
	cached, ok := a.indexCache[freshDB]
	if ok && cached.mtime == freshMtime {
		if e, hit := cached.entries[conversationID]; hit {
			return &e
		}
		return nil
	}
	entries, err := readTrajectorySummaries(freshDB)
	if err != nil {
		return nil
	}
	a.indexCache[freshDB] = &indexCacheEntry{mtime: freshMtime, entries: entries}
	if e, hit := entries[conversationID]; hit {
		return &e
	}
	return nil
}

// stateDBPathFor maps a session file path to its expected state.vscdb
// location. Antigravity's globalStorage path is fixed under the app's
// user-data dir per OS; we walk up from the session path to find the
// .gemini parent and try every plausible state.vscdb location.
//
// Two layers of candidates:
//
//  1. Same-home candidates (Antigravity native install): we walk up
//     from the session path to find the `.gemini` parent dir, then try
//     the OS-specific user-data subpath under its parent (.config on
//     Linux, AppData/Roaming on Windows, Library/Application Support
//     on macOS).
//
//  2. Cross-mount candidates: when the IDE runs on a different OS
//     than the conversation file (e.g. Antigravity-server on WSL with
//     the IDE running on Windows — conversations Linux-side under
//     /home/<u>/.gemini/, but state.vscdb Windows-side at
//     /mnt/c/Users/<u>/AppData/Roaming/Antigravity/...), the .gemini-
//     relative homeDir doesn't surface the IDE state at all.
//     crossmount.AllHomes() gives us the cross-mounted home roots; for
//     each, we try the OS-appropriate subpath.
//
// First existing file wins. Best-effort: when no candidate matches
// (e.g. custom install location), index lookup silently returns no
// entry.
func stateDBPathFor(sessionPath string) string {
	cur := filepath.Dir(sessionPath)
	for cur != "" && cur != filepath.Dir(cur) {
		base := filepath.Base(cur)
		if base == ".gemini" {
			break
		}
		cur = filepath.Dir(cur)
	}
	if filepath.Base(cur) != ".gemini" {
		return ""
	}
	homeDir := filepath.Dir(cur)
	candidates := []string{
		// Layer 1: same-home (Antigravity-native install).
		filepath.Join(homeDir, ".config", "Antigravity", "User", "globalStorage", "state.vscdb"),
		filepath.Join(homeDir, "Library", "Application Support", "Antigravity", "User", "globalStorage", "state.vscdb"),
		filepath.Join(homeDir, "AppData", "Roaming", "Antigravity", "User", "globalStorage", "state.vscdb"),
	}
	// Layer 2: cross-mount candidates. When the IDE lives on a
	// different OS than the conversation file (Antigravity-server on
	// WSL with IDE on Windows is the common case), the same-home
	// candidates don't exist; the IDE's globalStorage is reachable
	// via the cross-mounted home root. crossmount.AllHomes() returns
	// the native home plus every detected mount; we extend per OS.
	for _, h := range crossmount.AllHomes() {
		if h.Path == homeDir {
			continue // already covered by layer 1
		}
		switch h.OS {
		case crossmount.OSLinux:
			candidates = append(candidates,
				filepath.Join(h.Path, ".config", "Antigravity", "User", "globalStorage", "state.vscdb"))
		case crossmount.OSDarwin:
			candidates = append(candidates,
				filepath.Join(h.Path, "Library", "Application Support", "Antigravity", "User", "globalStorage", "state.vscdb"))
		case crossmount.OSWindows:
			candidates = append(candidates,
				filepath.Join(h.Path, "AppData", "Roaming", "Antigravity", "User", "globalStorage", "state.vscdb"))
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// pickFreshIndexDB returns the path of the most recently modified
// candidate (state.vscdb vs state.vscdb.backup) plus its unix mtime.
// VS Code writes both periodically; the doc-quoted recovery-tools
// community has documented cases where one is fresher than the other
// after a crash.
func pickFreshIndexDB(primary string) (string, int64) {
	candidates := []string{primary, primary + ".backup"}
	var bestPath string
	var bestMtime int64
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.ModTime().Unix() > bestMtime {
			bestPath = p
			bestMtime = fi.ModTime().Unix()
		}
	}
	return bestPath, bestMtime
}

// readTrajectorySummaries opens dbPath read-only, fetches the
// trajectorySummaries value, and parses the nested protobuf to
// extract the per-conversation enrichment.
//
// The protobuf shape (per the doc + JonDickson20/antigrav-recovery
// reverse-engineering):
//
//	Outer: repeated field 1 of:
//	  message {
//	    field 1 (string) : conversation_uuid
//	    field 2 (bytes)  : inner protobuf wrapper containing:
//	      field 1 (string) : base64-encoded payload protobuf with:
//	        field 1  (string)        : title
//	        field 9  (message)       : workspace_info { uri, scheme, "" }
//	        field 7  (message)       : created_timestamp { seconds, nanos }
//	        field 3  (message)       : modified_timestamp { seconds, nanos }
//	  }
//
// We extract title, workspace URI, created, modified per UUID. Model
// hint isn't in this blob — but other antigravityUnifiedStateSync.*
// keys may carry it; left for follow-up.
func readTrajectorySummaries(dbPath string) (map[string]indexEntry, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1&_pragma=busy_timeout(2000)", sqlitedsn.Escape(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var raw string
	row := db.QueryRowContext(ctx, "SELECT value FROM ItemTable WHERE key = ?", stateDBKey)
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return map[string]indexEntry{}, nil
		}
		return nil, err
	}
	// The stored value is the base64-encoded proto blob, sometimes
	// wrapped in JSON quotes. Trim and try base64-decode; fall back
	// to raw bytes.
	body := []byte(strings.Trim(raw, `"`))
	if decoded, err := base64.StdEncoding.DecodeString(string(body)); err == nil {
		body = decoded
	}
	return parseTrajectorySummaries(body)
}

// parseTrajectorySummaries walks the outer protobuf and extracts
// (uuid, indexEntry) pairs. Resilient to schema drift — fields we
// don't recognize are skipped.
func parseTrajectorySummaries(body []byte) (map[string]indexEntry, error) {
	out := map[string]indexEntry{}
	// Outer is a series of length-delimited entries. Walk the top
	// level; each WireBytes whose payload contains a UUID-shaped
	// string in its first text field is a candidate.
	err := protowire.Walk(body, func(f protowire.Field) error {
		if f.Depth != 0 || f.WireType != protowire.WireBytes {
			return nil
		}
		entry := parseSummaryEntry(f.Bytes)
		if entry.uuid != "" {
			out[entry.uuid] = entry
		}
		return nil
	})
	return out, err
}

// parseSummaryEntry extracts an indexEntry from one outer entry's
// payload. Heuristic — picks the first UUID-shaped string as the
// conversation ID, the first non-UUID string as the title, the
// first file:// URI as workspace, and the first plausible
// timestamp as created.
//
// The trajectorySummaries blob nests a payload protobuf as a
// base64-encoded string field. The outer Walk doesn't descend
// into text-shaped bytes, so we manually decode and re-walk on
// any string field that looks like base64-encoded protobuf.
// This is what surfaces title / workspace_uri / created /
// modified timestamps — they all live one nest deeper.
func parseSummaryEntry(body []byte) indexEntry {
	var entry indexEntry
	var workspaceCandidates []string
	var classify func(f protowire.Field) error
	classify = func(f protowire.Field) error {
		if f.WireType == protowire.WireBytes {
			s := strings.TrimSpace(string(f.Bytes))
			switch {
			case entry.uuid == "" && looksLikeUUID(s):
				entry.uuid = s
			case strings.HasPrefix(s, "file://") || strings.HasPrefix(s, "vscode-remote://"):
				workspaceCandidates = append(workspaceCandidates, s)
			case entry.title == "" && isLikelyTitle(s):
				entry.title = s
			case entry.modelHint == "" && isModelIdentifier(s):
				entry.modelHint = s
			}
			if decoded, ok := tryDecodeBase64Proto(s); ok {
				_ = protowire.Walk(decoded, classify)
			}
		} else if f.WireType == protowire.WireVarint && protowire.IsLikelyUnixTimestamp(f.Varint) {
			ts := parseUnixTimestamp(f.Varint)
			if entry.created.IsZero() {
				entry.created = ts
			} else if ts.After(entry.modified) {
				entry.modified = ts
			}
		}
		return nil
	}
	_ = protowire.Walk(body, classify)
	entry.workspaceURI = pickWorkspaceURI(workspaceCandidates)
	return entry
}

// isLikelyTitle reports whether s looks like a human-readable
// conversation title — short, ASCII-printable (no embedded wire-tag
// bytes from sibling protobuf fields leaking in), no URL markers.
// Conservative because the protobuf walker yields any text-shaped
// length-delimited field including sub-message bodies, so the title
// detector needs to reject those even when IsLikelyText accepts them.
func isLikelyTitle(s string) bool {
	if s == "" || len(s) > 200 || looksLikeUUID(s) {
		return false
	}
	if strings.Contains(s, "://") {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// pickWorkspaceURI selects the most workspace-folder-shaped URI from
// the candidates: skip the empty `file:///`, deprioritize Antigravity's
// per-conversation `brain/<uuid>/walkthrough.md` artifact path, prefer
// folder-shaped (no file extension) URIs, then prefer the shortest
// remaining (workspace folders are shorter than per-file paths).
func pickWorkspaceURI(candidates []string) string {
	type ranked struct {
		uri   string
		score int
	}
	var ranks []ranked
	for _, c := range candidates {
		stripped := strings.TrimPrefix(strings.TrimPrefix(c, "file://"), "vscode-remote://")
		stripped = strings.TrimPrefix(stripped, "/")
		if stripped == "" {
			continue
		}
		score := 0
		if strings.Contains(c, "/.gemini/antigravity/brain/") {
			score -= 10
		}
		ext := pathExt(c)
		if ext == "" {
			score += 5
		}
		ranks = append(ranks, ranked{uri: c, score: score})
	}
	if len(ranks) == 0 {
		return ""
	}
	best := ranks[0]
	for _, r := range ranks[1:] {
		if r.score > best.score || (r.score == best.score && len(r.uri) < len(best.uri)) {
			best = r
		}
	}
	return best.uri
}

// pathExt returns the file extension of the URI's last path segment,
// or "" when the segment has no extension. Lightweight inline impl —
// avoids importing path/filepath here just for this.
func pathExt(uri string) string {
	if i := strings.LastIndex(uri, "/"); i >= 0 {
		uri = uri[i+1:]
	}
	if i := strings.LastIndex(uri, "."); i > 0 && i < len(uri)-1 {
		return uri[i:]
	}
	return ""
}

// tryDecodeBase64Proto reports whether s is a base64-encoded byte
// stream that decodes to valid protobuf wire format. Used by the
// trajectorySummaries parser to descend into payload fields that
// Antigravity stores as base64 inside a string field — the outer
// recursive walker doesn't enter text-shaped bytes.
//
// Conservative: requires standard base64 alphabet, 4-byte alignment,
// at least 16 characters, and the decoded bytes must validate as
// protobuf for at least 3 records before we trust it.
func tryDecodeBase64Proto(s string) ([]byte, bool) {
	if len(s) < 16 || len(s)%4 != 0 {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '+', c == '/', c == '=':
		default:
			return nil, false
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if protowire.ValidatesAsProto(decoded, 3) < 3 {
		return nil, false
	}
	return decoded, true
}

// looksLikeUUID is a cheap structural check — 36 chars, hyphens at
// 8/13/18/23. Doesn't validate the version nibble.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

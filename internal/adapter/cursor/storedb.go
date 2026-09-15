package cursor

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// promptSection is one entry in cursor's per-conversation prompt-token
// budget: a named slice of the prompt (system_prompt, tools, rules,
// skills, mcp, subagents, summarized_conversation, conversation) with
// the token + char count cursor attributed to it. Cursor records only
// these COUNTS — the tool/rule/skill CONTENT itself is not persisted
// anywhere on disk (verified 2026-05-25). The counts still reconcile a
// turn's input: their sum ≈ the gross prompt the model received, so
// surfacing them explains where a large input went (tools + rules
// typically dominate, not the user's message).
type promptSection struct {
	Name        string // machine name, e.g. "tools"
	DisplayName string // human label, e.g. "Tool definitions"
	Tokens      int64
	Chars       int64
}

// cursorStoreData is everything observer extracts from a cursor-agent
// per-session blob store: the full system-prompt text (a real content
// blob) and the prompt-token budget breakdown (metadata only). The
// project root is NOT taken from here — the store.db sits under
// chats/<ws-hash>/ which doesn't encode the path, and the root blob's
// embedded workspace field proved unreliable across surfaces; the
// caller derives it from the sibling transcript's slug instead (see
// scan.go::projectRootForStoreDB) so these rows share the exact project
// attribution of their session's activity rows.
type cursorStoreData struct {
	Todos        []cursorTodoCall
	SystemPrompt string
	Sections     []promptSection
	// Model is the resolved model id from the turn blobs
	// (providerOptions.cursor.modelName, e.g. "composer-2.5"). Every
	// metadata surface (cli-config, meta.lastUsedModel, ai-tracking) reports
	// the placeholder "default" for auto-mode sessions, so the per-turn blob
	// is the only place the real model lives. "" when none found.
	Model string
}

// ResolveModelFromStore looks up the real model id for a conversation by
// scanning its store.db turn blobs, given the user's home dir and the
// conversation (= session) id. It globs the workspace-hash layer
// (~/.cursor/chats/<ws-hash>/<conversationID>/store.db) since the hook does
// not carry the hash. Returns "" when no store.db or concrete model is
// found — callers keep their existing value (e.g. the "default" sentinel)
// in that case. This is the resolver the cursor stop-hook uses to replace
// the auto-mode "default" model the hook body reports.
func ResolveModelFromStore(home, conversationID string) string {
	if home == "" || conversationID == "" {
		return ""
	}
	pattern := filepath.Join(home, ".cursor", "chats", "*", conversationID, "store.db")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return ""
	}
	for _, dbPath := range matches {
		if data, ok := scanStoreDB(dbPath); ok && data.Model != "" {
			return data.Model
		}
	}
	return ""
}

// scanStoreDB opens the blob store read-only (cursor-agent may hold the
// WAL) and pulls the system-prompt blob + the root blob's section
// index in a single pass over the blobs table.
//
//   - System prompt: the single `{"role":"system","content":"..."}`
//     JSON blob.
//   - Section budget: the root blob carries a protobuf section index
//     (it contains the ASCII markers "system_prompt" + "Tool
//     definitions"); parseSectionIndex extracts the per-section
//     token/char counts.
func scanStoreDB(dbPath string) (cursorStoreData, bool) {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return cursorStoreData{}, false
	}
	defer db.Close()
	rows, err := db.Query(`SELECT data FROM blobs`)
	if err != nil {
		return cursorStoreData{}, false
	}
	defer rows.Close()

	var out cursorStoreData
	// Section index: prefer the CURRENT root blob via
	// meta.latestRootBlobId — a session accumulates multiple root blobs
	// (one per state) as it grows, so picking by scan order would be
	// non-deterministic and could surface a stale budget. Marker-scan
	// is the fallback when meta can't be read.
	if rootID := latestRootBlobID(db); rootID != "" {
		var data []byte
		if db.QueryRow(`SELECT data FROM blobs WHERE id = ?`, rootID).Scan(&data) == nil {
			out.Sections = parseSectionIndex(data)
		}
	}
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			continue
		}
		if len(data) > 0 && data[0] == 0x12 {
			if call, ok := decodeCursorTodoCall(data); ok {
				out.Todos = append(out.Todos, call)
			}
		}
		switch {
		case bytes.HasPrefix(bytes.TrimSpace(data), []byte(`{"role"`)):
			if out.SystemPrompt == "" {
				if c := systemContentFromBlob(data); c != "" {
					out.SystemPrompt = c
				}
			}
		case bytes.Contains(data, []byte("Tool definitions")) &&
			bytes.Contains(data, []byte("system_prompt")):
			if len(out.Sections) == 0 { // fallback only (meta.latestRootBlobId missing)
				out.Sections = parseSectionIndex(data)
			}
		}
		if out.Model == "" {
			if m := modelFromBlob(data); m != "" {
				out.Model = m
			}
		}
	}
	return out, out.SystemPrompt != "" || len(out.Sections) > 0 || out.Model != "" || len(out.Todos) > 0
}

// modelFromBlob extracts a real model id from a turn blob's
// providerOptions.cursor.modelName field. The placeholder values
// ("default", "auto") that the metadata surfaces report are ignored, so
// only a concrete model id (e.g. "composer-2.5") is returned. "" when none.
func modelFromBlob(data []byte) string {
	const key = `"modelName":"`
	i := bytes.Index(data, []byte(key))
	for i >= 0 {
		rest := data[i+len(key):]
		end := bytes.IndexByte(rest, '"')
		if end <= 0 {
			return ""
		}
		v := string(rest[:end])
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "", "default", "auto":
			// placeholder — keep scanning for a concrete id
			next := bytes.Index(rest[end:], []byte(key))
			if next < 0 {
				return ""
			}
			i = i + len(key) + end + next
		default:
			return v
		}
	}
	return ""
}

// latestRootBlobID reads the current root blob hash from the meta table.
// cursor stores `{"agentId":...,"latestRootBlobId":"<hash>"}` as the meta
// value; it may be raw JSON bytes or hex-encoded text depending on how
// the column round-trips, so both are tried. Returns "" when absent.
func latestRootBlobID(db *sql.DB) string {
	rows, err := db.Query(`SELECT value FROM meta`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	parse := func(b []byte) string {
		var m struct {
			LatestRootBlobID string `json:"latestRootBlobId"`
		}
		if json.Unmarshal(b, &m) == nil {
			return m.LatestRootBlobID
		}
		return ""
	}
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			continue
		}
		if id := parse(raw); id != "" {
			return id
		}
		if decoded, err := hex.DecodeString(string(raw)); err == nil {
			if id := parse(decoded); id != "" {
				return id
			}
		}
	}
	return ""
}

// systemContentFromBlob returns the content of a role-message blob iff
// its role is "system". Turn blobs use an array-valued content which
// fails this string unmarshal and yields "" — fine, only the system
// blob has plain-string content.
func systemContentFromBlob(data []byte) string {
	var msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	if json.Unmarshal(data, &msg) != nil {
		return ""
	}
	if msg.Role == "system" {
		return strings.TrimSpace(msg.Content)
	}
	return ""
}

// parseSectionIndex extracts cursor's per-section prompt budget from the
// root blob. The protobuf layout (reverse-engineered 2026-05-25; the
// parser is defensive — any malformed/truncated field aborts cleanly
// and returns what it has, since this is an undocumented format that may
// drift across cursor-agent versions):
//
//	field 5  (sections container, bytes)
//	  field 3  (inner message, bytes)
//	    field 3  (repeated section descriptor, bytes)
//	      field 1  name         (string)
//	      field 2  display name (string)
//	      field 3  tokens       (varint)
//	      field 4  chars        (varint)
func parseSectionIndex(root []byte) []promptSection {
	container, ok := pbBytesField(root, 5)
	if !ok {
		return nil
	}
	inner, ok := pbBytesField(container, 3)
	if !ok {
		return nil
	}
	var sections []promptSection
	for _, f := range pbWalk(inner) {
		if f.num != 3 || f.wt != 2 {
			continue
		}
		var s promptSection
		for _, g := range pbWalk(f.b) {
			switch {
			case g.num == 1 && g.wt == 2:
				s.Name = string(g.b)
			case g.num == 2 && g.wt == 2:
				s.DisplayName = string(g.b)
			case g.num == 3 && g.wt == 0:
				s.Tokens = int64(g.v)
			case g.num == 4 && g.wt == 0:
				s.Chars = int64(g.v)
			}
		}
		if s.Name != "" {
			sections = append(sections, s)
		}
	}
	return sections
}

// pbField is one decoded protobuf field. v holds varint values
// (wireType 0); b holds length-delimited payloads (wireType 2).
type pbField struct {
	num int
	wt  int
	v   uint64
	b   []byte
}

// pbWalk decodes the top-level (non-recursive) protobuf fields of buf.
// Stops at the first malformed field rather than erroring — callers
// tolerate partial results for an undocumented, possibly-drifting
// format. Group-wire-types (3/4) are unsupported and terminate the walk.
func pbWalk(buf []byte) []pbField {
	var out []pbField
	i := 0
	for i < len(buf) {
		tag, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			break
		}
		i += n
		num := int(tag >> 3)
		wt := int(tag & 7)
		switch wt {
		case 0: // varint
			v, m := binary.Uvarint(buf[i:])
			if m <= 0 {
				return out
			}
			i += m
			out = append(out, pbField{num: num, wt: wt, v: v})
		case 2: // length-delimited
			ln, m := binary.Uvarint(buf[i:])
			if m <= 0 {
				return out
			}
			i += m
			if ln > uint64(len(buf)-i) {
				return out
			}
			out = append(out, pbField{num: num, wt: wt, b: buf[i : i+int(ln)]})
			i += int(ln)
		case 5: // fixed32
			if i+4 > len(buf) {
				return out
			}
			i += 4
		case 1: // fixed64
			if i+8 > len(buf) {
				return out
			}
			i += 8
		default:
			return out
		}
	}
	return out
}

// pbBytesField returns the payload of the first length-delimited field
// with the given number.
func pbBytesField(buf []byte, num int) ([]byte, bool) {
	for _, f := range pbWalk(buf) {
		if f.num == num && f.wt == 2 {
			return f.b, true
		}
	}
	return nil, false
}

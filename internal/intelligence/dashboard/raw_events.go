package dashboard

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

const (
	rawEventsDefaultLimit = 100
	rawEventsMaxLimit     = 500
	rawEventsExcerptBytes = 4096
)

type rawEventsResponse struct {
	SessionID string            `json:"session_id"`
	Tool      string            `json:"tool,omitempty"`
	Sources   []rawEventsSource `json:"sources"`
	Rows      []rawEventRow     `json:"rows"`
	Total     int               `json:"total"`
	Limit     int               `json:"limit"`
	Offset    int               `json:"offset"`
	Truncated bool              `json:"truncated,omitempty"`
}

type rawEventsSource struct {
	Path  string `json:"path"`
	Rows  int    `json:"rows"`
	Error string `json:"error,omitempty"`
}

type rawEventRow struct {
	SourceFile       string `json:"source_file"`
	SourceIndex      int    `json:"source_index"`
	Line             int    `json:"line"`
	ByteOffset       int64  `json:"byte_offset"`
	Bytes            int    `json:"bytes"`
	Timestamp        string `json:"timestamp,omitempty"`
	Type             string `json:"type,omitempty"`
	PayloadType      string `json:"payload_type,omitempty"`
	Role             string `json:"role,omitempty"`
	EventID          string `json:"event_id,omitempty"`
	ValidJSON        bool   `json:"valid_json"`
	Excerpt          string `json:"excerpt"`
	ExcerptTruncated bool   `json:"excerpt_truncated,omitempty"`
}

func (s *Server) handleSessionRawEvents(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	limit := clampRawEventsInt(queryRawEventsIntDefault(r, "limit", rawEventsDefaultLimit), 1, rawEventsMaxLimit)
	offset := clampRawEventsInt(queryRawEventsIntDefault(r, "offset", 0), 0, 1_000_000_000)

	ctx := r.Context()
	tool, err := sessionTool(ctx, s.db(), sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		writeErr(w, err)
		return
	}
	paths, err := sessionRawSourceFiles(ctx, s.db(), sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}

	resp := rawEventsResponse{
		SessionID: sessionID,
		Tool:      tool,
		Limit:     limit,
		Offset:    offset,
		Rows:      []rawEventRow{},
		Sources:   []rawEventsSource{},
	}
	scrubber := scrub.New()
	for sourceIdx, path := range paths {
		source, rows, err := readRawEventSource(ctx, path, sourceIdx, offset, limit, resp.Total, len(resp.Rows), scrubber)
		resp.Sources = append(resp.Sources, source)
		resp.Total += source.Rows
		resp.Rows = append(resp.Rows, rows...)
		if err != nil {
			resp.Sources[len(resp.Sources)-1].Error = err.Error()
		}
		if len(resp.Rows) >= limit {
			resp.Truncated = true
		}
	}
	writeJSON(w, resp)
}

func sessionTool(ctx context.Context, db *sql.DB, sessionID string) (string, error) {
	var tool string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(tool, '') FROM sessions WHERE id = ?`, sessionID).Scan(&tool); err != nil {
		return "", err
	}
	return tool, nil
}

func sessionRawSourceFiles(ctx context.Context, db *sql.DB, sessionID string) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT DISTINCT source_file FROM token_usage
		  WHERE session_id = ? AND source_file != ''
		 UNION
		 SELECT DISTINCT source_file FROM actions
		  WHERE session_id = ? AND source_file != ''
		 ORDER BY 1`, sessionID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("dashboard.rawEvents.sourceFiles: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		if isRawJSONLSource(path) {
			out = append(out, path)
		}
	}
	return out, rows.Err()
}

// isRawJSONLSource reports whether a stored source_file is a transcript this
// tab can read: a local absolute path on the daemon's OS with a JSON/JSONL
// extension. Absoluteness is not a leading "/": a Windows daemon stores
// C:\Users\... paths, which a SQL `LIKE '/%'` filter dropped, so every
// session showed zero raw events there. The check is
// pathnorm.IsLocalAbsPath, the one stored-path open gate (ledger
// CLOUDSESS-12), so a UNC, device or extended-length path is never opened (a
// Windows UNC open sends the owner's NTLM hash to the named host). A
// non-path marker in source_file is not absolute and stays excluded.
func isRawJSONLSource(path string) bool {
	if !pathnorm.IsLocalAbsPath(path) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jsonl" || ext == ".json"
}

func readRawEventSource(ctx context.Context, path string, sourceIdx, offset, limit, priorTotal, have int, scrubber *scrub.Scrubber) (rawEventsSource, []rawEventRow, error) {
	source := rawEventsSource{Path: path}
	f, err := os.Open(path)
	if err != nil {
		return source, nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var rows []rawEventRow
	var byteOffset int64
	lineNo := 0
	for {
		if err := ctx.Err(); err != nil {
			return source, rows, err
		}
		line, readErr := reader.ReadString('\n')
		if line != "" {
			lineNo++
			start := byteOffset
			byteOffset += int64(len(line))
			trimmed := strings.TrimRight(line, "\r\n")
			if strings.TrimSpace(trimmed) != "" {
				source.Rows++
				globalIdx := priorTotal + source.Rows - 1
				if globalIdx >= offset && have+len(rows) < limit {
					rows = append(rows, buildRawEventRow(path, sourceIdx, lineNo, start, trimmed, scrubber))
				}
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		return source, rows, readErr
	}
	return source, rows, nil
}

func buildRawEventRow(path string, sourceIdx, lineNo int, byteOffset int64, line string, scrubber *scrub.Scrubber) rawEventRow {
	row := rawEventRow{
		SourceFile:  path,
		SourceIndex: sourceIdx,
		Line:        lineNo,
		ByteOffset:  byteOffset,
		Bytes:       len(line),
		ValidJSON:   false,
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(line), &obj); err == nil {
		row.ValidJSON = true
		row.Timestamp = stringField(obj, "timestamp", "time", "created_at")
		row.Type = stringField(obj, "type", "event", "kind")
		row.Role = stringField(obj, "role")
		row.EventID = stringField(obj, "id", "event_id", "message_id", "call_id")
		if payload, ok := obj["payload"].(map[string]any); ok {
			row.PayloadType = stringField(payload, "type", "event", "kind")
			if row.Role == "" {
				row.Role = stringField(payload, "role")
			}
			if row.EventID == "" {
				row.EventID = stringField(payload, "id", "event_id", "message_id", "call_id")
			}
		}
	}
	capped := contentcap.Cap(line, rawEventsExcerptBytes)
	row.Excerpt = scrubber.String(capped)
	row.ExcerptTruncated = len(capped) < len(line)
	return row
}

func stringField(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := obj[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func queryRawEventsIntDefault(r *http.Request, key string, def int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func clampRawEventsInt(n, min, max int) int {
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

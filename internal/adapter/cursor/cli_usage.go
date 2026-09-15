package cursor

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// The CLI writes these records even when headless mode does not emit stop or
// afterAgentResponse. Counters match its final result. Input is ALREADY net of
// both cache buckets. A retried turn retains only the final attempt's usage.
const cliOutcomePrefix = "cursor-cli-outcome:"

var cliLogName = regexp.MustCompile(`^session-[0-9T.Z-]+-[0-9]+-[0-9]+\.log$`)

func matchesCLIUsageLog(path string) bool {
	norm := strings.ReplaceAll(path, `\`, "/")
	return strings.HasPrefix(filepath.Base(filepath.Dir(norm)), "cursor-agent-logs-") &&
		cliLogName.MatchString(filepath.Base(norm))
}

func cliUsageRoots(homes []crossmount.HomeRoot) []string {
	tempDirs := []string{os.TempDir()}
	var roots []string
	if u, err := user.Current(); err == nil {
		id := u.Uid
		if _, err := strconv.ParseUint(id, 10, 32); err != nil {
			name := strings.ReplaceAll(u.Username, `\`, "/")
			id = regexp.MustCompile(`[^A-Za-z0-9._-]`).ReplaceAllString(filepath.Base(name), "_")
		}
		roots = append(roots, filepath.Join(os.TempDir(), "cursor-agent-logs-"+id))
	}
	for _, h := range homes {
		if h.OS == crossmount.OSWindows {
			dir := filepath.Join(h.Path, "AppData", "Local", "Temp")
			tempDirs = append(tempDirs, dir)
			// Watch a known user's canonical directory before their first CLI run.
			roots = append(roots, filepath.Join(dir, "cursor-agent-logs-"+filepath.Base(h.Path)))
		}
	}
	for _, dir := range tempDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "cursor-agent-logs-*"))
		for _, path := range matches {
			if fi, err := os.Stat(path); err == nil && fi.IsDir() {
				roots = append(roots, path)
			}
		}
	}
	seen := map[string]bool{}
	out := roots[:0]
	for _, path := range roots {
		if !seen[path] {
			out = append(out, path)
			seen[path] = true
		}
	}
	return out
}

func (a *Adapter) parseCLIUsageLog(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return adapter.ParseResult{}, err
	}
	if fromOffset < 0 || fromOffset > fi.Size() {
		fromOffset = 0
	}
	if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
		return adapter.ParseResult{}, err
	}
	res := adapter.ParseResult{NewOffset: fromOffset}
	r := bufio.NewReader(io.LimitReader(f, fi.Size()-fromOffset))
	for {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		line, size, err := readCLIUsageLine(r)
		if errors.Is(err, io.EOF) {
			// Never advance past a partial final write.
			break
		}
		if err != nil {
			return res, err
		}
		res.NewOffset += size
		ev, ok := parseCLIOutcome(line)
		if !ok {
			continue
		}
		ev.SourceFile = path
		ev.Model, ev.ProjectRoot = a.cliUsageContext(ctx, ev.SessionID)
		res.TokenEvents = append(res.TokenEvents, ev)
	}
	return res, nil
}

// Discard oversized unrelated diagnostic lines without allocating their full
// contents. Keep the offset before an unfinished line so a later append heals it.
func readCLIUsageLine(r *bufio.Reader) (string, int64, error) {
	const limit = 1024 * 1024
	var line []byte
	var size int64
	for {
		part, err := r.ReadSlice('\n')
		size += int64(len(part))
		if size <= limit {
			line = append(line, part...)
		} else {
			line = nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(line), size, err
	}
}

func parseCLIOutcome(line string) (models.TokenEvent, bool) {
	const marker = "] structured-log.info "
	i := strings.Index(line, marker)
	if i < 2 || line[0] != '[' {
		return models.TokenEvent{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, line[1:i])
	if err != nil {
		return models.TokenEvent{}, false
	}
	var record struct {
		Key      string            `json:"key"`
		Message  string            `json:"message"`
		Metadata map[string]string `json:"metadata"`
	}
	if json.Unmarshal([]byte(line[i+len(marker):]), &record) != nil || record.Key != "agent_cli" || record.Message != "agent_cli.turn.outcome" {
		return models.TokenEvent{}, false
	}
	m := record.Metadata
	if m["surface"] != "headless" || !validCLIUsageID(m["conversation_id"]) || !validCLIUsageID(m["request_id"]) {
		return models.TokenEvent{}, false
	}
	var counts [4]int64
	for i, key := range []string{"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"} {
		n, err := strconv.ParseInt(m[key], 10, 64)
		if err != nil || n < 0 {
			return models.TokenEvent{}, false
		}
		counts[i] = n
	}
	reliability := models.ReliabilityAccurate
	if m["retries_attempted"] != "0" || m["outcome"] != "success" {
		reliability = models.ReliabilityUnreliable
	}
	return models.TokenEvent{
		SourceEventID: cliOutcomePrefix + m["request_id"],
		SessionID:     m["conversation_id"], MessageID: m["request_id"], TurnID: m["request_id"],
		Timestamp: ts.UTC(), Tool: models.ToolCursor, Source: models.TokenSourceJSONL, Reliability: reliability,
		InputTokens: counts[0], OutputTokens: counts[1], CacheReadTokens: counts[2], CacheCreationTokens: counts[3],
	}, true
}

func validCLIUsageID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// Resolve pricing context only from this conversation's native assistant
// messages. Ambiguous mixed-model history keeps its model unknown; current
// account preferences must never be used to price historical requests.
func (a *Adapter) cliUsageContext(ctx context.Context, sessionID string) (string, string) {
	for _, root := range a.roots {
		if filepath.Base(root) != "chats" {
			continue
		}
		paths, _ := filepath.Glob(filepath.Join(root, "*", sessionID, "store.db"))
		for _, path := range paths {
			return cliUsageModel(ctx, path), a.projectRootForStoreDB(path, sessionID)
		}
	}
	return "", ""
}

func cliUsageModel(ctx context.Context, path string) string {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(1000)", sqlitedsn.Escape(path)))
	if err != nil {
		return ""
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT data FROM blobs WHERE instr(CAST(data AS TEXT), '"modelName"') > 0`)
	if err != nil {
		return ""
	}
	defer rows.Close()
	var model string
	for rows.Next() {
		var raw []byte
		if rows.Scan(&raw) != nil {
			return ""
		}
		var message struct {
			Role    string `json:"role"`
			Content []struct {
				ProviderOptions struct {
					Cursor struct {
						ModelName string `json:"modelName"`
					} `json:"cursor"`
				} `json:"providerOptions"`
			} `json:"content"`
		}
		if json.Unmarshal(raw, &message) != nil || message.Role != "assistant" {
			continue
		}
		for _, part := range message.Content {
			name := part.ProviderOptions.Cursor.ModelName
			if name == "" || name == "default" || name == "auto" {
				continue
			}
			if model != "" && model != name {
				return ""
			}
			model = name
		}
	}
	if rows.Err() != nil {
		return ""
	}
	return model
}

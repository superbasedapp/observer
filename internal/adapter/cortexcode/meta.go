package cortexcode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// sessionMeta is the subset of conversations/<id>.json this adapter
// decodes. Of the account-bearing fields only `thread.accountHost` (the
// Snowflake ACCOUNT host the session's inference ran against, an
// account-level identity, never a person: operator ruling 2026-10-21) is
// decoded; connection_name, session_accounts and permission_cache stay
// absent so they are never decoded.
type sessionMeta struct {
	SessionID        string `json:"session_id"`
	WorkingDirectory string `json:"working_directory"`
	GitBranch        string `json:"git_branch"`
	CreatedAt        string `json:"created_at"`
	LastUpdated      string `json:"last_updated"`
	SessionType      string `json:"session_type"`
	// ParentSessionID names the spawning session of a subagent run. Both
	// spellings are read off the v1.2.18 bundle's orphan-subagent sweep
	// (`d.parent_session_id||d.parentSessionId`); not yet observed live.
	ParentSessionID      string `json:"parent_session_id"`
	ParentSessionIDCamel string `json:"parentSessionId"`
	// ForkedFrom names the source session of a `--fork-session` /
	// `/fork` copy, or of a subagent spawned with the parent's history
	// (bundle: `setForkedFrom(<source id>)`, persisted as `forked_from`,
	// camel spelling read back too). Not yet observed live.
	ForkedFrom      string                `json:"forked_from"`
	ForkedFromCamel string                `json:"forkedFrom"`
	TokenUsage      map[string]modelUsage `json:"token_usage"`
	Thread          *struct {
		AccountHost string `json:"accountHost"`
	} `json:"thread"`
}

// modelUsage is one token_usage[<model>] entry: session-cumulative counts,
// inputTokens GROSS of both cache columns.
type modelUsage struct {
	InputTokens      int64 `json:"inputTokens"`
	OutputTokens     int64 `json:"outputTokens"`
	CacheReadTokens  int64 `json:"cacheReadTokens"`
	CacheWriteTokens int64 `json:"cacheWriteTokens"`
}

// parent returns the subagent parent id under either spelling.
func (m sessionMeta) parent() string {
	if p := strings.TrimSpace(m.ParentSessionID); p != "" {
		return p
	}
	return strings.TrimSpace(m.ParentSessionIDCamel)
}

// forkedFrom returns the fork source id under either spelling.
func (m sessionMeta) forkedFrom() string {
	if f := strings.TrimSpace(m.ForkedFrom); f != "" {
		return f
	}
	return strings.TrimSpace(m.ForkedFromCamel)
}

// accountHost returns the Snowflake account host, lower-cased, or "".
func (m sessionMeta) accountHost() string {
	if m.Thread == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(m.Thread.AccountHost))
}

// lineage returns the session's lineage row, or false for a plain session.
// A subagent names its parent (and, when spawned with the parent's
// history, also the fork source); a user fork names only its source.
func (m sessionMeta) lineage(sessID string) (models.SessionLineage, bool) {
	parent, fork := m.parent(), m.forkedFrom()
	if parent == sessID {
		parent = ""
	}
	if fork == sessID {
		fork = ""
	}
	switch {
	case parent != "":
		return models.SessionLineage{SessionID: sessID, ParentThreadID: parent, ForkedFromID: fork, ThreadSource: "subagent"}, true
	case fork != "":
		return models.SessionLineage{SessionID: sessID, ForkedFromID: fork, ThreadSource: "user"}, true
	}
	return models.SessionLineage{}, false
}

// readMeta decodes a metadata document. ok is false when the file is
// missing or not (yet) valid JSON — the vendor rewrites it whole, so a read
// can race a write.
func readMeta(path string) (sessionMeta, int64, bool) {
	var m sessionMeta
	data, err := os.ReadFile(path) //nolint:gosec // watched session file or its sibling
	if err != nil {
		return m, 0, false
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, int64(len(data)), false
	}
	return m, int64(len(data)), true
}

// parseMeta parses one metadata document whole. It emits one TokenEvent per
// model in token_usage (input netted against BOTH cache columns) and, for a
// subagent run, one SessionLineage row. The cursor is the file size; the
// document is re-read on every call because it is rewritten in place.
func (a *Adapter) parseMeta(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, err
	}
	meta, size, ok := readMeta(path)
	if !ok {
		res := adapter.ParseResult{NewOffset: fromOffset}
		if size > 0 {
			// Present but undecodable: most likely a torn read of an
			// in-place rewrite. Keep the cursor and ask for a retry.
			res.RetrySuggested = true
			res.Warnings = append(res.Warnings, fmt.Sprintf("cortexcode.parseMeta: %s is not valid JSON yet", path))
		}
		return res, nil
	}
	sessID := sessionIDFromPath(path)
	root, branch, identity := resolveProjectRoot(meta.WorkingDirectory)
	if branch == "" {
		branch = meta.GitBranch
	}
	res := adapter.ParseResult{NewOffset: size}
	res.TokenEvents = a.tokenEvents(path, sessID, root, branch, meta)
	if l, ok := meta.lineage(sessID); ok {
		res.SessionLineages = append(res.SessionLineages, l)
	}
	a.stampFromLog(&res, path, sessID, meta.WorkingDirectory)
	adapter.ApplyProjectIdentity(&res, identity)
	return res, nil
}

// tokenEvents builds the session-level token rows, one per model, in
// sorted model order so a re-parse is byte-identical. All-zero entries are
// skipped so no phantom row lands.
func (a *Adapter) tokenEvents(path, sessID, root, branch string, meta sessionMeta) []models.TokenEvent {
	if len(meta.TokenUsage) == 0 {
		return nil
	}
	modelsSeen := make([]string, 0, len(meta.TokenUsage))
	for m := range meta.TokenUsage {
		modelsSeen = append(modelsSeen, m)
	}
	sort.Strings(modelsSeen)
	when := parseTime(firstNonEmpty(meta.LastUpdated, meta.CreatedAt))
	var out []models.TokenEvent
	for _, model := range modelsSeen {
		u := meta.TokenUsage[model]
		if u.InputTokens == 0 && u.OutputTokens == 0 && u.CacheReadTokens == 0 && u.CacheWriteTokens == 0 {
			continue
		}
		out = append(out, models.TokenEvent{
			SourceFile:          path,
			SourceEventID:       "tokens:session:" + sessID + ":" + model,
			SessionID:           sessID,
			ProjectRoot:         root,
			GitBranch:           branch,
			Timestamp:           when,
			Tool:                models.ToolCortexCode,
			Model:               model,
			InputTokens:         netInput(u),
			OutputTokens:        u.OutputTokens,
			CacheReadTokens:     u.CacheReadTokens,
			CacheCreationTokens: u.CacheWriteTokens,
			// Session-cumulative client-side counts from the metadata
			// file: trustworthy but neither per-turn nor proxy-observed.
			Source:      models.TokenSourceJSONL,
			Reliability: models.ReliabilityApproximate,
		})
	}
	return out
}

// netInput returns the non-cached input: inputTokens is GROSS of both the
// cache-read and the cache-write tokens (grounded: the remainder equals the
// client's uncached_tokens on both live sessions), clamped at zero.
func netInput(u modelUsage) int64 {
	n := u.InputTokens - u.CacheReadTokens - u.CacheWriteTokens
	if n < 0 {
		return 0
	}
	return n
}

// parseTime parses an RFC 3339 timestamp, returning the zero time when the
// value is empty or malformed.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

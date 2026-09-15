// Package mistralcode implements an adapter for Mistral Code, whose CLI
// binary is `vibe` (installed via `uv tool`). Mistral Code writes a
// per-session directory under ~/.vibe/logs/session/:
//
//	session_<YYYYMMDD_HHMMSS>_<8hex>/
//	  meta.json       session metadata: working_directory, git branch,
//	                  the model config, and SESSION-CUMULATIVE token stats
//	                  (session_prompt_tokens / _completion_tokens /
//	                  _cached_tokens / session_cost) — verified live 2026-08-18.
//	  messages.jsonl  append-only transcript: one JSON object per line,
//	                  role user|assistant|tool. Assistant records carry
//	                  OpenAI-shaped tool_calls[] ({id,function:{name,arguments}})
//	                  and reasoning_content; tool records carry the result.
//
// Token tier is SESSION-LEVEL: the transcript has no per-message usage, so
// this adapter emits ONE TokenEvent per session from meta.json's cumulative
// stats (prompt tokens are GROSS, netted against cached). The event's
// SourceEventID is fixed per session so the store's MAX-upgrade keeps it
// monotonic as the session grows.
//
// Off-limits (never read): ~/.vibe/.env (holds MISTRAL_API_KEY, mode 0600 —
// confirmed live 2026-08-25), ~/.vibe/config.toml (mode 0600), ~/.vibe/vibehistory
// (raw prompt history, mode 0600), ~/.vibe/connector_bootstrap_cache.json, and
// any other vibe-home file — this adapter reads only meta.json + messages.jsonl
// under a session directory.
package mistralcode

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

const (
	sessionsSubpath = "/.vibe/logs/session/"
	messagesName    = "messages.jsonl"
	metaName        = "meta.json"
	maxTargetLen    = 500
	maxReasoningLen = 2000
)

// Adapter parses Mistral Code (`vibe`) session directories.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default
// cross-mount watch roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolMistralCode }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// defaultRoots returns the watch roots for BOTH of this package's layouts
// (see ide.go's header for why one package owns two stores):
//
//   - the `vibe` CLI: ~/.vibe/logs/session across every detected home,
//     plus $VIBE_HOME/logs/session when the operator has overridden vibe's
//     home dir (VIBE_HOME is vibe's own documented override — `vibe --help`
//     lists it alongside LOG_LEVEL/LOG_MAX_BYTES/VIBE_*; only meaningful
//     for THIS process's env, so it isn't resolved per cross-mount home).
//     vibe uses the same layout on Linux, macOS, and Windows (the `vibe` /
//     `vibe-acp.exe` CLI is `uv tool`-installed; the session tree is under
//     the user home on both), so one join per cross-mount-resolved $HOME
//     covers a WSL2 observer reading a foreign Windows home too.
//   - the Continue-fork IDE store: ~/.mistralcode/sessions across every
//     detected home, plus $MISTRALCODE_GLOBAL_DIR/sessions (ide.go's
//     ideRoots).
//
// Duplicate and empty candidates are dropped so WatchPaths never carries
// the same directory twice.
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		seen[p] = true
		roots = append(roots, p)
	}
	if vh := strings.TrimSpace(os.Getenv("VIBE_HOME")); vh != "" {
		add(filepath.Join(vh, "logs", "session"))
	}
	for _, h := range homeRoots() {
		add(filepath.Join(h, ".vibe", "logs", "session"))
	}
	for _, p := range ideRoots() {
		add(p)
	}
	return roots
}

// homeRoots returns every cross-mount-resolved $HOME with a non-empty
// path, so both layouts enumerate the same home surface.
func homeRoots() []string {
	var homes []string
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		homes = append(homes, h.Path)
	}
	return homes
}

// IsSessionFile implements adapter.Adapter. A path qualifies when it is
// under a watch root AND matches one of the two layouts: the vibe CLI's
// per-session messages.jsonl (meta.json is read as a sibling, not tracked
// directly) or the IDE store's <sessionId>.json document (sessions.json is
// read as a sibling, not tracked directly).
func (a *Adapter) IsSessionFile(path string) bool {
	if classifyLayout(path) == layoutNone {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

func matchesShape(path string) bool {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if filepath.Base(lower) != messagesName {
		return false
	}
	return strings.Contains(lower, sessionsSubpath)
}

// vibeMeta is the subset of meta.json this adapter reads.
type vibeMeta struct {
	SessionID   string `json:"session_id"`
	StartTime   string `json:"start_time"`
	EndTime     string `json:"end_time"`
	GitBranch   string `json:"git_branch"`
	Environment struct {
		WorkingDirectory string `json:"working_directory"`
	} `json:"environment"`
	Stats struct {
		SessionPromptTokens        int64   `json:"session_prompt_tokens"`
		SessionCompletionTokens    int64   `json:"session_completion_tokens"`
		SessionCachedTokens        int64   `json:"session_cached_tokens"`
		SessionTotalLLMTokens      int64   `json:"session_total_llm_tokens"`
		SessionCost                float64 `json:"session_cost"`
		InputPricePerMillion       float64 `json:"input_price_per_million"`
		OutputPricePerMillion      float64 `json:"output_price_per_million"`
		CachedInputPricePerMillion float64 `json:"cached_input_price_per_million"`
	} `json:"stats"`
	Config struct {
		ActiveModel        string                  `json:"active_model"`
		RoutedDefaultModel string                  `json:"routed_default_model"`
		Models             map[string]vibeModelCfg `json:"models"`
	} `json:"config"`
}

// vibeModelCfg is the subset of a config.models[<alias>] entry this adapter
// reads — the per-million prices, which double as the only reliable way to
// resolve WHICH configured model a session actually used when active_model
// is empty (verified live 2026-08-25: it is empty on a real captured
// session even though config.models lists 3 candidates).
type vibeModelCfg struct {
	InputPrice       float64 `json:"input_price"`
	OutputPrice      float64 `json:"output_price"`
	CachedInputPrice float64 `json:"cached_input_price"`
}

// vibeRecord is one messages.jsonl line.
type vibeRecord struct {
	Role             string          `json:"role"`
	Content          json.RawMessage `json:"content"`
	MessageID        string          `json:"message_id"`
	ReasoningContent string          `json:"reasoning_content"`
	ToolCalls        []vibeToolCall  `json:"tool_calls"`
	Name             string          `json:"name"`
	ToolCallID       string          `json:"tool_call_id"`
	ToolResult       json.RawMessage `json:"tool_result"`
}

type vibeToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// ParseSessionFile implements adapter.Adapter. It dispatches on the file's
// LAYOUT (a path SHAPE, never a client identity) between the Continue-fork
// IDE store's whole-document sessions and the `vibe` CLI's append-only
// transcript.
//
// The IDE shape is the discriminating one, so it is tested first and the
// vibe transcript parser is the default: callers that hand us a transcript
// from outside a canonical `~/.vibe/logs/session` tree (fixtures, backfill
// over a copied store) keep the behaviour they had before the IDE layout
// existed. IsSessionFile stays strict — it gates on classifyLayout — so
// the watcher never widens.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if classifyLayout(path) == layoutIDE {
		return a.parseIDESession(ctx, path)
	}
	return a.parseVibeSession(ctx, path, fromOffset)
}

// parseVibeSession parses the `vibe` CLI layout. It re-reads the sibling
// meta.json every call (the only statement of the project root, model, and
// session token stats), streams messages.jsonl from fromOffset to the last
// complete line, and emits ToolEvents plus one session-level TokenEvent.
func (a *Adapter) parseVibeSession(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	meta := a.readMeta(path)
	sessID := sessionIDFromPath(path, meta)
	root, branch, projectIdentity := resolveProjectRoot(meta.Environment.WorkingDirectory)
	if branch == "" {
		branch = meta.GitBranch
	}
	base := parseTime(meta.StartTime)

	f, err := os.Open(path) //nolint:gosec // watched session file
	if err != nil {
		return adapter.ParseResult{}, nil // file vanished mid-poll; try later
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, 0); err != nil {
			return adapter.ParseResult{}, nil
		}
	}

	var res adapter.ParseResult
	res.NewOffset = fromOffset
	consumed := fromOffset

	// Collect complete lines (a trailing partial line is deferred).
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	var recs []vibeRecord
	for sc.Scan() {
		line := sc.Bytes()
		consumed += int64(len(line)) + 1 // +1 for the newline scanner stripped
		trimmed := strings.TrimSpace(string(line))
		if trimmed == "" {
			continue
		}
		var rec vibeRecord
		if err := json.Unmarshal([]byte(trimmed), &rec); err != nil {
			continue // skip malformed, keep advancing
		}
		recs = append(recs, rec)
	}
	res.NewOffset = consumed

	// Buffer tool results by call id so an assistant tool_call can carry its
	// outcome even though the result is a later record.
	results := map[string]string{}
	for _, rec := range recs {
		if rec.Role == "tool" && rec.ToolCallID != "" {
			// content is vibe's own flattened plain-text rendering of the
			// result (present on every observed tool record, including error
			// records shaped "<tool_error>...</tool_error>") — prefer it.
			// tool_result is the raw structured payload (duplicates most of
			// content's fields under presentation/output/stdout, and is
			// sometimes absent entirely) — a fallback only.
			results[rec.ToolCallID] = a.scrubber.String(jsonToText(rec.Content, rec.ToolResult))
		}
	}

	for i, rec := range recs {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		switch rec.Role {
		case "user":
			text := a.scrubber.String(jsonToText(nil, rec.Content))
			if text == "" {
				continue
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: "user:" + sessID + ":" + itoa(i),
				SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
				Tool: models.ToolMistralCode, ActionType: models.ActionUserPrompt,
				Target: truncate(text, maxTargetLen), Success: true,
			})
		case "assistant":
			reasoning := truncate(a.scrubber.String(rec.ReasoningContent), maxReasoningLen)
			if text := a.scrubber.String(jsonToText(nil, rec.Content)); text != "" {
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile: path, SourceEventID: "asst:" + sessID + ":" + firstNonEmpty(rec.MessageID, itoa(i)),
					SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
					Tool: models.ToolMistralCode, ActionType: models.ActionAssistantMessage,
					Target: truncate(text, maxTargetLen), Success: true, PrecedingReasoning: reasoning,
				})
			}
			for _, tc := range rec.ToolCalls {
				ev := a.toolEvent(path, sessID, root, branch, ts, tc, reasoning)
				if out, ok := results[tc.ID]; ok {
					ev.ToolOutput = out
					ev.Success = !looksLikeError(out)
				}
				res.ToolEvents = append(res.ToolEvents, ev)
			}
		}
	}

	if tk, ok := a.tokenEvent(path, sessID, root, meta); ok {
		res.TokenEvents = append(res.TokenEvents, tk)
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	if sessID != "" {
		// The vibe layout IS the terminal CLI by construction — the
		// store is written only by the `vibe` binary — so the kind is
		// grounded in the path shape, not guessed.
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID:   sessID,
			Surface:     models.SurfaceCLI,
			SurfaceHost: surfaceHostCLI,
		})
	}
	return res, nil
}

func (a *Adapter) toolEvent(path, sessID, root, branch string, ts time.Time, tc vibeToolCall, reasoning string) models.ToolEvent {
	action, target := mapVibeTool(tc.Function.Name, tc.Function.Arguments)
	return models.ToolEvent{
		SourceFile: path, SourceEventID: "tool:" + sessID + ":" + firstNonEmpty(tc.ID, target),
		SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
		Tool: models.ToolMistralCode, ActionType: action,
		RawToolName:        tc.Function.Name,
		RawToolInput:       a.scrubber.RawJSON([]byte(tc.Function.Arguments)),
		Target:             truncate(a.scrubber.String(target), maxTargetLen),
		Success:            true,
		PrecedingReasoning: reasoning,
	}
}

// tokenEvent builds the single session-level TokenEvent from meta.json's
// cumulative stats. prompt tokens are GROSS (include cached), so input is
// netted against cached (feedback_openai_input_is_gross).
func (a *Adapter) tokenEvent(path, sessID, root string, meta vibeMeta) (models.TokenEvent, bool) {
	s := meta.Stats
	if s.SessionPromptTokens == 0 && s.SessionCompletionTokens == 0 && s.SessionCachedTokens == 0 {
		return models.TokenEvent{}, false
	}
	netInput := s.SessionPromptTokens - s.SessionCachedTokens
	if netInput < 0 {
		netInput = 0
	}
	when := parseTime(firstNonEmpty(meta.EndTime, meta.StartTime))
	return models.TokenEvent{
		SourceFile:       path,
		SourceEventID:    "tokens:session:" + sessID,
		SessionID:        sessID,
		ProjectRoot:      root,
		Timestamp:        when,
		Tool:             models.ToolMistralCode,
		Model:            modelName(meta),
		InputTokens:      netInput,
		OutputTokens:     s.SessionCompletionTokens,
		CacheReadTokens:  s.SessionCachedTokens,
		EstimatedCostUSD: s.SessionCost,
		// Session-cumulative counts from meta.json (not per-message, not
		// proxy-observed): trustworthy but not invoice-verified.
		Source:      models.TokenSourceJSONL,
		Reliability: models.ReliabilityApproximate,
	}, true
}

func (a *Adapter) readMeta(messagesPath string) vibeMeta {
	var m vibeMeta
	data, err := os.ReadFile(filepath.Join(filepath.Dir(messagesPath), metaName)) //nolint:gosec // sibling of a watched file
	if err != nil {
		return m
	}
	_ = json.Unmarshal(data, &m)
	return m
}

// mapVibeTool maps a vibe function name to a normalized action type and a
// best-effort target extracted from the JSON arguments.
func mapVibeTool(name, args string) (string, string) {
	target := targetFromArgs(args)
	switch name {
	case "bash", "bash_output", "bash_stdin", "bash_sessions", "bash_log_file":
		return models.ActionRunCommand, target
	case "read_file":
		return models.ActionReadFile, target
	case "write_file":
		return models.ActionWriteFile, target
	case "edit":
		return models.ActionEditFile, target
	case "grep":
		return models.ActionSearchText, target
	case "task":
		return models.ActionSpawnSubagent, target
	case "web_fetch":
		return models.ActionWebFetch, target
	case "web_search":
		return models.ActionWebSearch, target
	case "todo":
		return models.ActionTodoUpdate, target
	case "ask_user_question":
		return models.ActionAskUser, target
	case "skill":
		return models.ActionSkillInvoke, target
	default:
		return models.ActionUnknown, target
	}
}

// targetFromArgs pulls the most human-meaningful field from a tool's JSON
// arguments (command / file_path / path / url / query / pattern).
func targetFromArgs(args string) string {
	if args == "" {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(args), &m); err != nil {
		return ""
	}
	for _, k := range []string{"command", "file_path", "path", "url", "query", "pattern", "name", "task"} {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// modelName returns the session's model. active_model / routed_default_model
// are direct signals but are frequently empty (verified live 2026-08-25: a
// real captured session left both blank with 3 candidates in config.models).
// When absent, the session's session_cost per-million prices in stats are
// matched against each config.models candidate's own prices — the price the
// session actually billed at is a far stronger signal than "some model in
// the catalog", and unlike active_model it can't be silently wrong the way
// picking an arbitrary map key would be. config.models is a Go map (range
// order is randomized per process — confirmed empirically: an early version
// of this function returned a different, WRONG model on repeated identical
// parses), so both the price-match scan and the last-resort fallback walk
// keys in sorted order to stay deterministic.
func modelName(meta vibeMeta) string {
	if meta.Config.ActiveModel != "" {
		return meta.Config.ActiveModel
	}
	if meta.Config.RoutedDefaultModel != "" {
		return meta.Config.RoutedDefaultModel
	}
	keys := make([]string, 0, len(meta.Config.Models))
	for k := range meta.Config.Models {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	s := meta.Stats
	if s.InputPricePerMillion != 0 || s.OutputPricePerMillion != 0 {
		for _, k := range keys {
			m := meta.Config.Models[k]
			if pricesMatch(m.InputPrice, s.InputPricePerMillion) && pricesMatch(m.OutputPrice, s.OutputPricePerMillion) {
				return k
			}
		}
	}
	if len(keys) > 0 {
		return keys[0] // no price signal to disambiguate; deterministic guess
	}
	return ""
}

// pricesMatch compares two per-million USD prices with a small epsilon for
// float round-trip noise through JSON.
func pricesMatch(a, b float64) bool {
	const eps = 1e-6
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}

// sessionIDFromPath returns the 8-hex session handle — the resume id
// `vibe --resume <8hex>` accepts and the session dir's name suffix. Falls
// back to the meta session_id's first segment when the dir shape is unusual.
func sessionIDFromPath(messagesPath string, meta vibeMeta) string {
	dir := filepath.Base(filepath.Dir(messagesPath)) // session_<date>_<8hex>
	if i := strings.LastIndex(dir, "_"); i >= 0 && i+1 < len(dir) {
		if suffix := dir[i+1:]; suffix != "" {
			return suffix
		}
	}
	if id := meta.SessionID; id != "" {
		if i := strings.IndexByte(id, '-'); i > 0 {
			return id[:i]
		}
		return id
	}
	return dir
}

func resolveProjectRoot(rawCWD string) (root, branch string, id git.Identity) {
	cwd := strings.TrimSpace(rawCWD)
	if cwd == "" {
		return "[mistral-code]", "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", git.Identity{}
	}
	return identity.Root, identity.Branch, identity
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// jsonTotext extracts a plain string from a JSON value that may be a string,
// null, or (for tool results) an object/array — best-effort. When primary is
// non-nil it takes precedence over fallback.
func jsonToText(primary, fallback json.RawMessage) string {
	for _, raw := range []json.RawMessage{primary, fallback} {
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
		return string(raw) // non-string JSON: carry the compact form
	}
	return ""
}

func looksLikeError(out string) bool {
	l := strings.ToLower(out)
	// `<tool_error>...</tool_error>` is the real wrapper vibe emits in
	// `content` for a failed tool call (verified live 2026-08-25: a real
	// failed bash call read "<tool_error>bash failed: ...</tool_error>",
	// which does NOT start with "error" and has no Python traceback).
	return strings.Contains(l, "<tool_error>") ||
		strings.HasPrefix(l, "error") ||
		strings.Contains(l, "traceback (most recent call last)")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func itoa(i int) string {
	return strconv.Itoa(i)
}

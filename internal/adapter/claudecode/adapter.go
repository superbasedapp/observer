package claudecode

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// EffortLookup fetches the claudecode_effort sidecar map for a session.
// Returns a map of Anthropic tool_use_id (toolu_xxx) → effort_level
// (low/medium/high/xhigh/max). Nil callback or nil map means "no
// effort to stamp" — the adapter skips enrichment silently.
//
// Production wiring: cmd/observer/main.go::buildWatcherWithOverride
// binds this to store.Store.LoadClaudecodeEffortMap so hook-captured
// effort fills the dashboard's per-action Effort column even for
// sessions whose JSONL never carried the field.
type EffortLookup func(ctx context.Context, sessionID string) (map[string]string, error)

// Adapter parses Claude Code's JSONL session logs under
// ~/.claude/projects/<encoded-path>/<session-id>.jsonl. See spec §4.1.
type Adapter struct {
	scrubber *scrub.Scrubber
	// watchRoot is the directory scanned for session files. Defaults to
	// ~/.claude/projects when empty.
	watchRoot string
	// effortLookup, when non-nil, returns the per-tool_use_id effort
	// level captured from the PreToolUse / PostToolUse hooks. Stamped
	// onto ToolEvents at parse time so the dashboard's Effort column
	// renders without a separate read-side join. See EffortLookup.
	effortLookup EffortLookup
}

// New returns a Claude Code adapter with the default scrubber and
// watch root (~/.claude/projects).
func New() *Adapter {
	return &Adapter{scrubber: scrub.New()}
}

// NewWithOptions returns an adapter with customized scrubber and/or watch
// root. Either argument may be zero value to use defaults.
func NewWithOptions(s *scrub.Scrubber, watchRoot string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{scrubber: s, watchRoot: watchRoot}
}

// WithEffortLookup installs the per-session effort-map fetcher used
// during ParseSessionFile to stamp tool_use ToolEvents with
// Metadata.EffortLevel. Pass nil to disable enrichment (test default).
func (a *Adapter) WithEffortLookup(fn EffortLookup) *Adapter {
	a.effortLookup = fn
	return a
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolClaudeCode }

// WatchPaths implements adapter.Adapter.
//
// Returns ".claude/projects" under every cross-mount-resolved $HOME so
// observer running in WSL2 picks up Claude Code sessions from a
// /mnt/c/Users/<u>/.claude/projects tree (and vice-versa from a
// Windows host with WSL distros mounted via \\wsl.localhost\). The
// subpath is identical across OSes — Claude Code uses ~/.claude on
// Linux, macOS, and Windows alike — so no per-home OS branching is
// needed here.
func (a *Adapter) WatchPaths() []string {
	if a.watchRoot != "" {
		return []string{a.watchRoot}
	}
	var roots []string
	for _, h := range crossmount.AllHomes() {
		roots = append(roots, filepath.Join(h.Path, ".claude", "projects"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter. Claude Code session files end in
// .jsonl under the projects tree. The under-WatchPaths constraint is
// required: before v1.4.51 the bare `.jsonl` extension match meant any
// JSONL file anywhere on disk was claimed by claude-code, which
// combined with alphabetical-sort dispatch in the watcher's poll
// fallback caused Codex rollout-*.jsonl files to be silently parsed
// by this adapter. See adapter.UnderAnyWatchRoot for the full
// background.
func (a *Adapter) IsSessionFile(path string) bool {
	if filepath.Ext(path) != ".jsonl" {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// nativeTools is the set of Claude Code tool names that map to native actions
// (as opposed to Bash shell invocations).
var nativeTools = map[string]struct{}{
	"Read":            {},
	"Write":           {},
	"Edit":            {},
	"Grep":            {},
	"Glob":            {},
	"WebSearch":       {},
	"WebFetch":        {},
	"Agent":           {},
	"TaskCreate":      {},
	"TaskUpdate":      {},
	"TaskList":        {},
	"TaskGet":         {},
	"TaskOutput":      {},
	"TaskStop":        {},
	"AskUserQuestion": {},
}

// actionMap translates Claude Code tool names to the normalized
// taxonomy. It is READ OUT of internal/tooltax, the one owner of the
// cross-adapter tool vocabulary (WP-T3 of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md). The
// hand-maintained literal that used to live here is now the
// claude-code rows of tooltax's ordered canonical table — add new
// native tool names THERE, not here.
//
// Shell-variant coverage: Bash is the canonical Claude Code tool name on
// Linux/macOS/WSL, but Windows-side Claude Code (and operator-installed
// shell wrappers) also surface PowerShell, pwsh, cmd, and cmd.exe as
// raw tool names. Without those rows they fall through to
// ActionUnknown and silently drop out of the dashboard's
// run_command-filtered views (see Issue #6 cross-adapter sweep).
//
// tooltax.For returns LITERAL rows only, so the `mcp__*` glob is still
// resolved by the models.IsMCPToolName fallback in toolUseEvent —
// unchanged behaviour.
//
// TestActionMapPreservesPreTooltaxFixture pins every pre-conversion
// pair as still present and unchanged; TestActionMapTooltaxAdditions
// pins the intended additions so an unreviewed one is loud.
var actionMap = tooltax.For(models.ToolClaudeCode)

// rawLine is the shape of a single JSONL record we care about. Claude Code's
// actual format is richer; we decode only the fields we need and let extras
// be ignored.
type rawLine struct {
	SessionID string          `json:"sessionId"`
	GitBranch string          `json:"gitBranch"`
	Cwd       string          `json:"cwd"`
	UUID      string          `json:"uuid"`
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Subtype   string          `json:"subtype"`
	Message   json.RawMessage `json:"message"`
	// Error is populated on type="system", subtype="api_error" records
	// that Claude Code writes when the upstream API rejects a request
	// (content-policy block, rate limit, invalid request, etc.).
	// Captured into ActionAPIError rows so failures show up on the
	// dashboard alongside the tool calls — pre-v1.4.20 these were
	// silently dropped because the adapter skipped records without a
	// `message` field.
	Error json.RawMessage `json:"error"`
	// IsSidechain marks lines emitted inside a sub-agent runtime
	// (spawned via the parent's `Agent` tool). The sub-agent shares
	// the parent's session_id but every line inside its execution
	// gets this flag set true. Used to segment cross-thread
	// redundancy on the Discovery tab and surface sub-agent volume
	// on the Sessions tab.
	IsSidechain bool   `json:"isSidechain"`
	AgentID     string `json:"agentId"`
	// V7d / audit B4 fields — populated for the four metadata line
	// types Claude Code emits that the adapter previously dropped
	// silently. ParentUuid links system events back to the assistant
	// turn they belong to (used by compact_boundary and turn_duration).
	ParentUuid string `json:"parentUuid"`
	// AgentName is set on `type:"agent-name"` lines and carries the
	// subagent persona id (e.g. "enterprise-tier-foundation-plan").
	// Closest analog to Copilot CLI's `agentId` attribution path.
	AgentName string `json:"agentName"`
	// CompactMetadata is set on `type:"system", subtype:"compact_boundary"`
	// lines and carries the pre-compaction token total + the tool
	// discovery roster at compaction time.
	CompactMetadata *struct {
		Trigger                   string   `json:"trigger"`
		PreTokens                 int64    `json:"preTokens"`
		PreCompactDiscoveredTools []string `json:"preCompactDiscoveredTools"`
	} `json:"compactMetadata"`
	// DurationMs + MessageCount are set on `type:"system",
	// subtype:"turn_duration"` lines and carry per-turn wall-clock data.
	// DurationMs is the authoritative per-turn wall-clock authority
	// when present (replaces the successor-timestamp inference for any
	// future per-turn-time surface). MessageCount is the number of
	// messages in the turn.
	DurationMs   int64 `json:"durationMs"`
	MessageCount int   `json:"messageCount"`
	// PermissionMode is set on `type:"permission-mode"` lines.
	// Empirically the field carries values like "plan", "acceptEdits",
	// "default" — Claude Code's permission-mode toggle states.
	PermissionMode string `json:"permissionMode"`
	// Entrypoint is present on every JSONL line (100% of a 60-file
	// sample, 2026-09-02) and identifies the client surface that wrote
	// the transcript: "cli", "claude-vscode", "claude-desktop",
	// "sdk-*" (Agent SDK embeddings), possibly "claude-jetbrains"
	// (unverified spelling). Resolved into the normalized
	// models.Surface* vocabulary by resolveClaudeSurface (surface.go)
	// — see docs/plans/ide-surface-capture-remediation-plan-2026-09-02.md
	// §0/§3 (Part E).
	Entrypoint string `json:"entrypoint"`
	// Version is the Claude Code CLI version stamped at the head of the
	// transcript (semver, e.g. "1.0.40"). Captured node-local for Issue 2
	// (migration 125) and emitted as a models.SessionToolVersion —
	// first-wins handles the head-of-transcript stamp. Observer's own
	// test fixtures strip it; it is proven present by the qoder adapter,
	// which decodes the same field from the identical Claude-Code JSONL.
	Version string `json:"version"`
}

type rawMessage struct {
	// ID is the Anthropic msg_* identifier when this is an assistant
	// message produced by an API call. One API call can produce N JSONL
	// records (1 per content block: text + tool_use × N), all sharing the
	// same ID and echoing the same accumulating usage envelope. Used as
	// the dedup key for token events.
	ID    string `json:"id"`
	Role  string `json:"role"`
	Model string `json:"model"`
	// Content is either a JSON array of rawContentBlock or a plain string
	// (for short text-only messages). decodeContent handles both.
	Content json.RawMessage `json:"content"`
	Usage   *rawUsage       `json:"usage"`
	// StopReason is the assistant message's terminal reason
	// (end_turn / max_tokens / tool_use / stop_sequence / refusal /
	// pause_turn). Per-message; stamped onto Metadata.StopReason for
	// session review. The hook payloads don't carry it — this is the
	// transcript path.
	StopReason string `json:"stop_reason"`
}

// decodeContent returns the content blocks regardless of whether the source
// encoded content as an array or as a bare string.
func decodeContent(raw json.RawMessage) []rawContentBlock {
	if len(raw) == 0 {
		return nil
	}
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var blocks []rawContentBlock
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return nil
		}
		return blocks
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil
		}
		return []rawContentBlock{{Type: "text", Text: s}}
	}
	return nil
}

func bytesTrimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end {
		c := b[start]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			start++
			continue
		}
		break
	}
	for end > start {
		c := b[end-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			end--
			continue
		}
		break
	}
	return b[start:end]
}

type rawContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	// Source is the attachment envelope on an `image` / `document` content
	// block ({"type":"base64","media_type":"image/png","data":...}). Only
	// the media_type is read (Issue 1 user-attachment capture) — the
	// base64 `data` is NEVER decoded or stored. Empty for text/tool blocks.
	Source json.RawMessage `json:"source"`
}

type rawUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	// CacheCreation is the per-tier breakdown Anthropic emits when the
	// caller opts into 1h ephemeral caching. The JSONL stream mirrors
	// the API response, so the adapter sees the same shape the proxy
	// does. Older sessions don't include this object — fields stay zero.
	CacheCreation struct {
		Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	// ServerToolUse is Anthropic's per-message count of server-side
	// tool invocations that incur a flat per-call fee — web_search at
	// $0.01/call (see [[feedback-web-search-rate-flat-0p01]]) and
	// web_fetch under similar Anthropic pricing. Captured into
	// TokenEvent.WebSearchRequests so the cost engine can add the fee
	// alongside per-token costs. Pre-v1.6.10 (audit B3) this field was
	// silently dropped on the JSONL path — every claude-code WebSearch
	// call lost its $0.01/call fee attribution unless the row also
	// arrived via the proxy (which captured it independently).
	ServerToolUse struct {
		WebSearchRequests int64 `json:"web_search_requests"`
		WebFetchRequests  int64 `json:"web_fetch_requests"`
	} `json:"server_tool_use"`
	// Speed is the provider's low-latency tier selector echoed back in the
	// usage envelope. Anthropic Opus 4.8's interactive `/fast` mode sets
	// `speed:"fast"` on the request, and the response usage block (which
	// the JSONL stream mirrors) carries it back. Captured into
	// TokenEvent.Fast so the cost engine applies Pricing.FastMultiplier on
	// the JSONL path the same way the proxy does on the api_turns path.
	// Distinct from `service_tier` (a separate dimension that stays
	// "standard" on a fast turn — don't conflate). Empty on every
	// non-fast turn and every pre-fast-mode transcript.
	Speed string `json:"speed"`
	// ServiceTier is Anthropic's served capacity tier for the turn
	// (standard / priority / batch). Mirrored from the API usage block
	// into the transcript. Stamped onto Metadata.ServiceTier for session
	// review. Distinct from Speed (the /fast selector) above.
	ServiceTier string `json:"service_tier"`
}

// ParseSessionFile implements adapter.Adapter.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("claudecode.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("claudecode.ParseSessionFile: seek: %w", err)
		}
	}

	res := adapter.ParseResult{NewOffset: fromOffset}
	_, fileAgent := subagentFileIdentity(path)
	agentIdentityValid := true
	// Tier-2 cache observation accumulator (spec §9 / C7). Walks
	// the running message-block list across this parse call; emits
	// one CacheTurnObservation per assistant-with-usage turn.
	// Capped at MaxBlocksPerSession to guard against watcher OOM
	// on runaway transcripts — past the cap, observations degrade
	// to BlockHashes=nil (Tier-3 for that session).
	tier2Acc := newTier2Accumulator(MaxBlocksPerSession)
	// Index of toolu_id → position in res.ToolEvents so we can update
	// success/error when the paired tool_result appears later.
	pending := map[string]int{}
	// Index of message.id → position in res.TokenEvents. One API call writes
	// N JSONL records (one per content block) with the same msg.id and a
	// progressing cumulative usage envelope. Last write wins (highest
	// output_tokens), so collapse same-msg.id events into a single
	// TokenEvent rather than emitting N rows that the cost engine would
	// then sum up.
	msgIDToIdx := map[string]int{}
	// Cache of project root per cwd.
	rootCache := map[string]projectGitInfo{}
	reasoningByTurn := []string{}
	// V7d / audit B4 — track the last seen line context for the four
	// metadata line types Claude Code emits without their own
	// timestamp / cwd (agent-name, permission-mode). Falling back to
	// the most recent token-bearing line keeps emitted ToolEvents
	// time-sortable on the dashboard.
	var lastTs time.Time
	lastCwd := ""
	lastBranch := ""
	// surfaceStamped gates Part E capture-surface attribution: stamp
	// at most once per ParseSessionFile call, from the first line in
	// THIS parse pass that carries a non-empty entrypoint + sessionId.
	// A later chunk (watcher resume) re-stamps the same value on its
	// own first entrypoint-bearing line — harmless, the store write is
	// first-wins-unless-empty (models.SessionSurface doc).
	surfaceStamped := false
	// versionStamped gates Issue 2 tool-version capture the same way:
	// stamp at most once per ParseSessionFile call, from the first line
	// carrying a non-empty `version` + sessionId. first-wins-unless-empty
	// makes a later chunk's re-stamp harmless.
	versionStamped := false
	// Per-file dedup for noisy state-assertion lines:
	//   • agent-name re-emits the same persona name per assistant turn
	//   • permission-mode re-emits the same mode per user prompt
	// Only emit a ToolEvent when the value changes from the previous
	// emission, so the actions timeline shows the toggle, not the
	// re-assertion noise.
	lastAgentName := ""
	lastPermissionMode := ""

	// Use bufio.Reader.ReadString instead of bufio.Scanner so the byte
	// cursor advances by the exact terminator length, including the
	// `\r\n` Windows-side / cross-mount writers may emit. bufio.Scanner +
	// `len(raw)+1` undercounts CRLF lines by 1 byte each, stranding the
	// cursor short of EOF and causing the watcher poll to loop forever.
	// Mirrors the cowork fix shape pinned by Invariants #52 + #53;
	// preemptive here to close the same bug class on the claudecode
	// path before it bites on a CRLF-emitting transcript.
	//
	// Claude Code transcripts can have very long lines (large tool
	// outputs). ReadString grows its return string dynamically when a
	// line spans buffers, so there's no maxLine cap — at the cost of
	// larger transient allocations on giant lines.
	reader := bufio.NewReaderSize(f, 64*1024)

	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, ctx.Err()
		}
		lineStr, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
			return res, fmt.Errorf("claudecode.ParseSessionFile: read: %w", readErr)
		}
		// ReadString includes the terminating '\n' when present. When
		// readErr == io.EOF, the final read may have returned a partial
		// trailing line (no '\n') — defer it to the next poll, do NOT
		// advance the cursor past it, because the writer may still be
		// appending.
		hasNewline := strings.HasSuffix(lineStr, "\n")
		if !hasNewline && readErr == io.EOF {
			break
		}
		bytesRead += int64(len(lineStr))
		lineNum++
		// Always commit NewOffset after a complete line — even when the
		// JSON body is empty / malformed / unknown shape. The byte cursor
		// must advance past every '\n' we've consumed or the poll will
		// loop. (Pre-fix bug class: empty trailing line skipped the
		// update via `continue` and the watcher repolled forever.)
		res.NewOffset = bytesRead

		raw := []byte(strings.TrimRight(lineStr, "\r\n"))
		if len(raw) == 0 {
			if readErr == io.EOF {
				break
			}
			continue
		}
		// Build the per-line candidate list. Happy path: one entry,
		// the line as-is. When the whole line fails to parse we fall
		// through to recoverConcatenatedJSONLines which scans the
		// buffer for embedded record starts and returns the
		// successfully-parsed sub-records — see that helper's doc
		// for the corruption pattern this protects against.
		var candidates [][]byte
		var probe rawLine
		firstErr := json.Unmarshal(raw, &probe)
		if firstErr == nil {
			candidates = [][]byte{raw}
		} else {
			candidates = recoverConcatenatedJSONLines(raw)
		}
		if len(candidates) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, firstErr))
			if readErr == io.EOF {
				break
			}
			continue
		}
		if firstErr != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON; recovered %d sub-record(s) via prefix scan: %v", lineNum, len(candidates), firstErr))
		}

		for _, raw := range candidates {
			var line rawLine
			if err := json.Unmarshal(raw, &line); err != nil {
				// Defensive — recoverConcatenatedJSONLines only returns
				// successfully-parsed sub-records, so this branch should
				// be unreachable. Skip rather than break the outer loop
				// if some future helper change weakens that guarantee.
				continue
			}
			if fileAgent != "" && line.AgentID != "" && fileAgent != line.AgentID {
				agentIdentityValid = false
			}
			// NewOffset already committed for the underlying physical line
			// above; the inner loop processes recovered sub-records that
			// share that same line.

			// API error envelopes — type=system, subtype=api_error. These
			// records have no `message` field (just `error`) so the
			// len(Message)==0 short-circuit below would drop them. Decode
			// the nested error and emit an ActionAPIError row so
			// content-policy blocks, rate limits, and the rest are visible
			// on the Actions / Sessions tabs.
			if line.Type == "system" && line.Subtype == "api_error" && len(line.Error) > 0 {
				ts := parseTimestamp(line.Timestamp)
				projectRoot := a.resolveProjectRoot(line.Cwd, rootCache)
				projectRemote := a.resolveProjectRemote(line.Cwd, rootCache)
				ev := buildAPIErrorEvent(path, line, ts, projectRoot, projectRemote)
				if ev != nil {
					res.ToolEvents = append(res.ToolEvents, *ev)
				}
				continue
			}

			// V7d / audit B4 — four metadata line types Claude Code
			// emits that the adapter previously dropped silently. Each
			// is non-token-bearing so emission happens BEFORE the
			// len(Message)==0 short-circuit. Operator confirmed
			// 2026-05-18 these are oversights, not deliberate skips.
			//
			// Track the most recent token-bearing line's context so
			// agent-name / permission-mode (which carry no timestamp /
			// cwd / branch / model of their own) get reasonable values.
			if ts := parseTimestamp(line.Timestamp); !ts.IsZero() {
				lastTs = ts
			}
			if line.Cwd != "" {
				lastCwd = line.Cwd
			}
			if line.GitBranch != "" {
				lastBranch = line.GitBranch
			}

			// Part E: capture-surface attribution (IDE-15 provenance
			// half) — stamp once per parse from the first line that
			// carries both an entrypoint and a session id.
			if !surfaceStamped && line.Entrypoint != "" && line.SessionID != "" {
				if kind, host, ok := resolveClaudeSurface(line.Entrypoint); ok {
					res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
						SessionID:   line.SessionID,
						Surface:     kind,
						SurfaceHost: host,
					})
				}
				surfaceStamped = true
			}

			// Issue 2: captured Claude Code CLI version from the
			// transcript's top-level `version`. Stamp once per parse; the
			// store write is first-wins-unless-empty + bounded-token
			// validated, so a re-stamp or absent field is harmless.
			if !versionStamped && line.Version != "" && line.SessionID != "" {
				res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{
					SessionID: line.SessionID,
					Version:   line.Version,
				})
				versionStamped = true
			}

			// compact_boundary — `system / compact_boundary` lines carry
			// compactMetadata.{trigger, preTokens, preCompactDiscoveredTools}.
			// Mirrors codex's buildCompactedEvent shape:
			// target = "<trigger>: ~<preTokens> tokens", RawToolInput is
			// the full compactMetadata JSON for analytic use.
			if line.Type == "system" && line.Subtype == "compact_boundary" && line.CompactMetadata != nil {
				ts := parseTimestamp(line.Timestamp)
				if ts.IsZero() {
					ts = lastTs
				}
				projectRoot := a.resolveProjectRoot(firstNonEmpty(line.Cwd, lastCwd), rootCache)
				projectRemote := a.resolveProjectRemote(firstNonEmpty(line.Cwd, lastCwd), rootCache)
				target := fmt.Sprintf("%s: ~%d tokens reclaimed", line.CompactMetadata.Trigger, line.CompactMetadata.PreTokens)
				rawIn, _ := json.Marshal(line.CompactMetadata)
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile:    path,
					SourceEventID: "compact:" + line.UUID,
					SessionID:     line.SessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     firstNonEmpty(line.GitBranch, lastBranch),
					GitRemote:     projectRemote,
					Timestamp:     ts,
					Tool:          models.ToolClaudeCode,
					ActionType:    models.ActionContextCompacted,
					Target:        truncate(target, 200),
					Success:       true,
					RawToolName:   "compact_boundary",
					RawToolInput:  string(rawIn),
					IsSidechain:   line.IsSidechain,
				})
				// Tier-2 cache observation: reset the running block
				// accumulator and flag the NEXT assistant emit with
				// CompactionSeen=true so the engine emits
				// kind=compaction_reset (spec §7 row 6).
				tier2Acc.observeCompaction()
				continue
			}

			// turn_duration — `system / turn_duration` lines carry
			// durationMs + messageCount with a parentUuid linking to the
			// assistant message that ended the turn. Captured as an
			// ActionContextCompacted-adjacent metadata row using the
			// existing ActionPostToolBatch type (used for per-batch
			// statistics rows in other adapters).
			//
			// V7e (audit B5) will use this data to cap inflated bash
			// durations at the turn's actual wallclock when present.
			// For now: just capture; the 30-min cap is the primary
			// bash-duration fix.
			if line.Type == "system" && line.Subtype == "turn_duration" && line.DurationMs > 0 {
				ts := parseTimestamp(line.Timestamp)
				if ts.IsZero() {
					ts = lastTs
				}
				projectRoot := a.resolveProjectRoot(firstNonEmpty(line.Cwd, lastCwd), rootCache)
				projectRemote := a.resolveProjectRemote(firstNonEmpty(line.Cwd, lastCwd), rootCache)
				target := fmt.Sprintf("%dms wallclock / %d msgs", line.DurationMs, line.MessageCount)
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile:    path,
					SourceEventID: "turn_dur:" + line.UUID,
					SessionID:     line.SessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     firstNonEmpty(line.GitBranch, lastBranch),
					GitRemote:     projectRemote,
					Timestamp:     ts,
					Tool:          models.ToolClaudeCode,
					ActionType:    models.ActionPostToolBatch,
					Target:        truncate(target, 200),
					Success:       true,
					DurationMs:    line.DurationMs,
					RawToolName:   "turn_duration",
					RawToolInput:  fmt.Sprintf(`{"parentUuid":%q,"durationMs":%d,"messageCount":%d}`, line.ParentUuid, line.DurationMs, line.MessageCount),
					IsSidechain:   line.IsSidechain,
				})
				continue
			}

			// agent-name — `type:"agent-name"` carries agentName (the
			// subagent persona id like "enterprise-tier-foundation-plan").
			// Re-emitted per assistant turn with the same name, so
			// adapter-level dedup: only emit on first-seen / on change.
			// Closest analog to Copilot CLI's `agentId` attribution path
			// per the v1.6.8 audit.
			if line.Type == "agent-name" && line.AgentName != "" {
				if line.AgentName == lastAgentName {
					continue
				}
				lastAgentName = line.AgentName
				projectRoot := a.resolveProjectRoot(lastCwd, rootCache)
				projectRemote := a.resolveProjectRemote(lastCwd, rootCache)
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile:    path,
					SourceEventID: "agent-name:" + line.AgentName,
					SessionID:     line.SessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     lastBranch,
					GitRemote:     projectRemote,
					Timestamp:     lastTs,
					Tool:          models.ToolClaudeCode,
					ActionType:    models.ActionSubagentStart,
					Target:        truncate(line.AgentName, 200),
					Success:       true,
					RawToolName:   "agent-name",
					RawToolInput:  fmt.Sprintf(`{"agentName":%q}`, line.AgentName),
					// Structured sub-agent identity so the /subagents read
					// model can label transcript-derived windows without
					// raw-field scraping (mirrors the hook path).
					Metadata:    &models.ActionMetadata{AgentID: line.AgentName},
					IsSidechain: line.IsSidechain,
				})
				continue
			}

			// permission-mode — `type:"permission-mode"` carries the
			// current mode ("default" | "plan" | "acceptEdits"). Like
			// agent-name, re-emitted per user prompt with the same value;
			// adapter-level dedup keeps only the toggle, not the
			// re-assertion noise. New ActionPermissionMode type (v1.6.10).
			if line.Type == "permission-mode" && line.PermissionMode != "" {
				if line.PermissionMode == lastPermissionMode {
					continue
				}
				lastPermissionMode = line.PermissionMode
				projectRoot := a.resolveProjectRoot(lastCwd, rootCache)
				projectRemote := a.resolveProjectRemote(lastCwd, rootCache)
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile:    path,
					SourceEventID: "permission-mode:" + line.PermissionMode,
					SessionID:     line.SessionID,
					ProjectRoot:   projectRoot,
					GitBranch:     lastBranch,
					GitRemote:     projectRemote,
					Timestamp:     lastTs,
					Tool:          models.ToolClaudeCode,
					ActionType:    models.ActionPermissionMode,
					Target:        truncate(line.PermissionMode, 200),
					Success:       true,
					RawToolName:   "permission-mode",
					RawToolInput:  fmt.Sprintf(`{"permissionMode":%q}`, line.PermissionMode),
					IsSidechain:   line.IsSidechain,
				})
				continue
			}

			if len(line.Message) == 0 {
				continue
			}
			var msg rawMessage
			if err := json.Unmarshal(line.Message, &msg); err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed message: %v", lineNum, err))
				continue
			}

			ts := parseTimestamp(line.Timestamp)
			projectRoot := a.resolveProjectRoot(line.Cwd, rootCache)
			projectRemote := a.resolveProjectRemote(line.Cwd, rootCache)

			if msg.Usage != nil {
				// Drop Claude Code's synthetic placeholder rows. The CLI emits
				// `model: "<synthetic>"` lines for compaction/subagent stitching
				// events that don't correspond to a real API call; in the live
				// install all such rows carry zero usage anyway, but filtering
				// at the adapter keeps them out of "unknown model" reports
				// and per-model breakdowns. Audit item C4.
				if msg.Model == "<synthetic>" {
					continue
				}
				// Prefer message.id as the dedup key — one API call shares it
				// across N content-block records — and fall back to the
				// per-record UUID when the JSONL line predates the id field
				// or is a non-API-call assistant entry.
				eventID := msg.ID
				if eventID == "" {
					eventID = line.UUID
				}
				cacheCreation := msg.Usage.CacheCreationInputTokens
				if cacheCreation == 0 {
					cacheCreation = msg.Usage.CacheCreation.Ephemeral5mInputTokens +
						msg.Usage.CacheCreation.Ephemeral1hInputTokens
				}
				ev := models.TokenEvent{
					SourceFile:            path,
					SourceEventID:         eventID,
					SessionID:             line.SessionID,
					ProjectRoot:           projectRoot,
					GitBranch:             line.GitBranch,
					GitRemote:             projectRemote,
					Timestamp:             ts,
					Tool:                  models.ToolClaudeCode,
					Model:                 msg.Model,
					InputTokens:           msg.Usage.InputTokens,
					OutputTokens:          msg.Usage.OutputTokens,
					CacheReadTokens:       msg.Usage.CacheReadInputTokens,
					CacheCreationTokens:   cacheCreation,
					CacheCreation1hTokens: msg.Usage.CacheCreation.Ephemeral1hInputTokens,
					// Server-side tool fees (audit B3, v1.6.10): per-message
					// count of Anthropic web_search invocations billed at
					// $0.01/call. web_fetch_requests is captured too but
					// currently not column-mapped (no column on token_usage
					// and unclear pricing — see audit doc §B3 / X-followup).
					WebSearchRequests: msg.Usage.ServerToolUse.WebSearchRequests,
					// Fast-tier capture (Opus 4.8 `/fast`): the usage block
					// echoes back the request's speed selector. Stamping it
					// here lets the cost engine apply Pricing.FastMultiplier
					// on the JSONL path, matching the proxy's api_turns path.
					Fast:        msg.Usage.Speed == "fast",
					Source:      models.TokenSourceJSONL,
					Reliability: models.ReliabilityUnreliable,
					MessageID:   msg.ID,
					// Sub-agent usage attribution (migration 087): the
					// same line-level isSidechain bit the tool events
					// carry. Without it a sub-agent's turns are counted
					// in the session totals but can't be bucketed into
					// its window by the dashboard's sub-agents view.
					IsSidechain: line.IsSidechain,
				}
				if msg.ID != "" {
					if idx, ok := msgIDToIdx[msg.ID]; ok {
						// Streaming usage progresses monotonically — keep the
						// later record (largest cumulative output_tokens). Don't
						// `continue` the outer loop — content blocks for this
						// JSONL line are still distinct from prior lines'
						// blocks and must be processed below.
						if ev.OutputTokens >= res.TokenEvents[idx].OutputTokens {
							res.TokenEvents[idx] = ev
						}
					} else {
						msgIDToIdx[msg.ID] = len(res.TokenEvents)
						res.TokenEvents = append(res.TokenEvents, ev)
					}
				} else {
					res.TokenEvents = append(res.TokenEvents, ev)
				}

				// Tier-2 cache observation emission (C7). Fires only on
				// assistant lines with a real msg.ID. Emits BEFORE the
				// blocks for THIS line are accumulated, so the observation
				// reflects the chain state the provider saw when it
				// generated this turn (= prefix WITHOUT the assistant's
				// own response). The assistant's blocks accumulate just
				// below for the NEXT turn's observation.
				//
				// Idempotency: SourceEventID is "cachetrack:"+msg.ID so a
				// re-parse of the same file produces identical
				// observations, deduplicable by (SourceFile, SourceEventID).
				if msg.Role == "assistant" && msg.ID != "" {
					cacheUsage := models.CacheUsage{
						NetInputTokens:        msg.Usage.InputTokens,
						OutputTokens:          msg.Usage.OutputTokens,
						CacheReadTokens:       msg.Usage.CacheReadInputTokens,
						CacheCreationTokens:   cacheCreation,
						CacheCreation1hTokens: msg.Usage.CacheCreation.Ephemeral1hInputTokens,
					}
					obs := tier2Acc.emit(
						path,
						line.SessionID,
						msg.ID,
						msg.Model,
						ts,
						cacheUsage,
						msg.Usage.Speed == "fast",
					)
					res.CacheObservations = append(res.CacheObservations, obs)
				}
			}

			blocks := decodeContent(msg.Content)

			// Tier-2 cache observation accumulation (C7). Content-bearing
			// lines fold into the running per-call chain in array order
			// (R3 determinism guard). For user/attachment lines this
			// becomes part of the NEXT assistant emit's prefix; for
			// assistant lines this becomes part of the turn-AFTER-next's
			// prefix (since the current turn's emit has already fired
			// just above).
			//
			// Role attribution: msg.Role wins; attachment lines without
			// a role fall back to "user" (R1: attachment lines carry
			// user-injected file content).
			if accumRole := tier2AccumulationRole(msg.Role, line.Type); accumRole != "" {
				tier2Acc.observeContent(blocks, accumRole)
			}

			// Emit a user_prompt action for user-role lines that carry text
			// content. Mirrors what every other adapter produces so the
			// per-message timeline shows a "user:<id>" row separating turns.
			// Tool-result-only user messages (programmatic responses to the
			// model) don't trigger this — their content is tool_result blocks,
			// not text — so the existing block loop below handles them
			// unchanged.
			// A user turn is either a role=user message OR a
			// type:"attachment" line (Claude Code injects @-mentioned /
			// dragged file bodies as their own user-side line — R1).
			if msg.Role == "user" || line.Type == "attachment" {
				// User-attachment capture (Issue 1): the image/document
				// blocks the user attached, plus a synthetic "file" for a
				// type:"attachment" line. Metadata only (kind + optional
				// media_type) — never a filename or bytes.
				atts := collectUserAttachments(blocks)
				if line.Type == "attachment" {
					atts = append(atts, models.UserAttachment{Kind: "file"})
				}
				text := userPromptText(blocks)
				// Emit the user_prompt row when there is prompt text OR the
				// turn carried attachments — an image-only user turn used to
				// produce no row at all (Issue 1 fix).
				if text != "" || len(atts) > 0 {
					truncated := text
					if len(truncated) > 200 {
						truncated = truncated[:200]
					}
					res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
						SourceFile:         path,
						SourceEventID:      line.UUID,
						SessionID:          line.SessionID,
						ProjectRoot:        projectRoot,
						Timestamp:          ts,
						GitBranch:          line.GitBranch,
						GitRemote:          projectRemote,
						Tool:               models.ToolClaudeCode,
						ActionType:         models.ActionUserPrompt,
						Target:             truncated,
						Success:            true,
						PrecedingReasoning: truncated,
						RawToolName:        "user_message",
						RawToolInput:       a.scrubber.String(text),
						IsSidechain:        line.IsSidechain,
						MessageID:          "user:" + line.UUID,
						UserAttachments:    atts,
					})
				}
			}

			for blockIdx, block := range blocks {
				switch block.Type {
				case "text":
					if msg.Role == "assistant" && strings.TrimSpace(block.Text) != "" {
						reasoningByTurn = appendCapped(reasoningByTurn, block.Text, 20)
						ev := a.assistantTextEvent(path, line, msg.ID, projectRoot, projectRemote, ts, blockIdx, block.Text)
						stampTurnMeta(&ev, msg)
						res.ToolEvents = append(res.ToolEvents, ev)
					}
				case "tool_use":
					evt := a.toolUseEvent(path, line, block, projectRoot, projectRemote, ts, msg.ID)
					evt.PrecedingReasoning = truncateReasoning(lastReasoning(reasoningByTurn))
					stampTurnMeta(&evt, msg)
					idx := len(res.ToolEvents)
					res.ToolEvents = append(res.ToolEvents, evt)
					if block.ID != "" {
						pending[block.ID] = idx
					}
				case "tool_result":
					// Cap BEFORE scrubbing (qwencode's order): the
					// 1 MiB ToolOutput contract in models.ToolEvent is
					// the store's, so a multi-megabyte result body must
					// never leave the adapter uncapped — in-window or
					// cross-tick.
					scrubbed := a.scrubber.String(
						contentcap.Cap(decodeResultContent(block.Content), contentcap.DefaultMaxBytes),
					)
					var resultErr string
					if block.IsError {
						resultErr = truncateResult(scrubbed)
					}
					idx, ok := pending[block.ToolUseID]
					if !ok {
						// Cross-tick: the tool_use lives in a PREVIOUS
						// parse window, so its row is already persisted
						// optimistically successful and the correlation
						// map is empty. Hand the outcome to the store
						// keyed by the same (source_file, block id) pair
						// toolUseEvent used as SourceEventID. DurationMs
						// stays 0 — the call's timestamp is in the prior
						// window; UpdateActionOutcome no-ops a zero.
						if block.ToolUseID != "" {
							res.OutcomeUpdates = append(res.OutcomeUpdates, models.ActionOutcomeUpdate{
								SourceFile:    path,
								SourceEventID: block.ToolUseID,
								SuccessKnown:  true, // is_error is always a verdict
								Success:       !block.IsError,
								ErrorMessage:  resultErr,
								ToolOutput:    scrubbed,
							})
						}
						continue
					}
					res.ToolEvents[idx].ToolOutput = scrubbed
					if block.IsError {
						res.ToolEvents[idx].Success = false
						res.ToolEvents[idx].ErrorMessage = resultErr
					}
					// Wall-clock duration: gap between the tool_use's
					// assistant-message timestamp and the tool_result's
					// user-message timestamp. Anthropic's JSONL doesn't
					// emit a structured per-tool elapsed field, so the
					// successor-timestamp delta is the only signal we
					// have. Skip when either timestamp is zero (legacy
					// rows) or the gap is negative (clock skew).
					//
					// V7e / audit B5 — cap inferred durations at 30
					// minutes (1,800,000ms). Claude Code's Bash tool
					// has a documented hard ceiling of 30min; native
					// tools (Read/Write/Edit/Grep/Glob) run in
					// sub-second wallclock. ANY computed duration
					// above the cap is a capture artifact — typically
					// auto-compact stitching the original tool_use
					// timestamp to a tool_result that landed hours
					// later, or session-idle resume re-attributing a
					// pending tool_use to a much-later result. Prior
					// audit (docs/claudecode-bash-duration-audit-
					// 2026-05-15.md) measured 246.4 false hours
					// across 62 rows on the maintainer corpus.
					const maxInferredDurationMs int64 = 30 * 60 * 1000
					call := &res.ToolEvents[idx]
					if call.DurationMs == 0 && !call.Timestamp.IsZero() && !ts.IsZero() {
						if d := ts.Sub(call.Timestamp).Milliseconds(); d > 0 {
							if d > maxInferredDurationMs {
								d = 0
							}
							call.DurationMs = d
						}
					}
					delete(pending, block.ToolUseID)
				}
			}
		}

		if readErr == io.EOF {
			break
		}
	}

	// Whatever is still in `pending` at EOF is a tool_use whose result
	// this window never saw. Its Success=true is a placeholder, so flag
	// it: the store holds failure-context bookkeeping for these rows
	// until the matching ActionOutcomeUpdate reports the real outcome.
	for _, idx := range pending {
		if idx < len(res.ToolEvents) {
			res.ToolEvents[idx].OutcomePending = true
		}
	}

	// Stamp per-turn effort on tool-use rows from the hook-captured
	// claudecode_effort sidecar. The Claude Code JSONL transcript
	// itself does NOT serialize the user's effort dropdown selection
	// (verified against code.claude.com/docs/en/hooks: effort.level is
	// emitted to tool-context hooks only, never to the response
	// stream). The hook handler upserts (session_id, tool_use_id) →
	// effort_level into the sidecar; we stamp here so the dashboard's
	// per-action Effort column populates even when the hook fired
	// BEFORE this parse pass saw the assistant message.
	//
	// Race-safe in the reverse ordering too: if a hook fires AFTER
	// this parse pass, UpsertClaudecodeEffort runs an UPDATE on the
	// just-inserted action row in the same transaction as the sidecar
	// upsert. Either path lands the same final state.
	a.stampEffortFromSidecar(ctx, &res)
	if agentIdentityValid {
		a.attributeSubagent(path, &res)
	}

	adapter.ApplyProjectIdentityByRoot(&res, identitiesByRoot(rootCache))
	return res, nil
}

// MaxBlocksPerSession caps the Tier-2 cache-observation accumulator's
// running block count per parse call (spec §9 memory guard). Once
// the cap is exceeded, subsequent CacheTurnObservation emissions
// carry BlockHashes=nil — degrading that session to Tier-3 for the
// rest of the call rather than risking a watcher OOM on a runaway
// transcript. Default 4096 per spec §11; configurable via
// [cachetrack].max_blocks_per_session in C12.
const MaxBlocksPerSession = 4096

// tier2Accumulator is the per-call Tier-2 cache-observation
// accumulator. Carries the running message-block list, the
// cumulative cap counter, and the compaction-since-last-emit flag.
//
// THIS IS THE MIRROR-ABLE TEMPLATE for C21–C24 adapter rollout per
// spec §14.3 (codex / opencode / kilo-cli / cline-cli). The shape
// — "observeContent appends in array order; observeCompaction
// resets and flags; emit produces one CacheTurnObservation with
// the delta since last emit then resets" — is adapter-independent.
// New adapters copy this struct + the three methods verbatim and
// only change the per-record argument shapes the call sites pass
// in.
type tier2Accumulator struct {
	// pendingBlocks is the delta since the last emit. The engine
	// receives this slice in CacheTurnObservation.BlockHashes and
	// pushes each entry into its rolling chain in order — so
	// preserving array order here is the chain-determinism guard
	// (spec §0 R3).
	pendingBlocks []models.CacheBlockMeta
	// totalBlocks is the cumulative count across all emits since
	// either parse start or the last compaction. Used to gate
	// capExceeded.
	totalBlocks int
	// compactionSeen carries forward to the NEXT emit so the
	// engine can flip kind=compaction_reset on that turn (§7
	// row 6).
	compactionSeen bool
	// capExceeded latches true once totalBlocks > maxBlocks; all
	// subsequent observations carry BlockHashes=nil for the rest
	// of this parse call. Reset by observeCompaction.
	capExceeded bool
	// maxBlocks is the cap; ≤0 disables capping entirely (used
	// only by tests that want to verify the uncapped path).
	maxBlocks int
}

// newTier2Accumulator returns a fresh accumulator with the given
// cap. maxBlocks ≤ 0 disables the cap.
func newTier2Accumulator(maxBlocks int) *tier2Accumulator {
	return &tier2Accumulator{maxBlocks: maxBlocks}
}

// observeContent appends ordered block metas from an Anthropic-
// shaped content array.
//
// ORDER PRESERVED: the input slice's order maps to the output
// append order — no Go-map iteration anywhere on the path. This
// determinism is the R3 guard that protects the engine's rolling
// chain hash from byte-instability across re-parses
// (TestAccumulateCacheBlocksTier2_Deterministic_R3Guard is the
// regression).
//
// Attachments fold in alongside text and tool_result blocks at
// the EXACT position they occupy in the source content array; they
// are NEVER deferred to the end of the chain. The caller hands
// pre-decoded blocks in source-array order; this function trusts
// that ordering.
func (a *tier2Accumulator) observeContent(blocks []rawContentBlock, role string) {
	if a.capExceeded {
		return
	}
	metas := accumulateCacheBlocksTier2(blocks, role)
	a.pendingBlocks = append(a.pendingBlocks, metas...)
	a.totalBlocks += len(metas)
	if a.maxBlocks > 0 && a.totalBlocks > a.maxBlocks {
		a.capExceeded = true
		// Drop the running buffer too — once capped the engine
		// can't reconstruct the chain anyway and the memory cost
		// of carrying it forward is the whole reason for the cap.
		a.pendingBlocks = nil
	}
}

// observeCompaction marks the next emission as following a
// compact_boundary and clears the running block accumulator. The
// cap counter is also reset — a long-running session that compacts
// regularly stays within memory bounds.
func (a *tier2Accumulator) observeCompaction() {
	a.pendingBlocks = nil
	a.totalBlocks = 0
	a.capExceeded = false
	a.compactionSeen = true
}

// emit builds the CacheTurnObservation for one assistant turn with
// usage. Resets pendingBlocks + compactionSeen for the next turn's
// delta. The returned observation carries BlockHashes=nil when the
// accumulator capExceeded.
//
// SourceEventID is "cachetrack:"+messageID so the (SourceFile,
// SourceEventID) idempotency key is unique per turn and a re-parse
// produces identical observations.
func (a *tier2Accumulator) emit(
	path, sessionID, messageID, model string,
	ts time.Time,
	usage models.CacheUsage,
	fast bool,
) models.CacheTurnObservation {
	obs := models.CacheTurnObservation{
		SourceFile:     path,
		SourceEventID:  "cachetrack:" + messageID,
		SessionID:      sessionID,
		MessageID:      messageID,
		Timestamp:      ts,
		Model:          model,
		Fast:           fast,
		Usage:          usage,
		CompactionSeen: a.compactionSeen,
	}
	if !a.capExceeded {
		obs.BlockHashes = a.pendingBlocks
	}
	a.pendingBlocks = nil
	a.compactionSeen = false
	return obs
}

// accumulateCacheBlocksTier2 converts an Anthropic-shaped content
// array into ordered Tier-2 CacheBlockMeta entries. INPUT ARRAY
// ORDER maps to OUTPUT SLICE ORDER — no Go-map iteration anywhere
// on this path. This determinism is the R3 byte-stability guard
// that protects the engine's rolling hash chain from drifting
// across re-parses of the same JSONL line.
//
// Each block's CanonicalBytes is produced via encoding/json on a
// fixed-field STRUCT (NOT map[string]any) so field ordering is
// deterministic across runs. Inner json.RawMessage fields (Input,
// Content) preserve their source bytes verbatim — a claim the
// determinism guard rests on: identical input JSON ⇒ identical
// Input/Content bytes ⇒ identical CanonicalBytes ⇒ identical
// chain hash.
//
// THIS IS THE MIRROR-ABLE TEMPLATE for C21–C24 (codex / opencode /
// kilo-cli / cline-cli per spec §14.3). The shape — "decode
// content array → walk in array order → produce CacheBlockMeta per
// entry" — is identical across Anthropic-shaped sources; only the
// per-adapter source record's content-field shape differs, and the
// caller decodes that before calling this function.
func accumulateCacheBlocksTier2(blocks []rawContentBlock, role string) []models.CacheBlockMeta {
	if len(blocks) == 0 {
		return nil
	}
	out := make([]models.CacheBlockMeta, 0, len(blocks))
	for _, b := range blocks {
		if b.Type == "" {
			continue
		}
		canon, err := marshalCanonicalBlockTier2(b)
		if err != nil {
			continue
		}
		out = append(out, models.CacheBlockMeta{
			LevelLabel:     "message", // R1: transcripts never expose tools/system
			Kind:           b.Type,
			CanonicalBytes: canon,
			Role:           role,
		})
	}
	return out
}

// tier2AccumulationRole picks the chain-accumulation role for a
// given (msg.Role, line.Type) tuple. Returns "" when the line is
// NOT content-bearing (Tier-2 skips it) — system / agent-name /
// permission-mode / etc. all return "". Attachment lines without
// a msg role fall back to "user" per R1 (transcripts inject file
// content as user-side context).
func tier2AccumulationRole(msgRole, lineType string) string {
	switch msgRole {
	case "user", "assistant":
		return msgRole
	}
	if lineType == "attachment" {
		return "user"
	}
	return ""
}

// marshalCanonicalBlockTier2 produces the deterministic JSON
// canonical form of a single Anthropic content block. The payload
// is an explicit STRUCT (not a map) — encoding/json marshals
// struct fields in declaration order, NEVER via the map-iteration
// randomness that would break R3 byte-stability across re-parses.
func marshalCanonicalBlockTier2(b rawContentBlock) ([]byte, error) {
	payload := struct {
		Type      string          `json:"type,omitempty"`
		Text      string          `json:"text,omitempty"`
		ID        string          `json:"id,omitempty"`
		Name      string          `json:"name,omitempty"`
		ToolUseID string          `json:"tool_use_id,omitempty"`
		IsError   bool            `json:"is_error,omitempty"`
		Input     json.RawMessage `json:"input,omitempty"`
		Content   json.RawMessage `json:"content,omitempty"`
	}{
		Type:      b.Type,
		Text:      b.Text,
		ID:        b.ID,
		Name:      b.Name,
		ToolUseID: b.ToolUseID,
		IsError:   b.IsError,
		Input:     b.Input,
		Content:   b.Content,
	}
	return json.Marshal(payload)
}

// stampTurnMeta stamps the assistant message's per-turn stop_reason +
// service_tier (both from the transcript usage/message envelope, NOT the
// hooks) onto an assistant event's Metadata, so session review surfaces
// them per message. Only fills empty fields — an upstream stamp wins.
// No-op when the message carries neither (pre-field transcripts).
func stampTurnMeta(ev *models.ToolEvent, msg rawMessage) {
	stopReason := msg.StopReason
	var serviceTier string
	if msg.Usage != nil {
		serviceTier = msg.Usage.ServiceTier
	}
	if stopReason == "" && serviceTier == "" {
		return
	}
	if ev.Metadata == nil {
		ev.Metadata = &models.ActionMetadata{}
	}
	if stopReason != "" && ev.Metadata.StopReason == "" {
		ev.Metadata.StopReason = stopReason
	}
	if serviceTier != "" && ev.Metadata.ServiceTier == "" {
		ev.Metadata.ServiceTier = serviceTier
	}
}

// stampEffortFromSidecar fills ToolEvent.Metadata.EffortLevel on every
// tool-use row in res whose (session_id, source_event_id) has a match
// in the claudecode_effort sidecar. Per-session cache so multi-session
// files (rare on Claude Code, but cheap to support) only fetch once.
//
// No-op when effortLookup is nil (test default) or when the lookup
// errors (best-effort enrichment — never break ingest on a sidecar
// failure).
func (a *Adapter) stampEffortFromSidecar(ctx context.Context, res *adapter.ParseResult) {
	if a.effortLookup == nil || len(res.ToolEvents) == 0 {
		return
	}
	// Per-session cache: nil sentinel means "looked up, no rows".
	cache := map[string]map[string]string{}
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.Tool != models.ToolClaudeCode || ev.SessionID == "" || ev.SourceEventID == "" {
			continue
		}
		// Only tool_use rows have a SourceEventID that matches the
		// Anthropic toolu_xxx ID the hook sees; assistant-text and
		// metadata rows use composite keys (uuid:text:N, agent-name:X,
		// etc.) that will never match the sidecar's tool_use_id.
		if ev.RawToolName == "" {
			continue
		}
		m, ok := cache[ev.SessionID]
		if !ok {
			loaded, err := a.effortLookup(ctx, ev.SessionID)
			if err != nil {
				// Cache the failure as nil so we don't re-hit the DB
				// for every tool_use row in the same file.
				cache[ev.SessionID] = nil
				continue
			}
			cache[ev.SessionID] = loaded
			m = loaded
		}
		level, ok := m[ev.SourceEventID]
		if !ok || level == "" {
			continue
		}
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		// Don't overwrite a value already set by an upstream path
		// (none today, but future-proofs against duplicate stamping).
		if ev.Metadata.EffortLevel == "" {
			ev.Metadata.EffortLevel = level
		}
	}
}

// assistantTextEvent emits a standalone assistant-text row for each text
// content block on a `role=assistant` JSONL record. Multiple text blocks on
// the same message each get their own row (rare in practice but supported
// by the Claude API content-block schema). SourceEventID embeds the line
// UUID and the block index for uniqueness across re-parses; MessageID
// prefers the upstream Anthropic msg_xxx id for cross-event linkage,
// falling back to the per-record UUID for compaction-style assistant
// records that lack msg.id. No token/cost fields are set — usage flows
// through the dedicated per-message TokenEvent path.
func (a *Adapter) assistantTextEvent(
	sourceFile string,
	line rawLine,
	messageID string,
	projectRoot string,
	projectRemote string,
	ts time.Time,
	blockIdx int,
	text string,
) models.ToolEvent {
	body := strings.TrimSpace(text)
	preview := truncate(a.scrubber.String(body), 200)
	resolvedMsgID := messageID
	if resolvedMsgID == "" {
		resolvedMsgID = "asst:" + line.UUID
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("%s:text:%d", line.UUID, blockIdx),
		SessionID:     line.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     line.GitBranch,
		GitRemote:     projectRemote,
		Tool:          models.ToolClaudeCode,
		// Per-text-block row: one per `text` content block of EVERY
		// assistant message, mid-turn included (85% of claude-code turns
		// carry more than one). assistant_message, not task_complete —
		// the turn-terminal row is the Stop hook's, which keeps
		// task_complete (cmd/observer/hook.go::buildClaudeStopEvent).
		ActionType:         models.ActionAssistantMessage,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "claudecode.assistant_text",
		ToolOutput:         a.scrubber.String(contentcap.Cap(body, contentcap.DefaultMaxBytes)),
		IsSidechain:        line.IsSidechain,
		MessageID:          resolvedMsgID,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// toolUseEvent builds a ToolEvent from a tool_use content block. The
// messageID parameter is the parent assistant message's Anthropic id
// (msg_xxx) — same upstream message that produced this tool call.
// Empty when the block has no parent message id (legacy JSONL).
func (a *Adapter) toolUseEvent(
	sourceFile string,
	line rawLine,
	block rawContentBlock,
	projectRoot string,
	projectRemote string,
	ts time.Time,
	messageID string,
) models.ToolEvent {
	rawInput := string(block.Input)
	scrubbedInput := a.scrubber.RawJSON(block.Input)

	actionType, ok := actionMap[block.Name]
	if !ok {
		actionType = models.ActionUnknown
		if models.IsMCPToolName(block.Name) {
			// mcp__<server>__<tool> calls aren't in actionMap; classify
			// them as MCP so the dashboard labels them (the identity
			// stays in raw_tool_name for the server/tool split).
			actionType = models.ActionMCPCall
		}
	}

	target := a.extractTarget(block.Name, block.Input, projectRoot)
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: block.ID,
		SessionID:     line.SessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     line.GitBranch,
		GitRemote:     projectRemote,
		Tool:          models.ToolClaudeCode,
		ActionType:    actionType,
		Target:        target,
		Success:       true,
		RawToolName:   block.Name,
		RawToolInput:  firstNonEmpty(scrubbedInput, scrub.Truncate(rawInput)),
		// ContentBytes is computed from the UNTRUNCATED block.Input (the
		// scrubbed/capped RawToolInput above would undercount large writes)
		// — the authored-code byte length for the Verbosity feature.
		ContentBytes: authoredBytes(actionType, block.Input),
		IsSidechain:  line.IsSidechain,
		MessageID:    messageID,
	}
}

// authoredBytes returns the byte length of the code the model authored in
// this tool call, dispatched on the NORMALIZED action_type (a capability,
// not a tool name — CLAUDE.md rule 3) over the Anthropic-shaped tool input:
// Write `content`, Edit `new_string`, MultiEdit Σ`new_string`, NotebookEdit
// `new_source`, run_command `command`. Returns 0 for every other action
// type (reads/searches/navigation author nothing) and on any unparseable
// input. It measures the ORIGINAL bytes — never stores them.
func authoredBytes(actionType string, rawInput []byte) int64 {
	if len(rawInput) == 0 {
		return 0
	}
	var in struct {
		Content   string `json:"content"`
		NewString string `json:"new_string"`
		NewSource string `json:"new_source"`
		Command   string `json:"command"`
		Edits     []struct {
			NewString string `json:"new_string"`
		} `json:"edits"`
	}
	if err := json.Unmarshal(rawInput, &in); err != nil {
		return 0
	}
	switch actionType {
	case models.ActionWriteFile:
		return int64(len(in.Content))
	case models.ActionEditFile:
		n := int64(len(in.NewString) + len(in.NewSource))
		for _, e := range in.Edits {
			n += int64(len(e.NewString))
		}
		return n
	case models.ActionRunCommand:
		return int64(len(in.Command))
	default:
		return 0
	}
}

// IsNativeTool reports whether a Claude Code tool name is one of the native
// (non-Bash) tools. Used by the store layer to set actions.is_native_tool.
func IsNativeTool(name string) bool {
	_, ok := nativeTools[name]
	return ok
}

func (a *Adapter) extractTarget(toolName string, rawInput []byte, projectRoot string) string {
	var input map[string]any
	if len(rawInput) == 0 {
		return ""
	}
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return ""
	}
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := input[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}

	switch toolName {
	case "Read", "Write", "Edit":
		if fp := pick("file_path"); fp != "" {
			if projectRoot != "" {
				return git.RelativePath(projectRoot, fp)
			}
			return fp
		}
	case "Bash":
		// Bash targets are scrubbed commands — always run them through the
		// scrubber even though raw_tool_input was already scrubbed.
		return a.scrubber.String(pick("command"))
	case "Grep":
		return pick("pattern")
	case "Glob":
		return pick("pattern")
	case "WebSearch":
		return pick("query")
	case "WebFetch":
		return pick("url")
	case "Skill":
		// The Skill tool's input is {"skill":"<name>","args":"…"}. The
		// NAME is the whole point: it is the token guidance.SkillKey
		// joins a scanned `.claude/skills/<name>/SKILL.md` row on, and
		// without it a skill_invoke action carries an empty target and
		// the name survives only inside raw_tool_input. `args` is free
		// user text and deliberately stays out of the target.
		return strings.TrimSpace(pick("skill"))
	}
	return ""
}

// projectGitInfo is the per-cwd cache entry for resolveProjectRoot /
// resolveProjectRemote: the resolved project root and its normalized
// "origin" remote, captured together from a single git.ResolveIdentity
// call so the two never drift and the filesystem walk never happens
// twice for the same cwd. Identity carries the fuller Project Identity
// Resolver v2 bundle from the same call.
type projectGitInfo struct {
	Root     string
	Remote   string
	Identity git.Identity
}

// resolveProjectRoot is cached per cwd because git.ResolveIdentity
// walks the filesystem — Claude Code sessions often contain hundreds
// of events sharing one cwd.
func (a *Adapter) resolveProjectRoot(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return ""
	}
	// Claude Code on Windows records cwd as a Windows-style path (e.g.
	// "C:\programsx\superbased"). When that JSONL is parsed by an
	// observer running in WSL2, filepath.Abs treats the string as
	// relative because Linux doesn't recognise the drive prefix —
	// which prepends the observer's CWD and then git.Resolve walks UP
	// looking for .git. In the worst case it lands on observer's own
	// repo and every Windows-side claude-code session gets misfiled
	// under /home/marmutapp/superbased-observer in the dashboard's
	// projects view. Translate to the WSL2 mount equivalent
	// ("/mnt/c/programsx/superbased") so git.Resolve operates on the
	// actual cross-mount path. No-op on Windows hosts and on cwds that
	// already look like native paths. Mirrors codex adapter.go:2494
	// (#54, [[feedback-foreign-path-git-resolve]]).
	cwd = crossmount.TranslateForeignPath(cwd)
	if entry, ok := cache[cwd]; ok {
		return entry.Root
	}
	// RootCommit is left nil: the lazy, cached root-commit exec belongs
	// only in the store-side path (Store.maybeRunLazyRootCommit), never
	// on a per-line adapter hot path.
	info, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		cache[cwd] = projectGitInfo{Root: cwd}
		return cwd
	}
	// info.Remote is already NormalizeRemote'd by ResolveIdentity.
	cache[cwd] = projectGitInfo{Root: info.Root, Remote: info.Remote, Identity: info}
	return info.Root
}

// resolveProjectRemote returns the normalized git remote for cwd, cached
// alongside the project root by resolveProjectRoot. Claude Code's own
// JSONL session lines never carry a remote (unlike GitBranch, which is
// sourced from line.GitBranch), so this is the adapter's only remote
// source. Callers must invoke resolveProjectRoot for the same cwd first
// so the cache entry exists — this never triggers its own git.Resolve
// call, to avoid resolving the same cwd twice.
func (a *Adapter) resolveProjectRemote(cwd string, cache map[string]projectGitInfo) string {
	if cwd == "" {
		return ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	return cache[cwd].Remote
}

// identitiesByRoot flattens a per-cwd projectGitInfo cache into a
// per-root git.Identity map suitable for
// adapter.ApplyProjectIdentityByRoot. Multiple cwds resolving to the
// same repo root collapse to one entry (they carry identical
// identity, since ResolveIdentity is keyed off the discovered root).
func identitiesByRoot(cache map[string]projectGitInfo) map[string]git.Identity {
	out := make(map[string]git.Identity, len(cache))
	for _, entry := range cache {
		if entry.Root == "" {
			continue
		}
		out[entry.Root] = entry.Identity
	}
	return out
}

// buildAPIErrorEvent decodes a Claude Code system/api_error JSONL
// record into an ActionAPIError tool event. The actual upstream
// payload lives at line.Error and has the shape:
//
//	{
//	  "status": 400,
//	  "headers": {...},
//	  "requestID": "req_011...",
//	  "error": {
//	    "type": "invalid_request_error",
//	    "message": "Output blocked by content filtering policy",
//	    "details": null
//	  },
//	  "type": "..."
//	}
//
// We map fields onto Action columns:
//
//   - Target → upstream request_id (joinable to api_turns.request_id
//     when both proxy + JSONL saw the same call)
//   - RawToolName → upstream error class
//     (invalid_request_error / rate_limit_error / overloaded_error)
//   - ErrorMessage → human-readable message after secrets scrubbing
//   - Success → false
//
// Returns nil when the line lacks the minimum fields the row needs
// (request id + non-empty message); these are recorded as a warning
// so silent ingest gaps surface in `observer status`.
func buildAPIErrorEvent(path string, line rawLine, ts time.Time, projectRoot, projectRemote string) *models.ToolEvent {
	var env struct {
		Status    int             `json:"status"`
		RequestID string          `json:"requestID"`
		Type      string          `json:"type"`  // outer type — sometimes the specific class
		Error     json.RawMessage `json:"error"` // nested error envelope (1–2 levels deep in live JSONL)
	}
	if err := json.Unmarshal(line.Error, &env); err != nil {
		return nil
	}
	// Walk the nested error chain; in live Claude Code logs the leaf
	// carries both the specific class (overloaded_error /
	// invalid_request_error / rate_limit_error) and the human message.
	// The outer envelope's `type` is sometimes the same specific class
	// but other times just the generic "error" string — prefer leaf,
	// fall back to outer.
	errType, message := findInnermostAPIError(env.Error)
	if errType == "" || errType == "error" {
		errType = env.Type
	}
	if errType == "" || errType == "error" {
		errType = "api_error"
	}
	if env.RequestID == "" && message == "" {
		return nil
	}
	eventID := line.UUID
	if eventID == "" {
		eventID = env.RequestID
	}
	return &models.ToolEvent{
		SourceFile:    path,
		SourceEventID: eventID,
		SessionID:     line.SessionID,
		ProjectRoot:   projectRoot,
		GitBranch:     line.GitBranch,
		GitRemote:     projectRemote,
		Timestamp:     ts,
		Tool:          models.ToolClaudeCode,
		ActionType:    models.ActionAPIError,
		Target:        env.RequestID,
		RawToolName:   errType,
		Success:       false,
		ErrorMessage:  truncateResult(message),
		IsSidechain:   line.IsSidechain,
		MessageID:     env.RequestID,
	}
}

// findInnermostAPIError recursively walks Anthropic's nested error
// envelope and returns the deepest (type, message) pair where the
// message is non-empty. Live Claude Code logs nest the same shape
// `{type, message, error: {…}}` 1–2 levels deep; the leaf carries the
// most-specific information. Returns empty strings when no message
// is present anywhere in the chain.
func findInnermostAPIError(raw json.RawMessage) (errType, message string) {
	if len(raw) == 0 {
		return "", ""
	}
	var node struct {
		Type    string          `json:"type"`
		Message string          `json:"message"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &node); err != nil {
		return "", ""
	}
	if t, m := findInnermostAPIError(node.Error); m != "" {
		return t, m
	}
	return node.Type, node.Message
}

func parseTimestamp(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	return time.Time{}
}

func truncateReasoning(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func truncateResult(s string) string {
	const max = 2048
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// decodeResultContent extracts the text body from a tool_result content
// payload. Claude Code encodes it as either a bare string or an array of
// {type:"text", text:"..."} blocks — both are handled.
func decodeResultContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	switch trimmed[0] {
	case '"':
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	case '[':
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return ""
		}
		var b strings.Builder
		for i, block := range blocks {
			if i > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(block.Text)
		}
		return b.String()
	}
	return ""
}

// userPromptText concatenates the text content of a user-role message's
// content blocks. Returns the trimmed result; empty when the message
// carries only tool_result blocks (programmatic responses) or no text.
func userPromptText(blocks []rawContentBlock) string {
	var b strings.Builder
	for _, block := range blocks {
		if block.Type != "text" {
			continue
		}
		t := strings.TrimSpace(block.Text)
		if t == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(t)
	}
	return strings.TrimSpace(b.String())
}

// collectUserAttachments scans a user turn's content blocks for the
// files/images the user attached (Issue 1). It records PRESENCE + KIND
// (+ optional MediaType) only — an `image` block becomes kind "image",
// a `document` block kind "file" — and NEVER reads the base64 `data` or
// any filename. Returns nil when the turn carried no attachment blocks.
func collectUserAttachments(blocks []rawContentBlock) []models.UserAttachment {
	var atts []models.UserAttachment
	for _, block := range blocks {
		switch block.Type {
		case "image":
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: attachmentMediaType(block)})
		case "document":
			atts = append(atts, models.UserAttachment{Kind: "file", MediaType: attachmentMediaType(block)})
		}
	}
	return atts
}

// attachmentMediaType pulls the IANA media_type off an attachment
// block's `source` envelope ("image/png", "application/pdf"), or the
// block's own top-level media_type as a fallback. Returns "" when the
// source exposes no type. It decodes ONLY the media_type field — never
// the base64 `data`.
func attachmentMediaType(block rawContentBlock) string {
	if len(block.Source) > 0 {
		var src struct {
			MediaType string `json:"media_type"`
		}
		if err := json.Unmarshal(block.Source, &src); err == nil && src.MediaType != "" {
			return src.MediaType
		}
	}
	return ""
}

// appendCapped appends v to xs, keeping at most n elements (oldest dropped).
func appendCapped(xs []string, v string, n int) []string {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}

func lastReasoning(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[len(xs)-1]
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// jsonlRecoveryAnchors are the substrings that mark the start of a
// fresh top-level Claude Code JSONL record. Two flavors observed
// across all files under ~/.claude/projects/: the canonical
// `{"parentUuid":...}` form (assistant/user messages and api_error
// envelopes) and `{"type":"..."}` system events
// (file-history-snapshot, last-prompt, permission-mode). The
// recovery scan walks every byte position where one of these
// anchors begins and tries to streaming-decode a record from there.
var jsonlRecoveryAnchors = [][]byte{
	[]byte(`{"parentUuid":`),
	[]byte(`{"type":"`),
}

// recoverConcatenatedJSONLines extracts every parseable Claude Code
// JSONL record embedded inside a malformed scanner line. Returns nil
// when no recovery was possible.
//
// USE CASE — Claude Code's own JSONL writer occasionally produces a
// corrupted line where two records were written without a separating
// newline. Observed 2026-05-04 on the user's host
// (~/.claude/projects/-home-marmutapp-superbased/ca17705d-1c4f-4258-9a14-d8392d5cccde.jsonl
// lines 131, 133, 134, 939): a record was being written, the writer
// was interrupted mid-string, and the next record's full payload was
// then appended directly. The combined byte sequence is invalid JSON
// as a whole, but the trailing record(s) are intact and parseable on
// their own. Pre-recovery the adapter would log a single
// "malformed JSON" warning and drop the entire line; post-recovery
// we still warn (so the corruption stays visible) but salvage every
// embedded record we can.
//
// Strategy: walk the buffer byte by byte, looking for a position
// where one of the jsonlRecoveryAnchors begins. At each such
// position try `json.Decoder.Decode` — it consumes exactly one
// top-level value and surfaces its end offset via InputOffset(),
// letting us advance past the parsed record and look for the next
// anchor in the remaining tail. The leading truncated record
// (anything before the first successfully-parsed anchor) is dropped
// — its tail was overwritten, no recovery possible.
//
// False-positive risk: an anchor substring appearing inside a
// string value of a *different* record could parse as a valid
// JSON object. In practice this is rare (would require a tool
// output that itself contains literal Claude Code JSONL) and is
// limited to lines that already failed the happy-path parse, so
// well-formed lines are unaffected.
func recoverConcatenatedJSONLines(raw []byte) [][]byte {
	var out [][]byte
	for i := 0; i < len(raw); {
		if raw[i] != '{' {
			i++
			continue
		}
		matched := false
		for _, anchor := range jsonlRecoveryAnchors {
			if bytes.HasPrefix(raw[i:], anchor) {
				matched = true
				break
			}
		}
		if !matched {
			i++
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(raw[i:]))
		var probe rawLine
		if err := dec.Decode(&probe); err != nil {
			i++
			continue
		}
		consumed := int(dec.InputOffset())
		if consumed <= 0 {
			// Defensive — Decode returning success with zero
			// consumed bytes would loop forever. Bail.
			return out
		}
		// Copy into a new slice; the caller may keep references
		// past the next scanner buffer flip.
		segment := make([]byte, consumed)
		copy(segment, raw[i:i+consumed])
		out = append(out, segment)
		i += consumed
	}
	return out
}

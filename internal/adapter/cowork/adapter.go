package cowork

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/cacheobs"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// Adapter parses Claude Cowork audit logs at
// <root>/<cowork-uuid>/<device-uuid>/local_<instance-uuid>/audit.jsonl.
// One Observer session = one local-instance directory.
type Adapter struct {
	scrubber *scrub.Scrubber
	// watchRoots, when non-empty, overrides path discovery and is the
	// explicit list of directories to scan. Used by tests to point at
	// fixtures without depending on a real Cowork install.
	watchRoots []string
}

// New returns a Cowork adapter with default scrubber.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New()}
}

// NewWithOptions customizes the scrubber and/or overrides watch roots.
func NewWithOptions(s *scrub.Scrubber, watchRoots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	return &Adapter{scrubber: s, watchRoots: watchRoots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolCowork }

// WatchPaths returns every plausible Cowork sessions root reachable
// from this process. Order: native home first, then cross-mount
// homes (WSL2 ↔ Windows bridge). Three layouts considered per home:
//
//   - Windows MSIX-packaged Claude Desktop (most current installs):
//     <home>/AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions
//   - Windows non-MSIX install:
//     <home>/AppData/Roaming/Claude/local-agent-mode-sessions
//   - macOS:
//     <home>/Library/Application Support/Claude/local-agent-mode-sessions
//
// Linux is not a known Cowork target as of this writing. Paths that
// don't exist at registry time are returned regardless — the watcher
// drops non-existent roots; that keeps WatchPaths static and the
// IsSessionFile under-WatchPaths constraint (Invariant #48)
// well-defined.
//
// The MSIX glob is expanded at call time (filepath.Glob). The
// `Claude_<hash>` package id is a publisher-derived stable string but
// can rotate across signing-key changes, so we match `Claude_*`
// rather than hardcoding the current hash.
//
// IDENTITY DEDUP: on a Windows MSIX install the first two layouts are
// the SAME directory — `%APPDATA%\Claude` is a reparse point onto
// `…\Packages\Claude_<hash>\LocalCache\Roaming\Claude`. Both spellings
// are still enumerated (the MSIX one is the only spelling a WSL daemon
// can traverse over DrvFs; the Roaming one is the only one a non-MSIX
// install has), then collapsed by adapter.DedupRootsByIdentity —
// otherwise the watcher walks one tree twice and every audit.jsonl is
// ingested under two distinct source_file values, doubling every
// action and token row (audit finding IDE-01). Deduping HERE as well
// as in the watcher keeps this adapter's own IsSessionFile root set
// equal to the set the watcher walks.
//
// The explicit watchRoots override (tests / fixtures) is returned
// verbatim — it is an injected, already-canonical list, not discovery
// output.
func (a *Adapter) WatchPaths() []string {
	if len(a.watchRoots) > 0 {
		return a.watchRoots
	}
	var roots []string
	for _, h := range allHomesFunc() {
		roots = append(roots, candidateRoots(h)...)
	}
	return adapter.DedupRootsByIdentity(roots)
}

// allHomesFunc is the test seam over crossmount.AllHomes — tests swap
// in a synthetic home set so root discovery is assertable without
// depending on the host's filesystem layout. Same shape as
// clinecli.allHomesFunc / aider.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

func candidateRoots(h crossmount.HomeRoot) []string {
	switch h.OS {
	case crossmount.OSWindows:
		var roots []string
		// MSIX-redirected Roaming. Expand Claude_* glob.
		msixPattern := filepath.Join(
			h.Path, "AppData", "Local", "Packages",
			"Claude_*", "LocalCache", "Roaming", "Claude",
			"local-agent-mode-sessions",
		)
		if matches, _ := filepath.Glob(msixPattern); len(matches) > 0 {
			roots = append(roots, matches...)
		}
		// Non-MSIX install (legacy / npx layout).
		roots = append(
			roots,
			filepath.Join(h.Path, "AppData", "Roaming", "Claude", "local-agent-mode-sessions"),
		)
		return roots
	case crossmount.OSDarwin:
		return []string{
			filepath.Join(h.Path, "Library", "Application Support", "Claude", "local-agent-mode-sessions"),
		}
	}
	// Linux: no known Cowork install target.
	return nil
}

// IsSessionFile matches per-local-instance audit.jsonl files under
// one of this adapter's WatchPaths. The under-WatchPaths constraint
// enforces the v1.4.51 dispatch contract (Invariant #48).
//
// Shape: filename is exactly "audit.jsonl" AND the path contains a
// "local_<uuid>/" segment AND it sits under a Cowork sessions root.
func (a *Adapter) IsSessionFile(path string) bool {
	if filepath.Base(path) != "audit.jsonl" {
		return false
	}
	// Must live inside a local_<id>/ directory (immediate parent's
	// basename must start with "local_"). This rules out any stray
	// audit.jsonl placed outside Cowork's instance layout.
	parent := filepath.Base(filepath.Dir(path))
	if !strings.HasPrefix(parent, "local_") {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// actionMap translates Cowork tool names — which mirror Claude Code's
// CLI tool surface plus a few Cowork-specific additions — to the
// normalized action taxonomy. It is READ OUT of internal/tooltax, the
// one owner of the cross-adapter tool vocabulary (WP-T3 of
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md). Names
// with no row get ActionUnknown and keep their raw name in
// RawToolName.
//
// Cowork's SEMANTIC REMAPS are preserved verbatim as cowork-specific
// tooltax rows — they are deliberate adapter semantics, not drift, and
// they intentionally differ from the claude-code rows for the same
// native names:
//
//   - `mcp__workspace__bash` is semantically equivalent to the built-in
//     `Bash` tool, just routed through the workspace MCP server, so it
//     is run_command rather than mcp_call; `mcp__workspace__web_fetch`
//     is the MCP twin of `WebFetch`.
//   - The remaining `mcp__*` names are server-side helpers (cowork
//     directory / present_files / visualize widgets) that don't map to
//     a single primitive action — they land as `mcp_call`.
//   - `Skill` and `ToolSearch` are Anthropic-platform-level tools
//     (skills + deferred-tool loader); on THIS adapter both surface as
//     mcp_call, where claude-code maps them to skill_invoke /
//     tool_search.
//
// tooltax.For returns LITERAL rows only, so an unlisted `mcp__*` name
// is still resolved by the models.IsMCPToolName fallback in the
// tool_use branch — unchanged behaviour.
//
// TestActionMapPreservesPreTooltaxFixture pins every pre-conversion
// pair as still present and unchanged (including every semantic
// remap); TestActionMapTooltaxAdditions pins the intended additions so
// an unreviewed one is loud.
var actionMap = tooltax.For(models.ToolCowork)

// nativeTools is the set of Cowork tools that are first-class agent
// actions (not Bash shell wrappers). Used by IsNativeTool to set the
// is_native_tool column on actions.
var nativeTools = map[string]struct{}{
	"Read":            {},
	"Write":           {},
	"Edit":            {},
	"NotebookEdit":    {},
	"Grep":            {},
	"Glob":            {},
	"WebSearch":       {},
	"WebFetch":        {},
	"Agent":           {},
	"Task":            {},
	"TaskOutput":      {},
	"TaskStop":        {},
	"TaskCreate":      {},
	"TaskUpdate":      {},
	"TaskList":        {},
	"TaskGet":         {},
	"TodoWrite":       {},
	"AskUserQuestion": {},
	"Skill":           {},
}

// IsNativeTool reports whether a Cowork tool name is a first-class
// agent tool (not a Bash wrapper).
func IsNativeTool(name string) bool {
	_, ok := nativeTools[name]
	return ok
}

// rawRecord is the shape of one line in audit.jsonl. Only the fields
// we care about are decoded; everything else falls through.
//
// TopUsage and ModelUsage are populated only on `result` records (which
// carry the Claude Code SDK's authoritative per-batch usage + per-model
// breakdown). Assistant records carry their usage block inside
// `message.usage`, which is decoded via rawMessage.Usage instead.
type rawRecord struct {
	Type             string                         `json:"type"`
	Subtype          string                         `json:"subtype"`
	UUID             string                         `json:"uuid"`
	SessionID        string                         `json:"session_id"`
	ParentToolUseID  string                         `json:"parent_tool_use_id"`
	AuditTimestamp   string                         `json:"_audit_timestamp"`
	Cwd              string                         `json:"cwd"`
	Message          json.RawMessage                `json:"message"`
	Tools            json.RawMessage                `json:"tools"`
	Summary          string                         `json:"summary"`
	PrecedingToolIDs []string                       `json:"preceding_tool_use_ids"`
	IsError          bool                           `json:"is_error"`
	DurationMs       int64                          `json:"duration_ms"`
	DurationAPIMs    int64                          `json:"duration_api_ms"`
	NumTurns         int                            `json:"num_turns"`
	Result           string                         `json:"result"`
	TotalCostUSD     float64                        `json:"total_cost_usd"`
	StopReason       string                         `json:"stop_reason"`
	RateLimitInfo    json.RawMessage                `json:"rate_limit_info"`
	TopUsage         *rawUsage                      `json:"usage,omitempty"`
	ModelUsage       map[string]rawResultModelUsage `json:"modelUsage,omitempty"`
	// system-event subtype payloads. Each is populated only on the
	// matching subtype:
	//   compact_boundary    → CompactMetadata
	//   permission_request  → ToolName, ToolInput
	//   permission_response → ToolName, Decision, Granted (note: response
	//                         shares its UUID with the originating request,
	//                         so we patch the request row instead of emitting
	//                         a new one)
	//   permission_denied   → ToolName, ToolUseID, AgentID, DecisionReasonType,
	//                         plus the human-readable reason at the top-level
	//                         `message` field (decoded as a string from
	//                         rawRecord.Message — for user/assistant records
	//                         that field is a JSON object, not a string).
	CompactMetadata    *coworkCompactMetadata `json:"compact_metadata,omitempty"`
	ToolName           string                 `json:"tool_name,omitempty"`
	ToolInput          json.RawMessage        `json:"tool_input,omitempty"`
	Decision           string                 `json:"decision,omitempty"`
	Granted            *bool                  `json:"granted,omitempty"`
	AgentID            string                 `json:"agent_id,omitempty"`
	DecisionReasonType string                 `json:"decision_reason_type,omitempty"`
	ToolUseID          string                 `json:"tool_use_id,omitempty"`
}

// coworkCompactMetadata is the payload of a
// `type:"system", subtype:"compact_boundary"` audit record.
type coworkCompactMetadata struct {
	Trigger    string `json:"trigger"`
	PreTokens  int64  `json:"pre_tokens"`
	PostTokens int64  `json:"post_tokens"`
	DurationMs int64  `json:"duration_ms"`
}

// rawResultModelUsage is one entry in `result.modelUsage` — the Claude
// Code SDK's per-model accounting for the result-batch. Cowork's
// authoritative cost figure is exactly the sum of CostUSD across all
// modelUsage entries within a result, which in turn equals the
// result's top-level total_cost_usd.
//
// This is the canonical source for cowork token accounting. Per-
// assistant-row `message.usage` is a streaming snapshot that drops
// output_tokens on most chunks and never sees haiku invocations that
// Cowork dispatches internally — see
// docs/cowork-cost-drift-investigation-2026-05-15.md for the rationale.
type rawResultModelUsage struct {
	InputTokens              int64   `json:"inputTokens"`
	OutputTokens             int64   `json:"outputTokens"`
	CacheReadInputTokens     int64   `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64   `json:"cacheCreationInputTokens"`
	CostUSD                  float64 `json:"costUSD"`
	WebSearchRequests        int64   `json:"webSearchRequests"`
	ContextWindow            int64   `json:"contextWindow"`
	MaxOutputTokens          int64   `json:"maxOutputTokens"`
}

type rawMessage struct {
	ID      string          `json:"id"`
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
	Usage   *rawUsage       `json:"usage"`
}

type rawUsage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreation            struct {
		Ephemeral5mInputTokens int64 `json:"ephemeral_5m_input_tokens"`
		Ephemeral1hInputTokens int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	ServiceTier  string `json:"service_tier"`
	InferenceGeo string `json:"inference_geo"`
}

type rawContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	// Source is the attachment envelope on an image/document block
	// ({type:"base64", media_type, data}). Only media_type is read
	// (Issue 1 user-attachment capture); the base64 `data` is never
	// decoded or stored.
	Source json.RawMessage `json:"source"`
}

// imageMediaType reads the media_type off an image/document block's
// source envelope ("image/png"), or "" when absent. Reads ONLY the
// media type, never the base64 data.
func (b rawContentBlock) imageMediaType() string {
	if len(b.Source) == 0 {
		return ""
	}
	var src struct {
		MediaType string `json:"media_type"`
	}
	if err := json.Unmarshal(b.Source, &src); err == nil {
		return src.MediaType
	}
	return ""
}

// sidecar is the canonical per-local-instance metadata at
// `<device-uuid>/local_<instance-uuid>.json`, sibling to the
// local-instance directory itself.
type sidecar struct {
	SessionID           string   `json:"sessionId"`
	ProcessName         string   `json:"processName"`
	CliSessionID        string   `json:"cliSessionId"`
	Cwd                 string   `json:"cwd"`
	UserSelectedFolders []string `json:"userSelectedFolders"`
	Model               string   `json:"model"`
	Title               string   `json:"title"`
	HostLoopMode        bool     `json:"hostLoopMode"`
	IsArchived          bool     `json:"isArchived"`
}

// loadSidecar reads `<device-uuid>/local_<inst>.json` for the local-
// instance whose audit.jsonl is `auditPath`. Best-effort — returns a
// zero-value sidecar with no error when the file is missing. Missing
// or malformed sidecar metadata never blocks parsing; we just lose
// the userSelectedFolders / title / processName decorations.
func loadSidecar(auditPath string) (sidecar, error) {
	// auditPath: .../local_<id>/audit.jsonl
	// sidecar:   .../local_<id>.json   (parent's parent + same basename + .json)
	instDir := filepath.Dir(auditPath)
	parentDir := filepath.Dir(instDir)
	sidecarPath := filepath.Join(parentDir, filepath.Base(instDir)+".json")
	b, err := os.ReadFile(sidecarPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sidecar{}, nil
		}
		return sidecar{}, fmt.Errorf("cowork.loadSidecar: read %s: %w", sidecarPath, err)
	}
	var s sidecar
	if err := json.Unmarshal(b, &s); err != nil {
		return sidecar{}, fmt.Errorf("cowork.loadSidecar: parse %s: %w", sidecarPath, err)
	}
	return s, nil
}

// ProjectAttribution returns the (Observer session ID, project root,
// normalized git remote) triple that ParseSessionFile would attribute
// to a given audit.jsonl path, without actually parsing the file. Used
// by the --cowork-project-root backfill to re-attribute rows ingested
// before a project-resolution bug fix.
//
// Returns ok=false when the path doesn't follow the local_<uuid>/
// layout (in which case the file shouldn't have been ingested by the
// adapter in the first place).
func ProjectAttribution(auditPath string) (sessionID, projectRoot, remote string, ok bool) {
	sessionID = instanceSessionID(auditPath)
	if sessionID == "" {
		return "", "", "", false
	}
	sc, err := loadSidecar(auditPath)
	if err != nil {
		// Don't block re-attribution on a missing sidecar — the
		// parser falls back to "" project root in that case, and
		// the backfill should converge on the same behavior.
		sc = sidecar{}
	}
	projectRoot, remote, _ = resolveProjectRoot(sc, map[string]projectGitInfo{})
	return sessionID, projectRoot, remote, true
}

// instanceSessionID extracts the local-instance UUID from an audit.jsonl
// path. Returns "" if the path doesn't follow the expected layout.
// Used as the canonical Observer session ID so re-parses are stable.
func instanceSessionID(auditPath string) string {
	parent := filepath.Base(filepath.Dir(auditPath))
	if !strings.HasPrefix(parent, "local_") {
		return ""
	}
	return parent // "local_<uuid>"
}

// resolveProjectRoot picks the most informative project root for a
// local-instance: sidecar.userSelectedFolders[0] when set (the user
// pointed Cowork at a real workspace), else sidecar.Cwd, else "".
//
// Handles three path shapes Cowork's sidecar can carry:
//
//  1. Windows-native (e.g. C:\programsx\foo). Translates to
//     /mnt/<drive>/foo on WSL2 when the corresponding mount exists.
//     If the translated path is reachable, git.Resolve runs on it;
//     otherwise the original Windows form is preserved verbatim.
//
//  2. Cowork sandbox synthetic (e.g. /sessions/clever-festive-mendel).
//     These don't exist on the observer's host; stored verbatim so
//     the dashboard shows what Cowork named them.
//
//  3. Native Unix path that actually exists on disk. git.Resolve
//     runs and returns the working-tree root.
//
// CRITICAL: git.Resolve is only called when the (translated)
// candidate exists on disk. Without that gate, filepath.Abs prepends
// the observer process's CWD to Windows-shaped paths — which then
// finds the observer's OWN .git and mis-attributes every Cowork
// session pointing at a Windows workspace to the observer's repo.
// That's what v1.4.54 fixed.
// projectGitInfo is the per-candidate cache entry for resolveProjectRoot:
// the resolved project root and its normalized "origin" remote,
// captured together from a single git.Resolve call so the two never
// drift and the filesystem walk never happens twice for the same
// candidate.
type projectGitInfo struct {
	Root   string
	Remote string
	// Identity is the Project Identity Resolver v2 bundle (2026-09-06,
	// §3.1 / W1) resolved alongside Root/Remote, zero-valued on every
	// branch that doesn't run git.ResolveIdentity (an honest gap, never
	// a fabricated value). Applied to every event in the ParseResult via
	// adapter.ApplyProjectIdentity — cowork resolves at most one identity
	// per ParseSessionFile call.
	Identity git.Identity
}

// resolveProjectRoot returns (root, remote, identity). remote/identity
// are only populated when git.ResolveIdentity actually ran and found a
// repo (the reachable-path branch below); the sandbox-synthesis and
// unreachable-path branches never call it, so both are zero there — an
// honest gap, not a fabricated value.
func resolveProjectRoot(s sidecar, cache map[string]projectGitInfo) (string, string, git.Identity) {
	candidate := ""
	if len(s.UserSelectedFolders) > 0 && s.UserSelectedFolders[0] != "" {
		candidate = s.UserSelectedFolders[0]
	} else if s.Cwd != "" {
		candidate = s.Cwd
	}
	if candidate == "" {
		return "", "", git.Identity{}
	}

	// Cowork-internal cwd (the session's own .../local_<id>/outputs
	// folder under local-agent-mode-sessions) means the user didn't
	// point Cowork at a real workspace. Surfacing that path as a
	// "project" on the dashboard is useless — it's just where the
	// session stored its scratch files. Synthesize a sandbox name
	// matching Cowork's own `/sessions/<adj-adj-name>` convention
	// (which it uses for non-host-loop sessions) so the two flavours
	// of project-less sessions group together in the dashboard.
	//
	// Only triggers when userSelectedFolders is empty AND cwd lives
	// inside the cowork tree; if a user explicitly picked a workspace
	// inside local-agent-mode-sessions (vanishingly unlikely), that
	// path lands on the userSelectedFolders branch above and bypasses
	// this synthesis.
	if len(s.UserSelectedFolders) == 0 && strings.Contains(s.Cwd, "local-agent-mode-sessions") {
		name := s.ProcessName
		if name == "" {
			name = s.SessionID
		}
		if name != "" {
			return "/sessions/" + name, "", git.Identity{}
		}
	}

	if r, ok := cache[candidate]; ok {
		return r.Root, r.Remote, r.Identity
	}

	// Translate Windows-style paths to /mnt/<drive>/ on WSL2
	// (no-op for native paths). The returned value MAY not exist
	// on disk — we stat-check below.
	translated := crossmount.TranslateForeignPath(candidate)

	if _, err := os.Stat(translated); err == nil {
		if id, err := git.ResolveIdentity(translated, git.IdentityOptions{}); err == nil && id.IsGit {
			// id.Remote is already NormalizeRemote'd by ResolveIdentity;
			// no separate NormalizeRemote call needed.
			cache[candidate] = projectGitInfo{Root: id.Root, Remote: id.Remote, Identity: id}
			return id.Root, id.Remote, id
		}
		// Path exists but isn't a git repo — return the reachable
		// form rather than the foreign-OS string the sidecar emitted.
		cache[candidate] = projectGitInfo{Root: translated}
		return translated, "", git.Identity{}
	}
	// Translated path isn't reachable from this host (sandbox paths
	// like "/sessions/<adj-adj-name>" hit this; so do Windows paths
	// to drives not mounted under /mnt/). Preserve the candidate
	// verbatim — git.Resolve would otherwise interpret it as relative
	// to the observer's CWD and mis-attribute the session to the
	// observer's own repo (v1.4.54 regression).
	cache[candidate] = projectGitInfo{Root: candidate}
	return candidate, "", git.Identity{}
}

// ParseSessionFile implements adapter.Adapter. Streams audit.jsonl
// from fromOffset to EOF, lifting sidecar metadata once per call.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cowork.ParseSessionFile: open %s: %w", path, err)
	}
	defer f.Close()

	if fromOffset > 0 {
		if _, err := f.Seek(fromOffset, io.SeekStart); err != nil {
			return adapter.ParseResult{}, fmt.Errorf("cowork.ParseSessionFile: seek: %w", err)
		}
	}

	sc, err := loadSidecar(path)
	if err != nil {
		// Carry as warning but continue; parsing without sidecar
		// degrades metadata richness, not correctness.
		return adapter.ParseResult{NewOffset: fromOffset, Warnings: []string{err.Error()}}, nil
	}

	sessionID := instanceSessionID(path)
	rootCache := map[string]projectGitInfo{}
	projectRoot, projectRemote, projectIdentity := resolveProjectRoot(sc, rootCache)

	res := adapter.ParseResult{NewOffset: fromOffset}
	// Part E: capture-surface attribution (IDE-15 provenance half).
	// Cowork audit.jsonl is ALWAYS the Claude Desktop agent-mode
	// runtime — there is no other host this format is written from —
	// so every parse of a local-instance's audit.jsonl stamps the
	// session desktop/claude-desktop unconditionally, no discriminator
	// table needed. Re-stamping the same value on every chunk is
	// harmless (Store.SetSessionSurface is first-wins-unless-empty). See
	// docs/claude-cowork.md "Surface attribution" for why the Claude
	// Code tab embedded inside Claude Desktop is a SEPARATE session
	// captured by the claudecode adapter (entrypoint="claude-desktop"),
	// not this one.
	if sessionID != "" {
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID:   sessionID,
			Surface:     models.SurfaceDesktop,
			SurfaceHost: "claude-desktop",
		})
	}
	pending := map[string]int{}            // tool_use_id → index in res.ToolEvents (PRUNED on tool_result pair)
	allToolUseIdx := map[string]int{}      // tool_use_id → index in res.ToolEvents (NEVER pruned, for tool_use_summary join)
	pendingPermissions := map[string]int{} // permission_request UUID → index, patched on the matching permission_response
	reasoning := []string{}                // last-N thinking blocks, claudecode-style

	// Sidechain UUID set, populated once from inner subagents/agent-*.jsonl
	// transcripts under this local-instance's .claude/projects tree.
	// Audit-record UUIDs in this set get IsSidechain=true on their
	// emitted actions. Empty when the local-instance had no sub-agent
	// activity (or no .claude/projects/ tree at all).
	sidechain := collectSidechainUUIDs(filepath.Dir(path))

	// cacheAcc is the per-session Tier-2 cache-observation
	// accumulator (see cachetrack.go). It receives every user +
	// assistant content block in transcript order and emits one
	// CacheTurnObservation per model at each `result` record — the
	// only place cowork carries authoritative per-turn token
	// accounting (handleAssistant's doc comment above explains why
	// the streaming assistant.message.usage snapshot is not used).
	cacheAcc := cacheobs.New(MaxBlocksPerSession)

	// Use bufio.Reader.ReadString instead of bufio.Scanner so we get
	// the exact byte count of each line (incl. the \r\n terminator
	// Cowork's Windows-side audit.jsonl writer uses). bufio.Scanner +
	// `len(raw)+1` undercounted CRLF lines by 1 byte each, stranding the
	// cursor short of EOF and causing the watcher poll to loop forever.
	//
	// Cowork audit.jsonl lines have been observed up to ~50 KB; the
	// default bufio.NewReaderSize(f, 64KiB) buffer comfortably handles
	// these. ReadString grows its return string dynamically when a line
	// spans buffers, so there's no maxLine cap to worry about — at the
	// cost of larger transient allocations on giant lines, which the
	// audit.jsonl format doesn't produce.
	reader := bufio.NewReaderSize(f, 64*1024)

	bytesRead := fromOffset
	lineNum := 0
	for {
		if ctx.Err() != nil {
			adapter.ApplyProjectIdentity(&res, projectIdentity)
			return res, ctx.Err()
		}
		line, readErr := reader.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			adapter.ApplyProjectIdentity(&res, projectIdentity)
			return res, fmt.Errorf("cowork.ParseSessionFile: read: %w", readErr)
		}
		// ReadString includes the terminating '\n' when present. When
		// readErr == io.EOF, the final read may have returned a partial
		// line (no trailing '\n') — in that case we must NOT advance the
		// cursor past it because the next poll might find the line
		// completed (Cowork is actively writing to these files).
		hasNewline := strings.HasSuffix(line, "\n")
		if !hasNewline && readErr == io.EOF {
			// Either EOF with no bytes read, or a partial trailing
			// line we should defer to the next poll. Stop without
			// advancing res.NewOffset past it.
			break
		}
		bytesRead += int64(len(line))
		lineNum++
		// Always commit NewOffset after a complete line — even when the
		// JSON body is empty / malformed / unknown type. The byte cursor
		// must advance past every \n we've consumed or the poll will
		// loop. (Pre-fix bug: an empty trailing line skipped the update
		// via `continue` and the watcher repolled forever.)
		res.NewOffset = bytesRead

		raw := strings.TrimRight(line, "\r\n")
		if len(raw) == 0 {
			if readErr == io.EOF {
				break
			}
			continue
		}

		var rec rawRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: malformed JSON: %v", lineNum, err))
			if readErr == io.EOF {
				break
			}
			continue
		}

		ts := parseTimestamp(rec.AuditTimestamp)

		switch rec.Type {
		case "user":
			a.handleUser(&res, path, rec, sessionID, projectRoot, projectRemote, &sc, ts, pending, sidechain, cacheAcc)
		case "assistant":
			a.handleAssistant(&res, path, rec, sessionID, projectRoot, projectRemote, &sc, ts, pending, allToolUseIdx, &reasoning, sidechain, cacheAcc)
		case "system":
			a.handleSystem(&res, path, rec, sessionID, projectRoot, projectRemote, &sc, ts, pendingPermissions)
		case "result":
			a.handleResult(&res, path, rec, sessionID, projectRoot, projectRemote, &sc, ts, cacheAcc)
		case "tool_use_summary":
			handleToolUseSummary(&res, rec, allToolUseIdx)
		case "rate_limit_event":
			a.handleRateLimitEvent(&res, path, rec, sessionID, projectRoot, projectRemote, &sc, ts)
		default:
			res.Warnings = append(res.Warnings, fmt.Sprintf("line %d: unknown record type %q", lineNum, rec.Type))
		}

		if readErr == io.EOF {
			break
		}
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	return res, nil
}

// handleUser emits ActionUserPrompt for free-text user messages and
// pairs tool_result content blocks with the matching tool_use index.
func (a *Adapter) handleUser(
	res *adapter.ParseResult,
	path string,
	rec rawRecord,
	sessionID, projectRoot, projectRemote string,
	sc *sidecar,
	ts time.Time,
	pending map[string]int,
	sidechain map[string]struct{},
	cacheAcc *cacheobs.Accumulator,
) {
	if len(rec.Message) == 0 {
		return
	}
	var msg rawMessage
	if err := json.Unmarshal(rec.Message, &msg); err != nil {
		return
	}
	blocks := decodeContent(msg.Content)
	cacheAcc.ObserveBlocks(accumulateCacheBlocksTier2(blocks, firstNonEmpty(msg.Role, "user")))
	if len(blocks) == 0 {
		return
	}

	// Pass 1: pair tool_result blocks with prior tool_use events.
	for _, b := range blocks {
		if b.Type != "tool_result" {
			continue
		}
		idx, ok := pending[b.ToolUseID]
		if !ok {
			continue
		}
		body := decodeResultContent(b.Content)
		scrubbed := a.scrubber.String(body)
		res.ToolEvents[idx].ToolOutput = scrubbed
		if b.IsError {
			res.ToolEvents[idx].Success = false
			res.ToolEvents[idx].ErrorMessage = truncate(scrubbed, 500)
		}
		call := &res.ToolEvents[idx]
		if call.DurationMs == 0 && !call.Timestamp.IsZero() && !ts.IsZero() {
			if d := ts.Sub(call.Timestamp).Milliseconds(); d > 0 {
				call.DurationMs = d
			}
		}
		delete(pending, b.ToolUseID)
	}

	// Pass 2: emit user_prompt for free-text content (excluding tool_result-only messages).
	// Image-only user messages (no text, no tool_result, just image
	// attachments) would otherwise fall through silently — emit a
	// marker row instead so the dashboard shows the user activity.
	// Image cost lands on the next result.modelUsage.input bucket;
	// this row is observability-only.
	// Structured user-attachment metadata (Issue 1): the images/documents
	// the user attached to this turn (kind + optional media_type),
	// captured for image-only turns and turns that also carry text.
	// Metadata only — no bytes, no filename.
	var atts []models.UserAttachment
	for _, b := range blocks {
		switch b.Type {
		case "image":
			atts = append(atts, models.UserAttachment{Kind: "image", MediaType: b.imageMediaType()})
		case "document":
			atts = append(atts, models.UserAttachment{Kind: "file", MediaType: b.imageMediaType()})
		}
	}
	text := userPromptText(blocks)
	if text == "" {
		if len(atts) > 0 {
			text = fmt.Sprintf("[user sent %d image attachment(s)]", len(atts))
		} else {
			return
		}
	}
	preview := truncate(text, 200)
	_, isSidechain := sidechain[rec.UUID]
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         path,
		SourceEventID:      rec.UUID,
		SessionID:          sessionID,
		ProjectRoot:        projectRoot,
		GitRemote:          projectRemote,
		Timestamp:          ts,
		Tool:               models.ToolCowork,
		ActionType:         models.ActionUserPrompt,
		Target:             preview,
		Success:            true,
		PrecedingReasoning: preview,
		RawToolName:        "user_message",
		RawToolInput:       a.scrubber.String(text),
		MessageID:          "user:" + rec.UUID,
		IsSidechain:        isSidechain,
		Metadata:           coworkMetadata(sc, "", "", 0, 0, 0),
		UserAttachments:    atts,
	})
}

// handleAssistant emits ToolEvents for assistant text + thinking +
// tool_use content blocks. Token accounting is NOT emitted here — the
// audit.jsonl's assistant.message.usage is a streaming snapshot
// (output_tokens often stuck at 0 mid-stream) and never surfaces the
// haiku invocations Cowork dispatches internally. TokenEvents for
// cowork sessions are emitted from `result.modelUsage` in handleResult
// instead, which is the SDK's authoritative per-model accounting.
// See docs/cowork-cost-drift-investigation-2026-05-15.md.
func (a *Adapter) handleAssistant(
	res *adapter.ParseResult,
	path string,
	rec rawRecord,
	sessionID, projectRoot, projectRemote string,
	sc *sidecar,
	ts time.Time,
	pending map[string]int,
	allToolUseIdx map[string]int,
	reasoning *[]string,
	sidechain map[string]struct{},
	cacheAcc *cacheobs.Accumulator,
) {
	_, isSidechain := sidechain[rec.UUID]
	if len(rec.Message) == 0 {
		return
	}
	var msg rawMessage
	if err := json.Unmarshal(rec.Message, &msg); err != nil {
		return
	}

	blocks := decodeContent(msg.Content)
	cacheAcc.ObserveBlocks(accumulateCacheBlocksTier2(blocks, firstNonEmpty(msg.Role, "assistant")))
	for blockIdx, b := range blocks {
		switch b.Type {
		case "text":
			text := strings.TrimSpace(b.Text)
			if text == "" {
				continue
			}
			*reasoning = appendCapped(*reasoning, text, 20)
			preview := truncate(a.scrubber.String(text), 200)
			meta := coworkMetadata(sc, "", "", 0, 0, 0)
			if msg.Usage != nil {
				meta = coworkMetadata(
					sc,
					msg.Usage.ServiceTier, msg.Usage.InferenceGeo,
					msg.Usage.CacheCreation.Ephemeral5mInputTokens,
					msg.Usage.CacheCreation.Ephemeral1hInputTokens,
					0,
				)
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:         path,
				SourceEventID:      fmt.Sprintf("%s:text:%d", rec.UUID, blockIdx),
				SessionID:          sessionID,
				ProjectRoot:        projectRoot,
				GitRemote:          projectRemote,
				Timestamp:          ts,
				Tool:               models.ToolCowork,
				Model:              msg.Model,
				ActionType:         models.ActionAssistantMessage,
				Target:             preview,
				Success:            true,
				PrecedingReasoning: preview,
				RawToolName:        "cowork.assistant_text",
				ToolOutput:         a.scrubber.String(contentcap.Cap(text, contentcap.DefaultMaxBytes)),
				MessageID:          firstNonEmpty(msg.ID, "asst:"+rec.UUID),
				IsSidechain:        isSidechain,
				Metadata:           meta,
			})

		case "thinking":
			th := strings.TrimSpace(b.Thinking)
			if th == "" {
				continue
			}
			// REASONING SEMANTICS (B3 convergence, 2026-07-31): the
			// thinking block is accumulated into the per-message
			// reasoning buffer and reaches the timeline ONLY as
			// PrecedingReasoning on the tool_use rows that follow it in
			// this message (FAN-OUT accumulate — see lastReasoning below;
			// one thinking block can precede several tool calls and each
			// carries it). It is deliberately NOT emitted as a standalone
			// task_complete row: a reasoning block is not an action, and
			// the phantom rows polluted every action aggregate (see
			// docs/plans/b3-reasoning-convergence-plan-2026-07-31.md §1).
			*reasoning = appendCapped(*reasoning, th, 20)

		case "tool_use":
			rawInput := string(b.Input)
			scrubbedInput := a.scrubber.RawJSON(b.Input)
			actionType, ok := actionMap[b.Name]
			if !ok {
				actionType = models.ActionUnknown
				if models.IsMCPToolName(b.Name) {
					// mcp__<server>__<tool> not in the semantic remap
					// table defaults to a plain MCP call.
					actionType = models.ActionMCPCall
				}
			}
			meta := coworkMetadata(sc, "", "", 0, 0, 0)
			if msg.Usage != nil {
				meta = coworkMetadata(
					sc,
					msg.Usage.ServiceTier, msg.Usage.InferenceGeo,
					msg.Usage.CacheCreation.Ephemeral5mInputTokens,
					msg.Usage.CacheCreation.Ephemeral1hInputTokens,
					0,
				)
			}
			evt := models.ToolEvent{
				SourceFile:         path,
				SourceEventID:      b.ID,
				SessionID:          sessionID,
				ProjectRoot:        projectRoot,
				GitRemote:          projectRemote,
				Timestamp:          ts,
				Tool:               models.ToolCowork,
				Model:              msg.Model,
				ActionType:         actionType,
				Target:             extractTarget(b.Name, b.Input, projectRoot),
				Success:            true,
				PrecedingReasoning: truncate(lastReasoning(*reasoning), 1000),
				RawToolName:        b.Name,
				RawToolInput:       firstNonEmpty(scrubbedInput, scrub.Truncate(rawInput)),
				MessageID:          firstNonEmpty(msg.ID, "asst:"+rec.UUID),
				IsSidechain:        isSidechain,
				Metadata:           meta,
			}
			idx := len(res.ToolEvents)
			res.ToolEvents = append(res.ToolEvents, evt)
			if b.ID != "" {
				pending[b.ID] = idx
				allToolUseIdx[b.ID] = idx
			}
		}
	}
}

// handleResult emits ActionTaskComplete from a `result` record AND a
// TokenEvent for each model in result.modelUsage. The modelUsage map
// is Cowork's authoritative per-batch per-model accounting: summing
// CostUSD across modelUsage entries equals the result's top-level
// total_cost_usd to the cent across every observed session. This is
// the cowork adapter's canonical token source — assistant-row
// message.usage is streaming-snapshot data and is no longer used.
//
// The 5m/1h cache-creation tier split is derived from the result's
// top-level usage.cache_creation block when present. The fraction
// applies uniformly to each model's cacheCreationInputTokens; this is
// approximate (the tier split is per-final-turn, not per-batch) but
// matches Cowork's own internal accounting exactly for opus-4-6 and
// is close-enough for sonnet/haiku (the residual <10% drift is a
// pricing-table-vs-Cowork-rate-card question, not a token-attribution
// one — see docs/cowork-cost-drift-investigation-2026-05-15.md).
func (a *Adapter) handleResult(
	res *adapter.ParseResult,
	path string,
	rec rawRecord,
	sessionID, projectRoot, projectRemote string,
	sc *sidecar,
	ts time.Time,
	cacheAcc *cacheobs.Accumulator,
) {
	preview := truncate(a.scrubber.String(rec.Result), 200)
	meta := coworkMetadata(sc, "", "", 0, 0, rec.TotalCostUSD)
	// Cowork's authoritative stop_reason lives on the `result` record
	// root (the assistant message's is null mid-stream — same reason
	// tokens come from result.modelUsage, not the streaming usage block).
	if rec.StopReason != "" {
		if meta == nil {
			meta = &models.ActionMetadata{}
		}
		meta.StopReason = rec.StopReason
	}
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:         path,
		SourceEventID:      rec.UUID,
		SessionID:          sessionID,
		ProjectRoot:        projectRoot,
		GitRemote:          projectRemote,
		Timestamp:          ts,
		Tool:               models.ToolCowork,
		ActionType:         models.ActionTaskComplete,
		Target:             preview,
		Success:            !rec.IsError,
		ErrorMessage:       "",
		DurationMs:         rec.DurationMs,
		PrecedingReasoning: preview,
		RawToolName:        "cowork.result",
		ToolOutput:         a.scrubber.String(contentcap.Cap(rec.Result, contentcap.DefaultMaxBytes)),
		MessageID:          "result:" + rec.UUID,
		Metadata:           meta,
	})

	// Derive the 1h-tier fraction from the result's top-level usage
	// when available. Falls back to 0 (all 5m) when the usage block is
	// missing or carries zero cache_creation.
	var tier1hFrac float64
	if rec.TopUsage != nil {
		topCw := rec.TopUsage.CacheCreationInputTokens
		if topCw == 0 {
			topCw = rec.TopUsage.CacheCreation.Ephemeral5mInputTokens +
				rec.TopUsage.CacheCreation.Ephemeral1hInputTokens
		}
		if topCw > 0 {
			tier1hFrac = float64(rec.TopUsage.CacheCreation.Ephemeral1hInputTokens) / float64(topCw)
		}
	}

	// Stable ordering across map iterations so resume-from-offset
	// returns the same TokenEvent sequence on every run.
	models_ := make([]string, 0, len(rec.ModelUsage))
	for m := range rec.ModelUsage {
		models_ = append(models_, m)
	}
	sort.Strings(models_)

	for _, model := range models_ {
		mu := rec.ModelUsage[model]
		cw := mu.CacheCreationInputTokens
		cw1h := int64(float64(cw) * tier1hFrac)
		if cw1h > cw {
			cw1h = cw
		}
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile:            path,
			SourceEventID:         rec.UUID + ":" + model,
			SessionID:             sessionID,
			ProjectRoot:           projectRoot,
			GitRemote:             projectRemote,
			Timestamp:             ts,
			Tool:                  models.ToolCowork,
			Model:                 model,
			InputTokens:           mu.InputTokens,
			OutputTokens:          mu.OutputTokens,
			CacheReadTokens:       mu.CacheReadInputTokens,
			CacheCreationTokens:   cw,
			CacheCreation1hTokens: cw1h,
			WebSearchRequests:     mu.WebSearchRequests,
			Source:                models.TokenSourceJSONL,
			Reliability:           models.ReliabilityAccurate,
			MessageID:             "result:" + rec.UUID + ":" + model,
		})
	}

	res.CacheObservations = append(res.CacheObservations,
		emitCacheObservationsTier2(cacheAcc, path, sessionID, rec, ts, rec.ModelUsage, tier1hFrac, models_)...)
}

// coworkMetadata builds an ActionMetadata stamped with sidecar
// decorations + per-event usage fields. Returns nil when every field
// is zero — avoids allocating a struct only to have store.Ingest
// marshal it to NULL.
func coworkMetadata(sc *sidecar, serviceTier, inferenceGeo string, cache5m, cache1h int64, totalCostUSD float64) *models.ActionMetadata {
	m := models.ActionMetadata{
		CoworkProcessName: sc.ProcessName,
		CoworkTitle:       sc.Title,
		HostLoopMode:      sc.HostLoopMode,
		ServiceTier:       serviceTier,
		InferenceGeo:      inferenceGeo,
		CacheCreate5mTok:  cache5m,
		CacheCreate1hTok:  cache1h,
		TotalCostUSD:      totalCostUSD,
	}
	if m.IsZero() {
		return nil
	}
	return &m
}

// userPromptText extracts the free-text content from a user message,
// ignoring tool_result blocks. Returns "" when no text exists.
func userPromptText(blocks []rawContentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && strings.TrimSpace(b.Text) != "" {
			parts = append(parts, b.Text)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n")
}

// decodeContent handles both array and bare-string forms of
// message.content (mirrors claudecode's helper).
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

// decodeResultContent unwraps a tool_result's content field which
// may be a plain string, a single object, or an array of objects with
// `type:"text"` blocks (matches the Claude API tool_result shape).
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
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	case '[':
		var blocks []rawContentBlock
		if err := json.Unmarshal(raw, &blocks); err == nil {
			var parts []string
			for _, b := range blocks {
				if b.Text != "" {
					parts = append(parts, b.Text)
				}
			}
			return strings.Join(parts, "\n")
		}
	case '{':
		var b rawContentBlock
		if err := json.Unmarshal(raw, &b); err == nil {
			return b.Text
		}
	}
	return string(raw)
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

// extractTarget pulls the human-meaningful target string from a
// tool_use input payload. Mirrors claudecode's helper for shared
// tool names. Cowork-specific names fall through to "".
func extractTarget(toolName string, rawInput []byte, projectRoot string) string {
	if len(rawInput) == 0 {
		return ""
	}
	var input map[string]any
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
	case "Read", "Write", "Edit", "NotebookEdit":
		if fp := pick("file_path"); fp != "" {
			if projectRoot != "" {
				return git.RelativePath(projectRoot, fp)
			}
			return fp
		}
	case "Bash", "mcp__workspace__bash":
		return pick("command")
	case "Grep":
		return pick("pattern")
	case "Glob":
		return pick("pattern")
	case "WebSearch":
		return pick("query")
	case "WebFetch", "mcp__workspace__web_fetch":
		return pick("url")
	case "Task", "Agent":
		return pick("subagent_type", "description")
	case "Skill":
		return pick("skill", "name")
	}
	return ""
}

// parseTimestamp handles the audit.jsonl `_audit_timestamp` field
// (ISO-8601 with milliseconds; UTC `Z` suffix in practice).
func parseTimestamp(s string) time.Time {
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

func appendCapped(s []string, v string, cap int) []string {
	s = append(s, v)
	if len(s) > cap {
		return s[len(s)-cap:]
	}
	return s
}

func lastReasoning(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// handleToolUseSummary joins a tool_use_summary record to the matching
// tool_use action via preceding_tool_use_ids[0] and stamps the summary
// text onto that action's Metadata.CoworkToolSummary. Idempotent: a
// second summary for the same tool_use overwrites (last write wins —
// Cowork emits at most one per tool batch in observed data).
func handleToolUseSummary(res *adapter.ParseResult, rec rawRecord, allToolUseIdx map[string]int) {
	if rec.Summary == "" || len(rec.PrecedingToolIDs) == 0 {
		return
	}
	idx, ok := allToolUseIdx[rec.PrecedingToolIDs[0]]
	if !ok {
		return
	}
	ev := &res.ToolEvents[idx]
	if ev.Metadata == nil {
		ev.Metadata = &models.ActionMetadata{}
	}
	ev.Metadata.CoworkToolSummary = truncate(rec.Summary, 500)
}

// handleSystem dispatches the six system-subtype records:
//
//   - init                — session bootstrap (intentionally skipped; the
//     cwd is already reflected in the sidecar, and Cowork's `tools[]` /
//     `mcp_servers[]` / `slash_commands[]` rosters don't fit any single
//     Observer action_type. Future work: lift `init.model` to fill in
//     model attribution for stub sessions that never reach a `result`).
//   - status              — heartbeat (intentionally skipped; carries
//     only `status: "requesting"` and no payload of interest).
//   - permission_request  → ActionPermissionRequest (queued; the
//     matching permission_response patches Success + ApprovalKind).
//   - permission_response → patches the queued request with the
//     granted/denied outcome (response shares UUID with request).
//   - permission_denied   → ActionPermissionDenied with the platform's
//     reason text in ErrorMessage and the decision-reason-type in
//     RawToolName.
//   - compact_boundary    → ActionContextCompacted mirroring the
//     claudecode shape — Target is "<trigger>: ~<preTokens> tokens
//     reclaimed", RawToolInput carries the full metadata JSON.
func (a *Adapter) handleSystem(
	res *adapter.ParseResult,
	path string,
	rec rawRecord,
	sessionID, projectRoot, projectRemote string,
	sc *sidecar,
	ts time.Time,
	pendingPermissions map[string]int,
) {
	switch rec.Subtype {
	case "init", "status":
		return
	case "permission_request":
		meta := &models.ActionMetadata{
			CoworkProcessName: sc.ProcessName,
			CoworkTitle:       sc.Title,
			HostLoopMode:      sc.HostLoopMode,
		}
		if meta.IsZero() {
			meta = nil
		}
		rawIn := a.scrubber.RawJSON(rec.ToolInput)
		if rawIn == "" {
			rawIn = scrub.Truncate(string(rec.ToolInput))
		}
		idx := len(res.ToolEvents)
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: rec.UUID,
			SessionID:     sessionID,
			ProjectRoot:   projectRoot,
			GitRemote:     projectRemote,
			Timestamp:     ts,
			Tool:          models.ToolCowork,
			ActionType:    models.ActionPermissionRequest,
			Target:        rec.ToolName,
			Success:       true, // pending — patched by permission_response
			RawToolName:   "permission_request",
			RawToolInput:  rawIn,
			MessageID:     "perm:" + rec.UUID,
			Metadata:      meta,
		})
		if rec.UUID != "" {
			pendingPermissions[rec.UUID] = idx
		}
	case "permission_response":
		// Patches the matching request (same UUID). When a request
		// row isn't in flight (e.g. resumed parse where the request
		// landed in a prior batch), the response is dropped — the
		// adapter doesn't retro-update DB rows.
		idx, ok := pendingPermissions[rec.UUID]
		if !ok {
			return
		}
		ev := &res.ToolEvents[idx]
		granted := rec.Granted != nil && *rec.Granted
		ev.Success = granted
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		ev.Metadata.PermissionApprovalKind = rec.Decision
		delete(pendingPermissions, rec.UUID)
	case "permission_denied":
		// `message` field carries the human-readable denial reason
		// as a JSON string. For user/assistant records the same
		// rawRecord.Message field is a JSON object, but on
		// permission_denied it's always a string — try-decode it as
		// one and fall through silently if the type doesn't match.
		var reason string
		_ = json.Unmarshal(rec.Message, &reason)
		meta := &models.ActionMetadata{
			CoworkProcessName: sc.ProcessName,
			CoworkTitle:       sc.Title,
			HostLoopMode:      sc.HostLoopMode,
		}
		if meta.IsZero() {
			meta = nil
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: rec.UUID,
			SessionID:     sessionID,
			ProjectRoot:   projectRoot,
			GitRemote:     projectRemote,
			Timestamp:     ts,
			Tool:          models.ToolCowork,
			ActionType:    models.ActionPermissionDenied,
			Target:        rec.ToolName,
			Success:       false,
			ErrorMessage:  a.scrubber.String(truncate(reason, 500)),
			RawToolName:   firstNonEmpty(rec.DecisionReasonType, "permission_denied"),
			MessageID:     "perm:" + rec.UUID,
			Metadata:      meta,
		})
	case "compact_boundary":
		if rec.CompactMetadata == nil {
			return
		}
		cm := rec.CompactMetadata
		target := fmt.Sprintf("%s: ~%d tokens reclaimed", cm.Trigger, cm.PreTokens)
		rawIn, _ := json.Marshal(cm)
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile:    path,
			SourceEventID: "compact:" + rec.UUID,
			SessionID:     sessionID,
			ProjectRoot:   projectRoot,
			GitRemote:     projectRemote,
			Timestamp:     ts,
			Tool:          models.ToolCowork,
			ActionType:    models.ActionContextCompacted,
			Target:        truncate(target, 200),
			Success:       true,
			DurationMs:    cm.DurationMs,
			RawToolName:   "compact_boundary",
			RawToolInput:  string(rawIn),
			MessageID:     "compact:" + rec.UUID,
		})
	}
}

// handleRateLimitEvent emits an ActionRateLimit row carrying the
// rate-limit window status. Cowork polls rate limits periodically
// (~50/session in observed data); each poll lands as a distinct
// row so the dashboard can chart status transitions over time. Not
// deduped — see plan §M2/T20 for the rationale.
func (a *Adapter) handleRateLimitEvent(
	res *adapter.ParseResult,
	path string,
	rec rawRecord,
	sessionID, projectRoot, projectRemote string,
	sc *sidecar,
	ts time.Time,
) {
	if len(rec.RateLimitInfo) == 0 {
		return
	}
	var info struct {
		Status                string `json:"status"`
		ResetsAt              int64  `json:"resetsAt"`
		RateLimitType         string `json:"rateLimitType"`
		OverageStatus         string `json:"overageStatus"`
		OverageDisabledReason string `json:"overageDisabledReason"`
		IsUsingOverage        bool   `json:"isUsingOverage"`
	}
	if err := json.Unmarshal(rec.RateLimitInfo, &info); err != nil {
		return
	}

	// Base sidecar decorations + rate-limit-specific fields.
	meta := &models.ActionMetadata{
		CoworkProcessName:      sc.ProcessName,
		CoworkTitle:            sc.Title,
		HostLoopMode:           sc.HostLoopMode,
		RateLimitStatus:        info.Status,
		RateLimitType:          info.RateLimitType,
		RateLimitResetsAt:      info.ResetsAt,
		RateLimitOverageStatus: info.OverageStatus,
	}
	if meta.IsZero() {
		meta = nil
	}

	scrubbed := a.scrubber.String(string(rec.RateLimitInfo))
	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    path,
		SourceEventID: rec.UUID,
		SessionID:     sessionID,
		ProjectRoot:   projectRoot,
		GitRemote:     projectRemote,
		Timestamp:     ts,
		Tool:          models.ToolCowork,
		ActionType:    models.ActionRateLimit,
		Target:        info.RateLimitType,
		Success:       info.Status == "allowed",
		ErrorMessage:  info.OverageDisabledReason,
		RawToolName:   info.Status,
		RawToolInput:  scrubbed,
		MessageID:     "ratelimit:" + rec.UUID,
		Metadata:      meta,
	})
}

// collectSidechainUUIDs walks the local-instance's inner Claude Code
// subagent transcripts (under `.claude/projects/<encoded-cwd>/<id>/subagents/agent-*.jsonl`)
// and returns the set of assistant.uuid values seen — these are the
// audit.jsonl rows we should flag IsSidechain=true.
//
// Best-effort: missing `.claude` tree returns an empty set without
// error. Empty set is the common case for local-instances that never
// spawned sub-agents.
//
// Implementation: filepath.WalkDir descends recursively, picking only
// files whose basename matches `agent-*.jsonl` AND whose parent dir
// is named `subagents`. Each line is JSON-decoded just for `uuid` +
// `type`.
func collectSidechainUUIDs(instanceDir string) map[string]struct{} {
	out := map[string]struct{}{}
	claudeProjects := filepath.Join(instanceDir, ".claude", "projects")
	info, err := os.Stat(claudeProjects)
	if err != nil || !info.IsDir() {
		return out
	}
	_ = filepath.WalkDir(claudeProjects, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable subtrees; not fatal.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(p)
		if !strings.HasPrefix(base, "agent-") || filepath.Ext(base) != ".jsonl" {
			return nil
		}
		if filepath.Base(filepath.Dir(p)) != "subagents" {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for sc.Scan() {
			var rec struct {
				Type string `json:"type"`
				UUID string `json:"uuid"`
			}
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				continue
			}
			if rec.Type == "assistant" && rec.UUID != "" {
				out[rec.UUID] = struct{}{}
			}
		}
		return nil
	})
	return out
}

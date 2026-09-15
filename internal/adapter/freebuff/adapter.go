// Package freebuff implements an adapter for Freebuff, the free CodebuffAI
// coding agent (npm `freebuff`; the Manicode -> Codebuff -> Freebuff
// lineage, which is why the store lives under a legacy `manicode` dir).
//
// TWO LAYOUTS, ONE TOOL ID. Freebuff ships a CLI and a desktop app; both are
// the same product line, so both report `models.ToolFreebuff` and differ only
// in their store shape and their capture-surface stamp (see layoutSurfaces).
// The layout is resolved from the path SHAPE at the boundary — never by
// branching on tool identity downstream (CLAUDE.md module rule #3).
//
// Layout 1 — CLI chats (same on Linux, macOS, and Windows: Freebuff uses
// ~/.config/manicode on every OS, per the CodebuffAI/freebuff Windows
// bug report referencing .config\manicode\freebuff.exe):
//
//	~/.config/manicode/projects/<slug>/chats/<RFC3339-timestamp>/
//	  chat-messages.json  the transcript: an array of message objects,
//	                      variant "user"|"ai", each with a `blocks` array
//	                      (text/tool/agent/mode-divider). The <RFC3339>
//	                      dir name is the `freebuff --continue <id>` handle.
//	  run-state.json      large state sidecar; sessionState.fileContext.
//	                      projectRoot is the ONLY statement of the real cwd.
//
// THIN store: the CLI layout records NO per-turn token accounting (run-state
// has a running contextTokenCount, which is a context-window size, not
// billable usage), so it emits sessions + actions only — no TokenEvents.
//
// Layout 2 — Freebuff Desktop (also `.config` on every OS):
//
//	~/.config/freebuff-desktop/projects/<name>-<uuid>/
//	  desktop-v2.db   the store: SQLite in WAL mode (the live data is
//	                  usually in the -wal). Tables projects / threads /
//	                  messages (+ queue_items, thread_deliveries, ...). One
//	                  thread = one session; one assistant `messages` row
//	                  holds the WHOLE turn in an ordered parts_json array.
//	  project.json    {projectId, projectPath, database} — the last-resort
//	                  project-root fallback.
//
// Unlike the CLI, the Desktop DOES persist real per-turn usage
// (messages.metrics_json), so the desktop layout emits TokenEvents; input is
// OpenAI-style GROSS and is netted against cachedInputTokens. See
// desktop.go::desktopTokenEvent.
//
// Off-limits (never read): credentials.json, the freebuff ELF/exe binary,
// message-history.json (raw input strings), and log.jsonl (which carries
// hostname / userId / userEmail PII) on the CLI side; `state.json` (which
// holds an OAuth-style auth TOKEN plus the operator's name and email under
// `authSessions`) and `state.json.orchestrator-lock.sqlite` on the Desktop
// side. This adapter reads only chat-messages.json + its sibling
// run-state.json (CLI) and desktop-v2.db + its sibling project.json
// (Desktop). The avoidance is structural: IsSessionFile matches ONLY those
// two entry points, and the sibling reads are the two named files.
// TestOffLimitsFilesNeverDispatchedOrIngested and
// TestDesktopOffLimitsFilesNeverDispatchedOrIngested pin it.
package freebuff

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	projectsSubpath = "/manicode/projects/"
	chatsSegment    = "/chats/"
	messagesName    = "chat-messages.json"
	runStateName    = "run-state.json"

	// Desktop layout.
	desktopProjectsSubpath = "/freebuff-desktop/projects/"
	desktopDBName          = "desktop-v2.db"
	desktopProjectJSONName = "project.json"
	// desktopStateName holds an auth TOKEN plus the operator's name and
	// email under `authSessions`; desktopStateLockDBName is its sibling
	// orchestrator lock. Both are named ONLY so isDesktopOffLimits can
	// reject them by name — neither is ever opened.
	desktopStateName       = "state.json"
	desktopStateLockDBName = "state.json.orchestrator-lock.sqlite"

	maxTargetLen    = 500
	maxReasoningLen = 2000
	// maxAgentNestDepth caps recursive descent into agent blocks' own
	// nested blocks arrays. Grounded real data nests one level deep (a
	// subagent's private tool-call transcript); the cap is a defensive
	// bound against adversarial/malformed input, not an observed depth.
	maxAgentNestDepth = 6
)

// Adapter parses Freebuff session directories.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default roots.
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
func (*Adapter) Name() string { return models.ToolFreebuff }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// layout names one of Freebuff's two on-disk store shapes.
type layout uint8

const (
	// layoutUnknown is "not a freebuff session file".
	layoutUnknown layout = iota
	// layoutCLIChats is ~/.config/manicode/projects/<slug>/chats/<ts>/chat-messages.json.
	layoutCLIChats
	// layoutDesktop is ~/.config/freebuff-desktop/projects/<name>-<uuid>/desktop-v2.db.
	layoutDesktop
)

// layoutSurfaces is the ONE table mapping a store layout onto its
// capture-surface stamp. The path SHAPE is the grounded discriminator: the
// CLI writes only under `manicode/projects/.../chats`, the Desktop only under
// `freebuff-desktop/projects`, and (as of the 2026-09-03 grounding) neither
// writes the other's store. Same pattern as kirocli's layoutSurfaces.
var layoutSurfaces = map[layout]models.SessionSurface{
	layoutCLIChats: {Surface: models.SurfaceCLI, SurfaceHost: "freebuff"},
	layoutDesktop:  {Surface: models.SurfaceDesktop, SurfaceHost: "freebuff-desktop"},
}

// surfaceFor returns the surface stamp for one session of a given layout.
// An unknown layout stamps nothing (the honest "no grounded discriminator").
func surfaceFor(l layout, sessionID string) models.SessionSurface {
	s, ok := layoutSurfaces[l]
	if !ok {
		return models.SessionSurface{}
	}
	s.SessionID = sessionID
	return s
}

// defaultRoots returns both layouts' project directories across every
// detected home. Freebuff uses `.config` on EVERY OS for both stores —
// `.config/manicode` for the CLI (per the CodebuffAI/freebuff Windows bug
// report referencing `.config\manicode\freebuff.exe`) and
// `.config/freebuff-desktop` for the Desktop (grounded 2026-09-03 against a
// native Windows install at `C:\Users\<u>\.config\freebuff-desktop`) — so
// there is no per-OS subpath table here, unlike goose or kiro-cli.
func defaultRoots() []string {
	seen := map[string]bool{}
	var roots []string
	add := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		roots = append(roots, p)
	}
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, ".config", "manicode", "projects"))
		add(filepath.Join(h.Path, ".config", "freebuff-desktop", "projects"))
	}
	return roots
}

// IsSessionFile implements adapter.Adapter: the per-chat chat-messages.json
// (CLI) or the per-project desktop-v2.db (Desktop) under a watch root.
// run-state.json and project.json are read as siblings, not tracked.
func (a *Adapter) IsSessionFile(path string) bool {
	if layoutFor(path) == layoutUnknown {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// layoutFor resolves a path onto its store layout by SHAPE alone (no I/O).
func layoutFor(path string) layout {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	base := filepath.Base(lower)
	switch {
	case isDesktopOffLimits(base):
		return layoutUnknown
	case base == messagesName &&
		strings.Contains(lower, projectsSubpath) && strings.Contains(lower, chatsSegment):
		return layoutCLIChats
	case (base == desktopDBName || base == desktopDBName+"-wal" || base == desktopDBName+"-shm") &&
		strings.Contains(lower, desktopProjectsSubpath):
		// The `-wal` / `-shm` siblings are CLAIMED (the pattern every
		// WAL-SQLite adapter here uses — cline-cli, kirocli, antigravity):
		// a live capture lives almost entirely in the WAL (1.28 MB of WAL
		// against a 4 KB main file on the grounding run), and the
		// watcher's cursor poll cannot re-fire this layout — it gates on
		// file size vs cursor, and the cursor is an epoch-ms watermark far
		// above any file size. fsnotify on the sidecars is what keeps the
		// store live; parseDesktopStore maps them back onto the main db
		// (desktopMainDBPath) so every row keys on one SourceFile.
		return layoutDesktop
	default:
		return layoutUnknown
	}
}

// isDesktopOffLimits names the Desktop files that must never be dispatched
// to the parser, regardless of where they sit. `state.json` carries an auth
// token and the operator's identity; its orchestrator lock is a private
// SQLite sibling.
func isDesktopOffLimits(base string) bool {
	return base == desktopStateName || base == desktopStateLockDBName
}

// freebuffMessage is one element of chat-messages.json.
type freebuffMessage struct {
	Variant string          `json:"variant"`
	Content string          `json:"content"`
	ID      string          `json:"id"`
	Blocks  []freebuffBlock `json:"blocks"`
}

type freebuffBlock struct {
	Type     string `json:"type"`
	TextType string `json:"textType"`
	Content  string `json:"content"`
	// tool block
	ToolName   string          `json:"toolName"`
	ToolCallID string          `json:"toolCallId"`
	Input      json.RawMessage `json:"input"`
	Output     json.RawMessage `json:"output"`
	// agent block. InitialPrompt is empty in every real capture; the
	// actual invocation args live in Params (e.g. {"command":"..."}).
	// Blocks is the subagent's OWN private tool-call transcript — real
	// captures show it non-empty (walked recursively, depth-capped).
	AgentName     string          `json:"agentName"`
	AgentType     string          `json:"agentType"`
	InitialPrompt string          `json:"initialPrompt"`
	Params        json.RawMessage `json:"params"`
	Blocks        []freebuffBlock `json:"blocks"`
}

// ParseSessionFile implements adapter.Adapter. chat-messages.json is a whole
// JSON array rewritten in place, so the persisted cursor is a MESSAGE COUNT
// (fromOffset = messages already emitted), not a byte offset: it re-reads the
// file, emits messages[fromOffset-1:] (re-covering the last, possibly-updated
// message — block SourceEventIDs are stable so the store dedupes), and returns
// the new message count. No TokenEvents (Freebuff records no per-turn usage).
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	if layoutFor(path) == layoutDesktop {
		return a.parseDesktopStore(ctx, path, fromOffset)
	}
	return a.parseCLIChats(path, fromOffset)
}

// parseCLIChats is the CLI (manicode/chats) layout's parser.
func (a *Adapter) parseCLIChats(path string, fromOffset int64) (adapter.ParseResult, error) {
	data, err := os.ReadFile(path) //nolint:gosec // watched session file
	if err != nil {
		return adapter.ParseResult{}, nil // vanished mid-poll; retry later
	}
	var msgs []freebuffMessage
	if err := json.Unmarshal(data, &msgs); err != nil {
		return adapter.ParseResult{NewOffset: fromOffset}, nil // partial write; retry
	}

	sessID := sessionIDFromPath(path)
	root, branch, projectIdentity := a.resolveProjectRoot(path)
	base := parseChatDirTime(sessID)

	res := adapter.ParseResult{NewOffset: int64(len(msgs))}
	// Re-cover the last already-seen message (it may have grown new blocks).
	start := int(fromOffset) - 1
	if start < 0 {
		start = 0
	}
	for i := start; i < len(msgs); i++ {
		ts := base.Add(time.Duration(i) * time.Second)
		a.emitMessage(&res, path, sessID, root, branch, ts, i, msgs[i])
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	res.SessionSurfaces = append(res.SessionSurfaces, surfaceFor(layoutCLIChats, sessID))
	return res, nil
}

func (a *Adapter) emitMessage(res *adapter.ParseResult, path, sessID, root, branch string, ts time.Time, msgIdx int, m freebuffMessage) {
	if m.Variant == "user" {
		text := a.scrubber.String(firstNonEmpty(m.Content, userTextFromBlocks(m.Blocks)))
		if text == "" {
			return
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile: path, SourceEventID: idFor(sessID, msgIdx, "0", "user"),
			SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
			Tool: models.ToolFreebuff, ActionType: models.ActionUserPrompt,
			Target: truncate(text, maxTargetLen), Success: true,
		})
		return
	}
	// variant "ai": walk blocks (depth 0 = the message's own top-level array).
	a.emitBlocks(res, path, sessID, root, branch, ts, msgIdx, m.Blocks, "", 0)
}

// emitBlocks walks one blocks array (a message's top-level blocks, or an
// agent block's own nested transcript) and appends ToolEvents. idPrefix is
// the dotted SourceEventID path of the parent (empty at the top level, so a
// top-level block's id is unchanged from before this was made recursive);
// depth guards against unbounded recursion into nested agent blocks.
func (a *Adapter) emitBlocks(res *adapter.ParseResult, path, sessID, root, branch string, ts time.Time, msgIdx int, blocks []freebuffBlock, idPrefix string, depth int) {
	// sidechain is true for every block emitted from INSIDE a nested
	// agent block's own transcript (depth > 0) — i.e. everything this
	// call walks except the message's own top-level blocks (depth 0).
	// The "agent" block that SPAWNS a subagent is emitted at the depth
	// of its parent's context, so a top-level spawn (depth 0) is never
	// flagged, matching the convention that the spawn action itself is
	// not a sidechain — only the spawned work is. A nested agent block
	// found while already inside a subagent (depth > 0, agent-in-agent)
	// is itself sidechain, since spawning it is already subagent work.
	sidechain := depth > 0
	// A leading run of reasoning text threads onto the next actionable
	// block as PrecedingReasoning; scoped to this blocks array only — a
	// subagent's own transcript does not inherit its parent's reasoning.
	var reasoning string
	for bi, b := range blocks {
		blockPath := idPrefix + strconv.Itoa(bi)
		switch b.Type {
		case "text":
			if b.TextType == "reasoning" {
				reasoning = truncate(a.scrubber.String(firstNonEmpty(reasoning, b.Content)), maxReasoningLen)
				continue
			}
			if txt := a.scrubber.String(b.Content); txt != "" {
				res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
					SourceFile: path, SourceEventID: idFor(sessID, msgIdx, blockPath, "text"),
					SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
					Tool: models.ToolFreebuff, ActionType: models.ActionAssistantMessage,
					Target: truncate(txt, maxTargetLen), Success: true, PrecedingReasoning: reasoning,
					IsSidechain: sidechain,
				})
				reasoning = ""
			}
		case "tool":
			action, target := mapFreebuffTool(b.ToolName, b.Input)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: idFor(sessID, msgIdx, blockPath, firstNonEmpty(b.ToolCallID, "tool")),
				SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
				Tool: models.ToolFreebuff, ActionType: action, RawToolName: b.ToolName,
				RawToolInput:       a.scrubber.RawJSON(b.Input),
				Target:             truncate(a.scrubber.String(target), maxTargetLen),
				ToolOutput:         a.scrubber.String(rawToText(b.Output)),
				Success:            true,
				PrecedingReasoning: reasoning,
				IsSidechain:        sidechain,
			})
			reasoning = ""
		case "agent":
			// InitialPrompt is empty in every real capture; Params carries the
			// actual invocation args (e.g. {"command":"..."}) and is the far
			// more useful target when present.
			target := firstNonEmpty(b.InitialPrompt, targetFromInput(b.Params), b.AgentName)
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: idFor(sessID, msgIdx, blockPath, "agent"),
				SessionID: sessID, ProjectRoot: root, GitBranch: branch, Timestamp: ts,
				Tool: models.ToolFreebuff, ActionType: models.ActionSpawnSubagent,
				RawToolName: firstNonEmpty(b.AgentType, b.AgentName, "agent"),
				Target:      truncate(a.scrubber.String(target), maxTargetLen),
				Success:     true, PrecedingReasoning: reasoning,
				IsSidechain: sidechain,
			})
			reasoning = ""
			// Real agent blocks carry their own nested tool-call transcript;
			// walk it (depth-capped) so a subagent's actions are captured too.
			if len(b.Blocks) > 0 && depth < maxAgentNestDepth {
				a.emitBlocks(res, path, sessID, root, branch, ts, msgIdx, b.Blocks, blockPath+".", depth+1)
			}
		default:
			// mode-divider and unknown block kinds are non-actionable.
		}
	}
}

// mapFreebuffTool maps a freebuff tool name to a normalized action + target.
func mapFreebuffTool(name string, input json.RawMessage) (string, string) {
	target := targetFromInput(input)
	switch name {
	case "read_files", "read_file":
		return models.ActionReadFile, target
	case "write_file", "create_file":
		return models.ActionWriteFile, target
	case "str_replace", "edit_file":
		return models.ActionEditFile, target
	case "run_terminal_command", "run_command", "bash":
		return models.ActionRunCommand, target
	case "code_search", "grep":
		return models.ActionSearchText, target
	case "find_files", "glob", "list_directory":
		return models.ActionSearchFiles, target
	case "web_search":
		return models.ActionWebSearch, target
	case "read_url", "web_fetch":
		return models.ActionWebFetch, target
	case "spawn_agents", "spawn_agent":
		// Defensive/likely-vestigial: real captures always represent a
		// subagent spawn as a "agent"-typed block (see emitBlocks), never
		// as a "tool"-typed block with this toolName — even though
		// spawn_agents does appear as an internal call in the app's own
		// debug log. Kept for forward compatibility.
		return models.ActionSpawnSubagent, target
	case "write_todos":
		return models.ActionTodoUpdate, target
	case "ask_user":
		return models.ActionAskUser, target
	case "skill":
		return models.ActionSkillInvoke, target
	case "browser_use":
		return models.ActionBrowserAction, target
	case "set_output":
		return models.ActionTaskComplete, target
	default:
		// suggest_prompts (desktop) / suggest_followups (CLI) ARE observed
		// live but are not tools the model acts with (they render UI
		// suggestions) — deliberately rowless, ActionUnknown with the raw
		// name preserved. tmux_cli, read_subtree, render_ui, gravity_index,
		// file_picker, context_pruner: present in the app's capability-list
		// toolNames but never observed as an actual invocation — left
		// honestly unmapped rather than guessed. See
		// docs/freebuff-adapter.md known gaps.
		return models.ActionUnknown, target
	}
}

func targetFromInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, k := range []string{"command", "path", "paths", "file_path", "filePath", "url", "query", "pattern"} {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func (a *Adapter) resolveProjectRoot(messagesPath string) (root, branch string, id git.Identity) {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(messagesPath), runStateName)) //nolint:gosec // sibling of a watched file
	if err != nil {
		return "[freebuff]", "", git.Identity{}
	}
	var rs struct {
		SessionState struct {
			FileContext struct {
				ProjectRoot string `json:"projectRoot"`
				Cwd         string `json:"cwd"`
			} `json:"fileContext"`
		} `json:"sessionState"`
	}
	if err := json.Unmarshal(data, &rs); err != nil {
		return "[freebuff]", "", git.Identity{}
	}
	cwd := strings.TrimSpace(firstNonEmpty(rs.SessionState.FileContext.ProjectRoot, rs.SessionState.FileContext.Cwd))
	if cwd == "" {
		return "[freebuff]", "", git.Identity{}
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	// STAT-GATE before git.ResolveIdentity (the goose / crush precedent): a
	// path that isn't locally reachable is returned verbatim, because
	// filepath.Abs would otherwise CWD-prefix the foreign string onto the
	// observer's own drive (a WSL cwd read on a Windows host becomes
	// `D:\home\dev\...`).
	if _, err := os.Stat(cwd); err != nil {
		return cwd, "", git.Identity{}
	}
	identity, err := git.ResolveIdentity(cwd, git.IdentityOptions{})
	if err != nil {
		return cwd, "", git.Identity{}
	}
	return identity.Root, identity.Branch, identity
}

// sessionIDFromPath returns the chat dir name — the RFC3339 timestamp that is
// the `freebuff --continue <id>` handle.
func sessionIDFromPath(messagesPath string) string {
	return filepath.Base(filepath.Dir(messagesPath))
}

// parseChatDirTime turns Freebuff's filesystem-safe chat dir name
// (2026-08-11T07-07-38.552Z, dashes where a timestamp has colons) into a
// time. Per-message timestamps in the transcript are display-only ("12:38
// PM", no date), so the dir name is the only real anchor.
func parseChatDirTime(dir string) time.Time {
	// Convert the two dashes in the time portion (after 'T') to colons.
	t := dir
	if i := strings.IndexByte(t, 'T'); i >= 0 {
		head, tail := t[:i+1], t[i+1:]
		tail = strings.Replace(tail, "-", ":", 2)
		t = head + tail
	}
	if v, err := time.Parse(time.RFC3339Nano, t); err == nil {
		return v
	}
	if v, err := time.Parse(time.RFC3339, t); err == nil {
		return v
	}
	return time.Time{}
}

func userTextFromBlocks(blocks []freebuffBlock) string {
	for _, b := range blocks {
		if b.Type == "text" && b.Content != "" {
			return b.Content
		}
	}
	return ""
}

func rawToText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// idFor builds a stable per-block SourceEventID. blockPath is a dotted path
// (e.g. "4" for a top-level block, "4.1" for the second block inside the
// agent block at top-level index 4) so nested-agent blocks get distinct,
// stable ids without colliding with top-level ones.
func idFor(sessID string, msgIdx int, blockPath, kind string) string {
	return kind + ":" + sessID + ":" + strconv.Itoa(msgIdx) + ":" + blockPath
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

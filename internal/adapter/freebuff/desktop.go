package freebuff

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// desktopPart is one element of a `messages.parts_json` array.
//
// NOTE the deliberate absence of an `ad` field. Freebuff Desktop interleaves
// advertising parts (`{"kind":"ad", "ad":{…}}`) into the assistant turn, and
// their `clickUrl` embeds a signed JWT carrying the operator's own user id.
// Not declaring the field means the payload is never even decoded, let alone
// persisted — structural avoidance, not a filtered copy.
type desktopPart struct {
	Kind     string          `json:"kind"`
	ID       string          `json:"id"`
	Text     string          `json:"text"`
	ToolName string          `json:"toolName"`
	Input    json.RawMessage `json:"input"`
	Output   json.RawMessage `json:"output"`
	Status   string          `json:"status"`
	Files    []desktopChange `json:"files"`
}

// desktopChange is one entry of a `changes` part's `files` array — the
// turn's workspace diff panel.
type desktopChange struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Adds   int64  `json:"adds"`
	Dels   int64  `json:"dels"`
}

// desktopUsage is the per-turn usage envelope from `messages.metrics_json`.
//
// `context.usedTokens` / `windowTokens` are DELIBERATELY not decoded: they
// are context-window OCCUPANCY, not billable usage, and turning them into a
// token row would be the same category error the CLI layout avoids with
// `contextTokenCount`.
type desktopMetrics struct {
	Usage struct {
		InputTokens       int64 `json:"inputTokens"`
		CachedInputTokens int64 `json:"cachedInputTokens"`
		OutputTokens      int64 `json:"outputTokens"`
		TotalTokens       int64 `json:"totalTokens"`
	} `json:"usage"`
	CostUSD float64 `json:"costUsd"`
}

// parseDesktopStore is the desktop layout's ParseSessionFile body. fromOffset
// is the epoch-millis watermark returned by the previous call.
func (a *Adapter) parseDesktopStore(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	// A `-wal` / `-shm` sibling event parses the MAIN store and keys
	// every row on it, so the three watched paths converge on one
	// SourceFile (each path keeps its own cursor row; the parse is
	// idempotent, so a sidecar-triggered re-read is a no-op past the
	// watermark).
	path = desktopMainDBPath(path)
	db, err := openDesktopDB(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("freebuff.ParseSessionFile: open: %w", err)
	}
	defer db.Close()

	latest, err := desktopWatermark(ctx, db)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("freebuff.ParseSessionFile: watermark: %w", err)
	}
	res := adapter.ParseResult{NewOffset: latest}
	if latest <= fromOffset {
		return res, nil
	}

	threads, err := loadTouchedThreads(ctx, db, fromOffset)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("freebuff.ParseSessionFile: threads: %w", err)
	}
	for _, th := range threads {
		if th.TurnState != "" && th.TurnState != "idle" {
			// A turn is still streaming: the assistant row is rewritten
			// in place until it ends (metrics_json is `{}` meanwhile), so
			// nothing from this thread is final yet. Turn end bumps
			// threads.updated_at past this watermark and the thread is
			// re-covered whole. Older schemas without turn_state read ""
			// and are never gated.
			continue
		}
		msgs, err := loadDesktopMessages(ctx, db, th.ID)
		if err != nil {
			return adapter.ParseResult{}, fmt.Errorf("freebuff.ParseSessionFile: messages: %w", err)
		}
		if len(msgs) == 0 {
			continue
		}
		a.emitDesktopThread(&res, path, th, msgs)
	}
	return res, nil
}

// emitDesktopThread turns one thread (a session) and its messages into
// ToolEvents + TokenEvents + a surface stamp.
func (a *Adapter) emitDesktopThread(res *adapter.ParseResult, path string, th desktopThread, msgs []desktopMessage) {
	root, branch, remote := a.resolveDesktopProjectRoot(path, th)
	for _, m := range msgs {
		var parts []desktopPart
		if err := json.Unmarshal([]byte(m.PartsJSON), &parts); err != nil {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("freebuff-desktop: thread %s seq %d: parts_json: %v", th.ID, m.Seq, err))
			continue
		}
		ts := millisToTime(m.TS)
		if strings.EqualFold(m.Role, "user") {
			a.emitDesktopUserPrompt(res, path, th, root, branch, remote, ts, m.Seq, parts)
		} else {
			a.emitDesktopParts(res, path, th, root, branch, remote, ts, m.Seq, parts)
		}
		if te, ok := a.desktopTokenEvent(path, th, root, branch, remote, ts, m); ok {
			res.TokenEvents = append(res.TokenEvents, te)
		}
	}
	res.SessionSurfaces = append(res.SessionSurfaces, surfaceFor(layoutDesktop, th.ID))
}

func (a *Adapter) emitDesktopUserPrompt(res *adapter.ParseResult, path string, th desktopThread,
	root, branch, remote string, ts time.Time, seq int64, parts []desktopPart,
) {
	for i, p := range parts {
		if p.Kind != "text" {
			continue
		}
		text := strings.TrimSpace(a.scrubber.String(p.Text))
		if text == "" {
			continue
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile: path, SourceEventID: desktopIDFor("user", th.ID, seq, partKey(p, i)),
			SessionID: th.ID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
			Timestamp: ts, Tool: models.ToolFreebuff, Model: th.Model,
			ActionType: models.ActionUserPrompt,
			Target:     truncate(text, maxTargetLen), Success: true,
		})
	}
}

// emitDesktopParts walks an assistant message's ordered parts array.
//
// Part-kind handling, all grounded against a live 2026-09-03 capture:
//
//	text      → ActionAssistantMessage (whitespace-only separators skipped),
//	            matching the CLI layout's non-reasoning text block.
//	reasoning → threaded onto the NEXT actionable row as PrecedingReasoning,
//	            exactly like the CLI layout's textType=="reasoning" block.
//	tool      → the shared mapFreebuffTool normalization.
//	ad        → SKIPPED, never persisted (see desktopPart's doc comment).
//	changes   → per-file rows ONLY for paths no tool part in the SAME message
//	            already touched (see emitDesktopChanges).
func (a *Adapter) emitDesktopParts(res *adapter.ParseResult, path string, th desktopThread,
	root, branch, remote string, ts time.Time, seq int64, parts []desktopPart,
) {
	var reasoning string
	touched := touchedPaths(parts)
	for i, p := range parts {
		switch p.Kind {
		case "reasoning":
			reasoning = truncate(a.scrubber.String(firstNonEmpty(reasoning, p.Text)), maxReasoningLen)
		case "text":
			text := strings.TrimSpace(a.scrubber.String(p.Text))
			if text == "" {
				continue // "\n\n" spacer parts between tool calls
			}
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: desktopIDFor("text", th.ID, seq, partKey(p, i)),
				SessionID: th.ID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
				Timestamp: ts, Tool: models.ToolFreebuff, Model: th.Model,
				ActionType: models.ActionAssistantMessage,
				Target:     truncate(text, maxTargetLen), Success: true,
				PrecedingReasoning: reasoning,
			})
			reasoning = ""
		case "tool":
			action, target := mapFreebuffTool(p.ToolName, p.Input)
			if strings.TrimSpace(target) == "" {
				// Never a blank target: a tool with no path/command
				// argument (suggest_prompts) carries its own name so the
				// row stays attributable on the dashboard.
				target = p.ToolName
			}
			ok, errMsg := desktopOutcome(p.Status, rawToText(p.Output))
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile: path, SourceEventID: desktopIDFor("tool", th.ID, seq, partKey(p, i)),
				SessionID: th.ID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
				Timestamp: ts, Tool: models.ToolFreebuff, Model: th.Model,
				ActionType: action, RawToolName: p.ToolName,
				RawToolInput: a.scrubber.RawJSON(p.Input),
				Target:       truncate(a.scrubber.String(target), maxTargetLen),
				ToolOutput:   a.scrubber.String(rawToText(p.Output)),
				Success:      ok, ErrorMessage: truncate(a.scrubber.String(errMsg), maxTargetLen),
				PrecedingReasoning: reasoning,
			})
			reasoning = ""
		case "changes":
			a.emitDesktopChanges(res, path, th, root, branch, remote, ts, seq, i, p, touched)
		default:
			// "ad" and any future kind: non-actionable, never persisted.
		}
	}
}

// emitDesktopChanges emits one row per file in a `changes` part that no tool
// part in the SAME message already covered.
//
// Two grounded facts drive the design. (a) In the live capture the single
// changed file (`hello_world.py`) was already covered by a `write_file` and a
// `str_replace` tool part, so emitting it again would double-count the same
// edit — hence the per-message dedupe against touchedPaths. (b) The part's
// own `status` is NOT trustworthy as history: the capture reports the file as
// `"added"` even though the same turn ended by deleting it, so `changes` is a
// point-in-time diff panel, not an event log. Every surviving row is
// therefore emitted as the neutral ActionEditFile ("this turn changed this
// file") rather than trusting added/modified/deleted.
func (a *Adapter) emitDesktopChanges(res *adapter.ParseResult, path string, th desktopThread,
	root, branch, remote string, ts time.Time, seq int64, idx int, p desktopPart,
	touched map[string]bool,
) {
	for j, f := range p.Files {
		file := strings.TrimSpace(f.Path)
		if file == "" || touched[normalizePathKey(file)] {
			continue
		}
		res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
			SourceFile: path,
			SourceEventID: desktopIDFor("changes", th.ID, seq,
				partKey(p, idx)+"."+strconv.Itoa(j)),
			SessionID: th.ID, ProjectRoot: root, GitBranch: branch, GitRemote: remote,
			Timestamp: ts, Tool: models.ToolFreebuff, Model: th.Model,
			ActionType: models.ActionEditFile, RawToolName: "changes",
			Target:  truncate(a.scrubber.String(file), maxTargetLen),
			Success: true,
		})
	}
}

// touchedPaths collects the file paths a message's own tool parts already
// account for, so a `changes` part cannot double-count them.
func touchedPaths(parts []desktopPart) map[string]bool {
	out := map[string]bool{}
	for _, p := range parts {
		if p.Kind != "tool" {
			continue
		}
		// Only FILE-MUTATING tools count as coverage. A read_files part
		// names a path without accounting for a change to it, so treating
		// a read as coverage would suppress a genuine `changes` row for a
		// file some shell command rewrote.
		switch mapAction(p.ToolName) {
		case models.ActionWriteFile, models.ActionEditFile:
		default:
			continue
		}
		for _, v := range allPathsFromInput(p.Input) {
			out[normalizePathKey(v)] = true
		}
	}
	return out
}

// mapAction is mapFreebuffTool's action half, without the target derivation.
func mapAction(name string) string {
	action, _ := mapFreebuffTool(name, nil)
	return action
}

// normalizePathKey makes the dedupe separator-insensitive so a Windows-shaped
// tool input and a forward-slash `changes` path compare equal.
func normalizePathKey(p string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "./"))
}

// allPathsFromInput returns every file path a tool input names — both the
// singular spellings and `paths[]` / `replacements[].path`.
func allPathsFromInput(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	var out []string
	for _, k := range []string{"path", "file_path", "filePath"} {
		if s, ok := m[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if arr, ok := m["paths"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// desktopOutcome maps a tool part's `status` onto (success, errorMessage).
//
// Only `run_terminal_command` persists `status`/`output` in grounded data —
// `read_files` / `write_file` / `str_replace` / `list_directory` /
// `suggest_prompts` carry neither, BY DESIGN rather than because the result
// is still pending. An absent status is therefore read as success (and NOT
// as OutcomePending, which would file every silent tool as unobserved).
func desktopOutcome(status, output string) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "success", "ok", "completed":
		return true, ""
	default:
		return false, output
	}
}

// desktopTokenEvent builds the per-message token row from metrics_json.
//
// Netting: freebuff Desktop reports OpenAI-style GROSS input —
// `inputTokens` INCLUDES `cachedInputTokens` (108245 = 14037 fresh + 94208
// cached in the grounded capture, and totalTokens 109867 = inputTokens +
// outputTokens confirms input is the gross figure). The normalized row is
// therefore InputTokens = inputTokens − cachedInputTokens and
// CacheReadTokens = cachedInputTokens.
//
// No cache-CREATION counterpart exists in the envelope, so
// CacheCreationTokens stays 0 rather than being guessed.
//
// EstimatedCostUSD is only carried when the provider reported a non-zero
// `costUsd`; the grounded value is 0 (a free-tier gateway run), and leaving
// it at 0 lets the cost engine price `deepseek/deepseek-v4-flash` from its
// own table instead of pinning the turn at "free".
func (a *Adapter) desktopTokenEvent(path string, th desktopThread, root, branch, remote string,
	ts time.Time, m desktopMessage,
) (models.TokenEvent, bool) {
	var mt desktopMetrics
	if err := json.Unmarshal([]byte(m.MetricsJSON), &mt); err != nil {
		return models.TokenEvent{}, false
	}
	gross, cached, out := mt.Usage.InputTokens, mt.Usage.CachedInputTokens, mt.Usage.OutputTokens
	if gross <= 0 && cached <= 0 && out <= 0 {
		return models.TokenEvent{}, false
	}
	net := gross - cached
	if net < 0 {
		net = 0
	}
	te := models.TokenEvent{
		SourceFile:      path,
		SourceEventID:   desktopIDFor("tokens", th.ID, m.Seq, "usage"),
		SessionID:       th.ID,
		ProjectRoot:     root,
		GitBranch:       branch,
		GitRemote:       remote,
		Timestamp:       ts,
		Tool:            models.ToolFreebuff,
		Model:           th.Model,
		InputTokens:     net,
		OutputTokens:    out,
		CacheReadTokens: cached,
		Source:          models.TokenSourceJSONL,
		Reliability:     models.ReliabilityAccurate,
		MessageID:       th.ID + ":" + strconv.FormatInt(m.Seq, 10),
	}
	if mt.CostUSD > 0 {
		te.EstimatedCostUSD = mt.CostUSD
	}
	return te, true
}

// resolveDesktopProjectRoot resolves the session's project root through the
// grounded ladder: threads.project_path → projects.root_path → the sibling
// project.json's `projectPath`. Foreign-mount Windows paths are translated
// and STAT-GATED before git.Resolve, so an unreachable path is returned
// verbatim instead of being CWD-prefixed onto the observer's own repo.
func (a *Adapter) resolveDesktopProjectRoot(dbPath string, th desktopThread) (root, branch, remote string) {
	cwd := pickDesktopProjectPath(th.ProjectPath, th.RootPath, func() string {
		return projectPathFromSidecar(dbPath)
	})
	if cwd == "" {
		return "[freebuff]", th.Branch, ""
	}
	cwd = crossmount.TranslateForeignPath(cwd)
	if _, err := os.Stat(cwd); err != nil {
		return cwd, th.Branch, ""
	}
	info, err := git.Resolve(cwd)
	if err != nil {
		return cwd, th.Branch, ""
	}
	return info.Root, firstNonEmpty(info.Branch, th.Branch), git.NormalizeRemote(info.Remote)
}

// pickDesktopProjectPath is the pure half of the project-root ladder; the
// sidecar read is deferred behind a closure so the common case never opens a
// file.
func pickDesktopProjectPath(projectPath, rootPath string, sidecar func() string) string {
	if v := strings.TrimSpace(projectPath); v != "" {
		return v
	}
	if v := strings.TrimSpace(rootPath); v != "" {
		return v
	}
	if sidecar == nil {
		return ""
	}
	return strings.TrimSpace(sidecar())
}

// partKey returns the stable per-part component of a SourceEventID: the
// part's own id when it has one (tool call ids, and the `p<n>-<inputId>`
// ids Freebuff Desktop stamps on reasoning / ad / changes parts), otherwise
// its array index. Parts are APPENDED as a turn streams, so an index is
// stable for every part already written.
func partKey(p desktopPart, idx int) string {
	if id := strings.TrimSpace(p.ID); id != "" {
		return id
	}
	return strconv.Itoa(idx)
}

// desktopIDFor builds a deterministic SourceEventID.
//
// The shape is intentionally DISJOINT from the CLI layout's
// (`<kind>:<RFC3339 chat dir>:<message index>:<block path>`): the desktop id
// is keyed on the thread UUID plus the `messages.seq` AUTOINCREMENT, neither
// of which the CLI store has. Should a future Freebuff build ever write both
// stores for one run, the two layouts' rows can never be mistaken for each
// other — and, as measured on 2026-09-03, the Desktop writes NO
// `~/.config/manicode` store at all, so no twin exists today.
func desktopIDFor(kind, threadID string, seq int64, part string) string {
	return kind + ":" + threadID + ":" + strconv.FormatInt(seq, 10) + ":" + part
}

// millisToTime converts freebuff Desktop's epoch-MILLISECOND timestamps.
func millisToTime(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

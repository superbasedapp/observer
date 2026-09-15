package kirocrew

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Adapter is the file-watcher implementation of the Kiro Crew adapter.
// It reads ONE thing — the desktop app's chat transcripts under
// `~/.kiro/crew/sessions/*.jsonl` — and applies the double-count rule
// documented in doc.go before emitting anything.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an Adapter with the platform-default roots (KIROCREW_HOME
// override, or every cross-mount-resolved `<home>/.kiro/crew/sessions`)
// and a default scrubber.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customises scrubber and roots for tests. Pass nil
// scrubber for the default; pass no roots for default platform discovery.
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
func (*Adapter) Name() string { return models.ToolKiroCrew }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// IsSessionFile reports whether path is a Kiro Crew chat transcript: a
// `*.jsonl` file sitting DIRECTLY under a `sessions` watch root, and
// nested under one of this adapter's WatchPaths.
//
// The `.jsonl` suffix test also rejects the `<name>.jsonl.lock` sibling
// the Gateway writes next to every live transcript.
//
// Deliberately not narrowed to the grounded `dashboard_chat-*` basename:
// `dashboard` is the SOURCE THREAD, and session_map.json's sibling keys
// (`slack_thread_ts` / `slack_channel_id`) show Crew addresses chats from
// other threads too. Narrowing on the one observed thread would silently
// drop those. The shape gate that actually matters runs at parse time —
// a file whose first line is not a `_type:metadata` header emits nothing
// and warns.
func (a *Adapter) IsSessionFile(path string) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".jsonl") {
		return false
	}
	if filepath.Base(filepath.Dir(path)) != sessionsDir {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.roots)
}

// CursorSemanticsFor implements adapter.CursorSemantics. A Crew chat
// transcript is whole-file re-read on every tick (see parseConversation)
// with the FILE SIZE persisted as the cursor, so byte lag is meaningful
// and the size gate applies — but zero action rows is the EXPECTED
// outcome, not a misroute fingerprint: on every grounded capture the chat
// is driven by a kiro-cli agent session that internal/adapter/kirocli
// already owns, and this adapter deliberately emits nothing for it.
//
// Pure and cheap as the interface requires: no I/O, no map read.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorNoActions,
		Detail: "kiro-crew chat transcripts are a view of a kiro-cli agent session; the conversation's rows are emitted by the kiro-cli adapter",
	}
}

// ParseSessionFile implements adapter.Adapter.
//
// NewOffset is always the file SIZE, not a resume point: the transcript's
// line 1 is a mutable metadata header, so the file is re-read whole every
// tick and idempotence comes from deterministic SourceEventIDs.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return res, fmt.Errorf("kirocrew.ParseSessionFile: %w", err)
	}
	res.NewOffset = info.Size()

	body, err := os.ReadFile(path) //nolint:gosec // path derives from a validated watch-root trigger
	if err != nil {
		return res, fmt.Errorf("kirocrew.ParseSessionFile: %w", err)
	}

	conv := parseConversation(body)
	res.Warnings = append(res.Warnings, conv.warnings...)
	if len(conv.events) == 0 {
		return res, nil
	}

	// THE DOUBLE-COUNT RULE (doc.go "Ownership"): a Crew chat driven by a
	// kiro-cli agent session is the SAME conversation as that session's
	// own store, down to byte-identical tool-call ids. kiro-cli owns it.
	switch own, twinSID := resolveOwnership(path); own {
	case ownedByKiroCLI:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"kiro-crew: chat %s is driven by kiro-cli session %s; rows emitted by the kiro-cli adapter, not duplicated here",
			mapKeyForFile(path), twinSID))
		return res, nil
	case ownershipUnresolved:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"kiro-crew: cannot resolve whether chat %q has a kiro-cli agent session (%s absent/unreadable); emitting nothing rather than risk a duplicate conversation",
			filepath.Base(path), sessionMapFile))
		return res, nil
	}

	a.emit(&res, path, conv)
	return res, nil
}

// emit turns a decoded conversation into ToolEvents. Reached ONLY on the
// ownedBySelf branch — a Crew chat with no kiro-cli twin, where this
// transcript is the only record of the conversation.
//
// No TokenEvents are ever emitted: the Crew transcript carries NO token
// or usage fields of any kind (see doc.go "Tokens"). An honest zero, not
// a fabricated one.
func (a *Adapter) emit(res *adapter.ParseResult, path string, conv conversation) {
	sessionID := sessionIDFor(path)
	if sessionID == "" {
		res.Warnings = append(res.Warnings, "kiro-crew: cannot derive a session id from "+filepath.Base(path))
		return
	}
	projectRoot, gitBranch, gitRemote := resolveProjectRoot(conv.meta.Project)
	model := strings.TrimSpace(conv.meta.Model)

	base := models.ToolEvent{
		SourceFile:  path,
		SessionID:   sessionID,
		ProjectRoot: projectRoot,
		GitBranch:   gitBranch,
		GitRemote:   gitRemote,
		Model:       model,
		Tool:        models.ToolKiroCrew,
	}

	for _, ev := range conv.events {
		e := base
		e.Timestamp = ev.ts
		e.TurnIndex = ev.turn
		switch ev.kind {
		case "user":
			e.SourceEventID = eventID(ev.mid, "user", ev.order)
			e.ActionType = models.ActionUserPrompt
			e.Target = a.scrubber.String(contentcap.Cap(ev.text, contentcap.DefaultMaxBytes))
			e.Success = true
		case "assistant":
			e.SourceEventID = eventID(ev.mid, "assistant", ev.order)
			e.ActionType = models.ActionAssistantMessage
			e.Target = a.scrubber.String(contentcap.Cap(ev.text, contentcap.DefaultMaxBytes))
			e.Success = true
			// Present only on the line that closed a user turn.
			e.DurationMs = ev.durationMs
		case "tool":
			action, target, contentBytes := resolveTool(ev.tool)
			if action == models.ActionUnknown {
				res.Warnings = append(res.Warnings,
					"kiro-crew: tool call "+ev.tool.id+" has an unmapped kind "+
						strconv.Quote(ev.tool.kind)+" (recorded as unknown)")
			}
			out, success, errMsg := toolOutcome(ev.tool)
			e.SourceEventID = ev.tool.id
			e.ActionType = action
			e.Target = a.scrubber.String(contentcap.Cap(target, contentcap.DefaultMaxBytes))
			e.RawToolName = ev.tool.kind
			e.RawToolInput = a.scrubber.String(contentcap.Cap(ev.tool.input, contentcap.DefaultMaxBytes))
			e.ToolOutput = a.scrubber.String(contentcap.Cap(out, contentcap.DefaultMaxBytes))
			e.ContentBytes = contentBytes
			// Outcome comes from the shell envelope's exit_status, NOT
			// from `done` — Crew sets `done` on the completion half of
			// every pair, successful or not (see toolOutcome). A call
			// still in flight is marked OutcomePending so the store does
			// not file an unobserved success.
			e.Success = success
			e.ErrorMessage = errMsg
			e.OutcomePending = !ev.tool.done
		default:
			continue
		}
		res.ToolEvents = append(res.ToolEvents, e)
	}

	res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
		SessionID:   sessionID,
		Surface:     models.SurfaceDesktop,
		SurfaceHost: surfaceHost,
	})
}

// sessionIDFor derives the session id from the transcript basename — the
// chat-slot key ("dashboard_chat-2-1700000002"), which is stable for the
// life of the chat tab and unique within a Crew install.
func sessionIDFor(path string) string {
	return strings.TrimSuffix(filepath.Base(path), ".jsonl")
}

// eventID builds a deterministic SourceEventID. The transcript's own
// `mid` is preferred; a line without one falls back to its 1-based record
// ordinal, which is stable because the transcript is append-only below
// the metadata header.
func eventID(mid, role string, order int) string {
	if mid != "" {
		return mid + ":" + role
	}
	return role + ":" + strconv.Itoa(order)
}

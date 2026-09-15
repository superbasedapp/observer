package droid

import "github.com/marmutapp/superbased-observer/internal/models"

// This file owns droid's SESSION-LANE attribution: which client
// (Factory Desktop vs the standalone CLI) produced a session (the
// capture surface), and whether a session is a user-initiated fork of
// another one (the fork lineage). Both are resolved from grounded
// fields the transcript itself carries, at the adapter boundary, so
// nothing outside this file interprets a droid-specific token
// (CLAUDE.md #3/#5).
//
// # Why there is no separate "cli" surface value
//
// Grounded live 2026-09-03 across a 4-session capture (5-turn prompt
// kit, one Factory Desktop run forked mid-session, one CLI session
// started fresh and continued via `droid --resume <id>`, one empty
// "New Session" desktop scratch session): every real user-typed turn
// (`message.role="user"`, no `visibility`) a Factory Desktop-composed
// session sends carries `message.userMessageSource:"desktop"`. Every
// CLI-composed prompt — in this capture AND in the pre-existing
// `testdata/factory/` Linux/Windows CLI fixtures — OMITS the field
// entirely; there is no observed `"cli"` (or any other) value. A
// session_start-level field (`client`, `entrypoint`, `source`,
// `platform`, …) was also grepped for across all 4 files' `session_start`
// records and found nowhere; `hostId` is identical across all 4
// sessions (same machine ran both lanes) so it is not a client
// discriminator either.
//
// So the only grounded signal is a POSITIVE one: the field's presence
// proves Desktop composed at least one turn. Its absence proves
// nothing — a session with no `userMessageSource` at all is NOT assumed
// to be CLI, because a future droid surface (or an older/newer build)
// could simply not stamp the field either way. This is the same
// discipline the devin adapter's surfaceRules table documents: only
// the presence of a grounded per-client marker is trusted; absence
// never becomes a guessed alternative.
const userMessageSourceDesktop = "desktop"

// factoryDesktopHost is the SurfaceHost token stamped alongside
// models.SurfaceDesktop, naming the concrete client the same way
// devin stamps "devin-desktop" and cowork stamps "claude-desktop".
const factoryDesktopHost = "factory-desktop"

// desktopSurface returns the stamp to emit once a session is known to
// have at least one message.userMessageSource=="desktop" turn.
func desktopSurface(sessionID string) models.SessionSurface {
	return models.SessionSurface{
		SessionID:   sessionID,
		Surface:     models.SurfaceDesktop,
		SurfaceHost: factoryDesktopHost,
	}
}

// threadSourceUserFork is the models.SessionLineage.ThreadSource value
// for a droid session forked from another one. It deliberately reuses
// codex's existing "user" token (models.SessionLineage's own doc
// comment: `ThreadSource` is `"user"` — normal + user-fork — or
// `"subagent"`) rather than inventing a `"fork"` vocabulary word:
// droid's `session_start.parent` marks exactly a codex-shaped
// user-fork — the operator explicitly branched a NEW session off an
// existing one at a message boundary (`forkedAtMessageId`), not a
// runtime spawning a sub-agent thread for itself. droid has no
// observed self-spawned-subagent session shape to capture (the
// Task/TaskOutput/TaskStop "background task" tool calls documented in
// records.go's actionMap are a DIFFERENT surface — droid's own
// mission/worker sessions — and were never grounded live), so
// threadSourceUserFork is the only ThreadSource value this adapter
// emits today.
const threadSourceUserFork = "user"

// lineageForHeader returns the fork-lineage marker for a session whose
// session_start carries a non-blank `parent`. ParentThreadID is left
// empty: droid's wire has only the one `parent` field, unlike codex's
// distinct forked_from_id/parent_thread_id pair — there is no separate
// "spawning thread" concept to fill it with, and models.SessionLineage
// is COALESCE-preserving so leaving it blank is a no-op, never a lie.
// forkedAtMessageId is a MESSAGE id inside the parent transcript, not a
// session/thread id, so it has no field to land on and is not captured.
func lineageForHeader(sessionID, parent string) (models.SessionLineage, bool) {
	if sessionID == "" || parent == "" {
		return models.SessionLineage{}, false
	}
	return models.SessionLineage{
		SessionID:    sessionID,
		ForkedFromID: parent,
		ThreadSource: threadSourceUserFork,
	}, true
}

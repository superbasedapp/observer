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

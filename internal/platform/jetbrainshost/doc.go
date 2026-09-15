// Package jetbrainshost is the ONE owner of JetBrains-IDE host vocabulary
// for this codebase: where a JetBrains IDE keeps its per-product config
// directory on each OS, which surface-host token each product line maps
// to, how the IDE's AI Assistant names an agent session it drove through
// the ACP registry, and which Observer adapter owns that agent's own
// store. It is the JetBrains sibling of internal/platform/vscodehost and
// carries the same discipline: a data table plus path builders, no I/O of
// its own (directory listings are injected), so every consumer resolves
// the same products the same way.
//
// # Why a host helper and not an adapter
//
// A JetBrains IDE (2026.2 AI Assistant) is an ORCHESTRATION LAYER over
// agents that each keep their own store: Junie writes ~/.junie/sessions,
// the Claude Agent ACP runtime writes ~/.claude/projects, Codex writes
// ~/.codex/sessions, GitHub Copilot writes ~/.copilot/session-state — and
// every one of those is already captured by its own adapter. What the IDE
// adds is a per-task record under its config dir:
//
//	<config>/JetBrains/<Product><ver>/aia-task-history/<task-uuid>.agentsession
//	    one line: `acp.registry.<agent>:<agent's own session id>`
//	<task-uuid>.events   `AUI_EVENTS_V1` header, then base64(JSON) UI render
//	                     events — NO tokens, NO model (grounded 2026-09-03,
//	                     7 tasks / 4 agents: only prompt text, tool block
//	                     titles/commands/diffs, terminal output)
//	<task-uuid>.usage    `{"used":N,"size":M}` — context-WINDOW occupancy,
//	                     NOT billable tokens
//	<task-uuid>.lastid   the last event id
//
// So the IDE's record is worth exactly one thing to Observer: the fact
// that the agent's session was HOSTED by this IDE. That is a surface
// stamp on a session another adapter already ingested (`ide` /
// `jetbrains-idea`), applied through the hosted branch of
// Store.SetSessionSurface (models.SessionSurface.Hosted) by the
// internal/surfaceenrich loop — never a second tool id, never a second
// conversation row, never a token row. Building a `jetbrains` capture
// adapter over the .events files would double-count every agent's
// conversation and add no data the agent's own store lacks.
//
// # Config-directory convention
//
// JetBrains products keep per-version config under a vendor root whose
// location follows the platform convention (jetbrains.com/help/idea/
// directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs):
//
//   - Windows:           <home>/AppData/Roaming/JetBrains/<Product><ver>
//   - Windows (native):  %APPDATA%/JetBrains/<Product><ver> when the process
//     runs natively on Windows against its own home (the roaming profile
//     can live off the default drive — the same override vscodehost applies)
//   - macOS:              <home>/Library/Application Support/JetBrains/<Product><ver>
//   - Linux:              <home>/.config/JetBrains/<Product><ver>
//
// The version-suffixed directory names are whatever the IDE creates
// (`IntelliJIdea2026.2`, `IdeaIC2025.2`, `PyCharm2026.1`, …); this package
// never guesses a version — a consumer lists the vendor root and this
// package classifies each entry by its product prefix.
//
// # Host tokens
//
// The surface-host token for a product is `jetbrains-<product>` —
// `jetbrains-idea` for IntelliJ IDEA (Ultimate and Community share it: the
// same IDE, two editions), `jetbrains-pycharm`, `jetbrains-goland`, … —
// and the bare `jetbrains` when the product is not in the table. The
// same tokens resolve from the client string vendors' own agents write
// when the IDE spawns them: Codex's session_meta `originator` and Copilot
// CLI's `workspace.yaml` `client_name` both carry `JetBrains.IntelliJ IDEA`
// (grounded on the 2026-09-03 live run), so HostForClientName lets those
// adapters self-stamp the SAME token the enricher would apply.
//
// # ACP registry agents
//
// The `.agentsession` token names the agent through the IDE's ACP
// registry id. The table holds the agents driven on the grounding box
// whose pointer sid is byte-identical to the owning adapter's sessions.id
// — verified against the live database: junie / claude-acp / codex-acp /
// github-copilot (installed.json 2026-09-03) plus cline / kilo / devin /
// opencode (2026-09-04). Agents that ran but do NOT round-trip by exact
// id are stamped via an acpAgents NormalizeSessionID (mistral-vibe: the
// pointer's full uuid is truncated to the 8-hex the adapter stores).
// One agent remains absent (pi wrote no .agentsession pointer — see the
// acpAgents comment; antigravity-acp is now captured via the antigravity
// adapter's third ~/.gemini/antigravity-acp tree). An agent id outside the table resolves to nothing: the
// honesty rule (no stamp is better than a guessed tool) applies here
// exactly as it does in the adapters.
package jetbrainshost

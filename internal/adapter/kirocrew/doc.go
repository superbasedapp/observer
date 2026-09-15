// Package kirocrew captures AWS's Kiro Crew — the multi-agent "crew"
// orchestration layer on top of Kiro: a desktop app plus a `kirocrew`
// CLI, both talking to a local HTTP Gateway on localhost:5476.
//
// GROUNDED 2026-09-03 against a live signed-in Windows install (Google
// sign-in, Crew desktop; no `kirocrew` binary on PATH — the app lives
// under %LOCALAPPDATA%\kirocrew-desktop-updater). Every path, field and
// vocabulary token below was read off that install; the pre-grounding
// skeleton's central assumption was WRONG and is corrected here.
//
// # Store
//
//	~/.kiro/crew/sessions/<thread>_<slot>.jsonl   THE capture target.
//	                                              One file per desktop
//	                                              chat tab. Observed:
//	                                              dashboard_chat-2-1700000002.jsonl
//	~/.kiro/crew/session_map.json                 chat slot → driven
//	                                              kiro-cli session id.
//	                                              Read ONLY for the `sid`
//	                                              field (see Ownership).
//
// Data root override: KIROCREW_HOME (then `<root>/sessions`). Identical
// layout on every OS — Windows uses C:\Users\<u>\.kiro\crew, NOT
// %LOCALAPPDATA%, matching kiro-cli's own `~/.kiro/sessions`.
//
// CORRECTION vs the skeleton: the vendor README / kiro.dev docs tree
// names `~/.kiro/crew/conversations/`. That directory DOES NOT EXIST on a
// live install — the whole Crew root was listed on the step-in host and
// the transcripts are under `sessions/`. The skeleton's roots and
// IsSessionFile pointed at a directory that is never created.
//
// # Record shape
//
// Line 1 is the metadata header and is MUTABLE (title is auto-derived
// after the first turn; human_seen / last_consolidated flip with UI use):
//
//	{"_type":"metadata","created_at":"2026-09-03T09:41:06.472819+00:00",
//	 "last_consolidated":0,"memory_mode":"persistent",
//	 "title":"Hello World Python Project","title_origin":"auto",
//	 "agent":"default","model":"","project":"C:\\Users\\…\\antigravity",
//	 "folder_id":"f0000000feed","origin":"user","tags":["t0000000tag0"],
//	 "auto_tagged":true,"human_seen":true,"tab_id":"c0000000tab0"}
//
// Every later line carries role / content / ts / source_thread /
// source_user / meta. `role` is one of:
//
//	user       meta.mid; meta.pastes echoes content verbatim (not read)
//	assistant  meta.mid
//	tool       meta.{tool_call_id,purpose,input,kind,mid,done,output}
//
// A tool call appears as a PAIR of lines sharing one tool_call_id: the
// call half ("🔧 <label>", carrying `kind`) and the completion half
// ("✅ <label>", `kind:""`). The call half of an EDIT carries a
// human-readable unified diff in `input`; the completion half carries the
// structured JSON arguments. mergeToolLines folds them into one record
// and prefers the JSON-valid input. On the grounded capture 9 unique
// tool_call_ids span 17 tool lines (one call had no completion half).
//
// Because line 1 is mutable, the file is NOT byte-offset tailable: the
// header's length changes mid-session and a resume would land inside a
// line. The whole file is re-read on every tick with the file SIZE
// persisted as the cursor, and idempotence comes from deterministic
// SourceEventIDs (`mid` / `tool_call_id`) — the same tactic
// internal/adapter/kirocli uses for its flat bundle.
//
// # Ownership / the double-count rule
//
// Crew DRIVES kiro-cli as its execution engine. A Crew chat's turns are
// ALSO written to kiro-cli's own store at
// `~/.kiro/sessions/cli/<sid>.{json,jsonl}` with `session_state.
// agent_name == "kirocrew"`, and the two stores share BYTE-IDENTICAL
// `tooluse_*` call ids — they are provably the same conversation.
//
// kiro-cli is the CANONICAL owner. The evidence, from the step-in host:
//
//   - The kiro-cli store is the SUPERSET. It held THREE `agent_name ==
//     "kirocrew"` sessions (a dashboard chat, a Crew-workspace chat, and
//     one further agent run) while `sessions/` held ONE transcript.
//     Making Crew canonical and suppressing the twin would have silently
//     dropped two real sessions.
//   - The kiro-cli store is structurally richer for the shared chat: 10
//     assistant steps vs Crew's 5 narration messages, typed tool kinds
//     (`BuiltIn.FileWrite{command:"strReplace"}`) vs Crew's lossy
//     `kind:"edit"` label, a per-call success/failure `status`, thinking
//     blocks, per-turn `metering_usage`, and the model id (`auto`;
//     Crew's metadata `model` is the empty string).
//   - Crew's assistant text is a strict projection of kiro-cli's — the
//     first narration line is byte-identical in both files.
//
// So: internal/adapter/kirocli owns the rows and stamps those sessions
// `desktop`/`kiro-crew` from its own `agent_name` field (a self-contained,
// race-free discriminator — see kirocli's agentSurfaces table). This
// adapter emits conversation rows ONLY when session_map.json shows the
// chat has NO kiro-cli twin, and emits NOTHING when ownership cannot be
// resolved — including the case where the map entry EXISTS with a blank
// `sid` (the Gateway reserved the slot but has not minted the agent
// session yet). A missed session is recoverable by a later parse; a
// duplicated one is not.
//
// KNOWN LIMITATION: session_map.json is an OPEN-SLOT index, so a NEGATIVE
// verdict is only as durable as the slot. See resolveOwnership's
// ownedBySelf comment and docs/kiro-crew-adapter.md "The open-slot
// caveat" (follow-up KC-1).
//
// What Crew uniquely holds and kiro-cli does not: the human title
// (kiro-cli's is literally "[AGENT SYSTEM PROMPT]"), the memory_mode,
// the tag ids, and the user's REAL prompt — a Crew-driven kiro-cli
// session's first `Prompt` record is the ~73 KB agent system prompt, not
// the user's message. Carrying those onto another adapter's session would
// need a cross-adapter session-metadata seam that does not exist; the gap
// is documented in docs/kiro-crew-adapter.md rather than papered over.
//
// # Tokens
//
// NONE, honestly. The Crew transcript has no usage/token/cost field of
// any kind. The driven kiro-cli bundle reports `input_token_count: 0` /
// `output_token_count: 0` structurally, and bills in CREDITS
// (`metering_usage`), which this repo deliberately does not treat as
// tokens. `~/.kiro/crew/context_snapshots.json` carries a `used_tokens`
// figure, but that is a CONTEXT-WINDOW occupancy reading, not billable
// usage — the same trap as freebuff's contextTokenCount — and is not
// read. TokenTier is therefore "none".
//
// # Telemetry (vendor's own, for the record)
//
// Crew ships anonymous telemetry of five fields, controlled by
// `kirocrew telemetry status|disable` or KIROCREW_TELEMETRY_DISABLED=1;
// a per-install `telemetry_salt` sits at the Crew root. Usage and context
// records stay on device. Observer neither reads nor alters any of this.
//
// # Off-limits (never read, regardless of shape)
//
//	.env                    credentials — Slack bot tokens, workspace
//	                         owner id. NEVER read under any circumstance.
//	config.json(.bak)       account / workspace identifiers, integrations
//	.local_secret,
//	token_signing.key,
//	telemetry_salt          secrets
//	memory.db(-wal/-shm),
//	memory_index.db,
//	workspace/knowledge/**  free-text + indexed memory content
//	workspace/memory/*.md,
//	workspace/HEARTBEAT.md  free-text user/project memory
//	audit.log               privileged-operation audit trail
//	security_events.jsonl   tool-access events (a .jsonl, but NOT under
//	                         `sessions/`, so IsSessionFile rejects it)
//	gateway.log, logs/**,
//	scratch/**, cron-history/**, cache/**, imports/**, run/**,
//	trust/**, usage/**, members/**, apps/**, skills/**, artifacts/**
//	crons.json, hooks.json, mcp.json, folders.json, tags.json,
//	recent_projects.json, context_snapshots.json, agent_model_state.json
//
// The ONE sidecar read besides the transcript is session_map.json, and
// only its `sid` values — the sibling `slack_thread_ts` /
// `slack_channel_id` keys are not decoded (sessionMapEntry types only
// `sid`).
//
// The Gateway HTTP API (localhost:5476, KIROCREW_PORT) is NOT a capture
// target: CLAUDE.md's Don'ts forbid network calls from the watcher.
//
// # Not wired (deliberate)
//
//   - MCP: Crew HAS an MCP surface (`~/.kiro/crew/mcp.json`, standard
//     `mcpServers` shape). It is NOT wired — the registry row records
//     MCP: none. Wiring it is a separate, grounded ticket.
//   - Proxy / routing: Kiro is hard-wired to AWS SigV4 endpoints; there
//     is no base-URL knob, so Routability is native_exempt, the same
//     answer kiro-cli carries.
//   - Hooks: `hooks.json` exists but is `{"hooks": []}` with no
//     documented command contract. HookNone.
package kirocrew

// surfaceHost is the SurfaceHost token this adapter stamps alongside
// models.SurfaceDesktop. The SAME token is stamped by
// internal/adapter/kirocli for a Crew-driven session, so the two feed
// paths agree by construction; kirocrew_surface_test.go pins the equality.
const surfaceHost = "kiro-crew"

// ToolName is retained as a package-local alias of the canonical
// models.ToolKiroCrew constant so existing references keep compiling.
const ToolName = "kiro-crew"

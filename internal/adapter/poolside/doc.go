// Package poolside parses Poolside's agentic coding model ("laguna")
// session trajectories.
//
// # The tool
//
// Poolside ships today ONLY as a JetBrains AI Assistant ACP agent
// (`acp.registry.poolside`) — no standalone CLI/TUI launch surface was
// found on the grounding host (Windows 11, IntelliJ IDEA 2026.2.2,
// 2026-09-05). JetBrains' IDE downloads the per-OS binary under
//
//	<JetBrains vendor root>/acp-agents/poolside/<version>/pool-<os>-<arch>[.exe]
//
// (Windows-grounded: `pool-windows-amd64.exe`, version 1.0.16) and drives
// it over the Agent Client Protocol (JSON-RPC over stdio) — the agent has
// no independent process the operator launches directly. Because of that,
// this package has no `Handoff.Launch` / `Attach` / `Resume` registry
// capability: there is nothing for `observer <tool>` to exec.
//
// # Storage layout
//
// Two roots, grounded on Windows 2026-09-05 (the Linux layout follows
// after this block):
//
//	~/.config/poolside/                          (XDG-style, UNIVERSAL —
//	                                               used even on Windows,
//	                                               the same convention
//	                                               Kilo Code follows)
//	    settings.yaml                             pool.api_url etc.
//	    credentials.json                          OAuth/API tokens  (NEVER READ)
//	    skills/<name>/SKILL.md                    bundled skill prompts (not parsed)
//	<AppData-Local-equivalent>/poolside/          (OS-native data home;
//	                                               ONLY the Windows shape
//	                                               is grounded — see below)
//	    acp/<encoded-cwd>/<sessionId>.json         flat per-session SUMMARY
//	                                               (title/usageTotals) —
//	                                               redundant with the
//	                                               trajectory; NOT PARSED
//	    pool/logs/<encoded-cwd>/<sessionId>/
//	        acp.log.jsonl                          the ACP JSON-RPC
//	                                               protocol log — NOT
//	                                               PARSED (no per-call
//	                                               tokens; the trajectory
//	                                               below is the richer
//	                                               source for everything
//	                                               this log carries)
//	    trajectories/
//	        trajectory-<agentId>_<sessionId>.ndjson   THE session log —
//	                                               the only file parsed
//
// `<encoded-cwd>` is the project working directory with `:` and path
// separators rewritten to `-` (mirrors the antigravity/claude-code
// encoded-path convention); this package never needs to decode it because
// the trajectory itself states the real cwd in its `session.start` record.
//
// `ShapeWindowsLocal` (`%LOCALAPPDATA%\poolside`) is grounded on the
// Windows JetBrains ACP install (2026-09-05).
//
// Linux (T-706, standalone `pool` 1.0.16 TUI on demo node 1, 2026-10-08)
// splits the same tree across two XDG homes:
//
//	~/.local/state/poolside/                     ($XDG_STATE_HOME)
//	    trajectories/trajectory-standalone_<sid>.ndjson   THE session log
//	    sessions/session-<sid>.json               run/session id pointer (not parsed)
//	    pool/logs/<encoded-cwd>/<sid>/{acp,tui}.log.jsonl  (not parsed)
//	    pool/<encoded-cwd>/prompt-history.json    (never read: prompt text)
//	    logs/pool-<id>.log                        (not parsed)
//	~/.local/share/poolside/                     ($XDG_DATA_HOME)
//	    acp/<encoded-cwd>/<sid>.json              flat summary (NOT PARSED)
//
// The trajectory format and filename are the ones documented below; the
// session id in the filename is a UUIDv7 and matches the summary's
// sessionId. `ShapeXDGState` covers it (the adapter honours an absolute
// $XDG_STATE_HOME on the native home). The Windows-and-Linux pair is the
// state-home mapping a Go XDG library makes per OS, so macOS stays
// declared as `Library/Application Support/poolside`: an expectation,
// NOT verified on a live macOS install.
//
// The Linux TUI's session.start carries `client_metadata` (version, host,
// environment); host "acp:pool" (the TUI is itself the ACP client) is
// stamped as the `cli` / `poolside-cli` capture surface. The Windows ACP
// capture has no client_metadata; its surface comes from
// internal/surfaceenrich's JetBrains pointer, which wins over any
// self-report. The Linux TUI also advertises tools never called in the
// grounding run (question, shell_list, shell_tail, shell_status,
// shell_kill, shell_send, shell_wait, skill, subagent, switch_mode,
// list_secrets, web_fetch); they are not mapped until a call is seen, and
// a call to one lands as an unknown action with its raw name kept.
//
// # Off-limits files
//
//   - `~/.config/poolside/credentials.json` — OAuth + API credentials.
//   - `<data-home>/poolside/acp/<encoded-cwd>/<sessionId>.json` — the flat
//     per-session summary. Every field it carries (title, agentName,
//     usageTotals) is DERIVABLE from the trajectory this adapter already
//     parses (session.input's prompt, tool_call.inference.start's model,
//     the summed tool_call.inference.end usage), so reading it too would
//     be a second, redundant source of the same facts rather than new
//     data — reading only the trajectory keeps one canonical parse path.
//   - `<data-home>/poolside/pool/logs/…/acp.log.jsonl` — the ACP
//     protocol-level JSON-RPC log. It carries the initialize handshake,
//     config-option churn and a final CUMULATIVE usage total, but no
//     per-call tokens and no tool-call bodies; strictly a subset of what
//     the trajectory states.
//
// # Record shape
//
// The trajectory is an append-only, flat-envelope NDJSON stream. Every
// line has the same two-key shape: a `type` discriminator plus ONE nested
// object keyed by `type` with `.` replaced by `_`:
//
//	{"id":"<uuidv7>","step_id":"<uuidv7>","timestamp":"2026-09-05T01:33:15.68…+05:30",
//	 "type":"tool_call.parsed","tool_call_parsed":{"id":"chatcmpl-tool-…","name":"shell","args":{…},"raw_args":"…"}}
//
// `id` is a per-record uuid (stable across re-parses — used as the
// SourceEventID suffix); `step_id` groups every record belonging to one
// model turn (one `thought.start/end` + one `assistant_message.start/end`
// + zero or more `tool_call.*` all share a `step_id`) and is how this
// adapter joins a `tool_call.inference.start`'s stated MODEL onto its
// paired `tool_call.inference.end`'s usage, and a `thought.end`'s
// reasoning text onto the assistant_message.end of the same step.
// `timestamp` is ISO-8601 with a numeric offset and sub-second precision
// (parsed with time.RFC3339Nano).
//
// The session id is NEVER stated inside the body — it lives ONLY in the
// filename (`trajectory-<agentId>_<sessionId>.ndjson`, agentId
// "standalone" observed) — grounded exact-match against the ACP registry
// pointer sid (`acp.registry.poolside:<sessionId>`), which is what lets
// `internal/surfaceenrich` stamp a poolside session `ide`/`jetbrains-…`.
//
// Record types this adapter acts on:
//
//	session.start                 session_start.working_directories[0] — cwd
//	session.input                 session_input.prompt — the user's turn
//	thought.end                   thought_end.thought — reasoning text,
//	                               attached as PrecedingReasoning to the
//	                               SAME step's assistant_message
//	assistant_message.end         assistant_message_end.assistant_message
//	tool_call.inference.start     tool_call_inference_start.chat_completion_
//	                               request.model — the per-step model id
//	tool_call.inference.end       tool_call_inference_end.{input_tokens,
//	                               output_tokens,cache_read_input_tokens,
//	                               cache_write_input_tokens} — the token row
//	tool_call.parsed              tool_call_parsed.{id,name,args,raw_args,
//	                               validation_error} — the tool call itself.
//	                               A non-nil validation_error (e.g. "tool
//	                               <x> is not available") means the call
//	                               never ran — Success=false immediately,
//	                               no later approval/result is expected.
//	tool_call.approval             tool_call_approval.{tool_call_id,denied,
//	                               reason} — denied=true fails the call
//	tool_call.result              tool_call_result.{id,tool_name,
//	                               execution_latency,observation,
//	                               <tool>_tool_result} — the outcome. The
//	                               generic `observation` string is ALWAYS
//	                               present and is what this adapter uses
//	                               as ToolOutput; a typed per-tool result
//	                               object exists too but only two shapes
//	                               (`shell_run_tool_result.exit_code`,
//	                               `todo_action_tool_result.success` /
//	                               `exit_tool_result.success`) carry an
//	                               explicit pass/fail signal — read/write/
//	                               edit carry none, so those three stay
//	                               optimistically successful absent a
//	                               denial or a later contradicting signal.
//	session.exit                  session_exit.reason — the session's end
//
// Every other type (`tool_call.start`, `tool_call.inference.start`'s own
// envelope beyond the model field, `thought.start`, `assistant_message.
// start`, `tool_call.approval.request`, `session.input.processed`) is a
// marker this adapter dispatches on for bookkeeping only (or skips
// entirely) — none produces a row of its own.
//
// # Cross-window tool outcomes (no rewind needed)
//
// A tool call and its approval/result can land many poll ticks apart (the
// operator may sit on an approval prompt for minutes). Unlike an adapter
// whose tool_use → tool_result correlation is only reconstructable from
// data seen DURING the tool_use's own parse window (which must then defer
// unpaired tails at EOF — see adapter.DeferUnpairedTail), Poolside's
// `tool_call.approval` and `tool_call.result` both restate the ORIGINAL
// call id verbatim. That means this adapter can always reconstruct the
// owning row's (SourceFile, SourceEventID) key from the outcome record
// ALONE, so a call whose approval/result arrives in a LATER parse window
// is patched via [adapter.ParseResult.OutcomeUpdates] instead of ever
// rewinding the byte cursor — simpler than the muse/openclaw pattern and
// possible only because of this id-restatement guarantee.
//
// The no-rewind guarantee covers tool OUTCOMES, not per-step model: on a
// resumed parse readHeader recovers the session cwd but not the per-step
// model map, so a `tool_call.inference.end` / `tool_call.parsed` whose
// paired `tool_call.inference.start` fell in an EARLIER parse window lands
// with an empty Model (an unknown-cost / by-model attribution gap for those
// rows only). Steps normally complete within one poll tick, so this is rare;
// it is a known limitation, not a correctness bug.
//
// # Tokens (Tier 2, transcript / approximate)
//
// `tool_call_inference_end`'s four fields, and what they mean:
//
//	input_tokens              GROSS — INCLUDES cache_read_input_tokens
//	cache_read_input_tokens   the cached prefix replayed this call
//	cache_write_input_tokens  cache-creation tokens (0 in every observed row)
//	output_tokens             the reply length; no reasoning-token field
//	                          is present in this envelope, so nothing is
//	                          netted out of output
//
// The GROSS-input claim is verified by SUMMING every tool_call_inference_
// end.input_tokens (and .cache_read_input_tokens) across a whole session
// and comparing against that session's flat acp/<cwd>/<id>.json summary
// (which this adapter does not otherwise read): a 22-call, single-prompt
// grounding session summed to input=582,746 / output=2,261 /
// cache_read=441,696 — an EXACT match to the summary's usageTotals. Net
// input is therefore `input_tokens - cache_read_input_tokens` (floored at
// zero), the same correction muse and codex apply for their own GROSS
// input fields.
//
// No pricing entry exists for `poolside/laguna-*` models (a brand-new,
// non-mainstream vendor) — cost rows resolve as `unknown` by design.
//
// # Project root
//
// `session.start.working_directories[0]` (always the first record in a
// fresh trajectory) is the authoritative absolute cwd; it is re-read from
// offset 0 on every parse, including a resumed one, the same way muse
// re-reads its header. `crossmount.TranslateForeignPath` runs before
// `git.Resolve` so a foreign-OS path never lets `filepath.Abs` CWD-prefix
// the observer's own `.git` onto every event.
//
// # Model
//
// Only `tool_call.inference.start.chat_completion_request.model` states
// the model per call (`poolside/laguna-s-2.1` observed — the
// JetBrains-surfaced config option list also offers `poolside/laguna-
// xs-2.1`). It is tracked per step_id and threaded onto the paired
// tool_call.inference.end's TokenEvent and every ToolEvent emitted for
// tool calls under that step.
//
// # Known gaps
//
//   - No hooks. No hook mechanism is documented or grounded for the ACP
//     agent surface; the registry declares HookNone.
//   - No proxy lane. Model traffic goes to `https://inference.poolside.ai`
//     per `~/.config/poolside/settings.yaml`'s `pool.api_url`; no
//     base-URL override flag or env var was grounded (the agent is
//     IDE-driven, not independently launched), so Routability is
//     probe_required rather than a fabricated route.
//   - No MCP writer. Poolside is itself an MCP CLIENT inside the ACP
//     session (the JetBrains host hands it the IDE's own `idea` MCP
//     server), not a target any existing `{"mcpServers":{…}}`-shaped
//     writer could register into.
//   - Not launchable / not attachable / no native resume: this package's
//     registry row carries no `Handoff.Launch`, matching Junie's
//     JetBrains-embedded precedent — there is no standalone process for
//     `observer poolside` to start or join.
//   - macOS data-home shape is an unverified, documented expectation; the
//     Linux state home is grounded since T-706 (see "Storage layout").
package poolside

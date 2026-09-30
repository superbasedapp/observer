// Package crush implements a SQLite-store adapter for Charm's Crush TUI
// agent (charmbracelet/crush). Unlike every other SQLite-backed adapter,
// Crush has NO central session directory: each project keeps its own
// store at <project>/.crush/crush.db. The watch roots are therefore
// discovered from the global state file
// ~/.local/share/crush/projects.json (Windows %LOCALAPPDATA%\crush\),
// which maps each known project path to its data dir.
//
// The store shape (live-verified 2026-07-09 on WSL + Windows):
//
//   - sessions(id, prompt_tokens, completion_tokens, cost, updated_at,
//     created_at, …) — a session-CUMULATIVE pre-computed dollar `cost`
//     (Crush is the only wave tool that stores its own cost), but
//     prompt_tokens / completion_tokens are the LAST step's
//     (input + cache-read) and output, OVERWRITTEN every step: the
//     context-window occupancy the TUI renders, not a running total
//     (charmbracelet/crush internal/agent/agent.go
//     updateSessionTokenCounters, v0.83.0 and v0.96.1). Timestamps are Unix SECONDS despite the
//     schema comment claiming milliseconds — the update trigger writes
//     strftime('%s','now').
//   - messages(id, session_id, role, parts JSON, model, provider,
//     created_at, updated_at, …; v0.96+ also prism_model_id — the model
//     that actually served a Hyper turn routed through a Prism router
//     model, preferred over `model` when set) — parts carry
//     text / reasoning / tool_call / tool_result / finish blocks.
//     tool_call and tool_result live in SEPARATE messages (assistant
//     vs. role="tool"), paired by tool_call id.
//
// Reasoning emission (B3, 2026-07-31): a `reasoning` part mints NO
// action row. Crush's thinking text rides the NEXT assistant-text or
// tool-call event as PrecedingReasoning, capped at the same 200-char
// preview the retired `crush.reasoning` row carried and scrubbed at the
// flush site. Consumption is grok-style — consumed-once (the first
// successor clears it), last-wins (a newer reasoning part replaces an
// unconsumed one), discarded at a user-prompt turn boundary. The state
// spans messages within one ParseSessionFile call because Crush writes
// the reasoning part and the tool_call it introduces on different rows.
//
// Token capture is session-level: one TokenEvent per session carrying
// Crush's own cumulative cost in TokenEvent.EstimatedCostUSD, with
// model+provider resolved from the NEWEST assistant message (so a
// bedrock→openai failover session reports the provider that actually
// finished the turn). The prompt/completion counts ride along ONLY for
// a session with at most one usage-bearing step (assistant messages not
// finished with reason error/canceled), where the last-step snapshot IS
// the total (Reliability approximate). Every other non-vacant session -
// multi-step, or a cost with no counters - still emits its row with the
// model and Crush's own cost (zero included) but 0/0 counts and
// Reliability unknown, never a context-window size (sessionTokenCounts's
// rule table). The prompt counter is
// gross of cache reads with the split not persisted, so a zero-cost
// one-step session re-priced read-side may over-bill its cached share (a
// documented limitation; the counts are kept). A session that grows from
// one step to several is re-emitted as 0/0 unknown under the same key, and
// the store's reliability reconcile table (internal/store/
// tokenreliability.go) demotes the stored row in place on live ingest.
// Rows an older parser over-reported are corrected by
// `observer backfill --crush-rescan`.
package crush

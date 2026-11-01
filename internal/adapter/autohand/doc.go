// Package autohand implements the capture adapter for the Autohand Code CLI
// (npm package `autohand-cli`, binaries `autohand` / `autohand-code` /
// `agent` / `ah`), distinct from every other tool in the registry.
//
// # Store layout
//
// Autohand keeps its data home at ~/.autohand on Linux, macOS and Windows
// alike (%USERPROFILE%\.autohand; the vendor's own AUTOHAND_HOME override is
// honoured for the running process). Sessions live one directory each:
//
//	~/.autohand/sessions/<uuid>-<epoch-ms>/
//	  conversation.jsonl   append-only transcript, one JSON object per line
//	  metadata.json        mutable session record, rewritten atomically
//	~/.autohand/sessions/index.json   project → session-id index (not read)
//
// The directory name IS the canonical session id: it equals
// metadata.json's sessionId and is exactly what `autohand resume <id>`
// accepts, so it is used verbatim for every event.
//
// # Transcript records (conversation.jsonl)
//
// Four shapes, keyed on `role` (live-grounded 2026-10-21 on Linux/WSL and
// Windows, autohand-cli 0.9.8; shapes confirmed against the bundled
// SessionManager source):
//
//	{role:"user",      content, timestamp}
//	{role:"assistant", content, timestamp, toolCalls:[{id, tool, args}]}
//	{role:"tool",      content, name, timestamp, tool_call_id}
//	(the same three, optionally with a `_meta` object)
//
// There is NO per-message model, usage, reasoning or session field. Tool
// results carry no success flag; the adapter infers failure only from the
// two shapes the vendor source writes (`Command exited with code N`,
// `Error: ...`).
//
// # Tokens (metadata.json)
//
// Usage is SESSION-CUMULATIVE in metadata.json `usage`
// ({promptTokens, completionTokens, totalTokens, cacheReadTokens,
// cacheWriteTokens, turnCount, tokenUsageStatus, updatedAt}), summed turn by
// turn by the vendor's Session.recordTurnUsage. The adapter therefore emits
// ONE TokenEvent per session under a fixed SourceEventID so the store's
// MAX-upgrade keeps it monotonic as the session grows.
//
//   - promptTokens is GROSS: the vendor's normalizer rejects a cache count
//     that exceeds the prompt count, and the Anthropic provider sums
//     input + cache_creation + cache_read into it. Net input is
//     promptTokens - cacheReadTokens - cacheWriteTokens, clamped at zero.
//   - completionTokens already includes reasoning (OpenAI convention), so
//     ReasoningTokens stays zero and reasoning is billed at the output rate
//     through OutputTokens (checklist §8.4).
//   - tokenUsageStatus "actual" is Approximate (session snapshot, not
//     per-call). "unavailable" is sticky once ANY turn lacked usage and the
//     counts then cover only the turns that reported, so they are a lower
//     bound: those rows are Unreliable.
//
// # Sessions inherited from elsewhere
//
// A forked/cloned session (`--fork`, metadata.branch) copies its source's
// messages AND usage into the new directory; an imported session
// (metadata.importedFrom) carries another tool's transcript. Messages whose
// timestamp precedes the branch/import time are inherited and are skipped,
// and a branch's usage is reported net of the source's snapshot (or not at
// all when the source has moved on and the split is unknowable). The branch
// is recorded as session lineage.
//
// # Synced duplicates
//
// Autohand's account "settings sync" mirrors ~/.autohand files between
// devices, so the Windows home on a dual-boot/WSL box ends up holding a copy
// of every WSL-authored session and vice versa. A copy sitting under a home
// of the OTHER operating-system family than the session's own projectPath
// (a drive-letter path under a POSIX home, a POSIX path under a Windows
// home) is a sync artifact and is skipped, so one session is captured once.
// Roots whose OS is unknown (custom roots) are never filtered.
//
// # Off-limits (never read)
//
// config.json (provider API keys, auth token, company secret, user email),
// traces/** (settings.json carries a cloud auth token and a control token;
// the rest is a derived cross-harness index), typed-message-history.json
// (raw prompt history), projects/**, memory/**, hooks/*.sh, .sync-state.json,
// device-id, last-ping.json, model-catalog/**, feedback/**, telemetry/**.
//
// # Read beside the sessions (bounded, field-selective)
//
// Besides conversation.jsonl and metadata.json (and, for a branch, the source
// session's metadata.json) the adapter reads four vendor housekeeping files,
// decoding only the named members:
//
//   - active-agents/<sessionId>[.<instance>].json: pid, sessionId,
//     workspaceRoot, updatedAt of the live CLI process's heartbeat record.
//     Feeds the process seed and the terminal resolver (the activity block,
//     which carries the current instruction and command, is never decoded).
//   - error.log (tail, 1 MiB): per record timestamp, cli.version,
//     context.workspace, error.name, error.message. Feeds the tool version
//     and api_error rows. The host block (hostname, user name, memory, CPU)
//     and the stack are never decoded.
//   - .account-skills/snapshot.json: accountId only (a device-level account
//     id, recorded account-level; its token hash is never read).
//   - <npm root>/autohand-cli/package.json: name and version (install-level
//     tool version when no error.log record covers the session).
//
// # Gaps (v1)
//
// The terminal client records no per-session version; the stamp is the build
// named by an error.log record written during the session, else the installed
// npm package, else the newest earlier record (native-only installs with no
// error.log history get none). No per-turn token rows (the transcript carries none), so no cache
// observation feed (§8.6); no sub-agent rows (delegated runs are not written
// to the session — spawn calls are classification-only, §7.1 mechanism 3);
// no effort/thinking capture (a launch flag, absent from the store, §7.2);
// no tool durations (a result's timestamp is not the call's start). See
// docs/autohand-adapter.md.
package autohand

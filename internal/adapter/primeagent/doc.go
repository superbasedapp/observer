// Package primeagent parses Prime Intellect's Prime Agent CLI session logs.
//
// # The tool
//
// Prime Agent ("prime-agent") is Prime Intellect's terminal coding and
// research harness, distributed as the npm package `prime-agent` and via
// `curl -fsSL https://app.primeintellect.ai/prime-agent/install.sh | sh`.
// Phase-0 grounding ran against `prime-agent 0.7.0` on WSL2 Linux
// (2026-08-06), cross-checked against the authoritative
// `docs/session-format.md` that ships inside the npm package.
//
// Prime Agent is a HARD FORK of pi-mono — the same upstream
// [internal/adapter/pi] covers — and still carries the inherited
// `@earendil-works/pi-*` package identifiers plus a `piConfig` manifest
// key. The session ENVELOPE is therefore recognisably pi-shaped. What it
// is not is a rebadge: the data home, the session-directory layout, the
// session-id derivation, the entry-type vocabulary, the native tool
// surface and the token-attribution model all differ (see the plan doc
// `docs/plans/prime-agent-adapter-plan-2026-08-06.md` §1 for the table),
// so this is a structural transposition with its own parser rather than
// the §2.1 boundary retag `codex.NewOpenInterpreter` uses.
//
// # Storage layout
//
// Uniform across Linux, macOS and native Windows (`%USERPROFILE%\.prime`),
// so WatchPaths iterates crossmount.AllHomes() with no OS branching:
//
//	~/.prime/config.json                      Prime Intellect api_key    NEVER READ
//	~/.prime/agent/
//	    sessions/<session-uuid>.jsonl         THE session log — the only file parsed
//	    auth.json                             per-provider credentials   NEVER READ
//	    settings.json                         defaultProvider / defaultModel
//	    models.json                           custom providers (baseUrl) — the route surface
//	    prime-inference-private-models.json   private model-id fingerprint
//	    session-artifacts/<uuid>/
//	        kernel-state.dill                 PICKLED kernel namespace   NEVER READ
//	        kernel-state.json                 kernel metadata
//	    daemon-workers/<worker>/<id>.json     carries authenticationToken NEVER READ
//	    session-leases/…  logs/…  kernel-venv/  skills/
//
// The vendor doc states: "Current releases keep sessions in a flat
// directory; older per-project directories are migrated automatically."
// The shape predicate therefore binds only the `.jsonl` extension and
// leaves the install-root authority entirely to the under-WatchPaths
// gate, so both the flat and the legacy nested layout are covered.
//
// # Off-limits files
//
// This adapter reads `sessions/*.jsonl` and nothing else. Named refusals:
//
//   - `~/.prime/config.json` — a single `api_key` key, the Prime Intellect
//     platform credential.
//   - `~/.prime/agent/auth.json` — the per-provider OAuth / API-key store
//     (same class as muse's auth.json and clinecli's secrets.json).
//   - `~/.prime/agent/daemon-workers/<worker>/<id>.json` — carries
//     `authenticationToken`, the daemon RPC bearer.
//   - `~/.prime/agent/session-artifacts/<uuid>/kernel-state.dill` — a
//     Python PICKLE of the live IPython kernel namespace. Bulk user data
//     by definition, and deserialising a pickle is arbitrary code
//     execution.
//   - `~/.prime/agent/logs/*` — daemon and supervisor logs.
//
// # Record shape (session version 3)
//
// Append-only JSONL. Every line is one entry `{type, id, parentId,
// timestamp, …}` where `id` is an 8-char hex entry id, `parentId` links
// entries into a TREE (branching happens in place, without a new file)
// and `timestamp` is an ISO-8601 string. The first line is the header and
// carries no tree position:
//
//	{"type":"session","version":3,"id":"<session-uuid>","timestamp":"…",
//	 "cwd":"/path/to/project","rlmDepth":0,
//	 "git":{"repoUrl":"…","commit":"…","branch":"main"}}
//
// Consumed entry types: `session`, `message`, `model_change`,
// `compaction`, `child_usage_attributed`. Every other documented type —
// `agent_status`, `session_state`, `git_state`, `session_info`, `label`,
// `custom`, `custom_message`, `branch_summary`, `thinking_level_change`,
// `service_tier_change` — is skipped SILENTLY (§4.4e). That is not
// laziness: `agent_status` alone was 103 of the 147 lines in the
// grounding session, so a warning per unconsumed line would flood the
// watcher log on every poll.
//
// # Timestamps — two units, deliberately
//
// The entry envelope's `timestamp` is an ISO-8601 STRING; the inner
// `message.timestamp` is Unix MILLISECONDS (the vendor types it
// `timestamp: number // Unix ms`). Not microseconds (muse), not seconds
// (crush). The inner value wins when present; parseUnixMillis rejects a
// value outside a sane epoch window rather than silently minting a 1970
// row if a future schema switches units.
//
// # Message roles
//
// `user`, `assistant`, `toolResult`, `bashExecution`, `custom`,
// `branchSummary`, `compactionSummary`.
//
// A message's `content` is POLYMORPHIC: the vendor types UserMessage and
// CustomMessage as `string | (TextContent | ImageContent)[]`, and their
// own parsing example uses the bare-string form. The live capture happens
// to use the array form throughout — which is exactly the shape of the
// Gemini "drop-the-whole-line" bug (§4.4d), where a strict `[]part` type
// made json.Unmarshal fail on the WHOLE envelope and silently dropped the
// user's prompt. contentParts.UnmarshalJSON therefore normalises string →
// one text part, array → parts, object → one part.
//
// # Tokens (Tier 2, jsonl / approximate)
//
//	"usage":{"input":328,"output":291,"cacheRead":4352,"cacheWrite":0,
//	         "totalTokens":4971,"cost":{…,"total":1.60236e-4}}
//
// Input is already NET of the cached prefix. The evidence is arithmetic
// and it holds on every usage-bearing row of the grounding session:
// `totalTokens == input + output + cacheRead + cacheWrite` EXACTLY
// (328+291+4352+0 = 4971). Per checklist §4.4c that is the net signature —
// a gross source would show `cacheRead ⊆ input` and the identity would
// not close. No netting is applied, and TestUsageIsNetNotGross pins it.
//
// There is NO reasoning-token field in the usage envelope on either API
// lane (`openai-responses` or `openai-completions`). Reasoning TEXT does
// arrive as `thinking` content parts and becomes PrecedingReasoning; the
// reasoning COUNT is simply not published. Declared gap, not an omission.
//
// `usage.cost.total` is the provider-reported USD figure and feeds
// EstimatedCostUSD — the same Tier-2 treatment pi and opencode get.
// Observer ships no pricing rows for the models seen (gpt-5.4,
// nvidia/nemotron-*, deepseek/deepseek-v4-flash via prime-inference and
// openrouter) and none are invented, so cost.Compute resolves those rows
// as `unknown` while the provider figure remains available.
//
// An all-zero usage envelope emits NO token row (§4.4b). 14 of the 22
// assistant messages in the grounding session were provider failures
// (401 / 402) carrying a zero usage block; a phantom row per attempt
// would be 14 junk rows in a 34-message session.
//
// # Models
//
// `provider` + `model` sit on each assistant message; a `model_change`
// entry records switches. Model ids can carry a `provider/` path segment
// and a `~` alias sigil (`~deepseek/deepseek-v4-flash-latest`). A
// successful turn also reports `responseModel` — the RESOLVED model the
// alias landed on (`deepseek/deepseek-v4-flash-0731`), i.e. what was
// actually billed — so modelString prefers it and falls back to the
// selected id.
//
// # Tool surface
//
// `ipython` is the ONLY built-in tool ("Available built-in tools:
// `ipython`" — README; "Prime Agent gives the model one built-in tool,
// `ipython`" — docs/quickstart.md). Reading files, editing code and
// running project commands all happen as Python in one persistent kernel.
// `docs/extensions.md` names `ipython`, `bash` and `edit` as the built-in
// tools an extension may override, so those three are the grounded native
// vocabulary; the rest of mapToolName is the conventional defensive set.
//
// Skills are Python-backed and execute INSIDE the kernel, and MCP servers
// are reached from Python as `integration.<tool>(…)` — neither produces a
// distinct LLM tool call, so there is no `mcp__*` surface in practice.
// The models.IsMCPToolName arm is kept for an extension that registers
// one.
//
// `toolResult.details` carries `{durationMs,status,stdout,stderr,
// kernelRestarted}`; durationMs populates ToolEvent.DurationMs.
//
// # RLM child usage — the double-count that isn't
//
// A `child_usage_attributed` entry records usage an RLM child run folded
// into a PARENT assistant message: `{targetId, childUsage,
// aggregateUsage}`, and the vendor states "Reload applies
// `aggregateUsage` to the target assistant message". Emitting it as its
// own token row would double-count against the parent's own `usage`.
// Instead it is emitted under the SAME SourceEventID as the target's
// token row ("usage:<targetId>"), so InsertTokenEvents' ON CONFLICT
// MAX-upgrade path (§8.2) folds the larger aggregate in place. One key,
// one owner, no double count — and it works whether or not the target
// message was parsed in this same window.
//
// # Cross-tick tool pairing
//
// A toolCall and its `toolResult` are separate lines written however long
// the tool took apart. A poll tick landing between them would persist an
// optimistic success that the store's ON CONFLICT clause can never flip.
// The tail deferral (adapter.DeferUnpairedTail) rewinds the cursor to the start of the
// unanswered assistant entry, bounded by tail size and file mtime, so the
// pair always resolves inside ONE parse window — the same mechanism
// commandcode uses.
//
// # Routability
//
// `~/.prime/agent/models.json` accepts a custom provider with an explicit
// `baseUrl` and `"api":"openai-completions"` (vendor docs/models.md), and
// the CLI selects it with `--provider <name>` — structurally the same
// route `cmd/observer/pi.go` already drives for pi. The integration
// registry therefore records Routability=routable_now, but leaves Proxy
// nil until a launcher exists and a live turn has landed an api_turns row
// (checklist §10.1f).
package primeagent

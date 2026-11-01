// Package kimchi parses session transcripts of Kimchi, Cast AI's coding
// agent CLI (github.com/getkimchi/kimchi, npm identity `@kimchi-dev/cli`,
// binary `kimchi`).
//
// # The tool
//
// Kimchi is a pi-mono derivative: its package.json carries pi-mono's
// `piConfig` manifest key (`{"name":"kimchi","configDir":
// ".config/kimchi/harness","mcpProjectConfigDir":".kimchi"}`), the bundle
// still calls `pi.setModel()` / `pi.registerTool()`, and the transcript is
// pi-mono's session format VERSION 3 byte for byte. It is not a §2.1
// rebadge of [internal/adapter/pi], though: the data home, the session-id
// derivation, the native tool surface (todo / ferment / plan / remote-agent
// tools), the sub-agent file convention and the reasoning-token field all
// differ, and the log interleaves ~20 kimchi-specific `custom` telemetry
// entry kinds. So this is a structural transposition with its own parser
// (the prime-agent precedent), not a retag. Phase-0 grounding ran against
// kimchi 1.17.0 on WSL2 Ubuntu and native Windows 11 on 2026-10-21; the
// operator reference is docs/kimchi-adapter.md.
//
// # Storage layout
//
// Identical on Linux, macOS and native Windows — the bundle joins
// os.homedir() with ".config" unconditionally, so Windows lands in
// `C:\Users\<u>\.config\kimchi`, NOT %APPDATA%. `$KIMCHI_CODING_AGENT_DIR`
// relocates the `harness` dir.
//
//	~/.config/kimchi/
//	    config.json                     apiKey + deviceId + telemetry   NEVER READ
//	    org-policy.json                 org key fingerprint             NEVER READ
//	    harness/                        (= $KIMCHI_CODING_AGENT_DIR)
//	        sessions/--<cwd-slug>--/<ISO-ts>_<uuid>.jsonl   THE transcript — the only file parsed
//	        sessions/--<cwd-slug>--/image-cache/            pasted images              never read
//	        auth.json                   per-provider OAuth / keys       NEVER READ
//	        models.json                 providers: baseUrl + apiKey     NEVER READ (route surface only)
//	        settings.json               defaultProvider/defaultModel    ONE field read: lastChangelogVersion (install-level tool version)
//	        work/<work-uuid>/…          cost rows / request rows        not read (duplicates the transcript)
//	        work-attribution/…          git attribution objects         not read
//	        logs/tui.log  themes/  bin/fd  keybindings.json  pr-cost-reporting/
//
// The cwd slug is pi-mono's (`/home/u/proj` → `--home-u-proj--`,
// `C:\Users\u\proj` → `--C--Users-u-proj--`); the header's `cwd` is the
// authority for the project root, never the slug.
//
// # Session identity
//
// The filename's UUIDv7 suffix equals the header's `id` and is what
// `kimchi --session <id>` / `kimchi --resume <id>` accept, so it is the
// canonical session id, derived from the PATH so a resumed parse that
// seeks past the header can never split the session.
//
// # Entry vocabulary
//
// Consumed: `session` (cwd, parentSession), `model_change`,
// `thinking_level_change` (→ ActionMetadata.EffortLevel), `message`
// (roles user / assistant / toolResult / bashExecution /
// compactionSummary), `compaction`, and the `custom` entry
// `kimchi:subagent-session` (the sub-agent marker). Everything else is
// skipped silently. In particular `custom:llm_response_debug` repeats each
// assistant record's usage verbatim and `custom:cache_summary` carries a
// running cumulative — reading either as well would double-count every
// call.
//
// # Token semantics
//
// One assistant record = one model call. Its `usage` is NET of the cached
// prefix (`totalTokens == input + output + cacheRead + cacheWrite` on
// every live row, both the `openai-codex-responses` and the
// `openai-completions` lane), so input is not re-netted. `output` INCLUDES
// `reasoning` (the Responses lane's reasoning count; the key is absent
// from the observed completions-lane rows), so OutputTokens = output − reasoning and
// ReasoningTokens = reasoning. Summed over each live session the parsed
// rows reproduce the vendor's own final `cache_summary` cumulative
// exactly (input, output + reasoning, cacheRead and dollars). A
// provider error leaves an all-zero envelope and produces no token row.
// `usage.cost.total` is carried as EstimatedCostUSD. Tier-2 cache
// observations are fed per call; the implicit-vs-explicit cache shape is
// resolved from the record's `api` wire name, not its account-lane
// `provider`. GenMs is the record's own stream span (inner start
// timestamp → envelope append timestamp).
//
// # Sub-agents and forks
//
// The `Agent` tool (ferment mode) writes the child run to a SIBLING
// transcript whose header names the parent's file in `parentSession` and
// whose second entry is `custom:kimchi:subagent-session`; that becomes a
// SessionLineage with ThreadSource "subagent". Any other parentSession
// (pi-mono branch / fork flows) is ThreadSource "user". The spawn call
// itself classifies as spawn_subagent.
//
// # Off-limits files
//
// Only `sessions/**/*.jsonl` is opened, plus `harness/settings.json` for its
// single non-secret `lastChangelogVersion` field. `config.json` (the Kimchi apiKey),
// `harness/auth.json`, `harness/models.json` (per-provider apiKey beside
// the baseUrl) and `org-policy.json` are never read by this package.
package kimchi

// Package commandcode implements the adapter for Command Code
// (commandcode.ai's `command-code` npm package; the binaries `cmd`,
// `cmdc`, `command-code` and `commandcode` are four names for the same
// obfuscated, closed-source bundle).
//
// # Storage shape
//
// Command Code persists one Claude-Code-shaped JSONL transcript per
// session under a per-project dash-encoded directory:
//
//	~/.commandcode/projects/<dash-encoded-cwd>/<uuid>.jsonl
//	~/.commandcode/projects/<dash-encoded-cwd>/<uuid>.meta.json
//	~/.commandcode/projects/<dash-encoded-cwd>/<uuid>.checkpoints.jsonl
//	~/.commandcode/projects/<dash-encoded-cwd>/config.json
//
// The layout is identical on Linux, macOS and native Windows
// (`%USERPROFILE%\.commandcode`) — the tool mirrors the XDG-ish `$HOME`
// convention everywhere, so a WSL2 observer picks up Windows-side
// sessions through crossmount.AllHomes().
//
// The transcript is one JSON object per line:
//
//   - line 1 is the session header:
//     `{"type":"session","version":3,"id":<uuid>,"timestamp":<ISO8601>,
//     "cwd":<absolute raw OS path>}`
//   - every subsequent line is
//     `{"type":"message","id":<8-hex>,"parentId":<8-hex|null>,
//     "timestamp":<ISO8601>,"message":{role,content[],meta{…}},
//     "usage":{…},"model":<string>}` — note that `usage` and `model`
//     sit on the OUTER record, not inside `message`.
//
// `message.content` is an array of Anthropic-shaped content blocks:
// `text`, `tool_use` (`id`/`name`/`input`; ids carry the
// OpenAI-Chat-Completions `chatcmpl-tool-<hex>` prefix, evidence of an
// `@ai-sdk/openai-compatible` backend) and `tool_result`
// (`tool_use_id`/`content[]`/`is_error`). A bare-string `content` and a
// `thinking`/`reasoning` block are both handled defensively — neither
// was observed in the Phase-0 capture, which only exercised a
// non-reasoning free model.
//
// # Dash encoding is LOSSY and never decoded
//
// The directory name drops the leading path separator entirely (NO
// leading dash, unlike Claude Code), lowercases a Windows drive letter,
// drops its colon, and folds `/`, `\` AND `_` into `-` with adjacent
// dashes collapsed — `/tmp/cc_probe_two/sub_dir` becomes
// `tmp-cc-probe-two-sub-dir`. The mapping is therefore not invertible.
// It does not matter: the session header line carries the RAW absolute
// `cwd` inline, so this adapter resolves the project root from that
// field and NEVER decodes a directory name.
//
// # Token capture (Tier 2, JSONL)
//
// Per-assistant-message usage arrives inline as
// `{"inputTokens","outputTokens","cacheReadTokens","cacheWriteTokens",
// "costUsd"}`. `inputTokens` is GROSS — it INCLUDES `cacheReadTokens`
// (triangulated across three live sessions: a brand-new session's very
// first turn already reported ~7,900 cache-read tokens from the
// cross-session-warm system-prompt prefix, and subsequent turns showed
// `cacheReadTokens` tracking `inputTokens` to within tens of tokens
// while `inputTokens` itself barely grew). [models.TokenEvent.InputTokens]
// must be NET, so the adapter subtracts cache-read and clamps at zero,
// exactly as the qwencode adapter does for its OpenAI-shaped backend.
// `cacheWriteTokens` was zero in every sample, so whether it is also
// folded into `inputTokens` is UNVERIFIED — it is carried through as
// CacheCreationTokens and NOT subtracted.
//
// `costUsd` is provider-reported. Command Code proxies ~12 open-weight
// models (deepseek / kimi / glm / minimax / poolside / …) through its
// own gateway, and observer has no independent rate card for them, so
// the reported figure is passed straight through as
// [models.TokenEvent.EstimatedCostUSD] — the same "trust the tool's own
// cost" treatment the opencode and pi adapters get. A genuinely free
// model reports `costUsd: 0`, which the cost engine reads as "no
// recorded cost" and falls back to the pricing table for; a miss there
// surfaces the model as unpriced rather than as a fabricated number.
//
// # Files this adapter deliberately does NOT read
//
//   - `~/.commandcode/auth.json` — the OAuth/session credential for the
//     operator's Command Code account (mode 0600). NEVER read, not even
//     for existence checks that would surface its contents.
//   - `~/.commandcode/history.jsonl` — a CROSS-PROJECT raw-prompt log
//     (`{"p":<prompt>,"t":<unix-ms>}`) with no session correlation.
//     Sensitive and fully redundant with the per-session transcripts;
//     the same call the clinecli adapter makes on
//     `user_input_history.jsonl`.
//   - `<uuid>.checkpoints.jsonl` — one `/rewind` restore point per user
//     turn. It re-copies the raw prompt text and adds nothing to token
//     or action capture, so it is excluded by IsSessionFile even though
//     it also ends in `.jsonl`.
//   - per-project `config.json` — carries a `tasteOnboarding.
//     skippedSessions` map keyed by OTHER tools' names (`claude-code`,
//     `codex`) with THEIR session UUIDs, which is Command Code's
//     `/import` / `/learn-taste` bookkeeping about sibling tools. It is
//     not session data and must not be mistaken for one.
//   - `ide/`, `skills/`, `telemetry-install-id`, `updates.json` — live
//     connection plumbing, user extensions, install telemetry.
//
// The `<uuid>.meta.json` sidecar IS read — LAZILY, at most once per
// parse and only when a usage-bearing record omits its inline model —
// purely as a fallback source for the session's model. (Reading it only
// at offset 0 lost the fallback on every resumed parse.) Its `title` (a
// model-generated session title that can echo pasted secrets) and
// `traceIds` (the tool's own OpenTelemetry ids) are intentionally not
// surfaced. A missing sidecar is a no-op — and so is a SYMLINKED one:
// `<uuid>.meta.json` is a DERIVED path read without the watcher having
// claimed it, so sidecarModel os.Lstats it first and refuses symlinks.
// Without that guard a symlink planted at the sidecar name would
// redirect the read at `auth.json` or `history.jsonl` above.
//
// # Cursor discipline
//
// The byte cursor advances past every fully terminated line, with two
// deliberate deferrals: a partially written trailing line, and the
// record of a tool_use whose tool_result has not landed yet. The second
// exists because store's action ON CONFLICT clause updates neither
// `success` nor `error_message` — an optimistic row shipped between the
// two records could never be corrected, and the parse-local correlation
// map means the later result would be discarded outright. Bounded by
// adapter.MaxDeferTailBytes + adapter.PendingResultGrace so an interrupted
// call cannot stall ingestion; see adapter.DeferUnpairedTail.
//
// # Security
//
// Every string that leaves the adapter — user prompts, assistant text,
// tool inputs, tool outputs, error bodies — passes through the injected
// scrub.Scrubber first.
package commandcode

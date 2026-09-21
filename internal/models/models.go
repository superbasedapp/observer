package models

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// IsMCPToolName reports whether a raw tool name is an MCP tool call in the
// Claude/Anthropic convention `mcp__<server>__<tool>`. Adapters whose MCP
// tools follow this convention call it at their tool-name→action_type
// boundary to promote such calls to ActionMCPCall (instead of
// ActionUnknown). Adapters with a different MCP naming — e.g. Cline's
// `use_mcp_tool` — map those names explicitly rather than through this
// predicate. Keeping the "what is an MCP tool name" test in one place
// keeps the detection consistent across adapters.
//
// Thin wrapper: internal/tooltax.MCPIdentity is the SINGLE Go owner of
// the `mcp__<server>__<tool>` parse (taxonomy plan §1). tooltax imports
// nothing project-internal, so this dependency direction is acyclic by
// construction. Behaviour is unchanged — MCPIdentity's ok result is
// exactly the `mcp__` prefix test this function has always been.
func IsMCPToolName(name string) bool {
	return tooltax.IsMCPToolName(name)
}

// Tool identifiers. These are the stable string values stored in the `tool`
// column of sessions, actions, and token_usage. Adapters must return one of
// these from Adapter.Name().
const (
	ToolClaudeCode = "claude-code"
	ToolCodex      = "codex"
	ToolCursor     = "cursor"
	// ToolCline is the VS Code Cline extension (`saoudrizwan.claude-dev`)
	// — stores task history as a JSON array at
	// `<globalStorage>/saoudrizwan.claude-dev/tasks/<task-id>/
	// api_conversation_history.json`. Distinct from ToolClineCLI
	// (the npm-distributed `cline` 3.x CLI), which is a different
	// product from the same authors with its own SQLite-backed
	// persistence at `~/.cline/data/`.
	ToolCline   = "cline"
	ToolRooCode = "roo-code"
	// ToolZooCode is ZooCode (`ZooCodeOrganization.zoo-code`), the
	// community continuation of Roo Code v3.54.0 published on the VS
	// Code Marketplace since 2026-05-16 after Roo's 2026-04-21
	// shutdown — the vendor's own listing describes it as "same
	// features, settings structure" as Roo v3.54.0. Like ToolRooCode
	// it is a cline-package RETAG, not an adapter of its own:
	// internal/adapter/cline recognises its globalStorage directory
	// (`zoocodeorganization.zoo-code` — VS Code lower-cases the
	// marketplace id on disk; the on-disk spelling is still unconfirmed
	// on a live install) via the clineExtensions table and emits
	// Tool="zoo-code" for tasks found there, parsed by the exact same
	// Roo-shaped task layout. Matching the roo-code precedent, it has
	// no internal/integration registry row by design (see
	// registryRowlessTaxonomyTools in internal/integration).
	ToolZooCode  = "zoo-code"
	ToolCopilot  = "copilot"
	ToolOpenCode = "opencode"
	ToolOpenClaw = "openclaw"
	// ToolPi is the pi coding agent (npm
	// @earendil-works/pi-coding-agent, pi.dev), which persists session
	// JSONL under ~/.pi/agent/sessions/<encoded-cwd>/<ts>_<uuid>.jsonl.
	// Distinct from ToolPrimeAgent, which is a HARD FORK of the same
	// upstream (pi-mono) with its own data home, session layout, entry
	// vocabulary and single-tool (`ipython`) surface.
	ToolPi = "pi"
	// ToolGeminiCLI is Google's Gemini CLI agent (`@google/gemini-cli`),
	// the Node.js terminal AI tool that writes plain JSON / JSONL
	// session files under ~/.gemini/tmp/<project_hash>/chats/.
	// Unrelated to ToolAntigravity despite the shared parent dir.
	ToolGeminiCLI = "gemini-cli"
	// ToolAntigravity is Google's Antigravity IDE (VS Code fork shipped
	// alongside Gemini 3, Nov 2025). Stores conversation state as
	// AES-encrypted Protocol Buffer files under
	// ~/.gemini/antigravity/conversations/<uuid>.pb plus a SQLite-
	// backed index in state.vscdb.
	ToolAntigravity = "antigravity"
	// ToolAntigravityCLI is Google's Antigravity CLI agent (`agy`).
	// Writes plaintext-protobuf SQLite DB at
	// ~/.gemini/antigravity-cli/conversations/<uuid>.db or
	// ~/.gemini/antigravity-cli/conversations/<uuid>.pb.
	ToolAntigravityCLI = "antigravity-cli"
	// ToolCowork is Anthropic's Claude Cowork (the "knowledge-work"
	// desktop product layered on top of Claude Code's CLI). Stores
	// session data as audit.jsonl per local-instance under
	// %LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\local-agent-mode-sessions\
	// (MSIX-redirected on Windows) or
	// ~/Library/Application Support/Claude/local-agent-mode-sessions
	// (macOS). Each local-instance directory is one Observer session;
	// audit.jsonl carries the canonical assistant/user/system/result
	// records plus the inner-Claude-Code session's rich usage payload
	// (5m/1h cache split, service_tier, inference_geo).
	ToolCowork = "cowork"
	// ToolCopilotCLI is GitHub's agentic Copilot CLI (`@github/copilot`
	// npm package, binary at `~/.nvm/.../bin/copilot`), distinct from
	// ToolCopilot (the VS Code Copilot Chat extension). Stores session
	// data as event-stream JSONL at
	// ~/.copilot/session-state/<uuid>/events.jsonl plus per-process
	// debug logs at ~/.copilot/logs/process-*.log. With
	// `--log-level debug` set, the log captures full upstream API
	// response usage objects (prompt_tokens, completion_tokens,
	// cached_tokens, reasoning_tokens) that are NOT exposed in
	// events.jsonl. The adapter joins log usage to events.jsonl
	// assistant.message rows via Request-ID.
	ToolCopilotCLI = "copilot-cli"
	// ToolHermes is Nous Research's Hermes Agent, an open-source
	// multi-platform autonomous AI agent (MIT, Python, schema v14
	// SQLite-backed at ~/.hermes/state.db). 70+ built-in tools across
	// ~28 toolsets, MCP client+server, persistent SOUL.md / MEMORY.md,
	// 18+ LLM providers (Anthropic / OpenAI / OpenRouter / Nous Portal /
	// Gemini / Nvidia / …). Capture is hooks-primary (the documented
	// public plugin API — ctx.register_hook("post_tool_call", …) etc.
	// — installed as a Python plugin at ~/.hermes/plugins/superbased-
	// observer/) with SQLite backfill for historical sessions. The
	// SQLite backfill path reads model strings with provider prefixes
	// (e.g. "nvidia/nemotron-3-ultra:free") and OpenRouter-style :suffix
	// tails that the cost engine strips before pricing lookup.
	// Distinct from Nous Research's Hermes LLM family (Hermes 3, …) —
	// this is the agent runtime.
	ToolHermes = "hermes"
	// ToolKiloCode is the legacy Kilo Code IDE extension (`kilocode.kilo-code`,
	// a Cline + Roo Code fork distributed as a VS Code / JetBrains extension).
	// Persistence layout is byte-identical to ToolCline: per-task directories
	// under `<vsCodeGlobalStorage>/kilocode.kilo-code/tasks/<taskId>/` carrying
	// `api_conversation_history.json` (Anthropic-shaped) + `ui_messages.json`.
	// The kilo-code adapter shares the Cline parse loop and re-tags emitted
	// rows with Tool = "kilo-code" rather than "cline". Distinct from
	// ToolKiloCodeCLI (the npm-distributed @kilocode/cli, an OpenCode fork
	// with its own SQLite store).
	ToolKiloCode = "kilo-code"
	// ToolKiloCodeCLI is the current Kilo Code CLI (`@kilocode/cli` npm
	// package, binary `kilo`, a fork of sst/opencode). The all-new IDE
	// extension is rebuilt on this CLI runtime. Captures via a SQLite store
	// at `~/.local/share/kilo/kilo.db` — same path on Linux, macOS, AND
	// Windows (Kilo intentionally mirrors XDG on every OS). Schema is
	// OpenCode-shaped (`message`/`part`/`todo`) plus Kilo extensions
	// (`project`/`workspace`/`event`/`session_message`/`account`/
	// `permission`/`session_share`). Tokens land on every assistant message
	// in `data.tokens = {total, input, output, reasoning, cache: {read, write}}`.
	// Provider id is `kilo` (the bundled Kilo Gateway,
	// pkg=@kilocode/kilo-gateway); model id form is `kilo-auto/<tier>` for
	// Gateway auto-routing or `<provider>/<model>` for direct providers.
	// Distinct from ToolOpenCode (sst/opencode itself, watching
	// `~/.local/share/opencode/opencode.db`). The cross-mount stageMirror
	// pattern from the opencode adapter applies — foreign-mount kilo.db
	// reads via /mnt/c on WSL need a local mirror before SQLite can open.
	ToolKiloCodeCLI = "kilo-code-cli"
	// ToolClineCLI is the npm-distributed `cline` 3.x CLI (Cline Bot Inc.,
	// Apache-2.0; binary at `%APPDATA%\npm\node_modules\cline\bin\cline`
	// on Windows or `~/.local/bin/cline` on Linux/macOS), distinct from
	// ToolCline (the VS Code Cline extension). Stores all session data
	// under `~/.cline/data/` (every OS, NOT %LOCALAPPDATA% on Windows):
	// `db/sessions.db` (WAL, 28-column sessions table + subagent_spawn_queue
	// + schedules + schedule_executions) paired with per-session JSON at
	// `sessions/<id>/<id>.json` (metadata + cost aggregates) and
	// `sessions/<id>/<id>.messages.json` (Anthropic-shaped content-block
	// conversation history). Capture strategy is SQLite-backfill primary +
	// messages.json content-block walker; optional hook-log JSONL tailer
	// against `logs/hooks.jsonl` once the operator registers hook commands
	// under `<workspace>/.clinerules/hooks/` or `<CLINE_DIR>/hooks/`.
	// First-class sub-agent model — `parent_session_id` / `parent_agent_id` /
	// `agent_id` / `is_subagent` columns surface directly onto the dashboard's
	// parent-child grouping. The 18 `team_*` tools (team_spawn_teammate,
	// team_send_message, team_broadcast, …) all map to `mcp_call` for v1;
	// dedicated team-comm action types may come in v2. NEVER reads
	// `settings/providers.json` (carries WorkOS OAuth tokens + per-provider
	// API keys), `cache/user_input_history.jsonl` (cross-session prompts),
	// or `secrets.json`.
	ToolClineCLI = "cline-cli"
	// ToolQwenCode is Alibaba's Qwen Code CLI (npm `@qwen-code/qwen-code`,
	// binary `qwen`, a diverged Gemini-CLI fork). Sessions persist as
	// Claude-Code-shaped JSONL at
	// `~/.qwen/projects/<dash-sanitized-cwd>/chats/<uuid>.jsonl` (records
	// carry uuid/parentUuid/sessionId/cwd/gitBranch/message) with a
	// companion `<uuid>.runtime.json` (pid/hostname/work_dir). Token usage
	// is the richest of the 2026-07 adapter wave: `ui_telemetry` system
	// records carry input/output/cached_content/thoughts/total token
	// counts (camelCase Gemini names + snake_case duplicates), mirrored
	// into the sidecars `~/.qwen/usage_record.jsonl` and
	// `~/.qwen/usage/token-usage-YYYY-MM.jsonl`. Per-turn model may be
	// non-Qwen (openai-compat providers; gpt-4o/GLM observed live).
	// Directory names dash-sanitize the cwd (`c--programsx-regulation` on
	// Windows) while records carry the raw OS path — translate the record
	// path, not the dir name. NEVER read `~/.qwen/settings.json` content
	// into events: it embeds plaintext provider API keys
	// (DASHSCOPE/ZAI/DEEPSEEK observed 2026-07-09). Boundary note: ships
	// an Alibaba RUM telemetry beacon (default-on usage stats).
	ToolQwenCode = "qwen-code"
	// ToolKiroCLI is AWS's Kiro CLI (`kiro-cli`, the rebranded Amazon Q
	// Developer CLI; standalone install, AWS Builder ID auth, SigV4
	// endpoints — NOT base-URL routable). MODE-DEPENDENT DUAL STORE
	// (live-verified 2026-07-09 on WSL + Windows): interactive sessions
	// write flat-file bundles `~/.kiro/sessions/cli/<uuid>.{json,jsonl,
	// history,lock}` (the `.json` state carries per-turn
	// `conversation_metadata.user_turn_metadatas[]` with
	// input/output_token_count + credit `metering_usage`; the `.jsonl` is
	// the Prompt / AssistantMessage / ToolResults stream, whose content
	// blocks are POLYMORPHIC — only `kind:"text"` carries a string,
	// while `thinking` / `toolUse` / `toolResult` carry objects), while
	// `--no-interactive` runs
	// write ONLY the SQLite `conversations_v2` table in
	// `~/.local/share/kiro-cli/data.sqlite3` (Windows:
	// `%LOCALAPPDATA%\Kiro-Cli\data.sqlite3`), keyed by the RAW cwd string
	// (`C:\...` on Windows — the key itself needs crossmount translation),
	// value = full JSON conversation with env_context. The sqlite
	// `conversations`/`history` tables are shell-history/legacy — not chat.
	ToolKiroCLI = "kiro-cli"
	// ToolCrush is Charm's Crush TUI agent (charmbracelet/crush; npm
	// `@charmland/crush` / winget / brew; FSL-1.1-MIT). Sessions are
	// PROJECT-LOCAL: `<project>/.crush/crush.db` (SQLite) with
	// `sessions(id, title, message_count, prompt_tokens, completion_tokens,
	// cost, …)` — the only wave tool storing a pre-computed dollar cost —
	// and `messages(session_id, role, parts JSON, model, provider, …)`
	// whose parts carry text/reasoning/tool_call/tool_result/finish blocks.
	// The DB's filesystem location IS the project-root signal (cwd is not
	// stored). Global state `~/.local/share/crush/{providers,projects,
	// hyper}.json` (Windows `%LOCALAPPDATA%\crush\`); projects.json maps
	// project path → data dir (the watch-root discovery seam). Providers
	// support custom base_url incl. an `anthropic` type (proxy lane). No
	// seed-interactive lane (upstream issue #1791). Windows crush.json may
	// embed literal provider keys (observed 2026-07-09) — never read it.
	ToolCrush = "crush"
	// ToolKimiCode is Moonshot AI's kimi-code CLI (npm
	// `@moonshot-ai/kimi-code`, binary `kimi`, MIT — the TS successor the
	// Python kimi-cli is "evolving into"; live installs on BOTH OSes were
	// kimi-code, dir `~/.kimi-code/` NOT `~/.kimi/`). Sessions persist at
	// `~/.kimi-code/sessions/wd_<slug>_<hash>/session_<uuid>/` — `state.json`
	// + `agents/main/wire.jsonl` (a wire-protocol trace whose `usage.record`
	// events carry {inputOther, output, inputCacheRead, inputCacheCreation}
	// token splits) — with a `session_index.jsonl` mapping sessionId →
	// workDir. Windows records use FORWARD-slash `C:/Users/...` paths. `-p`
	// prints and exits (no seed-interactive lane → DocAssisted handoff).
	// NEVER read `~/.kimi-code/config.toml`: it holds a plaintext API key
	// (world-readable 644 observed 2026-07-09).
	ToolKimiCode = "kimi-code"
	// ToolGrok is xAI's Grok Build terminal agent (binary `grok`,
	// closed-source beta; community grok-cli npm packages are NOT xAI).
	// Sessions persist as 8-file bundles at
	// `~/.grok/sessions/<url-ENCODED-cwd>/<uuid>/` — chat_history.jsonl +
	// events.jsonl + updates.jsonl (cumulative `_meta.totalTokens`) +
	// rewind_points.jsonl + prompt_context.json + summary.json (carries
	// git_root_dir/git_remotes/head_branch/current_model_id/
	// reasoning_effort). Per-request token splits (prompt/cached_prompt/
	// completion/reasoning) live in the GLOBAL `~/.grok/logs/unified.jsonl`
	// and need session correlation. `session_search.sqlite` is an FTS
	// index only — not the store. Directory names percent-encode the cwd;
	// records carry the raw OS path.
	//
	// DISTINCT from ToolGrokbot, the Grok Bot DESKTOP app: different
	// product, different vendor stack, different on-disk format, no path
	// overlap (~/.grok vs %APPDATA%\Grok Bot).
	ToolGrok = "grok"
	// ToolDevin is Cognition's Devin CLI (binary `devin`, the local CLI
	// released ~2026-04, distinct from cloud Devin; proprietary,
	// live-captured 3000.1.27 on WSL + Windows 2026-07-09). Sessions
	// persist in SQLite `~/.local/share/devin/cli/sessions.db` (Windows
	// `%APPDATA%\devin\cli\sessions.db`): `message_nodes` is a TREE
	// (node_id/parent_node_id) under adjective-noun session ids (e.g.
	// `cobalt-fruit`) with a raw-OS-path working_directory; per-message
	// `metadata.metrics` carried token/ttft fields in the WSL capture
	// while the credit columns (`total_credit_cost`/`total_acu_cost`)
	// existed but read 0. Rendered transcript exports live at
	// `cli/transcripts/<id>.json` (ATIF-v1.7). Backend "Windsurf",
	// model ids like `swe-1-6-slow`; no base-URL override.
	ToolDevin = "devin"
	// ToolAider is Aider (pip `aider-chat`, Apache-2.0). NO central
	// session dir — sessions are per-repo dotfiles at the git root:
	// `.aider.chat.history.md` (Markdown transcript; opens with the argv
	// echoed; token usage appears only as prose like "Tokens: 10k sent")
	// + `.aider.input.history`; `.aider.tags.cache.v4/` is a repo-map
	// cache, not chat. Aider auto-adds `.aider*` to the repo .gitignore.
	// Global `~/.aider/` holds analytics/installs metadata only — no
	// session index, so watch dispatch is project-root-based. No
	// seed-interactive lane (`--message` exits after the turn).
	ToolAider = "aider"
	// ToolQoder is Alibaba's Qoder CLI (closed source; PAT auth against
	// the hardcoded api.qoder.com; the CN edition under `~/.qoder-cn/` is
	// a separate tool). Sessions are Claude-Code-shaped JSONL at
	// `~/.qoder/projects/<dash-sanitized-cwd>/<uuid>.jsonl` with sibling
	// `<sid>/state.json` (encrypted blobs) and run logs under
	// `logs/sessions/<sid>/segments/*.jsonl` whose Anthropic-style token
	// fields were ZERO in live capture — usage is server-side only: no
	// model string and no tokens locally (honest gaps; no base-URL
	// knob). `-i/--prompt-interactive` seed lane verified live.
	ToolQoder = "qoder"
	// ToolGoose is Block's goose agent (binary `goose`, Apache-2.0;
	// live-captured 1.41.0 on WSL 2026-07-09). Sessions persist in WAL
	// SQLite `~/.local/share/goose/sessions/sessions.db` (Windows
	// `%APPDATA%\Block\goose\data\sessions\sessions.db`): `sessions`
	// carries a raw-OS-path working_dir + the richest token columns of
	// the 2026-07 wave (last-turn total/input/output/cache_read/
	// cache_write + accumulated_* sums + accumulated_cost REAL +
	// provider_name + model_config_json.model_name); `messages` holds
	// MCP-shaped content_json blocks (text / toolRequest / toolResponse
	// with structuredContent) keyed by epoch-SECONDS created_timestamp.
	// messages.tokens was NULL in every 1.41.0 capture — token
	// attribution is session-level only. input_tokens is GROSS
	// (includes cache_read; single-turn proof 3062 vs 2944). Sessions
	// persist token-EMPTY when the provider errors. Proxy: goose reads
	// OPENAI_HOST, not OPENAI_BASE_URL. `~/.config/goose/secrets.yaml`
	// is NEVER read.
	ToolGoose = "goose"
	// ToolChatGPTWeb is OpenAI's browser ChatGPT web app (chatgpt.com),
	// captured by the opt-in MV3 browser extension — NOT a coding CLI.
	// The extension's MAIN-world interceptor taps the SSE completion
	// stream (POST /backend-api/conversation and the newer
	// /backend-api/f/conversation), estimates tokens client-side, and
	// relays a captured-turn payload through the native-messaging bridge
	// to `observer browser hook`. Distinct from ToolClaudeCode et al.:
	// no local session file, no server-side usage field, so tokens are
	// ALWAYS TokenSourceEstimated. It is the Phase-1 (ChatGPT-only) member
	// of the planned `*-web` browser-chatbot adapter family
	// (docs/plans/browser-extension-and-m365-copilot-proposal-2026-07-10.md);
	// claude-web / perplexity-web / gemini-web / copilot-web land in
	// Phase 2. The normalizer at internal/adapter/browserchat treats the
	// site as a DATA discriminator (one package, a lookup table), never a
	// per-site code branch.
	ToolChatGPTWeb = "chatgpt-web"
	// ToolClaudeWeb is Anthropic's browser Claude.ai web app, captured by
	// the opt-in MV3 browser extension. The MAIN-world interceptor taps the
	// SSE completion stream (POST /api/organizations/{org}/chat_conversations
	// /{conv}/completion, content_block_delta frames). Like every *-web
	// member tokens are ALWAYS TokenSourceEstimated (no authoritative count
	// in the stream). Phase-2 member of the browser-chatbot adapter family;
	// the site is a DATA discriminator in internal/adapter/browserchat.
	ToolClaudeWeb = "claude-web"
	// ToolPerplexityWeb is Perplexity's browser web app (perplexity.ai),
	// captured by the browser extension via the SSE endpoint
	// /rest/sse/perplexity_ask (NOT the Comet automation WebSocket). Tokens
	// estimated. Phase-2 *-web member; site = DATA discriminator.
	ToolPerplexityWeb = "perplexity-web"
	// ToolGeminiWeb is Google's browser Gemini web app (gemini.google.com),
	// captured by the browser extension via the BatchExecute RPC
	// (/_/BardChatUi/data/batchexecute). The RPC-fragment transport is the
	// hardest to parse of the family — the extension parser is BEST-EFFORT
	// / incomplete and the server row is a minimal degraded stub. Tokens
	// estimated. Phase-2 *-web member; site = DATA discriminator.
	ToolGeminiWeb = "gemini-web"
	// ToolCopilotWeb is Microsoft's CONSUMER Copilot web app
	// (copilot.microsoft.com) — NOT GitHub Copilot (see ToolCopilot /
	// ToolCopilotCLI) and NOT enterprise M365 Copilot. Captured by the
	// browser extension via a WebSocket frame parser (setOptions/send/
	// appendText/done frames, cf_clearance-gated), a genuinely different
	// transport from the SSE sites. Tokens estimated. Phase-2 *-web member;
	// site = DATA discriminator.
	ToolCopilotWeb = "copilot-web"
	// ToolDroid is Factory AI's agentic CLI ("droid", binary droid,
	// distinct from the company name "Factory AI"). Stores per-session
	// transcripts as append-only JSONL at
	// ~/.factory/sessions/<dash-encoded-cwd>/<uuid>.jsonl plus a sidecar
	// <uuid>.settings.json (+ a .settings.json.bak snapshot of the PRIOR
	// settings state) carrying SESSION-LEVEL cumulative token usage — no
	// per-message token field exists in the JSONL itself. The
	// dash-encoded directory name is LOSSY; the authoritative project
	// root is the inline `cwd` field on the session's session_start
	// event. BYOK custom models (settings.json customModels[]) call the
	// underlying provider directly, bypassing Factory's own gateway.
	ToolDroid = "droid"
	// ToolOpenInterpreter is a rebadge of the OpenAI Codex CLI Rust
	// codebase, installed under ~/.openinterpreter instead of ~/.codex —
	// NOT the older Python "Open Interpreter" project. Its rollout JSONL
	// format and token_count event shape are byte-identical to
	// ToolCodex's (GROSS input, netted the same way); model_provider is
	// "openai". Distinguished from ToolCodex purely by install path and
	// binary name, not by wire shape.
	ToolOpenInterpreter = "open-interpreter"
	// ToolCommandCode is commandcode.ai's npm CLI package (binary
	// command-code, UNLICENSED closed-source obfuscated bundle).
	// Persists Claude-Code-shaped per-project dash-encoded transcript
	// directories under ~/.commandcode/projects/ — the dash-encoding
	// differs from ToolClaudeCode's (no leading dash; underscores also
	// fold to dashes). Token capture is per-assistant-message usage
	// envelopes (inputTokens/outputTokens/cacheReadTokens/
	// cacheWriteTokens/costUsd); inputTokens is almost certainly GROSS
	// (high confidence, not proxy-confirmed). COMMANDCODE_API_URL /
	// COMMAND_CODE_API_KEY / COMMANDCODE_API_ENV point at Command Code's
	// own closed gateway, not a BYOK Anthropic/OpenAI-shaped endpoint.
	ToolCommandCode = "command-code"
	// ToolMuse is Meta's Muse Code CLI ("muse") — a statically linked Rust
	// binary (`fbcode/musecode`, internal crate prefix `tbh_`) fronted by a
	// self-updating shell launcher at ~/.local/bin/muse. Linux + macOS only;
	// there is no Windows build. Persists an append-only EVENT-SOURCED log
	// (NOT a chat transcript) at the date-sharded path
	// ~/.local/share/muse/sessions/YYYY/MM/DD/<session-uuid>/session.jsonl,
	// with child-agent logs under `<session>/subagent/<child-uuid>/`. Every
	// line is a record envelope {schema_version,id,stream,sequence,
	// recorded_at,record_type,payload_type,payload}; `recorded_at` is
	// MICROSECONDS since epoch. Tokens come from the `model_completed`
	// event's usage envelope, where BOTH gross fields must be netted:
	// input_tokens INCLUDES cache_read_tokens and output_tokens INCLUDES
	// reasoning_tokens (the OpenAI-Responses convention this backend
	// speaks — `resp_`/`rs_`/`fc_`/`msg_` item ids). Model traffic goes to
	// https://api.meta.ai/v1 with a login-MINTED base URL, so there is no
	// operator-settable BYOK endpoint and no proxy lane today.
	ToolMuse = "muse"
	// ToolPrimeAgent is Prime Intellect's Prime Agent CLI ("prime-agent";
	// installed via curl -fsSL https://app.primeintellect.ai/prime-agent/
	// install.sh | sh — NOT a published npm package: the on-disk install is
	// npm-package-SHAPED (`npm ls -g` reports it as `prime-agent@0.7.0`)
	// but registry.npmjs.org/prime-agent 404s; see the integration
	// registry's Binary comment on this row, corrected 2026-08-07). A HARD
	// FORK of pi-mono — it still carries the inherited `@earendil-works/pi-*`
	// package identifiers and a `piConfig` manifest key — so its session
	// ENVELOPE is recognisably pi-shaped, but it is NOT a rebadge of
	// ToolPi: the data home is ~/.prime/agent (not ~/.pi/agent), sessions
	// are FLAT `sessions/<session-uuid>.jsonl` (not per-project
	// directories with a timestamp-prefixed basename), the entry
	// vocabulary adds compaction / child_usage_attributed / agent_status /
	// session_state / git_state / label / session_info, and the model is
	// given exactly ONE built-in tool, `ipython`, a persistent Python
	// kernel it drives to read, edit and run everything. Entry timestamps
	// are ISO-8601 strings; the inner `message.timestamp` is Unix
	// MILLISECONDS. `usage.input` is already NET of `cacheRead`
	// (totalTokens == input+output+cacheRead+cacheWrite holds exactly), and
	// the envelope publishes no reasoning-token count. Sessions carry a
	// provider-reported `usage.cost` breakdown.
	ToolPrimeAgent = "prime-agent"
	// ToolDeepSeek is DeepSeek Harness ("deepseek"; npm package
	// "@deepseek-ai/dsh", launched web-only via `npx @deepseek-ai/dsh
	// web` — a local GUI at http://127.0.0.1:3080, no separate
	// terminal/TUI mode). Its own event-sourced parser (not a §2.1 retag):
	// sessions live at ~/.dsh/sessions/<cwd-slug>/session-<uuid>/
	// session.jsonl.zstd, identical path on WSL and native Windows, and
	// the file is REWRITTEN WHOLE on every flush (full recompress, not an
	// append) — internal/adapter/deepseek re-decodes the entire file each
	// poll rather than streaming from a byte offset. Envelope shape
	// {"type","seq","time","data":{...}}; assistant/message carries a
	// data.usage SIBLING of data.message with {inputTokens,outputTokens,
	// cacheReadTokens?} already NET of cache (confirmed live: an
	// inputTokens smaller than that row's cacheReadTokens). Scope is
	// deliberately usage-capture only: no proxy, no hooks, no MCP, no
	// terminal/remote — see the package doc for the full record-shape
	// reference and the honest known-gaps list (Windows sessions are
	// backfill-only; sub-agent rollup is ungrounded).
	ToolDeepSeek = "deepseek"
	// ToolJunie is JetBrains Junie ("junie"), the TUI coding agent
	// embedded in JetBrains IDEs. Own event-sourced parser (not a §2.1
	// retag): sessions live at ~/.junie/sessions/<session-id>/
	// events.jsonl, one JSON envelope per line ({"kind",...} at the top
	// level, with agent-facing UI updates wrapped in a
	// SessionA2uxEvent{"event":{"kind",...}}). Blocks (Terminal /
	// FileChanges / Result) are collapsed by their stable `stepId`: the
	// SAME id recurs across IN_PROGRESS -> terminal-status transitions
	// and is REBROADCAST once more, byte-identical, at outer task
	// completion — the parser keys on stepId and updates in place rather
	// than emitting duplicates. Project root resolves from the first
	// non-empty CurrentDirectoryUpdatedEvent.currentDirectory seen in the
	// stream (empty on early occurrences, populated later), falling back
	// to the sibling ~/.junie/sessions/index.jsonl's projectDir keyed by
	// session id. Token usage comes from LlmResponseMetadataEvent.
	// modelUsage[], one entry per model, already NET of cache (no gross
	// subtraction needed). No proxy, no hooks, no MCP, no verified
	// interactive-seed/resume contract — see the package doc for the full
	// record-shape reference and the honest known-gaps list.
	ToolJunie = "junie"
	// ToolZcode is Z.AI's zcode CLI ("zcode"; npm `zcode-app-cli`), an
	// OpenCode fork. Structural transposition of internal/adapter/opencode
	// with ONE difference: OpenCode's per-message token bundle is ZEROED in
	// zcode, so tokens come from zcode's own model_usage table (per-call,
	// provider_id/model_id, full cache split; netInput = input_tokens -
	// cache_read) and the watermark includes model_usage. SQLite store at
	// ~/.zcode/cli/db/db.sqlite (same layout Linux/macOS/Windows). See
	// internal/adapter/zcode and docs/zcode-adapter.md.
	ToolZcode = "zcode"
	// ToolMistralCode is Mistral AI's `vibe` CLI ("mistral-code"; uv-tool
	// console script, Python 3.12+). Per-session-dir store at
	// ~/.vibe/logs/session/<...>/ (messages.jsonl + meta.json). Tokens are
	// SESSION-LEVEL from meta.json/stats (session_prompt_tokens GROSS →
	// netted vs session_cached_tokens; ON CONFLICT MAX-upgrade); no
	// per-message usage. See internal/adapter/mistralcode and
	// docs/mistral-code-adapter.md.
	ToolMistralCode = "mistral-code"
	// ToolFreebuff is Freebuff ("freebuff"; npm `freebuff`), the Manicode →
	// Codebuff → Freebuff lineage. Store under the legacy manicode dir:
	// ~/.config/manicode/projects/<slug>/chats/<RFC3339>/chat-messages.json
	// (+ run-state.json for the real cwd; `.config/manicode` on EVERY OS).
	// The whole-file cursor is a MESSAGE COUNT (the array is rewritten in
	// place). THIN store: NO billable tokens (contextTokenCount is a
	// context-window size, not usage) — sessions + actions only. See
	// internal/adapter/freebuff and docs/freebuff-adapter.md.
	ToolFreebuff = "freebuff"
	// ToolGrokbot is Grok Bot, the xAI DESKTOP agent app (Electron;
	// productName "Grok Bot", internal package name "sand", author
	// "SpaceXAI", built on Anysphere/Cursor's agent stack — the asar
	// depends on 30+ @anysphere/* workspaces and ships cursor-proclist).
	//
	// DISTINCT from ToolGrok, the Grok CLI: different product, different
	// format, no path overlap.
	//
	// Store: <electron userData>/sand-client-persistence/<base32(key)>.blob
	// (%APPDATA%\Grok Bot on Windows, ~/Library/Application Support/Grok Bot
	// on macOS; not distributed for Linux). Every blob is PLAINTEXT JSON
	// {"schemaVersion":N,"value":{…}} — no encryption/DPAPI/protobuf/SQLite.
	// The filename is the persistence-slice key in RFC-4648 base32 over a
	// LOWERCASE alphabet, unpadded. Only the
	// `…transcript.replicas.<agentId>` slice is ingested (one blob per
	// conversation, whole-file rewrite ⇒ the cursor is an ENTRY COUNT); the
	// sibling roster slice is deliberately not watched.
	//
	// THIN store: the agent executes in a REMOTE sandbox ("the box"), so
	// there are NO tokens, NO model names, NO cost and NO cwd on disk —
	// sessions + actions only, under the synthetic root "[grokbot]". The
	// roster's `path` (/home/box/sand-data/…) is a REMOTE path and must
	// never be resolved. NEVER read sand-secrets.json, the sealed
	// local-exec-daemon-*.json, "Local State", or Network/Cookies. See
	// internal/adapter/grokbot and
	// docs/plans/grokbot-adapter-plan-2026-08-28.md.
	ToolGrokbot = "grokbot"
	// ToolKiroCrew is AWS's Kiro Crew — the multi-agent orchestration
	// layer on top of Kiro: a desktop app (installed under
	// %LOCALAPPDATA%\kirocrew-desktop-updater on Windows) plus a
	// `kirocrew` CLI, both talking to a local HTTP Gateway on
	// localhost:5476. AWS Builder ID / Google sign-in; same auth gate as
	// kiro-cli. Grounded on a live signed-in Windows run 2026-09-03.
	//
	// Store: `~/.kiro/crew/sessions/<thread>_<slot>.jsonl` (override
	// KIROCREW_HOME) — one JSONL per desktop chat tab, line 1 a MUTABLE
	// `{"_type":"metadata", …}` header (title/project/agent/model/tags),
	// then `role` ∈ {user, assistant, tool} lines. NOT the
	// `conversations/` directory the vendor README's tree implies; that
	// directory does not exist on a live install.
	//
	// OWNERSHIP / DOUBLE-COUNT: Crew DRIVES kiro-cli as its execution
	// engine, and the driven session writes its own richer store at
	// `~/.kiro/sessions/cli/<sid>.{json,jsonl}` with `session_state.
	// agent_name == "kirocrew"` and BYTE-IDENTICAL `tooluse_*` call ids.
	// kiro-cli is the CANONICAL owner of the conversation (it is the
	// superset — 3 Crew-driven sessions on the grounded host vs 1 Crew
	// transcript — and carries typed tool kinds, per-turn metering and
	// the model id); the kirocli adapter stamps those sessions
	// `desktop`/`kiro-crew`. This adapter emits conversation rows ONLY
	// for a Crew chat with no kiro-cli twin, resolved through the
	// Gateway's `~/.kiro/crew/session_map.json` index.
	//
	// Tokens: NONE. The Crew transcript carries no usage fields at all,
	// and the driven kiro-cli bundle reports input/output_token_count
	// structurally 0 with billing in CREDITS (deliberately not tokens).
	//
	// NEVER read `~/.kiro/crew/.env` (Slack bot tokens, workspace owner
	// id), `config.json`, `audit.log`, `memory.db`, `workspace/**` or
	// `security_events.jsonl`. See internal/adapter/kirocrew and
	// docs/kiro-crew-adapter.md.
	ToolKiroCrew = "kiro-crew"
	// ToolPoolside is Poolside's agentic coding model ("laguna"), reached
	// today ONLY as a JetBrains AI Assistant ACP agent
	// (`acp.registry.poolside`) — no standalone CLI/TUI launch surface was
	// found on the grounding host. JetBrains downloads the per-OS binary
	// under `<JetBrains vendor root>/acp-agents/poolside/<ver>/
	// pool-<os>-<arch>[.exe]` (Windows-grounded 2026-09-05:
	// `pool-windows-amd64.exe`); config/skills/credentials live at the
	// UNIVERSAL (even on Windows) `~/.config/poolside/` XDG path
	// (settings.yaml, credentials.json — NEVER READ — skills/).
	//
	// Store: `<AppData-Local-equivalent>/poolside/trajectories/
	// trajectory-<agentId>_<sessionId>.ndjson` — an event-sourced,
	// flat-envelope NDJSON (one `{"type":"<kind>","<kind_with_dots_as_
	// underscores>":{...}}` record per line) recording the FULL turn
	// loop: thought.start/end (model reasoning), assistant_message.
	// start/end (visible reply), tool_call.parsed (name + args, a JSON
	// OBJECT not a string) + tool_call.approval (user allow/deny) +
	// tool_call.result (a per-tool typed result object PLUS a generic
	// `observation` string), and tool_call.inference.start/.end (the
	// PER-CALL token usage — richer than most Tier-2 sources). The
	// SESSION ID lives ONLY in the filename (no `session_id` field
	// anywhere in the body), matching the ACP registry pointer's sid
	// VERBATIM — grounded 2026-09-05 against a live IntelliJ IDEA
	// 2026.2.2 run (`acp.registry.poolside:01a06e04-7ef2-…`).
	//
	// Tokens: `tool_call_inference_end.input_tokens` is GROSS (includes
	// `cache_read_input_tokens`, confirmed by summing every per-call
	// value against the session-level `usageTotals` rollup in the
	// sibling flat `acp/<encoded-cwd>/<sessionId>.json` summary file —
	// exact match); netted the same way as muse/codex. No reasoning-
	// token field is present. No pricing entry exists for
	// `poolside/laguna-*` models, so cost rows resolve as `unknown`.
	//
	// NEVER reads `~/.config/poolside/credentials.json` (OAuth/API
	// tokens) or the sibling `acp/…/<id>.json` flat summary and
	// `pool/logs/…/acp.log.jsonl` protocol log — both are redundant with
	// (and derivable from) the trajectory this adapter parses. See
	// internal/adapter/poolside and docs/poolside-adapter.md.
	ToolPoolside = "poolside"

	// ToolZed is Zed's own NATIVE coding agent (zed.dev; the Claude-ACP-in-
	// Zed integration path did not persist a usable local store, so this
	// adapter targets the built-in agent instead). Grounded live 2026-09-06.
	//
	// Store: `<Zed-app-data-dir>/threads/threads.db` (SQLite, opened
	// read-only, WAL-tolerant) — a per-OS app-data directory (%LOCALAPPDATA%
	// \Zed on Windows, ~/Library/Application Support/Zed on macOS,
	// ~/.local/share/zed on Linux — note the Linux path is XDG_DATA_HOME,
	// NOT ~/.config). One `threads` row is one session; `data_type`="zstd"
	// + `data` (a zstd-compressed JSON blob, magic 28 B5 2F FD) hold the
	// FULL thread, REWRITTEN WHOLE on every turn — the freebuff-desktop
	// rewrite-in-place pattern, not an append. `updated_at` (TEXT,
	// RFC3339Nano) is the watermark; there is no per-message timestamp
	// anywhere in the payload, so per-block Timestamps are synthesized
	// from a session-start base plus a per-message-index increment (the
	// freebuff CLI-layout precedent) — never taken as literal wall-clock
	// times.
	//
	// The decompressed JSON's `messages` array is an EXTERNALLY-TAGGED
	// enum: each element is `{"User":{...}}` or `{"Agent":{...}}}`. A User
	// message carries `content:[{"Text":...}]`; an Agent message carries
	// `content` blocks (`Text` / `ToolUse` / `Thinking`, at minimum —
	// unknown kinds are skipped, never guessed) plus a `tool_results` map
	// keyed by the ToolUse call id. 7 grounded native tool names: read_file
	// / write_file / edit_file / list_directory / find_path / terminal /
	// delete_path.
	//
	// Tokens: `request_token_usage` (keyed by the user message id) is
	// per-turn and, unlike most adapters here, `input_tokens` is ALREADY
	// NET of `cache_read_input_tokens` — no netting arithmetic applies.
	// `cumulative_token_usage` is a thread-level running total and is
	// never itself turned into a row (it would double-count every
	// `request_token_usage` entry). Model traffic in the one grounded
	// capture reports `model.provider`="zed.dev" / `model.model`=
	// "gpt-5.6-luna" — Zed's own managed model gateway; no pricing entry
	// exists for it (a closed, non-mainstream backend), so cost rows
	// resolve as unknown rather than a fabricated price.
	//
	// Surface: stamped SurfaceIDE / "zed" — Zed is itself the editor, and
	// its built-in agent has no separate CLI/TUI launch surface for
	// `observer zed` to start (capture-only: no proxy, no hook, no MCP).
	//
	// NEVER reads Zed's `settings.json` / `keymap.json` or any credential
	// store — only `threads/threads.db` (+ its `-wal` / `-shm` siblings).
	// See internal/adapter/zed and docs/zed-adapter.md.
	ToolZed = "zed"
)

// Normalized action types. See spec §5. Adapters map their tool-specific
// action names onto this set; if no mapping fits, use ActionUnknown and keep
// the raw name in RawToolName.
const (
	ActionReadFile      = "read_file"
	ActionWriteFile     = "write_file"
	ActionEditFile      = "edit_file"
	ActionRunCommand    = "run_command"
	ActionSearchText    = "search_text"
	ActionSearchFiles   = "search_files"
	ActionWebSearch     = "web_search"
	ActionWebFetch      = "web_fetch"
	ActionBrowserAction = "browser_action"
	ActionMCPCall       = "mcp_call"
	// ActionSpawnSubagent is a sub-agent invocation. In Claude Code this
	// is the `Agent` tool — the parent thread emits a tool_use that
	// launches a sub-agent runtime; the sub-agent's activity is logged
	// inline in the SAME session JSONL with `isSidechain: true` per
	// line. Distinguishing this action type lets the dashboard count
	// "agent fan-out" separately from regular tool work.
	ActionSpawnSubagent = "spawn_subagent"
	// ActionTodoUpdate is a structured-todo-list management call. In
	// Claude Code this is TaskCreate / TaskUpdate / TaskList / TaskGet
	// / TaskOutput / TaskStop — administrative tools the agent uses to
	// track its own work plan. Distinct from spawn_subagent (Agent) and
	// from task_complete (legacy).
	ActionTodoUpdate = "todo_update"
	// ActionTaskComplete is an EVIDENCE-GROUNDED turn terminus: a row an
	// adapter emits because the source stream said the turn ended, not
	// because the assistant happened to speak. The contract is narrow on
	// purpose — a row may only carry this type when the harness itself
	// supplies the terminal signal:
	//
	//   - a stop/finish reason on the message (openclaw
	//     `message.assistant.stop`, gated on StopReason=="stop"; kilo-code-cli
	//     `assistant.stop`; opencode `complete:` rows),
	//   - a dedicated terminal event in the wire format (codex's
	//     `event_msg`/`task_complete`),
	//   - a turn-terminal HOOK firing (claude-code's Stop hook,
	//     cmd/observer/hook.go::buildClaudeStopEvent), or
	//   - a native completion tool the model called on purpose (cline
	//     `attempt_completion`, cline-cli `submit_and_exit`).
	//
	// It is NOT the label for the assistant merely producing text — use
	// ActionAssistantMessage for that. See its doc comment for the
	// exemplar pattern the whole family converges on.
	ActionTaskComplete = "task_complete"
	ActionAskUser      = "ask_user"
	ActionUserPrompt   = "user_prompt"
	// ActionAssistantMessage is the model's natural-language response text
	// (an assistant message / agent reply), recorded PER MESSAGE — one row
	// per text block / text part / prose chunk, mid-turn rows included.
	// Adapters emit it with RawToolName "<tool>.assistant_text".
	//
	// The exemplar is openclaw (internal/adapter/openclaw/adapter.go): each
	// text part of an assistant message becomes an `openclaw.assistant_text`
	// assistant_message row, AND a separate, stop-reason-gated
	// `message.assistant.stop` row carries ActionTaskComplete. Two raw
	// names, two action types, one unambiguous meaning each — per-message
	// text and turn terminus are different facts and get different rows.
	// claude-code is the same shape across two producers: the JSONL walker
	// emits the per-block assistant_message rows, its Stop hook emits the
	// task_complete one.
	//
	// Historically most adapters recorded assistant text as
	// ActionTaskComplete, which conflated the two facts (an assistant
	// narrating mid-turn is not a task completion — 85% of claude-code and
	// codex turns carry more than one such row). WP-T6/B2 swept the
	// remaining emit sites and migration 078 repairs the rows already on
	// disk, EXCEPT the claude-code Stop-hook rows, which are genuinely
	// terminal and keep task_complete.
	//
	// The dashboard assistant-text surface keys off the RawToolName
	// "<tool>.assistant_text" suffix (not the ActionType), and both types
	// sit in tooltax CategoryMeta, so the relabel is display- and
	// aggregate-safe. This type is for the spoken response only —
	// chain-of-thought must not be folded into it.
	//
	// Reasoning is NOT an action and has no action type (WP-T6/B3,
	// resolved 2026-07-31). A model thinking is not something it DID: the
	// chain-of-thought rides the successor event's PrecedingReasoning
	// column and never becomes a row of its own. The reference shape is
	// grok (internal/adapter/grok/adapter.go): capture the thinking into
	// pending state, flush it onto the next assistant-message / tool-call
	// event, scrub at flush, discard at the user-turn boundary. The
	// CONSUMPTION semantics are deliberately per-adapter — consumed-once
	// (grok/crush/hermes/cline-cli/antigravity), fan-out
	// (cline/cowork/codex-per-turn), shared-preamble (openclaw) — each
	// documented at its own emit site, because they track how the source
	// format scopes a preamble. An opaque placeholder (codex's
	// "(encrypted reasoning, N bytes)") is not content and is threaded
	// nowhere: it simply vanishes.
	ActionAssistantMessage = "assistant_message"
	// ActionTurnAborted is a turn that was interrupted before completion
	// (user pressed esc, cancelled the agent, etc.). Distinct from
	// task_complete with success=false: aborted turns never finished
	// generating, so the model output is partial. Codex emits a
	// dedicated event_msg/turn_aborted for this; for analysts the
	// distinction matters for cost analysis (aborted turns still
	// consumed input/output tokens up to the abort point).
	ActionTurnAborted = "turn_aborted"
	// ActionContextCompacted is an upstream-emitted context-window
	// compaction event — the model (or its host) decided to summarize/
	// drop earlier turns to stay within context. Codex emits a top-
	// level `compacted` event whose payload carries the replaced
	// messages; the row records msg-count + byte/token estimate so the
	// dashboard can surface compaction frequency without polluting the
	// file-edit timeline. NOT searchable like ActionEditFile —
	// dashboard filters typically exclude it from action-type browsers.
	ActionContextCompacted = "context_compacted"
	// ActionSystemPrompt is a system-prompt-shaped message captured
	// from a platform that exposes the model's seed instructions: codex
	// session_meta.base_instructions, codex turn_context.
	// developer_instructions, codex response_item.message.role=developer,
	// or openclaw custom/bootstrap-context:full. Symmetric to
	// ActionUserPrompt — both are message-shaped rows where the body
	// IS the value (RawToolInput carries the scrubbed text; Target a
	// short preview; MessageID a content hash for cross-row dedup).
	// Adapters MUST hash-dedup within a session so a single base
	// system prompt repeated across every turn_context only emits
	// one row.
	ActionSystemPrompt = "system_prompt"
	// ActionPromptContext is a NON-content prompt-budget component: a
	// named slice of the prompt (tool definitions, rules, skills,
	// subagent definitions, …) whose CONTENT the source tool does not
	// persist, but whose token/char COUNT it records. Distinct from
	// ActionSystemPrompt (which carries real content) so the dashboard
	// renders it as "Prompt context" rather than "System prompt".
	// Emitted as a zero-cost informational row (no token_usage) so the
	// operator can reconcile a turn's large input — the per-section
	// counts sum to ~the gross prompt the model received. First used by
	// the cursor adapter (store.db root-blob section index, where tools
	// + rules typically dominate the input). Target carries
	// "<Section> — N tokens, M chars"; RawToolName is
	// "prompt_section.<name>".
	ActionPromptContext = "prompt_context"
	// ActionAPIError captures upstream-API failures (Anthropic /
	// OpenAI / Gemini error responses) that the JSONL adapters or the
	// proxy observe. Surfaces content-policy blocks, rate limits,
	// invalid-request errors, etc. that pre-v1.4.20 were dropped on
	// the floor — the proxy filtered out non-2xx responses and the
	// claudecode adapter skipped the `type: "system"` records where
	// these land. Target carries the upstream `request_id` (joinable
	// to api_turns.request_id when both proxy + JSONL saw it),
	// ErrorMessage carries the human-readable body, RawToolName
	// preserves the upstream error class (`invalid_request_error` /
	// `rate_limit_error` / `overloaded_error` / etc.). Success is
	// always false.
	ActionAPIError = "api_error"
	// ActionToolFailure captures a tool call that failed at the host level
	// (the host returned an error to the model, distinct from an upstream
	// API error). Surfaces hook-side observability for tool failures whose
	// pairing in the JSONL transcript is awkward (the transcript carries
	// tool_result with is_error=true but not the structured failure_type
	// or duration_ms that the post-tool-failure hook does). Target carries
	// the tool name, RawToolName the failure_type when reported, ErrorMessage
	// the human-readable body. Success is always false.
	ActionToolFailure = "tool_failure"
	// ActionSubagentStart / ActionSubagentStop bracket a sub-agent's own
	// runtime, distinct from the parent's tool_use that launched it
	// (which remains ActionSpawnSubagent). The pair carries agent_id +
	// agent_type so dashboards can chart per-subagent fan-out, total
	// time, and final response length.
	ActionSubagentStart = "subagent_start"
	ActionSubagentStop  = "subagent_stop"
	// ActionSessionStart / ActionSessionEnd are explicit session-lifecycle
	// markers from hook events. Sources that capture sessions via JSONL
	// watcher (claude-code) infer these from the first/last record;
	// hook-only or proxy-only sources (codex pre-watcher, cursor) need
	// the explicit rows. Target carries the source/exit reason
	// ("startup|resume|clear|compact" for start; "clear|resume|logout|
	// prompt_input_exit|bypass_permissions_disabled|other" for end).
	ActionSessionStart = "session_start"
	ActionSessionEnd   = "session_end"
	// ActionNotification captures host-level notification dispatches —
	// permission_prompt, idle_prompt, auth_success, elicitation_*. Target
	// carries the notification_type, ErrorMessage carries the message body.
	ActionNotification = "notification"
	// ActionCwdChange records a working-directory change observed by the
	// host (Claude Code's CwdChanged hook). Target carries the new cwd,
	// PrecedingReasoning carries the previous cwd (so before/after pairs
	// are diffable from a single row).
	ActionCwdChange = "cwd_change"
	// ActionUserPromptExpansion captures a user prompt that expanded into a
	// slash-command or MCP-prompt invocation. Distinct from ActionUserPrompt
	// (the free-text submit): UserPromptExpansion fires AFTER UserPromptSubmit
	// when the input matches a registered slash-command or mcp-prompt name.
	// Target carries command_name; RawToolName carries expansion_type
	// ("slash_command" | "mcp_prompt"); RawToolInput carries the original
	// prompt text (slashes intact) plus command_source / command_args as
	// JSON so analysts can see what the user typed before expansion.
	ActionUserPromptExpansion = "user_prompt_expansion"
	// ActionPostToolBatch is the end-of-batch summary fired after a run
	// of consecutive tool calls. Distinct from per-tool PostToolUse rows:
	// PostToolBatch carries the LIST of tool_calls in the batch (their
	// names + serialized results) as one row. Target carries the batch
	// tool-count summary ("N tool call(s)"); RawToolInput carries the
	// tool_calls JSON array (scrubbed/truncated) so analysts can see the
	// batch composition without joining N rows.
	ActionPostToolBatch = "post_tool_batch"
	// ActionPermissionRequest captures an explicit permission-check fire
	// where the host asks the user (or auto-mode classifier) to authorize
	// a tool call. Target carries the tool_name being asked about;
	// RawToolName the tool_name verbatim; RawToolInput the tool_input
	// arguments scrubbed; PrecedingReasoning the permission_suggestions
	// JSON (e.g. addRules / setMode proposals) when present so analysts
	// can see WHAT was suggested as the resolution. Success is true (the
	// request itself is just the prompt — the outcome lands as either
	// a continued tool execution or an ActionPermissionDenied row).
	ActionPermissionRequest = "permission_request"
	// ActionPermissionDenied captures an auto-mode classifier denial.
	// Distinct from ActionToolFailure: ToolFailure is the tool itself
	// failing; PermissionDenied is the permission layer refusing to
	// dispatch the tool in the first place. Target carries tool_name;
	// RawToolName tool_name; RawToolInput the tool_input arguments;
	// ErrorMessage the classifier's reason text. Success is always false.
	ActionPermissionDenied = "permission_denied"
	// ActionPermissionMode captures a permission-mode toggle — Claude
	// Code's `permission-mode` line type, written whenever the user
	// enters or exits plan mode / acceptEdits / similar. Target carries
	// the new mode value ("plan" | "acceptEdits" | "default"); RawToolName
	// stays empty; RawToolInput holds the raw line's JSON for any
	// future-added fields. Lifecycle marker — not a tool call.
	//
	// Pre-v1.6.10 these lines were silently dropped on the claudecode
	// JSONL path (audit B4, operator-confirmed oversight 2026-05-18).
	ActionPermissionMode = "permission_mode"
	// ActionSetup captures Claude Code's per-session setup / maintenance
	// fire (`--init-only`, `-p --init`, `-p --maintenance`). Lifecycle
	// marker distinct from ActionSessionStart: Setup fires only on init/
	// maintenance modes, not on every session launch. Target carries the
	// trigger ("init" | "maintenance").
	ActionSetup = "setup"
	// ActionInstructionsLoaded captures a CLAUDE.md / instructions file
	// load fire. Lifecycle marker for which file landed in context and
	// why. Target carries the file_path; RawToolName the memory_type
	// ("User" | "Project" | "Local" | "Managed"); RawToolInput the
	// load_reason and optional globs / trigger_file_path / parent_file_path
	// fields as JSON.
	ActionInstructionsLoaded = "instructions_loaded"
	// ActionConfigChange captures a settings.json mutation observed by
	// the host. Lifecycle marker for cross-session policy / permission /
	// MCP-server changes. Target carries the file_path (when reported);
	// RawToolName the source ("user_settings" | "project_settings" |
	// "local_settings" | "policy_settings" | "skills").
	ActionConfigChange = "config_change"
	// ActionWorktreeCreate captures Claude Code's WorktreeCreate hook
	// fired when an Agent spawn requests `isolation: "worktree"`.
	// Blocking hook — observer's handler must output a worktree path
	// on stdout (per `code.claude.com/docs/en/hooks` matrix) or the
	// spawn fails. Target carries the worktree name; RawToolInput
	// carries the echoed path (so dashboards can confirm where the
	// worktree was placed). NOT in the default claudeCodeEvents
	// registration list — opt-in only via manual settings.json edit
	// (see docs/claude-worktree-hook.md).
	ActionWorktreeCreate = "worktree_create"
	// ActionWorktreeRemove captures Claude Code's WorktreeRemove hook
	// fired when a worktree is cleaned up. Non-blocking (logging only
	// per the docs matrix). Target carries the worktree_path; safe to
	// register by default — incorrect handler behavior cannot break
	// spawns.
	ActionWorktreeRemove = "worktree_remove"
	// ActionRateLimit captures a host-emitted rate-limit status check.
	// Cowork's audit.jsonl emits a `rate_limit_event` record per poll
	// (~50/session in observed data) carrying the current window
	// status (allowed/rejected) and reset time. Codex 0.130+ emits the
	// same shape inside `token_count.rate_limits.{primary,secondary,
	// credits}` per turn — when that landing lands, the codex adapter
	// emits ActionRateLimit too. Target carries the rateLimitType
	// (e.g. "five_hour" / "primary"); RawToolName the status; Success
	// is true when status=="allowed". The full rate_limit_info JSON
	// is scrubbed into RawToolInput; typed fields land on
	// ActionMetadata.RateLimit*.
	ActionRateLimit = "rate_limit"

	// The agent-orchestration + harness family, added by the tool-taxonomy
	// plan (docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md
	// §1/§6 WP-T4). They close the measured `unknown` gap that migration
	// 024's comment deferred as "a separate taxonomy decision": the codex
	// wait/wait_agent/spawn_agent/send_message/write_stdin family and the
	// claude-code ToolSearch/Monitor/SendMessage/Skill/ScheduleWakeup/
	// StructuredOutput family. internal/tooltax re-declares these VALUES
	// (it may not import this package); migration 077 backfills the
	// historical rows.

	// ActionSubagentWait is a blocking wait on one or more already-spawned
	// sub-agents (codex `wait` / `wait_agent`). Distinct from
	// ActionSpawnSubagent (the launch) and from ActionSubagentStart /
	// ActionSubagentStop (the child's own lifecycle bracket) — this row is
	// the PARENT blocking on a child.
	ActionSubagentWait = "subagent_wait"
	// ActionAgentMessage is an inter-agent message: work or instructions
	// handed to an EXISTING agent thread rather than to a new one (codex
	// `send_message` / `followup_task`, claude-code `SendMessage`).
	ActionAgentMessage = "agent_message"
	// ActionAgentControl is an orchestration verb that neither spawns,
	// waits, nor messages — enumerating, inspecting or interrupting the
	// agent/thread pool (codex `list_agents` / `interrupt_agent` /
	// `read_thread` / `list_threads` / `read_thread_terminal`,
	// claude-code `Monitor`).
	ActionAgentControl = "agent_control"
	// ActionSkillInvoke is a skill / packaged-instruction-set invocation
	// (claude-code `Skill`). It is countable separately from MCP tool use
	// on purpose; note the cowork adapter deliberately folds its own
	// `Skill` into ActionMCPCall, which stays a cowork-specific semantic
	// remap rather than being flattened here.
	ActionSkillInvoke = "skill_invoke"
	// ActionSchedule is a scheduling primitive: register / inspect /
	// cancel a future or recurring agent run (claude-code
	// `ScheduleWakeup` / `CronCreate` / `CronDelete` / `CronList`). The
	// droid adapter maps its own Cron*/Automation* family to
	// ActionConfigChange instead ("the closest honest bucket",
	// droid/records.go) — a recorded divergence, not an oversight.
	ActionSchedule = "schedule"
	// ActionToolSearch is the deferred-tool loader: the agent searching
	// the tool REGISTRY for a tool to load (claude-code `ToolSearch`). It
	// is a search over the harness, not over the project, which is why it
	// is not ActionSearchText / ActionSearchFiles.
	ActionToolSearch = "tool_search"
	// ActionStdinWrite writes to the stdin of a live agent / exec session
	// (codex `write_stdin`). It is the channel into an ALREADY-RUNNING
	// thread, not a fresh shell invocation, so it is not ActionRunCommand.
	ActionStdinWrite = "stdin_write"
	// ActionHarnessCall is the honest bucket for host-harness builtins
	// that are neither file, command, search, web, agent, skill nor MCP
	// work — claude-code `StructuredOutput` / `SendUserFile` / `Artifact`
	// / `Workflow`, codex `imagegen`, copilot-cli `report_intent`, the
	// `<tool>.step_finish` turn markers. It exists so these stop being
	// indistinguishable from genuinely unmapped tools in ActionUnknown.
	ActionHarnessCall = "harness_call"

	ActionUnknown = "unknown"
)

// Freshness classifications for file and command accesses. See spec §7.
const (
	FreshnessFresh             = "fresh"
	FreshnessStale             = "stale"
	FreshnessChangedBySelf     = "changed_by_self"
	FreshnessChangedExternally = "changed_externally"
	FreshnessUnknown           = "unknown"
)

// Token source and reliability tags. See spec §24 for the reliability matrix.
const (
	TokenSourceJSONL     = "jsonl"
	TokenSourceOTel      = "otel"
	TokenSourceHook      = "hook"
	TokenSourceProxy     = "proxy"
	TokenSourceEstimated = "estimated"
	// TokenSourceLogDelta is the copilot-cli Tier 2 estimate — derived
	// from `CompactionProcessor: Utilization X% (CTX/128000 tokens)`
	// snapshots in the process log when no upstream usage block was
	// captured for the matching response. Carries InputTokens only
	// (the gross prompt size at the time of the request); OutputTokens
	// is filled in by the Tier 3 (events.jsonl) row that shares the
	// same MessageID. Always reliability='approximate'.
	TokenSourceLogDelta = "log_delta"
	// TokenSourceSessionSummary is the copilot-cli Tier 0 capture —
	// derived from `session.shutdown.data.modelMetrics` in events.jsonl.
	// Each entry covers one model's cumulative usage delta for the work
	// span between the most recent `session.resume` and this
	// `session.shutdown`. Carries InputTokens / CacheReadTokens /
	// CacheCreationTokens (from `cacheWriteTokens`) / ReasoningTokens;
	// OutputTokens is left zero because Tier 3 (`source='jsonl'`)
	// already captures per-message outputTokens and including them
	// here would double-count. Superseded by Tier 1 (`source='otel'`)
	// when debug logging is on — the store-layer dedup drops
	// session_summary rows for any session that has an otel row, since
	// Tier 1 already has full per-request breakdowns. Always
	// reliability='approximate'.
	TokenSourceSessionSummary = "session_summary"

	ReliabilityAccurate    = "accurate"
	ReliabilityApproximate = "approximate"
	ReliabilityUnreliable  = "unreliable"
	ReliabilityUnknown     = "unknown"
)

// API providers recognized by the proxy (spec §9).
const (
	ProviderAnthropic = "anthropic"
	ProviderOpenAI    = "openai"
	// ProviderGoogle is Google's Gemini generateContent API
	// (generativelanguage.googleapis.com). Distinct wire shape from
	// Anthropic/OpenAI — the proxy parses usageMetadata for token capture.
	ProviderGoogle = "google"
)

// Project is a git-root-scoped grouping of sessions. Non-git directories use
// the working directory as the project root. See spec §20.
type Project struct {
	ID        int64
	RootPath  string
	GitRemote string
	// The following fields are the Project Identity Resolver v2 identity
	// bundle (docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
	// §3.1 / W1, migration 102). GitUpstreamRemote ships raw only under
	// ShareOptions.shipsRawContent() (like GitRemote); GitRemoteOwner and
	// GitUpstreamOwner have NO raw column at all — they exist only as
	// their sha256 hash (git_remote_owner_hash / git_upstream_owner_hash),
	// computed at store time from these transient string values.
	// RootCommitSHA and ContentFingerprint are NODE-LOCAL pre-images
	// (root_commit_sha / content_fingerprint columns) that never leave
	// the node in any share mode — only sha256(RootCommitSHA) and
	// sha256(ContentFingerprint) ship, always. RootCommitCheckedAt is the
	// 7-day retry fence for the lazy root-commit exec (see
	// internal/store/projectidentity.go's RootCommitNeedsCheck) and is
	// never on the wire.
	GitUpstreamRemote   string
	GitRemoteOwner      string
	GitUpstreamOwner    string
	RootCommitSHA       string
	ContentFingerprint  string
	RootCommitCheckedAt time.Time
	Name                string
	CreatedAt           time.Time
	LastSessionAt       time.Time
}

// Session is a single AI coding tool run. Session IDs are tool-supplied
// where possible and deterministic across re-parses.
type Session struct {
	ID           string
	ProjectID    int64
	Tool         string
	Model        string
	GitBranch    string
	StartedAt    time.Time
	EndedAt      time.Time
	TotalActions int
	Metadata     string // JSON blob for tool-specific extras.
	// OrgID / UserEmail are org-attribution (Teams & Org Visibility,
	// migration 029). Empty on solo-local installs; stamped by
	// identity.Stamper at insert time only when the agent is enrolled,
	// persisted as NULL otherwise.
	OrgID     string
	UserEmail string
	// ForkedFromID / ParentThreadID / ThreadSource are codex
	// fork/subagent lineage (migration 069), NODE-LOCAL — never on the
	// org-push wire. They are written ONLY through
	// Store.SetSessionLineage (not UpsertSession); a zero value here is
	// the norm for every non-codex and every normal codex session.
	ForkedFromID   string
	ParentThreadID string
	ThreadSource   string
	// Workspace / IsWorktree are the per-session half of the Project
	// Identity Resolver v2 bundle (migration 102, §3.1). Workspace is
	// the session cwd's position inside the repo ("" == repo root);
	// its raw value ships only under ShareOptions.shipsRawContent(),
	// like GitBranch, while workspace_hash ships always. IsWorktree
	// (whether this session's cwd reached the root through a linked git
	// worktree) ships always as a plain bool, never content.
	Workspace  string
	IsWorktree bool
	// Surface / SurfaceHost are the normalized capture-surface
	// attribution (migration 107): WHICH kind of client produced the
	// session (SurfaceCLI / SurfaceIDE / SurfaceDesktop / SurfaceSDK /
	// SurfaceWeb) and the concrete host token ("vscode", "cursor",
	// "jetbrains", "claude-desktop", ...). NODE-LOCAL — never on the
	// org-push wire. Written ONLY through Store.SetSessionSurface (not
	// UpsertSession), FIRST-WINS-UNLESS-EMPTY per column: the first
	// grounded stamp sticks and a later parse can only fill a column
	// that is still empty. Empty = the adapter found no grounded
	// discriminator on disk (never fabricated).
	Surface     string
	SurfaceHost string
	// ToolVersion is the captured tool/CLI version that produced the
	// session (migration 125): the free-form semver string an adapter
	// resolved from a grounded on-disk field (Codex
	// `session_meta.cli_version`, Cline `cline_version`, Claude Code
	// transcript top-level `version`, ...). NODE-LOCAL — never on the
	// org-push wire. Written ONLY through Store.SetSessionToolVersion
	// (not UpsertSession), FIRST-WINS-UNLESS-EMPTY. Empty = the adapter
	// found no grounded version on disk — the honest "unknown", NEVER
	// fabricated.
	ToolVersion string
}

// ActionMetadata is the per-event JSON-marshaled metadata column on
// actions (migration 017). Captures fields Claude Code and Codex
// hook payloads emit on every fire that don't fit the typed columns:
// the permission mode the host was in (default | bypass_permissions
// | plan), the Codex reasoning effort level (minimal | low | medium
// | high), and whether a tool failure was a user interrupt vs a
// genuine error.
//
// v1.4.52 added codex 0.130+ turn_context fields:
//   - CollaborationMode  ("default" | "plan" — high-signal because
//     plan mode is read-only-thinking)
//   - Personality        (Codex Desktop persona; "friendly" etc.)
//   - RealtimeActive     (bool — true while the real-time/voice
//     surface is active; unstable signal until docs land)
//   - TruncationMode +   (codex's per-turn truncation strategy +
//     TruncationLimit     token budget — useful for "why was this
//     turn shortened" forensics)
//   - TimeToFirstTokenMS (latency from task_started to first
//     assistant token on task_complete events
//     only; signals model warmup + queue time)
//
// All fields are omitempty — a zero-valued struct marshals to {} and
// the store layer persists NULL instead, so the column stays dense.
//
// Note: Codex Desktop's `speed` toggle (standard | fast) is NOT
// captured here because Codex 0.130.0-alpha.5 does not persist it
// into the rollout JSONL. Empirically verified by flipping the
// toggle mid-session on session 019e22b1-… and re-grepping — no
// `speed`/`priority`/`tier`/`latency` field appears anywhere in the
// post-flip rollout. Tracked as deferred until Codex emits it.
//
// v1.4.53 added Cowork-specific fields plus shared fields generalizable
// to other Anthropic-API consumers:
//   - CoworkProcessName  (per-local-instance "adj-adj-name" identifier
//     from sidecar.processName)
//   - CoworkTitle        (Cowork's auto-generated session title)
//   - HostLoopMode       (true = uses host filesystem; false = sandbox)
//   - ServiceTier        (assistant.message.usage.service_tier;
//     "standard" / "priority"). Generalizes — codex
//     0.130+ also emits this on token_count rows.
//   - InferenceGeo       (assistant.message.usage.inference_geo)
//   - CacheCreate5mTok / (5m vs 1h split inside cache_creation_input_tokens —
//     CacheCreate1hTok    the 1h tier is priced ~2× the 5m default; this
//     pair is the first time observer captures it on
//     the action row, complementing the existing
//     TokenEvent.CacheCreation1hTokens proxy field)
//   - TotalCostUSD       (Cowork-authoritative cost per task on result rows;
//     calibration target for observer's derived cost)
type ActionMetadata struct {
	PermissionMode     string `json:"permission_mode,omitempty"`
	EffortLevel        string `json:"effort_level,omitempty"`
	IsInterrupt        bool   `json:"is_interrupt,omitempty"`
	CollaborationMode  string `json:"collaboration_mode,omitempty"`
	Personality        string `json:"personality,omitempty"`
	RealtimeActive     bool   `json:"realtime_active,omitempty"`
	TruncationMode     string `json:"truncation_mode,omitempty"`
	TruncationLimit    int64  `json:"truncation_limit,omitempty"`
	TimeToFirstTokenMS int64  `json:"time_to_first_token_ms,omitempty"`
	CoworkProcessName  string `json:"cowork_process_name,omitempty"`
	CoworkTitle        string `json:"cowork_title,omitempty"`
	HostLoopMode       bool   `json:"host_loop_mode,omitempty"`
	ServiceTier        string `json:"service_tier,omitempty"`
	InferenceGeo       string `json:"inference_geo,omitempty"`
	// StopReason is the assistant message's terminal reason
	// (end_turn / max_tokens / tool_use / stop_sequence / refusal /
	// pause_turn). Per-message; surfaced per message in session review.
	// Captured from the on-disk transcript (claude-code, cowork) — the
	// hook payloads don't carry it. Distinct from api_turns.stop_reason
	// (the proxy path); this is the watcher/transcript path.
	StopReason             string  `json:"stop_reason,omitempty"`
	CacheCreate5mTok       int64   `json:"cache_create_5m_tok,omitempty"`
	CacheCreate1hTok       int64   `json:"cache_create_1h_tok,omitempty"`
	TotalCostUSD           float64 `json:"total_cost_usd,omitempty"`
	CoworkToolSummary      string  `json:"cowork_tool_summary,omitempty"`
	RateLimitStatus        string  `json:"rate_limit_status,omitempty"`
	RateLimitType          string  `json:"rate_limit_type,omitempty"`
	RateLimitResetsAt      int64   `json:"rate_limit_resets_at,omitempty"`
	RateLimitOverageStatus string  `json:"rate_limit_overage_status,omitempty"`
	// PermissionApprovalKind captures the specific approval granularity
	// reported by `permission.completed.result.kind`. Empirically observed
	// values: "approved" (generic, single-call), "approved-for-location"
	// (scoped to a filesystem prefix in LocationKey), "approved-for-session"
	// (scoped to the lifetime of the session), "denied". For plain "approved"
	// the field stays empty so the column doesn't churn — only the
	// non-default kinds are recorded. Source: copilotcli (v1.6.13).
	PermissionApprovalKind string `json:"permission_approval_kind,omitempty"`
	// PermissionLocationKey is the filesystem prefix bound to an
	// approved-for-location permission grant. Captured verbatim from
	// `permission.completed.result.locationKey`. Example: "D:\\OneDrive -
	// Microsoft". Source: copilotcli (v1.6.13).
	PermissionLocationKey string `json:"permission_location_key,omitempty"`
	// ParentSessionID identifies the parent of a sub-agent session.
	// Populated by the clinecli adapter from sessions.parent_session_id
	// (and by future adapters with first-class sub-agent models). Empty
	// for lead sessions and for sessions on platforms without explicit
	// parent linkage. Distinct from the existing Action.IsSidechain
	// flag — IsSidechain marks Claude-Code-style same-session sub-agent
	// activity; ParentSessionID marks a sub-agent whose lifecycle lives
	// in its OWN session row (the cline-cli / hermes model).
	ParentSessionID string `json:"parent_session_id,omitempty"`
	// ParentAgentID identifies the lead agent that spawned this sub-
	// agent. Pairs with ParentSessionID. Populated by clinecli from
	// sessions.parent_agent_id.
	ParentAgentID string `json:"parent_agent_id,omitempty"`
	// AgentID is the running session's own agent identifier — usually
	// a short string like "agt_lead_<sid>" or a teammate name. Empty
	// for sessions on platforms without an agent_id column.
	AgentID string `json:"agent_id,omitempty"`
	// IsSubagent marks whether the owning session is a sub-agent
	// (clinecli sessions.is_subagent = 1). Pre-existing
	// Action.IsSidechain serves the same role for Claude-Code-style
	// sub-agents; the two are independent.
	IsSubagent bool `json:"is_subagent,omitempty"`
	// TeamName is the team this session is enrolled in (Cline CLI's
	// teams.db namespace). Populated when sessions.team_name is set —
	// note that a session can have team_name without is_subagent=1
	// (the workspace has a team config but this run isn't spawned as
	// a teammate). Phase 0 reality-check finding.
	TeamName string `json:"team_name,omitempty"`
	// RequestURL is the upstream API path a browser-captured turn hit
	// (browserchat: CapturedTurn.RequestURL). It is a URL/path only —
	// never prompt or response content — surfaced as API-call detail on
	// the assistant message row. Empty for every non-browser adapter.
	RequestURL string `json:"request_url,omitempty"`
	// IDSource is the browser extension's per-turn provenance for how it
	// obtained the conversation id: "none" | "request" | "stream" |
	// "resume" (browserchat: CapturedTurn.IDSource). Empty for non-browser
	// adapters and for older bridges that omit it.
	IDSource string `json:"id_source,omitempty"`
	// Granularity is the EFFECTIVE (post-daemon-ceiling clamp) capture
	// granularity of a browser-captured turn: "usage_only" | "redacted" |
	// "full" (browserchat). It records how much content the row was allowed
	// to store, so the dashboard can be honest about a usage-only row's
	// missing prompt/response. Empty for non-browser adapters.
	Granularity string `json:"granularity,omitempty"`
	// PromptTokensEst / ResponseTokensEst are the browser extension's
	// per-turn ESTIMATED token counts (browserchat: always estimates, never
	// metered). Surfaced as API-call detail on the assistant row. Zero for
	// non-browser adapters and for turns with no estimate.
	PromptTokensEst   int64 `json:"prompt_tokens_est,omitempty"`
	ResponseTokensEst int64 `json:"response_tokens_est,omitempty"`
	// CaptureSource is the RAW client-discriminator value an adapter read
	// from the store before resolving it into the normalized
	// SessionSurface (antigravity: `trajectory_meta.source=<int>`).
	// Recorded on the session-opening user_prompt rows so an unmapped
	// value stays auditable after the fact; never interpreted downstream.
	CaptureSource string `json:"capture_source,omitempty"`
}

// IsZero reports whether the struct has no non-zero fields. Used by
// the store layer to decide between writing the JSON blob and NULL.
//
// IMPORTANT (Invariant #50): every new field added to ActionMetadata
// MUST be added to this check or sparse-zero rows will marshal to
// non-NULL "{}" and pollute the column. Pinned by the reflection
// invariant TestActionMetadata_IsZeroCoversEveryField.
func (m ActionMetadata) IsZero() bool {
	return m.hookFieldsZero() && m.telemetryFieldsZero() &&
		m.rateLimitFieldsZero() && m.identityFieldsZero()
}

// hookFieldsZero reports whether the hook / turn-shape metadata fields
// (permission, effort, interrupt, collaboration, personality, realtime,
// truncation, time-to-first-token) are all zero. Split out of IsZero to keep
// its cyclomatic complexity in bounds; the four *FieldsZero helpers together
// still cover every ActionMetadata field (Invariant #50).
func (m ActionMetadata) hookFieldsZero() bool {
	return m.PermissionMode == "" && m.EffortLevel == "" && !m.IsInterrupt &&
		m.CollaborationMode == "" && m.Personality == "" && !m.RealtimeActive &&
		m.TruncationMode == "" && m.TruncationLimit == 0 && m.TimeToFirstTokenMS == 0
}

// telemetryFieldsZero reports whether the cowork / service-tier / inference-geo /
// cache-create / cost metadata fields are all zero.
func (m ActionMetadata) telemetryFieldsZero() bool {
	return m.CoworkProcessName == "" && m.CoworkTitle == "" && !m.HostLoopMode &&
		m.ServiceTier == "" && m.InferenceGeo == "" &&
		m.CacheCreate5mTok == 0 && m.CacheCreate1hTok == 0 && m.TotalCostUSD == 0 &&
		m.CoworkToolSummary == ""
}

// rateLimitFieldsZero reports whether the rate-limit and permission-location
// metadata fields are all zero.
func (m ActionMetadata) rateLimitFieldsZero() bool {
	return m.RateLimitStatus == "" && m.RateLimitType == "" &&
		m.RateLimitResetsAt == 0 && m.RateLimitOverageStatus == "" &&
		m.PermissionApprovalKind == "" && m.PermissionLocationKey == ""
}

// identityFieldsZero reports whether the org/identity attribution and
// browser-estimate metadata fields are all zero.
func (m ActionMetadata) identityFieldsZero() bool {
	return m.ParentSessionID == "" && m.ParentAgentID == "" && m.AgentID == "" &&
		!m.IsSubagent && m.TeamName == "" && m.StopReason == "" &&
		m.RequestURL == "" && m.IDSource == "" && m.Granularity == "" &&
		m.PromptTokensEst == 0 && m.ResponseTokensEst == 0 && m.CaptureSource == ""
}

// Action is one normalized tool call within a session. The
// (SourceFile, SourceEventID) pair uniquely identifies an action so that
// re-parsing a session file never inserts duplicates.
type Action struct {
	ID                 int64
	SessionID          string
	ProjectID          int64
	Timestamp          time.Time
	TurnIndex          int
	ActionType         string
	IsNativeTool       bool
	Target             string
	TargetHash         string
	Success            bool
	ErrorMessage       string
	DurationMs         int64
	ContentHash        string
	FileMtime          time.Time
	FileSizeBytes      int64
	Freshness          string
	PriorActionID      int64
	ChangeDetected     bool
	PrecedingReasoning string
	RawToolName        string
	RawToolInput       string // Scrubbed tool input as rendered for the dashboard. Adapter-capped at 1 MiB via internal/contentcap.
	// RawToolOutput is the full, scrubbed tool_result body. Adapter-
	// capped at 1 MiB via internal/contentcap and stored verbatim in
	// actions.raw_tool_output so the dashboard's on-demand full-text
	// endpoint can serve the operator the real bytes (not just the
	// 2 KB FTS5 excerpt in action_excerpts). Empty when the adapter
	// never saw the paired result.
	RawToolOutput string
	Tool          string
	SourceFile    string
	SourceEventID string
	// IsSidechain marks actions emitted inside a sub-agent runtime
	// (spawned via the parent's `Agent` tool). Sub-agents share their
	// parent's SessionID; this flag is the only structural marker
	// distinguishing parent-thread work from sub-agent work. Used by
	// discover.staleReads to segment cross-thread redundancy and by
	// the Sessions tab to surface sub-agent volume.
	IsSidechain bool
	// MessageID is the upstream Anthropic message id (msg_xxx) that
	// produced this action. Populated by adapters that have access to
	// the parent message (claudecode reads it from each JSONL line's
	// `message.id` field). Empty for action types that don't have a
	// natural parent (user_prompt rows pre-backfill, platforms with
	// no upstream message id).
	MessageID string
	// Metadata is per-event JSON metadata captured by hook adapters
	// (permission_mode / effort_level / is_interrupt). Nil when no
	// fields apply; the store layer marshals non-nil values to JSON
	// for the actions.metadata column. See ActionMetadata.
	Metadata *ActionMetadata
	// OrgID / UserEmail are org-attribution (Teams & Org Visibility,
	// migration 029). Empty on solo-local installs; stamped by
	// identity.Stamper at insert time only when the agent is enrolled,
	// persisted as NULL otherwise.
	OrgID     string
	UserEmail string
	// ContentBytes is the byte length of the code the model AUTHORED in
	// this action (Output Composition / Verbosity feature, migration 054):
	// Write `content`, Edit `new_string`, MultiEdit Σ`new_string`,
	// NotebookEdit `new_source`, or the `command` for a run_command. It is
	// a length, never the content. 0 (→ NULL on disk) for actions that
	// authored nothing (reads, searches) and on adapters that don't yet
	// compute it. NODE-LOCAL — not on the org-push seam.
	ContentBytes int64
	// UserAttachments records the files/images/audio a USER attached to a
	// prompt turn (Issue 1, migration 126). PRESENCE + COUNT + KIND
	// (+ optional MediaType) only — NEVER filenames or bytes, since a
	// filename can encode ticket/codename ids (the same reasoning that
	// gated git_branch). Nil/empty = no attachments; the store layer
	// marshals a non-empty slice to JSON for actions.user_attachments.
	// NODE-LOCAL — not on the org-push seam.
	UserAttachments []UserAttachment
}

// UserAttachment is a single file/image/audio a user attached to a prompt
// turn. Metadata only, by design: Kind is the coarse class ("image" |
// "file" | "audio"), MediaType the optional IANA type ("image/png",
// "application/pdf") when the source exposes it. It deliberately carries
// NO filename and NO bytes — those are content and are never captured
// (Issue 1 privacy rule; same reasoning that gated git_branch). Captured
// at each adapter's own boundary (CLAUDE.md #3), resolved into these
// capability fields so nothing downstream switches on source shape.
type UserAttachment struct {
	Kind      string `json:"kind"`
	MediaType string `json:"media_type,omitempty"`
}

// ToolEvent is the adapter → storage transport type for a single tool call.
// It carries everything needed to insert an Action plus upsert its Session
// and Project.
type ToolEvent struct {
	SourceFile    string
	SourceEventID string
	SessionID     string
	ProjectRoot   string
	Timestamp     time.Time
	TurnIndex     int
	GitBranch     string
	// GitRemote is the adapter's normalized "origin" remote (via
	// git.NormalizeRemote — see internal/git/normalize.go), mirroring
	// GitBranch: adapters that resolve project git metadata set both
	// from the same internal/git.Info. Empty when the adapter has no
	// git remote to offer (a non-git project root, or an adapter whose
	// project-root resolution never calls internal/git — see the Team
	// Project Identity Mapping plan, 2026-08-21, §0.4). Flows to
	// Store.Ingest -> UpsertProject as the project-level identity
	// signal used for cross-machine/cross-developer team grouping.
	GitRemote string
	// The following six fields are the Project Identity Resolver v2
	// capture bundle (docs/plans/project-identity-resolver-v2-plan-2026-
	// 09-06.md §3.1 / W1), set from the same internal/git.Identity a
	// git-aware adapter already resolves alongside GitRemote/GitBranch.
	// Every field here ships to an org server as a hash ALWAYS
	// (git_upstream_remote_hash, git_remote_owner_hash,
	// git_upstream_owner_hash, root_commit_hash, content_fingerprint_hash,
	// workspace_hash — unsalted sha256, joinable across nodes); the raw
	// GitUpstreamRemote and Workspace values additionally ship in the
	// clear ONLY under ShareOptions.shipsRawContent(), exactly like
	// GitRemote/ProjectRoot today (internal/store/orgpush.go). RootCommitSHA
	// and ContentFingerprint have NO raw wire counterpart in any share
	// mode — only their hashes ever leave the node. All are honestly
	// empty when the adapter has no git info to offer, or (RootCommitSHA)
	// when the lazy per-project exec hasn't run yet — see
	// internal/store/projectidentity.go.
	GitUpstreamRemote  string
	GitRemoteOwner     string
	GitUpstreamOwner   string
	RootCommitSHA      string
	ContentFingerprint string
	// Workspace is this session's position inside the repo — the cwd's
	// nearest ancestor manifest directory, relative to the git root (""
	// == repo root). Raw value gated like GitUpstreamRemote above;
	// workspace_hash ships always.
	Workspace string
	// IsWorktree marks a session whose cwd reached its project root
	// through a linked git worktree rather than the main checkout. Ships
	// always (bool, not content).
	IsWorktree         bool
	Model              string
	Tool               string
	ActionType         string
	Target             string
	Success            bool
	ErrorMessage       string
	DurationMs         int64
	PrecedingReasoning string
	RawToolName        string
	RawToolInput       string
	// ContentBytes is the byte length of code the model authored in this
	// action (see [Action.ContentBytes]). Computed by the adapter from the
	// untruncated tool input; flows to actions.content_bytes.
	ContentBytes int64
	// ToolOutput is the scrubbed tool_result body. Lands in two places
	// at store time: (a) the actions.raw_tool_output column verbatim
	// (capped at 1 MiB by the adapter via internal/contentcap), so the
	// dashboard's on-demand full-text endpoint can serve it; and (b)
	// the FTS5 action_excerpts table, trimmed to 2 KiB by the Indexer
	// for search. Empty when the adapter didn't see the paired result.
	ToolOutput string
	// IsSidechain marks events emitted inside a sub-agent runtime.
	// See [Action.IsSidechain].
	IsSidechain bool
	// MessageID is the upstream Anthropic message id (msg_xxx) of the
	// API turn that contained this tool call. Populated by adapters
	// that have access to the parent message (claudecode reads it from
	// each JSONL line's `message.id` field). Empty when the adapter
	// can't determine the parent — e.g. user_prompt rows or platforms
	// where the upstream client doesn't surface a message id.
	MessageID string
	// Metadata is per-event hook metadata that survives the
	// ToolEvent → Action conversion in store.Ingest. Nil when the
	// adapter has no metadata to record. See [ActionMetadata].
	Metadata *ActionMetadata
	// OutcomePending marks a tool call whose in-window outcome was
	// never observed: the parse window ended before the tool_result
	// record, so Success=true here is optimistic, not measured.
	// Failure-context bookkeeping must wait for the matching
	// [ActionOutcomeUpdate] — recording it at insert time would file
	// an unobserved success, wrongly marking prior failures of the
	// same command eventually_succeeded. The action row itself still
	// inserts normally.
	OutcomePending bool
	// UserAttachments records the files/images/audio a USER attached to
	// this prompt turn (Issue 1, migration 126). PRESENCE + COUNT + KIND
	// (+ optional MediaType) only, NEVER filenames or bytes. Set by the
	// adapter at its own boundary from its own source shape; flows through
	// store.Ingest into actions.user_attachments. See [UserAttachment].
	UserAttachments []UserAttachment
}

// ActionOutcomeUpdate carries the late-arriving outcome of an already-
// persisted action: a tool_result parsed in a LATER watcher tick than the
// tool_use that created the row. Keyed by the action's
// (SourceFile, SourceEventID) uniqueness pair. Applied via
// Store.UpdateActionOutcome, whose merge rules hold: success is
// authoritative, error_message only written when non-empty, duration
// only backfills a zero, output length-merges.
//
// It deliberately carries no tool name / target: cross-tick the parser
// has already forgotten them (the tool_use lives in the previous parse
// window). The FTS index call tolerates the empty strings.
type ActionOutcomeUpdate struct {
	SourceFile    string
	SourceEventID string
	// SuccessKnown gates the Success field. False (the zero value, so
	// the safe default for a parser that forgets to set it) means the
	// result record reported no verdict and the persisted success
	// column must be left exactly as it is — writing an invented
	// success would flip a row an earlier telemetry record already
	// marked failed. True means Success is authoritative.
	SuccessKnown bool
	Success      bool
	ErrorMessage string
	ToolOutput   string
	DurationMs   int64
}

// TokenEvent is the adapter → storage transport type for per-turn token
// usage. The proxy produces accurate values; JSONL adapters produce
// approximate or unreliable ones — hence the Source+Reliability fields.
//
// ProjectRoot and GitBranch are carried so the store layer can upsert the
// owning session even for JSONL lines that have usage data but no tool_use
// block (e.g. subagent compaction turns).
type TokenEvent struct {
	SourceFile    string
	SourceEventID string
	SessionID     string
	ProjectRoot   string
	GitBranch     string
	// GitRemote is the adapter's normalized "origin" remote, mirroring
	// ToolEvent.GitRemote exactly (see that field's doc comment). Set
	// from the same per-session state GitBranch already flows through
	// wherever an adapter builds TokenEvent and ToolEvent from the same
	// source.
	GitRemote string
	// The following six fields mirror ToolEvent's Project Identity
	// Resolver v2 bundle exactly (see that struct's doc comment for the
	// full field-by-field hash-always / raw-gated wire posture); set
	// from the same per-session internal/git.Identity wherever an
	// adapter builds a TokenEvent and ToolEvent from the same source.
	GitUpstreamRemote   string
	GitRemoteOwner      string
	GitUpstreamOwner    string
	RootCommitSHA       string
	ContentFingerprint  string
	Workspace           string
	IsWorktree          bool
	Timestamp           time.Time
	Tool                string
	Model               string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	// CacheCreation1hTokens is the subset of CacheCreationTokens that
	// landed in Anthropic's 1h ephemeral tier (priced at 2× the 5m
	// default). Zero means all cache_creation tokens are 5m — correct
	// for any provider that doesn't expose the breakdown.
	CacheCreation1hTokens int64
	ReasoningTokens       int64
	// WebSearchRequests is the count of server-side web_search invocations
	// billed under Anthropic's "$10 per 1,000 searches" fee — separate from
	// per-token costs. Zero for non-Anthropic providers and for events that
	// didn't trigger web_search. The cost engine adds
	// web_search_requests × Pricing.WebSearchPerRequest to the total.
	WebSearchRequests int64
	// Fast marks turns served in the provider's low-latency "fast" tier
	// (Anthropic Opus 4.8 with speed:"fast" on the Messages API). When
	// true AND the model's Pricing.FastMultiplier > 0, the cost engine
	// scales the AI token cost by FastMultiplier. Stamped by the proxy
	// when the outbound request body carries "speed":"fast", and by the
	// claude-code JSONL adapter when the usage envelope echoes
	// `speed:"fast"`; defaults false everywhere else. Persisted to
	// token_usage.fast via migration 035.
	Fast             bool
	EstimatedCostUSD float64
	Source           string
	Reliability      string
	// MessageID is the per-API-call identifier this token row belongs to.
	// For Anthropic adapters (claudecode, cline, openclaw, …) it's the
	// upstream `msg_xxx` returned by the Messages API — one MessageID
	// per API request. For codex (v1.7.24+) it's the per-event identifier
	// derived from the rollout JSONL line (`tk:<file>:L<n>`), since codex
	// emits one token_count event per model inference and a single user-
	// turn typically produces multiple inferences. See TurnID below to
	// recover the turn-level grouping.
	MessageID string
	// TurnID groups token rows that belong to the same user-turn. Populated
	// by adapters whose per-API-call granularity is finer than the user-
	// turn boundary (codex emits N token_count events per turn). NULL on
	// adapters where MessageID already corresponds 1:1 to a user-turn
	// (claudecode and the other Anthropic adapters). Persisted to
	// token_usage.turn_id by migration 032.
	TurnID string
	// OrgID / UserEmail are org-attribution (Teams & Org Visibility,
	// migration 029). Empty on solo-local installs; stamped by
	// identity.Stamper at insert time only when the agent is enrolled,
	// persisted as NULL otherwise.
	OrgID     string
	UserEmail string
	// IsSidechain marks usage rows emitted inside a sub-agent runtime —
	// the token-usage analogue of [Action.IsSidechain] (migration 010):
	// claudecode reads the flag straight off each transcript line, so a
	// sub-agent's turns land on the PARENT's session flagged 1 and the
	// per-sub-agent token/cost rollups (dashboard sub-agents view,
	// migration 087) can bucket them without a separate session row.
	// NODE-LOCAL — not on the org-push wire.
	IsSidechain bool
}

// APITurn is one request/response pair observed by the proxy. Accurate token
// counts come from the provider's response body; session/project linkage is
// best-effort (nil session_id when the caller omits the X-Session-Id header).
// See spec §9 and the api_turns schema in §6.2.
// LimitSnapshot is one rate-limit / subscription-window observation
// parsed from an upstream HTTP response on the proxy path — the limit
// half of the Next-Message Cost & Limit Predictor. NODE-LOCAL (never
// pushed to an org server; migration 049). Optional window/classic
// fields are pointers so an absent header maps to a NULL column rather
// than a misleading zero.
type LimitSnapshot struct {
	ID         int64
	ScopeHash  string // auth-identity hash (R4); "default" fallback
	Provider   string // anthropic | openai
	SessionID  string // best-effort; "" when the proxy couldn't resolve one
	ObservedAt time.Time

	Window5hUtil  *float64 // 0..1
	Window5hReset *int64   // unix seconds
	Window7dUtil  *float64
	Window7dReset *int64

	ReqLimit     *int64
	ReqRemaining *int64
	ReqReset     *int64
	TokLimit     *int64
	TokRemaining *int64
	TokReset     *int64

	Status string // unified-status passthrough
	Raw    string // allow-listed, scrubbed header subset; "" when none
}

// HasAnyWindow reports whether the snapshot carries at least one
// subscription-window or classic limit signal — the gate for persisting
// it (a response with no limit headers at all is not worth a row).
func (s LimitSnapshot) HasAnyWindow() bool {
	return s.Window5hUtil != nil || s.Window7dUtil != nil ||
		s.ReqRemaining != nil || s.TokRemaining != nil
}

type APITurn struct {
	ID                  int64
	SessionID           string
	ProjectID           int64
	Timestamp           time.Time
	Provider            string // anthropic | openai
	Model               string
	RequestID           string
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	// CacheCreation1hTokens is the subset of CacheCreationTokens that
	// landed in Anthropic's 1h ephemeral tier. Zero means the proxy
	// didn't observe a tier breakdown (5m only) or the upstream
	// response didn't expose one.
	CacheCreation1hTokens int64
	// WebSearchRequests mirrors TokenEvent.WebSearchRequests on the proxy
	// path — number of server-side web_search invocations billed under
	// Anthropic's $10/1000 search fee, independent of per-token costs.
	WebSearchRequests int64
	// Fast marks turns served in the provider's low-latency "fast" tier
	// (Anthropic Opus 4.8 with speed:"fast" on the Messages API).
	// Mirrors TokenEvent.Fast — captured by the proxy when the outbound
	// request body carries "speed":"fast". Persisted to api_turns.fast
	// via migration 035. The CostUSD on this row is the FastMultiplier-
	// applied total computed at insert time.
	Fast             bool
	CostUSD          float64
	MessageCount     int
	ToolUseCount     int
	SystemPromptHash string
	// MessagePrefixHash is the SHA-256 of the stable cache-aligned message
	// prefix (spec §10 Layer 3). Empty when conversation compression is
	// disabled or no prefix was observable. See
	// internal/compression/conversation.PrefixHash.
	MessagePrefixHash string
	// CompressionOriginalBytes / CompressionCompressedBytes are the request
	// body size before and after conversation compression ran. Zero when
	// the compressor was disabled or skipped this turn.
	CompressionOriginalBytes   int64
	CompressionCompressedBytes int64
	// CompressionCount is how many tool_result bodies had their content
	// replaced by a per-type compressor.
	CompressionCount int64
	// CompressionDroppedCount is how many source messages were replaced
	// by a marker.
	CompressionDroppedCount int64
	// CompressionMarkerCount is how many marker messages were emitted.
	CompressionMarkerCount int64
	// CompressionEvents is the per-decision detail (one record per
	// compress or drop). Persisted into the compression_events table
	// (migration 009) by store.InsertAPITurn so the dashboard can
	// break down savings by mechanism. Empty when compression skipped.
	CompressionEvents  []CompressionEvent
	TimeToFirstTokenMS int64
	TotalResponseMS    int64
	StopReason         string
	// HTTPStatus / ErrorClass / ErrorMessage capture upstream API
	// failures (4xx / 5xx) the proxy observed. Pre-v1.4.20 these were
	// dropped — the proxy returned early on non-2xx responses. Now an
	// errored turn is recorded with zero token counts and these three
	// fields populated. ErrorClass is the parsed error type from the
	// Anthropic / OpenAI envelope (`invalid_request_error` /
	// `rate_limit_error` / `overloaded_error` / etc.); ErrorMessage is
	// the human-readable body after secrets scrubbing. Successful
	// turns leave HTTPStatus = 0 and the strings empty.
	HTTPStatus   int
	ErrorClass   string
	ErrorMessage string
	// OrgID / UserEmail are org-attribution (Teams & Org Visibility,
	// migration 029). Empty on solo-local installs; stamped by
	// identity.Stamper at insert time only when the agent is enrolled,
	// persisted as NULL otherwise.
	OrgID     string
	UserEmail string
	// Source is the provenance of this turn observation for cross-source
	// dedup (native-console integration, migration 047): "proxy" (or empty,
	// the legacy default), "cc_otel", or "jsonl". It maps to a
	// turnmerge.Fidelity at the store boundary, which decides precedence when
	// the same request_id is seen by more than one source. Node-local
	// metadata — never pushed to the org wire.
	Source string
	// Route / RoutingGeneration / AuthoritySource are the Plane B per-turn
	// authority stamps (Sol S5 / Luna L15, migration 095). Content-free
	// routing metadata — enum strings + an integer generation, never text
	// from a request. Unlike Source these DO ride the org wire
	// (orgcontract.APITurnRow) so a mixed-mode fleet's rollup can single-
	// count a turn and know which source owns its usage authority.
	//
	// Route is TurnRouteDirect / TurnRouteGateway / TurnRouteFallback (empty
	// == direct). RoutingGeneration is the immutable routing-snapshot
	// generation (proxy.Proxy.RoutingGeneration) the turn was served under;
	// 0 when no org route was live. AuthoritySource is TurnAuthorityNode /
	// TurnAuthorityGateway (empty == node).
	Route             string
	RoutingGeneration int64
	AuthoritySource   string
}

// Route classes for APITurn.Route (Plane B per-turn authority stamp, Sol
// S5). Content-free enum: how the node proxy served a turn.
const (
	// TurnRouteDirect is a turn forwarded straight to the fixed provider
	// upstream — Node Mode, or a build with no org route installed. The
	// zero value ("") is treated as direct everywhere.
	TurnRouteDirect = "direct"
	// TurnRouteGateway is a turn forwarded to the org AI Gateway primary
	// (Gateway Mode, Sol S8 default-lane redirect).
	TurnRouteGateway = "gateway"
	// TurnRouteFallback is a turn served via an org AI Gateway fallback
	// rung after the primary was unreachable (Sol S10 ladder).
	TurnRouteFallback = "fallback"
)

// Authority sources for APITurn.AuthoritySource (Sol S12 — who owns the
// org-level usage authority for a turn). Content-free enum.
const (
	// TurnAuthorityNode means this node's proxy observation is the
	// authority for the turn's org-level usage. The zero value ("") is
	// treated as node everywhere.
	TurnAuthorityNode = "node"
	// TurnAuthorityGateway means the org AI Gateway's own audit row is the
	// authority; this api_turns row is the node-side shadow and an org
	// rollup must let the gateway row win on a request_id collision.
	TurnAuthorityGateway = "gateway"
)

// OTelContent is one captured content body from a coding assistant's native
// OTel stream (native-console integration, migration 048): a user prompt, tool
// input/output, or raw API body, emitted only when the admin enabled the
// OTEL_LOG_* flags. Content is scrubbed for secrets before storage. Like
// actions.raw_tool_input, the node STORES it locally; the org-push boundary
// ships ContentHash always and Content (raw) only under the content-sharing
// gate (full_content / admin_managed).
type OTelContent struct {
	ID        int64
	RequestID string // turn join key (may be empty for session-level prompts)
	SessionID string
	ToolUseID string // set for tool_input/tool_output kinds
	Kind      string // prompt | tool_input | tool_output | raw_body
	Content   string // scrubbed raw body, bounded to a storage cap (may be truncated)
	// ContentHash is the sha256-hex of the FULL scrubbed body as received,
	// BEFORE any storage truncation — never of the (possibly-truncated)
	// Content above. It is the dedup/idempotency anchor
	// (UNIQUE(content_hash, kind, request_id, tool_use_id)); hashing the
	// truncated text would collide two distinct large bodies that share an
	// identical prefix and silently drop the second on insert. See
	// store.HashOTelContent / the ContentHash note on store.InsertOTelContent.
	ContentHash string
	Timestamp   time.Time
	Source      string // cc_otel
}

// CompressionEvent is one mechanism-tagged compression decision
// recorded during the conversation-compression pipeline. Stored in
// the compression_events table keyed off APITurn.ID. Mechanism is
// 'json' / 'code' / 'logs' / 'text' / 'diff' / 'html' (per-content-
// type compressor) or 'drop' (low-importance message replaced by a
// marker).
type CompressionEvent struct {
	APITurnID       int64
	Timestamp       time.Time
	Mechanism       string
	OriginalBytes   int64
	CompressedBytes int64
	MsgIndex        int
	ImportanceScore float64 // set only for Mechanism == "drop"
	// BodyHash is sha256-hex of the pre-compression body bytes
	// (V7-9, v1.7.12+). Empty for pre-v1.7.12 rows and 'drop'
	// events. Persisted into compression_events.body_hash via
	// migration 031.
	BodyHash string
}

// FileState is the cross-session record of a file's last observed content
// hash. Drives the freshness fast path (spec §7.2 step 2).
type FileState struct {
	ID             int64
	ProjectID      int64
	FilePath       string
	ContentHash    string
	FileMtime      time.Time
	FileSizeBytes  int64
	LastActionID   int64
	LastActionType string
	LastSeenAt     time.Time
	LastModifiedBy string
}

// CacheBlockMeta is one element of a Tier-2 cache observation's
// block chain (docs/plans/cache-tracking-implementation-spec-2026-06-08.md
// §9). Adapters populate this from the JSONL message-content
// blocks they parse; the engine consumes it via the
// internal/cachetrack package (the engine, NOT this models type,
// is where canonicalization + hashing happens).
//
// LevelLabel uses the schema-stable strings 'tools' / 'system' /
// 'message' so the boundary between adapter and engine stays
// data-only — adapters don't import the cachetrack package
// (spec §24.1) and the engine doesn't import models for its
// internal types (the BlockLevel enum stays internal).
type CacheBlockMeta struct {
	// LevelLabel is 'tools' | 'system' | 'message'. The empty
	// string is treated as 'message' by the engine — Tier-2
	// transcripts never expose tools/system blocks (R1 finding).
	LevelLabel string
	// Kind is the block type label: 'text' | 'tool_use' |
	// 'tool_result' | 'image' | 'thinking' | 'document' |
	// 'attachment' (spec §0 R1: attachment lines fold into the
	// chain).
	Kind string
	// CanonicalBytes is the JSON-serialized block body (sorted
	// keys, no HTML escape — same shape internal/compression/
	// conversation/anthropic.go::marshalEnvelope produces). The
	// engine wraps this in its own role/type envelope at hash
	// time (see internal/cachetrack/block.go::CanonicalizeTranscript).
	CanonicalBytes []byte
	// Role is 'user' / 'assistant' / 'system' / 'tool' — the
	// schema-stable transcript role label. Empty for blocks
	// that don't carry one (rare).
	Role string
}

// CacheUsage carries the per-turn provider-reported usage fields
// the engine reconciles against (spec §10). All counts are
// non-negative; zero means "not observed" rather than "actively
// zero." NetInputTokens is the input field AFTER subtracting
// CacheReadTokens (per the cost engine's net-input invariant —
// see internal/intelligence/cost::TokenBundle.Input).
type CacheUsage struct {
	NetInputTokens        int64
	OutputTokens          int64
	CacheReadTokens       int64
	CacheCreationTokens   int64
	CacheCreation1hTokens int64
}

// CacheTurnObservation is one assistant turn's cache-relevant
// view, emitted by adapters that can see content blocks + usage
// (Tier 2 — claudecode JSONL, codex rollout, opencode, kilo-cli,
// cline-cli per spec §14.3 rollout). The watcher's store.Ingest
// receives a slice of these via store.IngestOptions and feeds
// the cachetrack engine in C7+; for C6 the slice plumbing is
// additive only.
//
// SourceFile + SourceEventID are the idempotency key: a
// re-parse of the same JSONL file (Rescan, pollCursors) must
// produce the same observations, and the engine's dedup gate
// (store.CacheEventExistsForMessage) tolerates Tier-1 having
// already written events for the same MessageID.
type CacheTurnObservation struct {
	SourceFile    string
	SourceEventID string // adapter-deterministic per-turn id (idempotency)
	SessionID     string
	MessageID     string // upstream msg_xxx (joins to api_turns.request_id)
	Timestamp     time.Time
	Model         string
	Fast          bool
	// BlockHashes is the per-turn block chain, IN ORDER. Empty
	// slice signals "could not reconstruct" (e.g. cold-start
	// incremental parse) — the engine treats the observation as
	// kind=reanchor in that case.
	BlockHashes []CacheBlockMeta
	// Usage is the provider-reported usage envelope for this turn.
	Usage CacheUsage
	// CompactionSeen is true when a compact_boundary lifecycle
	// marker landed between the prior assistant turn and this
	// one in the same session. The engine emits a
	// kind=compaction_reset event when set.
	CompactionSeen bool
	// ImplicitCache is the §15.3 boundary-overlay flag: adapters
	// emitting against OpenAI / OpenAI-compatible providers (codex
	// Tier-2, cline-cli when routed through deepseek/etc.,
	// opencode/kilo when routed through non-Anthropic gateways)
	// set this so the engine dispatches to the reduced attribution
	// path (cachetrack.attributeImplicit) instead of the marker-
	// aware Anthropic decision tree. When true, BlockHashes is
	// IGNORED by the engine (the implicit path doesn't push the
	// chain) and only Usage.CacheReadTokens / Usage.NetInputTokens
	// are consumed. Default false → existing Anthropic-shape
	// behavior unchanged.
	ImplicitCache bool
}

// SessionProcessSeed is a candidate (OS pid → session) attribution
// link emitted by an adapter that discovers a live local process id
// for a session in its own session data (cline-cli's sessions.pid
// column, qwen-code's <uuid>.runtime.json sidecar). It is the
// watcher/SQLite-path analogue of the SessionStart hook's
// ancestor-walk: the daemon (not the tool's process tree) sees the
// pid, so the write is direct rather than an ancestry probe.
//
// The seed is a CANDIDATE — the store validates liveness + identity
// (internal/pidbridge.ValidateLocalProcess) before writing a
// session_pid_bridge row, because a stale/recycled pid must never
// false-attribute (a miss is strictly better than a wrong link).
// It crosses the adapter → ParseResult → IngestOptions seam as plain
// data; the session_pid_bridge table's own pidbridge.Entry type never
// leaks past the store boundary.
type SessionProcessSeed struct {
	// PID is the OS process id the adapter read from its session data.
	PID int
	// SessionID is the tool's session identifier the pid belongs to.
	SessionID string
	// Tool is the models.Tool* constant tagging the bridge row.
	Tool string
	// CWD is the session working directory (optional; drives the
	// R3 project overlay when the resolver falls back to it).
	CWD string
	// ExecHint is a lowercase substring the owning process's comm or
	// cmdline must contain for the seed to validate (e.g. "cline",
	// "qwen") — the identity guard against pid recycling.
	ExecHint string
}

// SubagentActionRef is the lean per-action projection the session-detail
// sub-agents read model consumes (store.SidechainActionsForSession). It
// carries identity + lifecycle shape only — never tool bodies. NODE-LOCAL:
// derived entirely from actions rows already pinned out of the org-push
// wire's content columns; no wire surface of its own.
type SubagentActionRef struct {
	ID          int64
	Timestamp   time.Time
	ActionType  string
	Target      string
	Success     bool
	DurationMs  int64
	RawToolName string
	// Metadata carries the structured sub-agent identity when the capture
	// path stamped it (hook SubagentStart/Stop, transcript agent-name
	// rows). Nil otherwise — the read model then falls back to time-window
	// grouping.
	Metadata *ActionMetadata
	// IsSidechain marks activity inside a sub-agent runtime (migration 010).
	IsSidechain bool
}

// SubagentTokenRef is the lean per-usage-row projection the session-detail
// sub-agents read model consumes (store.SidechainTokenUsageForSession) —
// the token half of buildSubagentSummaries' input, alongside
// [SubagentActionRef]. It carries usage magnitudes only — never prompts,
// outputs, model ids, or source paths. NODE-LOCAL: derived entirely from
// token_usage rows flagged is_sidechain (migration 087), a column with no
// org-push wire surface; this type has none of its own either.
type SubagentTokenRef struct {
	Timestamp           time.Time
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	EstimatedCostUSD    float64
}

// SessionLineage is a codex-session fork/subagent lineage marker an
// adapter captures from the owning session_meta record. It is
// NODE-LOCAL (migration 069): these columns must never enter the
// org-push wire (pinned by tests/invariant/privacy_test.go). Written
// through the single store seam Store.SetSessionLineage. Empty fields
// are no-ops (COALESCE-preserving), so a re-parse never clobbers a
// captured value.
type SessionLineage struct {
	// SourceFile identifies a transcript that older adapters stored under
	// ParentThreadID. Ingest transfers its existing rows to SessionID before
	// replay, preserving row IDs and avoiding duplicate usage. Empty is a no-op.
	SourceFile string
	// AgentID is the native runtime identity for that transcript, when known.
	AgentID string
	// SessionID is the owning (child) session the markers belong to.
	SessionID string
	// ForkedFromID is the parent session a user-fork or subagent spawn
	// forked from (empty for a normal session).
	ForkedFromID string
	// ParentThreadID is the spawning parent thread for a subagent
	// (empty for a normal or user-fork session).
	ParentThreadID string
	// ThreadSource discriminates the rollout origin: "user" (normal +
	// user-fork) or "subagent".
	ThreadSource string
}

// Surface KIND vocabulary — the normalized answer to "what kind of
// client produced this session?". Every adapter resolves its vendor's
// own discriminator (Claude Code `entrypoint`, Codex `originator` /
// `source`, Cline `source`, a path shape, ...) into one of these at
// its boundary through a table (CLAUDE.md #3/#5), so nothing
// downstream ever switches on a tool name to infer the surface. The
// finer identity of the host rides separately in SessionSurface.
// SurfaceHost so the kind set stays closed and small.
//
// "ide-vscode" in the audit's shorthand is Surface=SurfaceIDE +
// SurfaceHost="vscode"; "ide-jetbrains" is SurfaceIDE + "jetbrains".
const (
	// SurfaceCLI is an interactive or non-interactive terminal run of
	// the tool's own CLI (incl. `codex exec`, `claude -p`).
	SurfaceCLI = "cli"
	// SurfaceIDE is an editor extension / plugin / IDE fork driving the
	// tool (VS Code, JetBrains, Neovim, Cursor, Kiro, Windsurf, ...).
	SurfaceIDE = "ide"
	// SurfaceDesktop is a standalone desktop app (Claude Desktop,
	// Codex Desktop, Hermes Desktop, ...).
	SurfaceDesktop = "desktop"
	// SurfaceSDK is a programmatic embedding (Agent SDK, API harness).
	SurfaceSDK = "sdk"
	// SurfaceWeb is a browser / web-app surface.
	SurfaceWeb = "web"
)

// SessionSurface is the per-session capture-surface attribution an
// adapter resolved from a grounded on-disk discriminator. NODE-LOCAL
// (migration 107): `sessions.surface` / `sessions.surface_host` never
// enter the org-push wire (pinned by tests/invariant/privacy_test.go).
// Written through the single store seam Store.SetSessionSurface with
// FIRST-WINS-UNLESS-EMPTY semantics, per column: the first grounded
// stamp sticks, a later parse can only FILL a still-empty column, and a
// re-parse can never clear or change a captured value (an identical
// re-stamp — and a differing later one — are both no-ops). The surface
// is a property of the session's ORIGIN, fixed when the session was
// created, so a later re-derivation from less context is not a
// correction; genuine repair is a backfill concern. An adapter that
// finds NO grounded discriminator emits nothing — the zero value on
// the session row is the honest "unknown", never a guess.
type SessionSurface struct {
	// SessionID is the session the attribution belongs to.
	SessionID string
	// Surface is one of the Surface* kind constants.
	Surface string
	// SurfaceHost is a lowercase host token refining Surface: "vscode",
	// "cursor", "jetbrains", "neovim", "kiro", "claude-desktop",
	// "codex-desktop", "codex-exec", "cursor-agent", ... Never prose,
	// never a path. Optional.
	SurfaceHost string
	// Hosted marks a stamp that comes from the HOSTING layer's own
	// record rather than the agent's self-report: an IDE orchestration
	// store that names which agent session it drove (JetBrains
	// `aia-task-history/*.agentsession`, Qoder Work `main.sqlite`).
	// The host layer is strictly better informed about the session's
	// origin than the agent it spawned — Claude Code inside IntelliJ
	// truthfully reports `entrypoint=sdk-ts`, Qoder driven by Qoder Work
	// truthfully reports `entrypoint=cli` — so a hosted stamp is not a
	// weaker re-derivation of the same fact, it is the fact the
	// self-report cannot see. Store.SetSessionSurface therefore lets a
	// hosted stamp REPLACE a differing self-reported value (host-wins),
	// while an empty field still never clears a stored one and an
	// identical re-stamp is still a no-op. Zero value = the ordinary
	// first-wins-unless-empty self-report every adapter emits today.
	Hosted bool
}

// SessionToolVersion is the per-session tool/CLI version an adapter
// resolved from a grounded on-disk field. NODE-LOCAL (migration 125):
// `sessions.tool_version` never enters the org-push wire (pinned by
// tests/invariant/privacy_test.go). Written through the single store
// seam Store.SetSessionToolVersion with FIRST-WINS-UNLESS-EMPTY
// semantics: the first grounded stamp sticks, a later parse can only
// FILL a still-empty column, and a re-parse can never clear or change a
// captured value. The version is a property of the session's ORIGIN
// (the build that produced it), fixed when the session was created. An
// adapter that finds NO grounded version emits nothing — the zero value
// on the session row is the honest "unknown", never a guess.
type SessionToolVersion struct {
	// SessionID is the session the version belongs to.
	SessionID string
	// Version is the free-form semver-ish token the adapter read from a
	// grounded on-disk field ("0.150.0", "3.17.4"). Not an enum, but a
	// bounded token: the store length-caps it and rejects whitespace /
	// control / prose so a stray free-text field can never be persisted.
	Version string
}

// KnownSurface reports whether kind is one of the Surface* constants.
// Adapters should never need it (their tables emit constants), but
// the store uses it to refuse an out-of-vocabulary write loudly rather
// than persist a vendor token as a kind.
func KnownSurface(kind string) bool {
	switch kind {
	case SurfaceCLI, SurfaceIDE, SurfaceDesktop, SurfaceSDK, SurfaceWeb:
		return true
	}
	return false
}

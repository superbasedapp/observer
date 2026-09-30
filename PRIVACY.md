# Privacy

SuperBased Observer is **a local Go binary that stores everything on
your machine**. There is no telemetry, no analytics, no remote
reporting, no "anonymized usage" beacon, no crash uploader. The
project's authors cannot see what you ran, what you typed, or whether
you're running observer at all. The binary you install from npm is
the same binary published with SLSA provenance to the public GitHub
release — what you install is what runs.

This document spells out exactly what observer touches and what it
never touches.

## TL;DR

- **Local-only.** Observer's database, logs, and stash live under
  `~/.observer/` (per-user, per-platform). Nothing leaves your machine
  unless **you** explicitly turn on a feature that requires the network.
- **No telemetry.** Zero. The watcher, hook handler, dashboard, MCP
  server, and CLI never make an outbound network call on observer's
  behalf — only the optional API proxy forwards **your** requests
  unchanged to the AI provider you already use.
- **No "anonymized" sharing.** There is no opt-out toggle because
  there is no collection to opt out of.
- **No accounts required.** You can run observer offline, behind an
  air-gap, without ever signing in to anything.

## What observer stores locally

| Data | Where | What's in it |
|---|---|---|
| SQLite database | `~/.observer/observer.db` | Normalized session metadata: tool/model/timestamps, token counts, costs, file-path lists, command excerpts, conversation summaries. No raw prompt bodies, no file contents. |
| Operational logs | `~/.observer/logs/` | Start/stop, watcher errors, retention sweeps. No request bodies, no API keys. |
| Stash blobs | `~/.observer/stash/<sha256>` | Content-addressed blobs ONLY when the proxy's stash compressor is on (off by default for Claude Code). These are tool-result bodies your AI client already has copies of. |
| Compression artifacts | DB only | Per-event compression decisions, savings estimates. No content. |

You can inspect everything with standard SQLite tools:

```bash
sqlite3 ~/.observer/observer.db '.schema'
sqlite3 ~/.observer/observer.db 'SELECT * FROM actions LIMIT 5'
```

Delete it all at any time:

```bash
rm -rf ~/.observer/   # full removal, no traces elsewhere on your system
```

## What observer reads

Observer's watcher and hook handler read session logs your AI clients
already write to disk:

- `~/.claude/projects/**` (Claude Code)
- `~/.codex/sessions/**` (Codex)
- `~/.cursor/chats/**` + Cursor's `state.vscdb` (Cursor)
- `~/.copilot/{session-state,logs}/**` (Copilot CLI)
- VS Code's per-extension state for Copilot / Cline / OpenClaw / Pi / etc.
- Antigravity's per-session protobuf records (Google Antigravity)

These files exist whether observer is installed or not. Observer
parses them and writes normalized records into its own SQLite
database — it does not delete, modify, or upload the originals.

## What observer NEVER stores

Per the project's design spec (`superbased-final-spec-v2.md`):

- **File contents.** Only file paths and modification timestamps.
- **Raw command outputs.** Only the command line, exit code, and a
  short scrubbed excerpt.
- **Raw prompt bodies.** Only token counts and a per-message hash.
  Conversation summaries are stored only when message-summary is
  explicitly enabled.
- **Credentials.** The scrubber (`internal/scrub/`) removes API keys,
  bearer tokens, password forms, and known-secret regexes before
  any persistence.

## When observer DOES make a network call

These are the **only** code paths in the binary that touch the network.
Every one is gated behind explicit configuration — none are on by
default for a fresh install.

| Feature | When it talks to the network | What it sends | Opt-in via |
|---|---|---|---|
| **API proxy** | When your AI client points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at observer | **Your** API request, forwarded byte-identically to the upstream provider you chose (api.anthropic.com, chatgpt.com, openai.com, …) | `observer init --claude-code/--codex/--cursor` (writes the env-var hint into the AI client's config) |
| **Message summary** | If `[messagesummary] enabled = true` | A subset of your conversation, to the LLM endpoint **you** configure (`base_url`, `model`, `api_key`) | TOML config — you provide the endpoint and key |
| **Org enrolment** | If you ran `observer enroll <org-url>` | Aggregate per-day metrics (token totals, action counts, project hashes), and only the fields the org-server explicitly requests | `observer enroll` — explicit, prompts for org URL + token |
| **Antigravity gRPC fallback** | When parsing Antigravity sessions on macOS where keychain decrypt fails | Local IPC to a Google-installed gRPC socket — never the internet | Automatic; only fires on Antigravity sessions |

If none of these are configured, observer makes **zero** outbound
network calls. Verify with:

```bash
sudo lsof -p $(pgrep -f 'observer start') -i      # should show ONLY :8820/:8830/:8831 etc. on 127.0.0.1
```

## How to verify "no telemetry" yourself

The codebase is open source. To audit:

```bash
# 1. Confirm no HTTP client in the watcher / adapter / hook code paths
grep -rE 'http\.(Get|Post|Client|NewRequest)' cmd/observer internal/adapter internal/watcher internal/hook internal/store
# Returns zero. All outbound HTTP is in internal/proxy/ (forwarding), internal/orgclient/ (org enrolment, opt-in),
# and internal/intelligence/summary/ (message-summary opt-in). The code index (internal/codeintel) is in-process
# and makes no network calls.

# 2. Confirm no outbound DNS lookups from the binary
strings $(which observer) | grep -Ei 'telemetry|analytics|metrics\.|amplitude|segment\.|posthog|datadog|sentry'
# Returns zero matches.

# 3. Run observer in a network-namespaced shell and confirm everything (parsing, DB, MCP, dashboard) still works
unshare -rn observer start --no-dashboard
```

## What the proxy can see

When you use the proxy, observer's local process **reads** your AI
API requests and responses — it has to, to normalize them and compute
accurate token counts. That data lands in the same local SQLite
database described above. It is **forwarded** to the upstream provider
unchanged (Anthropic / OpenAI / etc.). Observer never sends a copy
anywhere else.

If you don't want the proxy to see request bodies, you can run
observer **without** the proxy:

- Watcher + dashboard + MCP only: `observer start` — observer parses
  your AI client's own session logs (which already contain the same
  data) and skips the proxy entirely.
- Don't run `observer init --claude-code/--codex/--cursor` (or run
  `observer init --skip-proxy-route`) — the AI client won't be
  configured to point at the proxy, so requests go direct to the
  provider.

## Org enrolment (opt-in)

Org enrolment (shipped in v1.7.2) lets organizations roll up
**aggregate** metrics from per-user observers into an org-server
dashboard. It is **opt-in** per user via `observer enroll <org-url>`.

What the org-server receives:

- Aggregate counts per day: total tokens, total actions, total cost
  estimate, per-project hashes (NOT paths).
- Capability hashes (which adapters fired) — no content.

What it does NOT receive:

- Per-request prompt bodies, file contents, command outputs.
- Identifiable project names — only opaque hashes.
- Anything in real time — payload is a once-per-day rollup.

If you don't want to send aggregate data to your organization's rollup
server, don't enroll. The org-server endpoint is not pre-configured;
there is no default destination.

## Source-of-truth and verification

- Source code: https://github.com/superbasedapp/observer
- npm package: https://www.npmjs.com/package/@superbased/observer
- SLSA provenance: attached as `multiple.intoto.jsonl` to each
  [public GitHub release](https://github.com/superbasedapp/observer/releases),
  verifiable with [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier)
  (`v2.7.0+` required for private-builder support).
- SBOM: `observer.cdx.json` attached to each release; lists every
  transitive dependency.

## Reporting

If you find behavior that contradicts anything on this page — a
network call we didn't list, a code path that stores something we
said it doesn't — file an issue at
https://github.com/superbasedapp/observer/issues with the
tag `privacy`, or email `contact@superbased.app`.

We treat any unintentional collection as a bug, not a feature.

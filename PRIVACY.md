# Privacy

SuperBased Observer is **a local Go binary that stores everything on
your machine**. Today the default install sends us no usage
statistics, analytics or crash reports, and it never sends your session
content (prompts, code, responses, file contents) without your explicit
consent. It needs no account. The project's authors cannot see what you
ran or what you typed unless you choose to upload it. By default observer makes a few small requests of its own that
carry none of your data; they are listed under "When observer DOES
make a network call" below. The binary you install from npm is the same
binary published with SLSA provenance to the public GitHub release:
what you install is what runs.

This document spells out exactly what observer touches and what it
never touches.

## TL;DR

- **Local-only.** Observer's database, logs, and stash live under
  `~/.observer/` (per-user, per-platform). Today none of it leaves your
  machine unless **you** explicitly turn on a feature that sends it.
- **Your content needs your consent.** Session content (prompts, code,
  responses, file contents) never leaves your machine without your
  explicit consent (enrolling a machine into your company's managed
  org is one such consent; see "Org enrolment" below). The optional
  API proxy forwards **your** requests
  unchanged to the AI provider you already use. The few requests
  observer makes on its own by default (a daily price-table download
  and TLS warm-up at proxy start) carry none of your data.
- **No usage statistics today.** The current default install sends us
  no usage statistics, analytics or crash reports. The aggregate-share
  rail (`observer aggregate enable`) is currently off by default and
  sends nothing without your consent.
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
database; it does not delete, modify, or upload the originals.

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

These are the main code paths in the binary that touch the network.
The pricing feed and TLS warm-up are on by default and carry none of
your data; the others are gated behind explicit configuration. Run
`observer privacy` for a list derived from your loaded config.

| Feature | When it talks to the network | What it sends | How it is enabled |
|---|---|---|---|
| **Pricing feed** | Once every 24 hours on a standalone (not enrolled) node | A plain `GET` of the public, signed model price table from superbased.app; none of your data | On by default; turn off with `[pricing.feed] enabled = false` |
| **TLS warm-up** | When the proxy starts | Bare `HEAD` requests to `[proxy].prewarm_targets` (default chatgpt.com and api.openai.com); none of your data | On by default; set by `[proxy].prewarm_targets` |
| **API proxy** | When your AI client points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at observer | **Your** API request, forwarded byte-identically to the upstream provider you chose (api.anthropic.com, chatgpt.com, openai.com, …) | `observer init --claude-code/--codex/--cursor` (writes the env-var hint into the AI client's config) |
| **Message summary** | If `[messagesummary] enabled = true` | A subset of your conversation, to the LLM endpoint **you** configure (`base_url`, `model`, `api_key`) | TOML config; you provide the endpoint and key |
| **Org enrolment** | If this machine was enrolled with `observer enroll` | To your organization's own server. Individual enrolment: metadata, with content-bearing fields as hashes (raw only under your local `full_content` opt-in). Managed (company) enrolment: the full session record, content included. See "Org enrolment" below | `observer enroll` (explicit; needs the org URL and an enrolment token, link or org sign-in) |
| **Antigravity gRPC fallback** | When parsing Antigravity sessions on macOS where keychain decrypt fails | Local IPC to a Google-installed gRPC socket, never the internet | Automatic; only fires on Antigravity sessions |

Today, with the pricing feed and TLS warm-up turned off and none of the opt-in
features configured, observer makes no outbound network calls of its
own. Verify with:

```bash
sudo lsof -p $(pgrep -f 'observer start') -i      # should show ONLY :8820/:8830/:8831 etc. on 127.0.0.1
```

## How to verify this yourself

The codebase is open source. To audit:

```bash
# 1. List the network paths your loaded config enables
observer privacy

# 2. Run observer in a network-namespaced shell and confirm everything (parsing, DB, MCP, dashboard) still works
unshare -rn observer start --no-dashboard
```

## What the proxy can see

When you use the proxy, observer's local process **reads** your AI
API requests and responses; it has to, to normalize them and compute
accurate token counts. That data lands in the same local SQLite
database described above. It is **forwarded** to the upstream provider
unchanged (Anthropic / OpenAI / etc.). Observer never sends a copy
anywhere else.

If you don't want the proxy to see request bodies, you can run
observer **without** the proxy:

- Watcher + dashboard + MCP only: `observer start`; observer parses
  your AI client's own session logs (which already contain the same
  data) and skips the proxy entirely.
- Don't run `observer init --claude-code/--codex/--cursor` (or run
  `observer init --skip-proxy-route`); the AI client won't be
  configured to point at the proxy, so requests go direct to the
  provider.

## Org enrolment (opt-in)

Org enrolment lets a team or company roll up activity from each
developer's observer into your organization's **own** server. Nothing
goes to that server until a machine is enrolled with `observer enroll`.
Its endpoint is not pre-configured; there is no default destination,
and the server belongs to your organization, not to us. What it receives depends on the kind of enrolment.

**Individual enrolment: you opt in to content.**

- By default the node pushes metadata: per-session and per-day rows
  such as token counts, costs, models, timings and action counts.
  Content-bearing fields (command targets, file paths, project roots,
  git remotes and branch names) ship only as sha256 hashes.
- Raw values for those fields ship only if you set
  `[org_client.share].full_content = true` in your own local
  `~/.observer/config.toml`. The org admin has no remote switch for
  that file.

**Managed (company) enrolment: full content.**

Enrolling a machine into your company's managed org is the explicit
consent for that machine's session content to go to that org. A
managed node sends its full session record, content included (raw
commands, assistant responses, file paths, project and git details),
to your organization's own server.

- `observer enroll` writes `full_content = true` into the local config
  for a managed enrolment (and `false` for an individual one). The
  value comes from the enrolment itself, and you can read it in the
  file.
- A machine enrolled as managed before that default existed is raised
  to full content by the org's signed `extract.managed` grant. It is
  shown to you at consent, in `observer org status` and in
  `observer org grant show`. It never silently rewrites your config, it
  does nothing on an individual enrolment, and it is refused if its
  signature, pinned key or generation does not verify.
- The org can lower this again through its signed governance policy,
  and that lowering wins.

In both cases a single SQL seam in the node builds every pushed row,
and an invariant test pins the content-bearing columns so a change is
loud. If you don't want to send anything to an organization's server,
don't enroll; `observer unenroll` stops it.

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

If you find behavior that contradicts anything on this page (a
network call we didn't list, a code path that stores something we
said it doesn't), file an issue at
https://github.com/superbasedapp/observer/issues with the
tag `privacy`, or email `contact@superbased.app`.

We treat any unintentional collection as a bug, not a feature.

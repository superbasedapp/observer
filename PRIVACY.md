# Privacy

SuperBased Observer is **a local Go binary that stores everything on
your machine** until you connect it to a dashboard. It needs no
account. Today the default install sends us no usage statistics,
analytics or crash reports, and none of your session content. By
default observer makes a few small requests of its own that carry none
of your data; they are listed under "When observer DOES make a network
call" below. If you sign in and connect a machine, it sends its
activity to the personal dashboard or team you approve, as described
below and in the full product privacy policy at
https://superbased.app/privacy (policy version 3). The binary you
install from npm is the same binary published with SLSA provenance to
the public GitHub release: what you install is what runs.

This document spells out exactly what observer touches and what it
never touches.

## TL;DR

- **Local until you connect.** Observer's database, logs, and stash
  live under `~/.observer/` (per-user, per-platform). None of it leaves
  your machine unless **you** connect the machine to a dashboard or
  turn on a feature that sends it.
- **Default requests carry none of your data.** Observer downloads the
  public price list (daily) and package-check lists (every 6 hours)
  from superbased.app, checks public package names with OSV and the
  package registries after showing you a notice first, and sends an
  empty `HEAD` request to chatgpt.com and api.openai.com when its proxy
  starts. Each has an off switch (table below).
- **Signing in sends your account details only.** Connecting a machine
  starts sending only after you approve it on a page at
  cloud.superbased.app, and only activity from then on.
- **Personal dashboard = Summary only; team = Full detail.** A personal
  dashboard receives tools, models, times, token counts and cost, with
  paths and project names as unsalted SHA-256 hashes. A team receives
  prompts, responses and file paths too, and the team's admins can
  read them.
- **No usage statistics today.** The current default install sends us
  no usage statistics, analytics or crash reports. The anonymous
  monthly totals command (`observer aggregate enable`) is off by
  default, and the server that would receive them is not running.
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
The first four run by default and carry none of your data; the others
need an explicit choice. Run `observer privacy` for a list derived
from your loaded config.

| Feature | When it talks to the network | What it sends | How it is enabled |
|---|---|---|---|
| **Pricing feed** | Once every 24 hours on a machine not connected to a dashboard or team server (a connected machine gets prices from it instead) | A plain `GET` of the public, signed model price list from superbased.app; none of your data | On by default; turn off with `[pricing.feed] enabled = false` |
| **Package-check lists** | Every 6 hours | A plain `GET` of the signed malicious-package and popular-name lists from superbased.app; none of your data | On by default; turn off with `[security.deps] index_download = false` |
| **Online package checks** | When an AI agent installs a package, and for the packages your projects use, only after the first-run notice is acknowledged on the dashboard or CLI | The package's ecosystem, public name and version to `api.osv.dev` and its public registry (npm, PyPI, Go proxy, crates.io, RubyGems); never paths, repo names or private package names | On by default after the notice; turn off with `[security.deps] online = false` |
| **TLS warm-up** | When the proxy starts | One empty `HEAD` request each to `[proxy].prewarm_targets` (default chatgpt.com and api.openai.com); no body, no key, none of your data | On by default; turn off with `[proxy] prewarm_targets = []` |
| **OSV databases** | Every 6 hours, only after the one-time accept | Download of the public OSV databases from superbased.app, falling back to Google's OSV bucket | `observer security scan db accept` or the Code security page |
| **Package lookup** | Only after its own consent | Requests for blocks of advisory data by a short hash of each package name, from `shards.superbased.app` | `observer security lookup mode` or the Privacy page |
| **API proxy** | When your AI client points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at observer | **Your** API request, forwarded byte-identically to the upstream provider you chose (api.anthropic.com, chatgpt.com, openai.com, …) | `observer init --claude-code/--codex/--cursor` (writes the env-var hint into the AI client's config) |
| **Message summary** | If `[messagesummary] enabled = true` | A subset of your conversation, to the LLM endpoint **you** configure (`base_url`, `model`, `api_key`) | TOML config; you provide the endpoint and key |
| **Sign-in and connect** | When you run `observer connect`, click Sign in, or install with `--connect` | To cloud.superbased.app: your account sign-in, and for the approval page this machine's name, OS, processor type, observer version, a public key it made, and the team name you typed | Your action; nothing about sessions is sent until you approve the machine |
| **Connected machine** | After you approve the machine on the approval page | To your personal dashboard (summary only) or your team (full detail), see "Personal and team dashboards we host" below | `observer connect`; stop with `observer unenroll` |
| **Your own team server** | If this machine was connected to a server your company runs | To that server; see "Servers you host yourself" below | `observer connect <server>` |
| **AI summaries, daily totals, community benchmarking** | After sign-in and each feature's own consent | See "AI summaries and other uploads" below | `observer cloud enable`, `observer cloud consent grant` |
| **Antigravity gRPC fallback** | When parsing Antigravity sessions on macOS where keychain decrypt fails | Local IPC to a Google-installed gRPC socket, never the internet | Automatic; only fires on Antigravity sessions |

Today, with the four default requests turned off and none of the opt-in
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

## Signing in and connecting a machine

Signing in (`observer connect`, the local dashboard's Sign in button,
the VS Code extension, or cloud.superbased.app) sends us your account
identifier, email address and name, from our sign-in provider. It
sends nothing about your coding sessions. Your first sign-in creates
an empty personal dashboard.

Connecting a machine always ends on an approval page at
cloud.superbased.app, where you choose your personal dashboard or one
of your team dashboards and read what will be sent. Until you click **Connect**,
nothing about your sessions is sent; after it, only activity from that
moment on is sent, never what was recorded before. **Not now** leaves
the machine signed in and sending nothing.

## Personal and team dashboards we host

SuperBased hosts every personal dashboard and every hosted team at its
own address under superbased.app, in France.

**Personal dashboard: Summary only.** Per session and action: tool and
version, model, timings, counts, success, token counts, cost, lines
changed and commit counts, stamped with your account email. File
paths, command targets, project folders and git remotes ship only as
SHA-256 hashes. The hashes are **not salted**: anyone who knows or
guesses a path can hash it and match it, so they hide names, they do
not anonymise them. Git branch names, prompts, responses, code and
command text are not sent, unless you yourself set
`[org_client.share].full_content = true` on that machine.

**Team: Full detail.** Everything above plus prompts and responses
where your AI tool records them, commands, raw file paths, project and
git details including branches, and pull request titles. The team's
**admins can read it**; other roles only what an admin grants. The
team is the controller of its data.

**Who else.** SuperBased support sees a dashboard only on a time-limited
(72 hours at most), read-only grant from you or a team admin, never
content, and every page is audited. Engineers who run the service can
technically reach the database, only to run, back up and restore it.

**Retention.** Activity is deleted after 30 days (personal free), 60
days (personal paid, Team), 180 days (Business) or 30 days (lapsed
team). Backups are encrypted and kept at most 30 days. Deleting your
account deletes your personal dashboard straight away; a team is
deleted by its owner after a 30-day wait (14 for an idle free team).

## Servers you host yourself

A company can also run the team server itself. Nothing goes to that
server until a machine is connected to it with `observer connect
<server>`. There is no default destination, the server belongs to the
company, and we receive none of its data. What it receives depends on
the kind of connection.

**Individual connection: you opt in to content.**

- By default the machine pushes metadata: per-session and per-day rows
  such as token counts, costs, models, timings and action counts.
  Content-bearing fields (command targets, file paths, project roots,
  git remotes) ship only as unsalted sha256 hashes, and branch names
  are not sent.
- Raw values for those fields ship only if you set
  `[org_client.share].full_content = true` in your own local
  `~/.observer/config.toml`. The server's admin has no remote switch
  for that file.

**Company-managed connection: full content.**

Connecting a machine to your company's managed server is the explicit
consent for that machine's session content to go there. A managed
machine sends its full session record, content included (raw
commands, assistant responses, file paths, project and git details),
to your company's own server.

- A managed connection writes `full_content = true` into the local
  config (and `false` for an individual one). The value comes from the
  connection itself, and you can read it in the file.
- A machine connected as managed before that default existed is raised
  to full content by the company's signed `extract.managed` grant. It
  is shown to you at consent, in `observer org status` and in
  `observer org grant show`. It never silently rewrites your config, it
  does nothing on an individual connection, and it is refused if its
  signature, pinned key or generation does not verify.
- The company can lower this again through its signed governance
  policy, and that lowering wins.

In every case a single SQL seam in the binary builds every pushed row,
and an invariant test pins the content-bearing columns so a change is
loud. If you don't want to send anything, don't connect;
`observer unenroll` stops it (a future `disconnect` verb may replace that name).

## AI summaries and other uploads

All need sign-in plus their own consent, and none is on by default.

- **AI summaries** of a session: the exact bytes are previewable first
  (`observer cloud preview`) and bound to a two-digest consent receipt;
  the uploaded evidence is deleted within an hour; the model is
  Anthropic's Claude API, under the provider terms the policy states.
- **Daily activity totals** (sent with AI summaries, or on their own
  consent) and **community benchmarking** (one number per measure per
  month): counts only, no paths, commands or excerpts. The rows carry
  random ids but are stored under your account and machine, so they are
  pseudonymous, not anonymous.
- **Anonymous monthly totals** (`observer aggregate enable`, then
  `observer aggregate submit`): per model family and tool, no account,
  a new random id each month, to `aggregate.superbased.app`. Off by
  default, and the receiving server is not running today, so nothing is
  collected.
- Sessions captured while the machine is connected to a dashboard, a
  team or a company's server are never used for these uploads.

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

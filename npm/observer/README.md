# @superbased/observer

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-idle-light-512.png" alt="Obs, the superbased mascot: a small robot with a terminal prompt for a face and a cape" width="112" align="right">

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/brand/superbased-lockup-light.png" alt="superbased" height="32">

**Track what every AI coding agent costs. See the limit coming.** See what 50 AI coding tools cost,
Claude Code, Codex and Cursor included, per session and per model, from the tokens your provider
actually billed. Free, Apache-2.0, and it runs on your machine.

[![npm](https://img.shields.io/npm/v/@superbased/observer.svg)](https://www.npmjs.com/package/@superbased/observer)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/superbasedapp/observer/blob/main/LICENSE)
[![Website](https://img.shields.io/badge/website-superbased.app-2EC4B6.svg)](https://superbased.app/)

![Session detail in the superbased dashboard: total cost, a low, typical and high cost for the next message, the 5-hour and weekly limit, and the cost of switching to a cheaper model](https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cost-and-limits.png)

## Try it without installing

```bash
npx @superbased/observer
```

Reads the session logs your coding agents already keep on disk, prints a 30-day cost table by tool
and model, and deletes its temporary database on exit. No config, no network.

On Windows PowerShell, type `npx.cmd` and `npm.cmd` instead of `npx` and `npm` (or use Command Prompt): PowerShell's default execution policy blocks the `npx.ps1` and `npm.ps1` scripts.

## Install

```bash
npm install -g @superbased/observer
observer --version
```

Prebuilt binaries for Linux (x64, arm64), macOS 13 or later (Intel, Apple Silicon) and Windows x64. npm fetches
only the one for your machine; there is no compile step and no postinstall download. Also on
[PyPI](https://pypi.org/project/superbased-observer/) and the
[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=superbased.superbased-observer)
with the same version numbers; install from one channel only.

## Why superbased

**One local binary that tracks Claude Code token usage, Codex cost and Cursor spend side by side,
and helps you control them.**

- **Provider-exact cost, not estimates.** An optional local proxy records the tokens your provider
  returned: net input, 5-minute vs 1-hour cache writes, reasoning tokens and long-context repricing.
- **Every coding agent in one place.** 50 adapters normalize Claude Code, Codex, Cursor, GitHub
  Copilot, Gemini CLI, Cline, Aider, Kiro, Devin, OpenCode, Junie and more into one local database.
- **Runs on your computer.** Everything lives in one SQLite file under `~/.observer/`. Sign in
  for a personal dashboard you can open anywhere; your sessions leave your computer only when you
  connect, after you approve it.
- **Know the next bill before it lands.** Prompt-cache tracking with expiry warnings, a cost band
  for your next message, and a 5-hour and weekly limit gauge for proxied sessions.
- **Guardrails on your own agents.** Built-in and custom rules for destructive commands, secrets
  egress, MCP pinning and budgets. Observe mode by default; `observer guard simulate` first.
- **Your agents as terminals.** Launch agent CLIs from the dashboard, join a running session from a
  paired device over your Tailscale tailnet, and hand a session from one tool to another.

![Overview page of the superbased dashboard: 30-day spend, sessions, actions and proxy-accurate API turns, cache efficiency, cost over time by billing bucket and actions over time by coding tool](https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/overview-dashboard.png)

## Get started

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-celebrate-light-small.png" alt="" width="54" align="right">

```bash
observer start    # proxy + watcher + dashboard; opens http://localhost:8081
observer scan     # backfill history from the session logs already on disk
observer doctor   # check the install
```

## Sign in (recommended)

```bash
observer connect          # your personal dashboard
observer connect acme     # or the team with the short name acme
```

One command signs you in and connects this machine. Your browser opens a page on
cloud.superbased.app that shows the machine and what will be shared; nothing is sent until you
click **Connect**. A personal dashboard gets **Summary only** (usage totals, not your prompts or
file paths). A team gets **Full detail** (prompts, responses and file paths, readable by the
team's admins). **Not now** keeps you signed in with nothing sent, and `observer disconnect`
stops sending at any time. You can also click **Sign in** in the local dashboard's top bar.
On a machine with no browser, `observer connect --no-browser` prints a code to enter at
cloud.superbased.app/connect.

Starting from scratch on a new machine? One command installs Observer, runs it as a background
service and connects:

```bash
curl -fsSL https://superbased.app/connect.sh | sh              # macOS and Linux
curl -fsSL https://superbased.app/connect.sh | sh -s -- acme   # straight into a team
```

```powershell
irm https://superbased.app/connect.ps1 | iex                   # Windows
```

Everything else in this README works without an account. See
[Start here](https://superbased.app/docs/getting-started/start-here).

For provider-exact tokens, route your agent through the proxy: in the dashboard open Compression,
click your tool's status pill and choose **Route through the observer proxy** (it previews the
config change and writes only when you confirm), or run `observer claude` / `observer codex` for a
one-off proxied session. `observer init` additionally registers the opt-in MCP server.

Prefer a plain download? [superbased.app/download](https://superbased.app/download) has the
Windows setup program, macOS and Linux downloads and every version, with SHA-256 checksums.

**macOS needs version 13 Ventura or later.** Observer is built with Go 1.27, which no longer runs
on macOS 12 Monterey. On macOS 12, stay on v1.36.0 or upgrade macOS first. v1.36.0 was meant to
carry an advance notice of this and did not. Linux and Windows are not affected.

## What you get

- A local dashboard for sessions, cost, cache, security and live activity, filterable by tool and
  project.
- Cost per session, model, project and tool, with cache read/write splits down to each API turn.
- An opt-in MCP server so your agents can query their own history across tools.
- Waste detection: stale re-reads, repeated commands and files several agents fight over.
- Dashboard terminals with multi-seat join and native resume.
- A CLI for everything: `observer usage`, `cost`, `predict`, `tail`, `statusline`.

<table>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/sessions.png" alt="Sessions page: one row per coding-agent session with tool, model, start time, elapsed time, actions and cost, plus tag totals" width="430"><br><sub><b>Sessions:</b> every session from every agent, with cost and tags.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/cache.png" alt="Cache page: live prompt caches with time left before they expire, cache ratio, reads and writes, and provider coverage" width="430"><br><sub><b>Cache:</b> which prompt caches are warm and when they go cold.</sub></td>
  </tr>
</table>

![Terminals page: Claude Code, Codex, Antigravity CLI and Copilot CLI running side by side as live terminals in one dashboard](https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/terminals-workspace.png)

## Inside a session

Click any session to open its detail view. Four of its tabs:

<table>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-detail.png" alt="Session detail, Overview tab: total cost, actions, elapsed time and tokens, the action breakdown, token buckets by billing tier and the cost per model" width="430"><br><sub><b>Overview:</b> cost, tokens by billing tier and the models used.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-messages.png" alt="Session detail, Messages tab: every message in the session with time, role, model, tool calls and cost" width="430"><br><sub><b>Messages:</b> each message with its model, tool calls and cost.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cost-and-limits-tab.png" alt="Session detail, Cost and limits tab: low, typical and high cost for the next message and the 5-hour and weekly limit" width="430"><br><sub><b>Cost &amp; limits:</b> what the next message will cost and how much of your limit is left.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cache-tab.png" alt="Session detail, Cache tab: the session's live cache and when it expires, cache hits, writes, rewrites and the read to write ratio" width="430"><br><sub><b>Cache:</b> the session's live cache, hits, writes and rewrites.</sub></td>
  </tr>
</table>

## Privacy

No account needed. Today the default install sends us no usage statistics, analytics or crash
reports, and your sessions leave your computer only when you connect. superbased stores paths,
commands and short excerpts, scrubs secrets before writing, and binds the proxy and dashboard to
`127.0.0.1` by default. The proxy forwards your own requests, unchanged, to the provider you
already use. See [PRIVACY.md](https://github.com/superbasedapp/observer/blob/main/PRIVACY.md).

### What Observer contacts by default

<!-- Hand-written from tests/invariant/egress_lanes_test.go and cmd/observer/privacy.go
     (2026-11-17). Regenerate from `observer privacy --markdown` once that output exists. -->

| What | Host | When | What it sends | Turn it off |
|---|---|---|---|---|
| Model price list | superbased.app | when Observer starts, then daily | nothing about you: a plain download of a signed public file | `[pricing.feed] enabled = false` |
| Package lists for the install check | superbased.app | every 6 hours | nothing about your projects: the same signed public files for everyone | `[security.deps] index_download = false` |
| Connection warm-up | chatgpt.com, api.openai.com | once when the proxy starts | a bare HEAD request, no body and none of your data | `[proxy] prewarm_targets = []` |

Everything else needs you to turn it on: your AI tool's own requests pass through the proxy only
when you route that tool through it, and your sessions go to cloud.superbased.app only after you
run `observer connect` and approve the machine. The vulnerability databases download only after
you accept them once. `observer privacy` lists every outbound request this build can make.

## Learn more

- [Documentation](https://superbased.app/docs) and [quickstart](https://superbased.app/docs/getting-started/quickstart)
- [Supported agents and per-tool setup](https://superbased.app/docs/track/overview)
- [How superbased compares](https://superbased.app/docs/compare/overview)
- [Source, issues and changelog](https://github.com/superbasedapp/observer)

## Troubleshooting

- **`EACCES` on `npm install -g`:** point npm at a user prefix
  (`npm config set prefix ~/.npm-global` and add `~/.npm-global/bin` to `PATH`) or use a Node version
  manager such as fnm or nvm.
- **`running scripts is disabled on this system` in PowerShell:** On Windows PowerShell, type
  `npx.cmd` and `npm.cmd` instead of `npx` and `npm` (or use Command Prompt): PowerShell's default
  execution policy blocks the `npx.ps1` and `npm.ps1` scripts. Changing the policy with
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` also works, but is not required.
- **`observer: command not found`:** make sure your npm global `bin` directory is on `PATH`, and that
  you installed `@superbased/observer` itself, not only a platform package.
- **Port 8820 or 8081 already in use:** another `observer start` is running; stop it first.

## License

Apache 2.0. This package is a small Node.js shim that runs the prebuilt binary from the matching
`@superbased/observer-<platform>-<arch>` package.

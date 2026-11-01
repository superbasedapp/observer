# superbased-observer

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-idle-light-512.png" alt="Obs, the SuperBased mascot: a small robot with a terminal prompt for a face and a cape" width="112" align="right">

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/brand/superbased-lockup-light.png" alt="SuperBased" height="32">

**Track what every AI coding agent costs. See the limit coming.** See what Claude Code, Codex,
Cursor and 37 more AI coding tools cost, per session and per model, from the tokens your provider
actually billed. Free, Apache-2.0, and it runs on your machine.

[![PyPI](https://img.shields.io/pypi/v/superbased-observer.svg)](https://pypi.org/project/superbased-observer/)
[![Python: 3.8+](https://img.shields.io/pypi/pyversions/superbased-observer.svg)](https://pypi.org/project/superbased-observer/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/superbasedapp/observer/blob/main/LICENSE)
[![Website](https://img.shields.io/badge/website-superbased.app-2EC4B6.svg)](https://superbased.app/)

![Session detail in the SuperBased dashboard: total cost, a low, typical and high cost for the next message, the 5-hour and weekly limit, and the cost of switching to a cheaper model](https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cost-and-limits.png)

## Try it without installing

```bash
uvx --from superbased-observer observer usage
```

Reads the session logs your coding agents already keep on disk, prints a 30-day cost table by tool
and model, and deletes its temporary database on exit. No config, no network. (The package is
`superbased-observer`; the command is `observer`.)

## Install

```bash
uv tool install superbased-observer    # or: pipx install superbased-observer
observer --version
```

Each wheel bundles its platform's prebuilt binary (manylinux2014 x86_64 and aarch64, macOS 13 or later on Intel
and Apple Silicon, win_amd64): no compile step, no download at install time, no Go toolchain. The
same binary ships on [npm](https://www.npmjs.com/package/@superbased/observer) and the
[VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=superbased.superbased-observer)
with the same version numbers; install from one channel only.

## Why SuperBased

**One local binary that tracks Claude Code token usage, Codex cost and Cursor spend side by side,
and helps you control them.**

- **Provider-exact cost, not estimates.** An optional local proxy records the tokens your provider
  returned: net input, 5-minute vs 1-hour cache writes, reasoning tokens and long-context repricing.
- **Every coding agent in one place.** 50 adapters normalize Claude Code, Codex, Cursor, GitHub
  Copilot, Gemini CLI, Cline, Aider, Kiro, Devin, OpenCode, Junie and more into one local database.
- **Local-first, no account.** No sign-in. Everything lives in one SQLite file under
  `~/.observer/`, and your session content is never uploaded without your explicit consent.
- **Know the next bill before it lands.** Prompt-cache tracking with expiry warnings, a cost band
  for your next message, and a 5-hour and weekly limit gauge for proxied sessions.
- **Guardrails on your own agents.** Built-in and custom rules for destructive commands, secrets
  egress, MCP pinning and budgets. Observe mode by default; `observer guard simulate` first.
- **Your agents as terminals.** Launch agent CLIs from the dashboard, join a running session from a
  paired device over your Tailscale tailnet, and hand a session from one tool to another.

![Overview page of the SuperBased dashboard: 30-day spend, sessions, actions and proxy-accurate API turns, cache efficiency, cost over time by billing bucket and actions over time by coding tool](https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/overview-dashboard.png)

## Get started

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-celebrate-light-small.png" alt="" width="54" align="right">

```bash
observer start    # proxy + watcher + dashboard; opens http://localhost:8081
observer scan     # backfill history from the session logs already on disk
observer doctor   # check the install
```

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
reports, and your session content is never uploaded without your explicit consent. SuperBased stores
paths, commands and short excerpts, scrubs secrets before writing, and binds the proxy and dashboard
to `127.0.0.1` by default. The proxy forwards your own requests, unchanged, to the provider you
already use. By default SuperBased also makes a few small requests of its own that carry none of
your data, such as a daily download of the public model price table from superbased.app (turn it
off with `[pricing.feed] enabled = false`). See
[PRIVACY.md](https://github.com/superbasedapp/observer/blob/main/PRIVACY.md).

## Learn more

- [Documentation](https://superbased.app/docs) and [quickstart](https://superbased.app/docs/getting-started/quickstart)
- [Supported agents and per-tool setup](https://superbased.app/docs/track/overview)
- [How SuperBased compares](https://superbased.app/docs/compare/overview)
- [Source, issues and changelog](https://github.com/superbasedapp/observer)

## Troubleshooting

- **`externally-managed-environment` from pip:** your distro protects the system Python (PEP 668).
  Use `uv tool install` or `pipx install`, which give the tool its own environment.
- **`observer: command not found`:** make sure the installer's `bin` directory (usually
  `~/.local/bin`) is on `PATH`; `pip show -f superbased-observer` lists the exact path.
- **Port 8820 or 8081 already in use:** another `observer start` is running; stop it first.

## License

Apache 2.0. This package is a small Python launcher that runs the prebuilt binary bundled in the
wheel.

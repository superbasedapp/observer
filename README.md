<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mascot/obs-idle-dark-512.png">
    <img src="docs/assets/mascot/obs-idle-light-512.png" alt="Obs, the SuperBased mascot: a small robot with a terminal prompt for a face and a cape" width="136">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/brand/superbased-lockup-dark.png">
    <img src="docs/assets/brand/superbased-lockup-light.png" alt="SuperBased" height="36">
  </picture>
</p>

<h1 align="center">Track what every AI coding agent costs. See the limit coming.</h1>

<p align="center">
  <strong>See what Claude Code, Codex, Cursor and 37 more AI coding tools cost, per session and per model,<br>
  from the tokens your provider actually billed. Free, Apache-2.0, and it runs on your machine.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@superbased/observer"><img src="https://img.shields.io/npm/v/@superbased/observer.svg?label=npm" alt="npm version"></a>
  <a href="https://pypi.org/project/superbased-observer/"><img src="https://img.shields.io/pypi/v/superbased-observer.svg?label=PyPI" alt="PyPI version"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=superbased.superbased-observer"><img src="https://img.shields.io/visual-studio-marketplace/v/superbased.superbased-observer.svg?label=VS%20Code" alt="VS Code Marketplace version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache 2.0"></a>
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg" alt="Platforms: Linux, macOS, Windows">
</p>

<p align="center">
  <a href="https://superbased.app/docs/getting-started/quickstart">Quickstart</a> ·
  <a href="https://superbased.app/docs">Docs</a> ·
  <a href="https://superbased.app/docs/compare/overview">Compare</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="https://superbased.app">Website</a>
</p>

<p align="center">
  <img src="docs/assets/screenshots/session-cost-and-limits.png" alt="Session detail in the SuperBased dashboard: total cost, a low, typical and high cost for the next message, the 5-hour and weekly limit, and the cost of switching to a cheaper model" width="900">
</p>

## Try it in one command

```bash
npx @superbased/observer
```

No install, no config, no network. It reads the session logs your coding agents already keep on
disk, prints a 30-day cost table by tool and model, and deletes its temporary database on exit.

On Windows PowerShell, type `npx.cmd` and `npm.cmd` instead of `npx` and `npm` (or use Command Prompt): PowerShell's default execution policy blocks the `npx.ps1` and `npm.ps1` scripts.

## Why SuperBased

**One local binary that tracks Claude Code token usage, Codex cost and Cursor spend side by side,
and helps you control them.**

- **Provider-exact cost, not estimates.** An optional local proxy records the tokens your provider
  returned: net input, 5-minute vs 1-hour cache writes, reasoning tokens and long-context repricing.
  Log-only trackers have to estimate those.
- **Every coding agent in one place.** 50 adapters normalize Claude Code, Codex, Cursor, GitHub
  Copilot, Gemini CLI, Cline, Aider, Kiro, Devin, OpenCode, Junie and more into one local database.
- **Local-first, no account.** No sign-in. Everything lives in one SQLite file under `~/.observer/`,
  and your session content is never uploaded without your explicit consent.
- **Know the next bill before it lands.** Prompt-cache tracking with expiry warnings, a low / typical
  / high cost band for your next message, and a 5-hour and weekly limit gauge for proxied sessions.
- **Guardrails on your own agents.** The guard checks each agent action against built-in rules
  (destructive commands, secrets egress, MCP pinning, budgets) and your own. It starts in observe
  mode; `observer guard simulate` replays your history before you turn on enforcement.
- **Your agents as terminals, from anywhere.** Launch agent CLIs from the dashboard as real terminals,
  join a running session from a paired device over your Tailscale tailnet, and hand a session from
  one tool to another.

<p align="center">
  <img src="docs/assets/screenshots/overview-dashboard.png" alt="Overview page of the SuperBased dashboard: 30-day spend, sessions, actions and proxy-accurate API turns, cache efficiency, cost over time by billing bucket and actions over time by coding tool" width="900">
</p>

## How it compares

| | SuperBased | ccusage | CodeBurn | Langfuse | Helicone | LiteLLM |
|---|---|---|---|---|---|---|
| Built for | Coding-agent cost & control | CC/Codex cost meter | Local CC spend + budget toolkit | LLM-app observability | LLM-app observability + gateway | AI gateway |
| Coding tools covered | **50 adapters** | Claude Code, Codex, + companion pkgs | 31-36 per their own docs | Instrument-per-app | Instrument-per-app | Anything routed through it |
| Provider-reported (not estimated) tokens | ✓ via local proxy | Partial (from logs) | Partial (from logs) | ✓ (SDK) | ✓ (proxy) | ✓ (proxy) |
| Cache 5-min vs 1-hour write split | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Reasoning + long-context surcharge accounting | ✓ | Partial | Partial | Partial | Partial | Partial |
| Runs 100% local, no cloud required | ✓ | ✓ | ✓ (opt-in team-sync preview) | Self-host a stack | Self-host or SaaS | Self-host |
| Agent-queryable memory over your history (MCP) | ✓ | ✓ (usage MCP) | ✓ | ✓ (trace MCP) | ✗ | ✗ |
| Cross-tool session handoff | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| License | Apache-2.0 | MIT | MIT | MIT (core) | Apache-2.0 | MIT |

Checked against each project's public repo (July 2026). Each of these tools is good at what it was
built for; the [full comparison](https://superbased.app/docs/compare/overview) covers more tools and
when to pick which.

## Install

| Channel | Command |
|---|---|
| npm | `npm install -g @superbased/observer` |
| PyPI | `uv tool install superbased-observer` (or `pipx install` / `pip install`) |
| VS Code | `code --install-extension superbased.superbased-observer` (Cursor, VSCodium and Windsurf: [Open VSX](https://open-vsx.org/extension/superbased/superbased-observer)) |
| Installer | `curl -fsSLO https://github.com/superbasedapp/observer/releases/latest/download/install.sh && sh install.sh` |

Every channel ships the same prebuilt, pure-Go binary for Linux (x64, arm64), macOS (Intel, Apple
Silicon) and Windows x64. The installer (Windows: `install.ps1`) also offers smaller editions
(`minimal`, `developer`, `managed`), checks each archive against `SHA256SUMS` and its Ed25519
signature, never runs sudo, and supports offline installs with `--from-dir`. Run
`sh install.sh --help` for every option.
On Windows PowerShell, type `npx.cmd` and `npm.cmd` instead of `npx` and `npm` (or use Command Prompt): PowerShell's default execution policy blocks the `npx.ps1` and `npm.ps1` scripts.

**macOS needs version 13 Ventura or later.** Observer is built with Go 1.27, which no longer runs
on macOS 12 Monterey. On macOS 12, stay on v1.36.0 or upgrade macOS first. v1.36.0 was meant to
carry an advance notice of this and did not. Linux and Windows are not affected.

## Get started

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mascot/obs-celebrate-dark-small.png">
  <img src="docs/assets/mascot/obs-celebrate-light-small.png" alt="" width="54" align="right">
</picture>

```bash
observer start    # proxy + watcher + dashboard; opens http://localhost:8081
observer scan     # backfill history from the session logs already on disk
```

1. **Route your agent through the proxy** for provider-exact tokens. In the dashboard, open
   Compression, click your tool's status pill and choose **Route through the observer proxy**: it
   previews the exact config change and writes only when you confirm. One-off alternatives:
   `observer claude` / `observer codex`, or `ANTHROPIC_BASE_URL=http://localhost:8820`.
2. **Use your agent as normal.** Sessions, cost and cache numbers appear within minutes.
3. **Optional:** `observer init` also registers the MCP server so your agents can query their own
   history (it adds tool schemas to every turn, so it stays opt-in).

`observer doctor` checks the install; `observer status` shows what has been captured.

<p align="center">
  <img src="docs/assets/screenshots/terminals-workspace.png" alt="Terminals page: Claude Code, Codex, Antigravity CLI and Copilot CLI running side by side as live terminals in one dashboard" width="900">
</p>

## What you get

- **Dashboard** (`localhost:8081`): Overview, Live, Sessions, Cost, Plans & limits, Cache, Security, Settings and
  more, filterable by tool and project, and readable on a phone.
- **Cost you can reconcile**: per session, model, project and tool, with cache read/write splits and
  a session drill-down down to each API turn.
- **Cross-tool memory**: an opt-in MCP server so an agent can ask what another agent already read,
  ran or broke in the same repo, plus `observer <tool> --continue-from <session>` handoffs.
- **Waste detection**: stale re-reads, repeated commands and files several agents fight over.
- **Terminals**: daemon-owned PTY terminals with multi-seat join, a live cost cockpit and native
  resume after a restart.
- **Your editor and shell**: a VS Code extension (status bar, sidebar, dashboard tab), a one-line
  `observer statusline`, and a CLI for everything (`observer usage`, `cost`, `predict`, `tail`).

<table>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/sessions.png" alt="Sessions page: one row per coding-agent session with tool, model, start time, elapsed time, actions and cost, plus tag totals" width="430"><br><sub><b>Sessions:</b> every session from every agent, with cost and tags.</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/cache.png" alt="Cache page: live prompt caches with time left before they expire, cache ratio, reads and writes, and provider coverage" width="430"><br><sub><b>Cache:</b> which prompt caches are warm and when they go cold.</sub></td>
  </tr>
</table>

Supported agents include Claude Code, Codex, Cursor, Copilot and Copilot CLI, Gemini CLI, Cline and
Cline CLI, Antigravity, OpenCode, OpenClaw, Pi, Hermes, Kilo Code, Qwen Code, Kiro CLI, Kiro Crew,
Crush, Kimi Code, Grok, Devin, Aider, Qoder, goose, droid, Open Interpreter, Command Code, Junie,
Poolside, Zed, Mistral Code, Muse, Prime Agent, DeepSeek, zcode, Freebuff, Cowork, Grok Bot, Autohand
Code, IBM Bob, Cortex Code, CodeBuddy Code, Deep Agents Code, DimCode, Dirac, Kimchi, Stakpak and
VT Code, plus ChatGPT, Claude, Gemini, Copilot and Perplexity on the web through an optional browser
extension.
Per-tool setup: [superbased.app/docs/track](https://superbased.app/docs/track/overview).

## Inside a session

Click any session to open its detail view. Four of its tabs:

<table>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/session-detail.png" alt="Session detail, Overview tab: total cost, actions, elapsed time and tokens, the action breakdown, token buckets by billing tier and the cost per model" width="430"><br><sub><b>Overview:</b> cost, tokens by billing tier and the models used.</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/session-messages.png" alt="Session detail, Messages tab: every message in the session with time, role, model, tool calls and cost" width="430"><br><sub><b>Messages:</b> each message with its model, tool calls and cost.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/assets/screenshots/session-cost-and-limits-tab.png" alt="Session detail, Cost and limits tab: low, typical and high cost for the next message and the 5-hour and weekly limit" width="430"><br><sub><b>Cost &amp; limits:</b> what the next message will cost and how much of your limit is left.</sub></td>
    <td width="50%"><img src="docs/assets/screenshots/session-cache-tab.png" alt="Session detail, Cache tab: the session's live cache and when it expires, cache hits, writes, rewrites and the read to write ratio" width="430"><br><sub><b>Cache:</b> the session's live cache, hits, writes and rewrites.</sub></td>
  </tr>
</table>

## Privacy

SuperBased needs no account. Today the default install sends us no usage statistics, analytics or
crash reports, and it never uploads your session content without your explicit consent. It stores
paths, commands and short excerpts, scrubs secrets before anything is written, and binds the proxy
and dashboard to `127.0.0.1` by default. The proxy forwards your own requests, unchanged, to the
provider you already use. By default it also makes a few small requests of its own that carry none
of your data, such as a daily download of the public model price table from superbased.app (turn it
off with `[pricing.feed] enabled = false`). Remove everything with `observer uninstall --all --purge`.
Details: [PRIVACY.md](PRIVACY.md).

## Documentation

- [Quickstart](https://superbased.app/docs/getting-started/quickstart) and
  [install options](https://superbased.app/docs/getting-started/install)
- [Connect your agents](https://superbased.app/docs/connect/overview) and
  [track costs by tool](https://superbased.app/docs/track/overview)
- Guides: [dashboard](https://superbased.app/docs/guides/dashboard),
  [token and cost tracking](https://superbased.app/docs/guides/token-cost-tracking),
  [cache tracking](https://superbased.app/docs/guides/cache-tracking),
  [cost predictor](https://superbased.app/docs/guides/cost-predictor),
  [terminals](https://superbased.app/docs/guides/terminals),
  [security guard](https://superbased.app/docs/guides/security-guard),
  [MCP server](https://superbased.app/docs/guides/mcp-server)
- Reference: [CLI](https://superbased.app/docs/reference/cli),
  [configuration](https://superbased.app/docs/reference/configuration),
  [measurement honesty](https://superbased.app/docs/reference/measurement-honesty)

## For organizations

Running coding agents across a whole engineering org? SuperBased also offers central visibility
across developers, budgets and policy, and SSO sign-in.
See [SuperBased for organizations](https://superbased.app/enterprise) or write to contact@superbased.app.

## Community

Questions go to [Discussions](https://github.com/superbasedapp/observer/discussions), bugs and
adapter requests to [Issues](https://github.com/superbasedapp/observer/issues), and security reports
through [SECURITY.md](SECURITY.md). Pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md)
(building needs Go 1.27+, no CGO). If SuperBased saves you a surprise bill, a star helps others find it.

## License

[Apache 2.0](LICENSE)

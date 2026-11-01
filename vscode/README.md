<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-idle-dark-512.png">
    <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-idle-light-512.png" alt="Obs, the SuperBased mascot: a small robot with a terminal prompt for a face and a cape" width="120">
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/brand/superbased-lockup-dark.png">
    <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/brand/superbased-lockup-light.png" alt="SuperBased" height="32">
  </picture>
</p>

<h1 align="center">SuperBased for VS Code</h1>

<p align="center">
  <strong>Track what every AI coding agent costs, inside your editor. See the limit coming.</strong><br>
  See what Claude Code, Codex, Cursor and 37 more AI coding tools cost, per session and per model,
  from the tokens your provider actually billed. No account, and your session content stays local.
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cost-and-limits.png" alt="Session detail in the SuperBased dashboard: total cost, a low, typical and high cost for the next message, the 5-hour and weekly limit, and the cost of switching to a cheaper model" width="860">
</p>

## Why SuperBased

- **Provider-exact cost.** A local proxy records the tokens your provider returned, including
  5-minute vs 1-hour cache writes, reasoning tokens and long-context repricing.
- **Every coding agent in one place.** 50 adapters: Claude Code, Codex, Cursor, GitHub Copilot,
  Gemini CLI, Cline, Aider, Kiro, Devin, OpenCode, Junie and more, in one local database.
- **Local-first.** Everything is stored in `~/.observer/observer.db` on your workspace host.
- **Know the next bill before it lands.** Prompt-cache expiry warnings and a cost band for your next
  message.

<p align="center">
  <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/overview-dashboard.png" alt="Overview page of the SuperBased dashboard: 30-day spend, sessions, actions and proxy-accurate API turns, cache efficiency, cost over time by billing bucket and actions over time by coding tool" width="860">
</p>

## Get started

<img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/mascot/obs-celebrate-light-small.png" alt="" width="54" align="right">

1. **Install the extension.** Each platform build bundles the `observer` binary, so there is nothing
   else to install.
2. **Nothing to start.** In the default `auto` mode the extension attaches to a running daemon or
   starts one, and only ever stops a daemon it started.
3. **Open the dashboard:** run **SuperBased: Open Dashboard**, or click the spend item in the status
   bar.
4. **Capture a session with exact tokens:** open a terminal with the **AI Coding Tool
   (SuperBased-proxied)** profile (terminal panel, the arrow next to `+`), then run `claude`,
   `codex` or another agent CLI. Or use **SuperBased: Launch Claude Code (proxied)** / **Launch Codex
   (proxied)**.

If something looks off, run **SuperBased: Doctor**. The **Get Started with SuperBased** walkthrough
(Help > Welcome) covers the rest.

**macOS needs version 13 Ventura or later.** The bundled `observer` binary is built with Go 1.27,
which no longer runs on macOS 12 Monterey. On macOS 12, stay on v1.36.0 or upgrade macOS first.
v1.36.0 was meant to carry an advance notice of this and did not. Linux and Windows are not
affected.

## What you get

| Surface | What it does |
|---|---|
| **Status bar** | Today's spend at a glance, plus a prompt-cache status item. Click to open the dashboard. |
| **Sidebar** | Today, Sessions, Discovery and Costs (7d) trees in the SuperBased activity bar view. |
| **Dashboard tab** | The full local dashboard (sessions, cost, cache, security, live activity) in an editor tab. |
| **File decorations** | A marker on files your agents touched recently, with who read or edited them. |
| **Terminal profile** | Pre-sets the proxy environment so agent CLIs started from it route through SuperBased. |
| **Instruction CodeLens** | Refresh or preview suggestions for your agent instruction files from captured patterns. |

<table>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/sessions.png" alt="Sessions page: one row per coding-agent session with tool, model, start time, elapsed time, actions and cost, plus tag totals" width="420"><br><sub><b>Sessions:</b> every session from every agent, with cost and tags.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/cache.png" alt="Cache page: live prompt caches with time left before they expire, cache ratio, reads and writes, and provider coverage" width="420"><br><sub><b>Cache:</b> which prompt caches are warm and when they go cold.</sub></td>
  </tr>
</table>

<p align="center">
  <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/terminals-workspace.png" alt="Terminals page: Claude Code, Codex, Antigravity CLI and Copilot CLI running side by side as live terminals in one dashboard" width="860">
</p>

## Inside a session

Click any session to open its detail view. Four of its tabs:

<table>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-detail.png" alt="Session detail, Overview tab: total cost, actions, elapsed time and tokens, the action breakdown, token buckets by billing tier and the cost per model" width="420"><br><sub><b>Overview:</b> cost, tokens by billing tier and the models used.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-messages.png" alt="Session detail, Messages tab: every message in the session with time, role, model, tool calls and cost" width="420"><br><sub><b>Messages:</b> each message with its model, tool calls and cost.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cost-and-limits-tab.png" alt="Session detail, Cost and limits tab: low, typical and high cost for the next message and the 5-hour and weekly limit" width="420"><br><sub><b>Cost &amp; limits:</b> what the next message will cost and how much of your limit is left.</sub></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/superbasedapp/observer/main/docs/assets/screenshots/session-cache-tab.png" alt="Session detail, Cache tab: the session's live cache and when it expires, cache hits, writes, rewrites and the read to write ratio" width="420"><br><sub><b>Cache:</b> the session's live cache, hits, writes and rewrites.</sub></td>
  </tr>
</table>

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `observer.daemon.mode` | `auto` | `auto` attaches or starts a daemon; `detect` only attaches. |
| `observer.binary.path` | empty | Use a specific `observer` binary instead of the bundled one. |
| `observer.binary.preferPathBinary` | `false` | Prefer an `observer` already on your `PATH`. |
| `observer.dashboard.port` | `8081` | Dashboard port. |
| `observer.proxy.port` | `8820` | Proxy port. |
| `observer.statusBar.enabled` | `true` | Show today's spend in the status bar. |
| `observer.cacheStatusBar.enabled` | `true` | Show the prompt-cache status item. |

## Privacy

No account needed. After the binary is in place, the extension talks only to
`127.0.0.1` on your workspace host; it contacts GitHub Releases only if it finds neither a bundled
nor a local binary. Remote-SSH, WSL, Dev Containers and Codespaces keep the data on the remote host.

## Learn more

- [User guide](https://github.com/superbasedapp/observer/blob/main/docs/vscode-extension-user-guide.md)
  and [command and settings reference](https://github.com/superbasedapp/observer/blob/main/docs/vscode-extension.md)
- [SuperBased docs](https://superbased.app/docs) and [source on GitHub](https://github.com/superbasedapp/observer)
- [Issues](https://github.com/superbasedapp/observer/issues) and
  [Discussions](https://github.com/superbasedapp/observer/discussions). The **SuperBased** output
  channel (View > Output) shows what the extension is doing; include it in bug reports.

<p align="center"><sub>Apache 2.0. Also available on <a href="https://open-vsx.org/extension/superbased/superbased-observer">Open VSX</a> for Cursor, VSCodium and Windsurf.</sub></p>

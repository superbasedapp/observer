<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/superbasedapp/observer/main/vscode/media/logo-light.png">
    <img src="https://raw.githubusercontent.com/superbasedapp/observer/main/vscode/media/logo-dark.png" alt="SuperBased" height="80">
  </picture>
</p>

<h1 align="center">SuperBased for VS Code</h1>

<p align="center">
  <strong>See what your AI coding tools are doing — locally, in your editor.</strong>
</p>

<p align="center">
  Claude Code cost tracking. Cursor token usage. Codex spend. Captures,
  normalises, and analyses tool-call activity across
  <a href="#supported-ai-tools">40 adapters</a> — Claude Code, Codex,
  Cursor, Cline, Copilot, Gemini CLI, Aider, Goose, Devin, and more.
  Zero telemetry. No data leaves your machine.
</p>

---

## ⚡ 5-minute quick start

### 1. You just installed the extension. Now what?

The extension wraps the `observer` binary — a small, local Go service
that watches your AI tools' log files and exposes a dashboard. The
binary either downloads automatically on first activation (~21 MB
from GitHub Releases) or uses one you've installed elsewhere
(`npm install -g @superbased/observer` works too).

### 2. Verify your install

Open the command palette (`Ctrl+Shift+P` / `⌘⇧P`) and run:

> **`SuperBased: Doctor`**

A terminal opens with a health-check. All four lines should show ✅.
If anything fails, the error tells you what to fix.

### 3. The daemon starts itself

Nothing to do — the extension ships in `auto` mode. It attaches to a
daemon you already have running, and otherwise starts one for you. It
only ever stops a daemon it started itself, so a daemon you launched in
a terminal is left alone when you close the editor.

**Prefer to run it yourself?**

```bash
observer start
```

Keep that terminal open. The extension attaches to it automatically.

### 4. Open the dashboard

> **`SuperBased: Open Dashboard`**

Or **click the spend indicator in the bottom-right status bar**
(`$(graph) $0.00` until your AI tools generate activity).

The full React analytics dashboard renders inside a VS Code editor
tab. **This is where you see your metrics.** Nine sections, all
linked to your real captured activity:

| Tab | Shows |
|---|---|
| **Overview** | Today's spend, top model, burn rate, month projection. |
| **Sessions** | Every AI coding session with cost, duration, tool — drill into action-by-action timelines. |
| **Cost** | Per-day / per-tool / per-model rollup with cache efficacy + compression savings. |
| **Discovery** | Cross-tool file overlap, stale re-reads, redundant command patterns. |
| **Analysis** | High-context turns, prior-month comparisons, cache-savings trend. |
| **Settings** | Schema-driven editor for every config knob in `~/.observer/config.toml`. |

### 5. Capture an AI session

Open a terminal in VS Code. **Click the down-arrow next to the
`+`** in the terminal panel → choose **"AI Coding Tool
(SuperBased-proxied)"**. The new terminal already has
`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `ENABLE_TOOL_SEARCH=true`
exported.

Run your AI CLI from that terminal:

```bash
claude     # or: cursor-agent, codex, cline-cli, gh copilot, …
```

Everything routes through the local proxy. Within ~30 seconds your
session shows up in the dashboard with **accurate** token counts
(not the ~3.4× over-bill you get from non-proxied JSONL adapters).

---

## 🎯 What you get

| Surface | What it does | How to access |
|---|---|---|
| **Status bar** | Today's spend at a glance, polled every 60s. Hover for delta vs yesterday, top model, burn rate, month projection. | Bottom-right corner. Click → open dashboard. |
| **Sidebar** | Four trees — **Today**, **Sessions**, **Discovery**, **Costs (7d)** — refreshed automatically. | Click the SuperBased icon in the activity bar (left rail). |
| **Dashboard webview** | The full React analytics SPA in an editor tab. Same surface as `http://127.0.0.1:8081/`. | `SuperBased: Open Dashboard` or status-bar click. |
| **File freshness** | Small dot in the file explorer next to files your AI tools touched in the last 24h. Hover shows last-read-by, edit count, stale re-reads flagged. | Just open a file — visible immediately. |
| **Notifications** | Budget breach (80% of monthly cap) + watcher-lag warnings. Deduped so they don't nag. | Automatic. Tunable thresholds in settings. |
| **Terminal profile** | "AI Coding Tool (SuperBased-proxied)" — pre-exports proxy env vars so AI CLIs launched from it route through observer. | Terminal panel → dropdown next to `+` → pick the profile. |
| **Instruction-file CodeLens** | "Refresh from SuperBased learnings" + "Preview suggestions" on `CLAUDE.md` / `AGENTS.md` / `.cursorrules`. Auto-updates the file from your captured patterns. | Open one of those three files — appears at the top. |
| **Get Started walkthrough** | 7-step interactive tour. | Help → Welcome → "Get Started with SuperBased". |

---

## ⚙️ Settings

| Setting | Default | Purpose |
|---|---|---|
| `observer.daemon.mode` | `auto` | `auto` attaches if a daemon is running, otherwise spawns one (and only stops what it spawned); `managed` behaves the same; `detect` attaches only and never spawns. |
| `observer.binary.path` | empty | Absolute path to override binary auto-detection. |
| `observer.dashboard.port` | `8081` | Where the dashboard listens. |
| `observer.proxy.port` | `8820` | Where the API reverse proxy listens. |
| `observer.statusBar.enabled` | `true` | Today-spend status bar item. |

---

## 🎛️ Common commands

Open the command palette (`Ctrl+Shift+P` / `⌘⇧P`) and type **SuperBased:**

| Command | Use it when |
|---|---|
| `SuperBased: Open Dashboard` | You want to see your metrics. |
| `SuperBased: Doctor` | Something seems off — health-check the install. |
| `SuperBased: Start Daemon` | You picked `managed` or `auto` mode and need to (re)start. |
| `SuperBased: Copy Proxy Env Vars` | You want to set up proxy routing in an existing terminal. |
| `SuperBased: Refresh All Trees` | The sidebar feels stale. |

---

## 🤖 Supported AI tools

- **Claude Code** (CLI + IDE) — via proxy + MCP server
- **Cursor** (CLI + IDE) — via proxy + agent-transcripts
- **Codex / Codex CLI** — via proxy
- **Cline** (VS Code) + **Roo Code** + **Continue** — via proxy
- **Cline CLI** (npm `cline` 3.0.20+) — via JSONL adapter (SQLite + per-session `<id>.messages.json`)
- **GitHub Copilot CLI** — via JSONL adapter (no proxy hook available upstream)
- **Cowork** + **Opencode** + **Openclaw** + **Pi** — via JSONL adapter
- **Antigravity** (desktop + `agy` CLI) + **WindSurf** — via watcher
- **Hermes Agent** (Nous Research) — via Python plugin hooks + SQLite backfill (`observer init --hermes`)
- **Kilo Code** (legacy IDE extension `kilocode.kilo-code` — Cline + Roo fork) + **Kilo Code CLI** (`@kilocode/cli`, OpenCode fork) — via JSONL / SQLite adapters
- **Aider**, **Goose**, **Devin**, **Qoder**, **Crush**, **Kimi Code**, **Grok**, **Kiro CLI**, **Qwen Code** — via JSONL / SQLite adapters
- **Factory `droid`**, **Open Interpreter**, **Command Code** — via JSONL adapters

40 adapters total, including five browser-based chat surfaces
(`chatgpt-web`, `claude-web`, `perplexity-web`, `gemini-web`,
`copilot-web`) captured via an opt-in browser extension that today
installs unpacked only — not yet in the Chrome Web Store.

Full integration details in the [user guide](https://github.com/superbasedapp/observer/blob/main/docs/vscode-extension-user-guide.md#per-ai-tool-integration).

---

## 🔒 Privacy + local-first

- **Zero telemetry.** Respects `telemetry.telemetryLevel`. No usage
  reporting, no crash analytics, no session beacons.
- **No outbound network calls at runtime.** The only network traffic
  the extension ever generates is the first-install binary download
  from GitHub Releases when no `observer` is found locally. After
  that, **all** communication is to `127.0.0.1:<dashboard.port>` on
  your workspace host.
- **No data leaves your machine.** Every byte captured stays in
  `~/.observer/observer.db`.
- **Codespaces / Remote-SSH / WSL2 / Dev Containers** all work via
  `portMapping` — data still doesn't cross any wire that wasn't
  already part of your VS Code remote-dev session.

---

## 📖 Going deeper

- **[User Guide](https://github.com/superbasedapp/observer/blob/main/docs/vscode-extension-user-guide.md)** —
  long-form walkthrough: daily workflow, per-AI-tool integration,
  customisation recipes, troubleshooting.
- **[Reference Docs](https://github.com/superbasedapp/observer/blob/main/docs/vscode-extension.md)** —
  full command + settings reference + compatibility matrix.
- **[GitHub](https://github.com/superbasedapp/observer)** —
  source, issues, releases.

---

## 💬 Help

- **Issues**: [github.com/superbasedapp/observer/issues](https://github.com/superbasedapp/observer/issues)
- **Discussions**: [github.com/superbasedapp/observer/discussions](https://github.com/superbasedapp/observer/discussions)
- **Output channel**: `View → Output → SuperBased` shows everything the
  extension is doing — include the relevant excerpt when filing bugs.

---

<p align="center">
  <sub>Built with Go + TypeScript. Apache-2.0 licensed. Zero telemetry.</sub>
</p>

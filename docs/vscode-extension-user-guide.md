# SuperBased for VS Code — User Guide

> A workflow-oriented walkthrough of the SuperBased
> extension. Pairs with the reference documentation at
> [`docs/vscode-extension.md`](./vscode-extension.md).

The extension's in-editor **Get Started** walkthrough (Help →
Welcome → "Get Started with SuperBased") is the
interactive version of this guide; this document is the long-form
read for users who prefer prose, or who want to dig into per-AI-tool
integration details.

---

## Contents

1. [Quick start](#quick-start) — 5 minutes from install to first dashboard view
2. [Daily workflow](#daily-workflow) — what each surface is for
3. [Per-AI-tool integration](#per-ai-tool-integration) — Claude Code, Cursor, Codex, Cline, Copilot
4. [Customisation](#customisation) — settings reference + recipes
5. [Troubleshooting](#troubleshooting) — what to do when something goes wrong
6. [Beyond the extension](#beyond-the-extension) — CLI parity, MCP, the Help drawer
7. [Privacy + local-first](#privacy--local-first) — what data leaves your machine (none)

---

## Quick start

### 1. Install

```bash
code --install-extension superbased.superbased-observer
```

Or open the Extensions view (`Ctrl+Shift+X` / `⌘⇧X`) and search
**"SuperBased"**.

If you're on Cursor, VSCodium, or Windsurf, the same VSIX ships to
[Open VSX](https://open-vsx.org/) — `cursor --install-extension
superbased.superbased-observer` works identically.

### 2. Confirm the binary is healthy

Open the command palette (`Ctrl+Shift+P` / `⌘⇧P`) and run **SuperBased:
Doctor**. A terminal opens with the binary's own health-check
(database integrity, hook integrity, MCP registrations, binary path
sanity). All four lines should show `✓`.

If Doctor says `binary not found`, set `observer.binary.path` in
your Settings to an absolute path (e.g. `/usr/local/bin/observer`)
and re-run.

### 3. Choose how the extension supervises the daemon

There are three options for `observer.daemon.mode`:

- **`detect`** (default) — Attach only. You start `observer start`
  yourself in a terminal; the extension reads the lockfile and
  shows everything in the editor.
- **`managed`** — The extension spawns the daemon on activation and
  kills it when VS Code exits. Refuses to spawn a second daemon
  when one is already running (safety rail against two daemons
  fighting over the same database).
- **`auto`** — Attach if a daemon is found; otherwise spawn one
  with the same supervision as `managed`.

If you don't already have a workflow around `observer start`,
**flip to `auto`**. The setting is at `observer.daemon.mode` in
the Settings UI or in `settings.json`.

### 4. Open the dashboard

Run **SuperBased: Open Dashboard**. The full React analytics SPA
renders inside an editor tab — same surface as
`http://127.0.0.1:8081/` outside the editor.

You're done with the quick start. The next section covers daily
use.

---

## Daily workflow

The extension contributes seven editor surfaces. You won't use all
of them every day; here's what each is for and when to reach for
it.

### Status bar

The bottom-right corner shows `$(graph) $<today's spend>`, polled
every 60 seconds. Hover for delta vs yesterday, top model, burn
rate per hour, and month projection. **Click it** to open the
dashboard panel.

Three states:

- **Live** (normal) — the dollar amount + a graph icon, prefixed with
  the `▞ superbased` wordmark (turn it off with `observer.statusBar.wordmark = false`).
- **Idle** (warning background) — "SuperBased idle" when no daemon
  is running.
- **Degraded** (error background) — "SuperBased unreachable" when the
  lockfile says a daemon is running but the dashboard port isn't
  answering. Usually means the daemon crashed; in `managed`/`auto`
  modes the extension will restart it within a few seconds.

Disable with `observer.statusBar.enabled = false` if you prefer a
cleaner bar.

### Activity-bar sidebar

The activity bar (left rail) has a **SuperBased** container with
four trees:

- **Today** — spend, top model, burn rate, month to date.
  Refreshes every 60 seconds.
- **Sessions** — the 20 most recent sessions with cost, duration,
  and action count. Refreshes every 60 seconds **and** on every
  file save in VS Code — so your most recent session shows up
  near-instantly. Right-click any row for:
  - **Open in Dashboard** (copies the session ID + opens the
    dashboard panel)
  - **Copy Session ID**
- **Discovery** — the top 20 files that multiple AI tools have
  touched, with the tool list and access count. Refreshes every
  5 minutes. Right-click → **Copy Path**.
- **Costs (7d)** — per-model cost rollup with turn count. Refreshes
  every 5 minutes.

Click the refresh icon in any view's title bar (or run
**SuperBased: Refresh All Trees**) to force-refresh without waiting
for the next poll.

### Dashboard webview

**SuperBased: Open Dashboard** opens the React SPA in an editor tab.
This is the same surface as the standalone
`http://127.0.0.1:8081/` — all nine tabs (Overview / Sessions /
Actions / Cost / Analysis / Tools / Compression / Discovery /
Settings) work identically.

The webview uses `retainContextWhenHidden: true`, so flipping
between editor tabs preserves your scroll position and the current
sub-view (e.g. if you're three levels deep into Sessions → session
detail → action detail, that state survives).

Under Codespaces / Remote-SSH / WSL2 / Dev Containers, the iframe's
`127.0.0.1` is rewritten to the workspace host's loopback via
`portMapping` — no operator intervention needed.

### File-freshness decorations

The explorer's file tree shows a small **`•`** dot next to files
your AI tools touched in the last 24 hours. Hover any file (in the
explorer **or** at the top of the editor) to see a Markdown summary:

- Last read by which tool, when
- Number of edits in the last 24h
- Number of stale re-reads **flagged** in the last 24h (SuperBased
  detects these but doesn't prevent the AI tool from issuing them;
  the count is the observability signal)
- Which tools touched the file

The 5-minute cache means once you've hovered a file, subsequent
hovers don't hit the API.

### Notifications

The extension surfaces two notifications **only when something
deserves your attention**, both deduped to avoid nagging:

- **Budget breach** — fires once per UTC calendar day when your
  monthly spend hits 80% of `intelligence.monthly_budget_usd`.
  Offers **Open Dashboard** / **Dismiss**.
- **Watcher lag** — fires when the watcher falls behind on a
  session file by more than 10 kB. Names the worst-lagging file in
  the toast body. Deduped per file on a 5-minute window. Offers
  **Show Output** / **Dismiss**.

The Output channel (`View → Output → SuperBased`) shows every poll
and any errors — useful when investigating why something didn't
fire.

### Daemon lifecycle commands

- **SuperBased: Start Daemon** — only meaningful in `managed`/`auto`
  modes. Spawns `observer start` with the configured ports.
- **SuperBased: Stop Daemon** — only kills daemons the extension
  spawned (status `managed`); never touches attached daemons.
  SIGTERM with a 5-second grace before SIGKILL.

In `managed` and `auto` modes, daemon crashes trigger automatic
restart with backoff `[1 s, 2 s, 5 s]`. After three failed
restarts, an error toast offers **Open Output Channel** / **Retry**.

### Binary resolution when the daemon can update itself

`observer` can now update its own binary in place, so the copy on your
`$PATH` may become newer than the one this extension shipped with.
That changes one thing about how the extension picks which `observer` to
run: **it re-checks on every activation, and it never lets its own bundled
copy override a newer one already installed on your machine.**

Concretely - the extension bundles a matching `observer` binary at build
time (so it works with nothing else installed), and by default checks that
bundled copy before your `$PATH` (`observer.binary.preferPathBinary` flips
the order). But every time VS Code activates the extension, it probes
`$PATH` once more even when the bundled copy would otherwise win, and
switches to the on-PATH binary if - and only if - it reports a **strictly
newer** version. An equal, older, or unparseable version changes nothing:
the bundled copy still wins ties and any uncertainty. This is what keeps
the extension from fighting a daemon that just updated itself - without
the check, a stale bundled binary would silently relaunch on top of the
newer one your org just rolled out to you.

The extension also tells the daemon which version of *itself* is running
(a loopback POST after every reconcile), so an org admin's Fleet →
Versions board can show extension/daemon skew across a team - this never
leaves your machine any differently than the rest of the extension's
`/api/*` traffic (see [Privacy + local-first](#privacy--local-first)).

### Terminal profile + proxy env vars

Two ways to route an AI CLI through SuperBased's reverse proxy
(needed for **accurate** token capture, which the JSONL adapter
path approximates):

- **Contributed terminal profile** — Open the terminal dropdown
  (down arrow next to **+** in the Terminal panel) → **AI Coding
  Tool (SuperBased-proxied)**. The new terminal already has
  `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and
  `ENABLE_TOOL_SEARCH=true` set.
- **SuperBased: Copy Proxy Env Vars** — Copies the same triple to
  the clipboard in your shell's syntax (bash/zsh/fish → `export …`;
  PowerShell → `$env:…`; cmd → `set …`). Paste into any existing
  terminal.

### CodeLens on instruction files

Open a `CLAUDE.md`, `AGENTS.md`, or `.cursorrules` and two
CodeLenses appear at line 1:

- **🔄 Refresh from SuperBased learnings** — runs
  `observer suggest --apply --project <workspaceRoot> --target <…>`
  and reloads the editor. Touches only content inside SuperBased's
  managed marker block; everything outside is preserved verbatim.
- **👁 Preview suggestions** — runs the dry-run and opens stdout
  as a new untitled markdown editor beside the original. Use this
  on first run.

---

## Per-AI-tool integration

SuperBased captures **fourteen** AI tools out of the box. Here's how
the extension integrates with the five most common ones.

### Claude Code

- **Proxy** — the contributed terminal profile sets
  `ANTHROPIC_BASE_URL=http://127.0.0.1:8820` and
  `ENABLE_TOOL_SEARCH=true`. Launch `claude` from that terminal and
  every API call goes through SuperBased.
- **MCP** — SuperBased's MCP server is registered via `observer init`
  outside the extension (the `observer.init` palette command is
  still a stub; use the CLI). Once registered, Claude Code spawns
  `observer serve` as a subprocess and can call `get_file`,
  `get_symbols`, `get_relations`, `retrieve_stashed`, etc.
- **Instruction file** — `CLAUDE.md` at the project root gets the
  two CodeLenses. The `--target claude` body composes hot files,
  common commands, edit→test pairs, onboarding reads, and
  learn-derived correction rules.

### Cursor

- **Proxy** — Cursor's CLI (`cursor-agent`) and the IDE both
  respect `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` when set. Open
  Cursor from the contributed terminal profile (or use Cursor's
  own settings → AI Provider → Base URL field).
- **Watcher** — SuperBased reads `~/.cursor/chats/<ws>/<conv>/store.db`
  directly for the CLI's system prompt + per-section token budget;
  the IDE's data lives in `globalStorage/state.vscdb` and is read
  by the IDE-side hook.
- **Instruction file** — `.cursorrules` at the project root gets
  the CodeLenses; `--target cursor`.

### Codex / Codex-CLI

- **Proxy** — `OPENAI_BASE_URL=http://127.0.0.1:8820/v1` from the
  contributed terminal profile. **Important**: codex 0.130+ has a
  shared app-server IPC quirk that can bypass the
  `-c openai_base_url=…` override; if you're seeing 0%
  capture-rate, run `observer codex --exclusive` to terminate the
  shared app-server before launching codex. The extension surfaces
  this gotcha via its watcher-lag notification on suspected
  misroutes.

### Cline / Roo Code

- **Proxy** — both respect `ANTHROPIC_BASE_URL`. Set it via the
  contributed terminal profile or in each extension's own
  preferences (Cline: VS Code Settings → Cline → Base URL).
- **Watcher** — SuperBased reads Cline's task transcripts under
  `~/.cline/` (and the Roo equivalent) directly.

### GitHub Copilot (Copilot CLI)

- **Proxy** — Copilot CLI doesn't expose a base-URL override; the
  capture path is the **JSONL adapter** reading the CLI's debug
  log + `events.jsonl`. Enable verbose logging with
  `copilot --log-level debug` to get the most accurate token
  counts.
- **No `OPENAI_BASE_URL`** — leaving it unset is fine; the CLI
  ignores it.

---

## Customisation

### Settings reference

| Setting | Default | Purpose |
|---|---|---|
| `observer.daemon.mode` | `detect` | `detect` / `managed` / `auto` — see [Quick start](#quick-start). |
| `observer.binary.path` | empty | Absolute path to override binary auto-detection. |
| `observer.dashboard.port` | `8081` | Where the dashboard listens. |
| `observer.proxy.port` | `8820` | Where the API reverse proxy listens. |
| `observer.statusBar.enabled` | `true` | Today-spend status bar item. |
| `observer.loc.reportSaves` | `true` | Report line COUNTS on each save so the dashboard can show human-written lines next to AI-written ones. Counts only, never content — see [Human line counts on save](#human-line-counts-on-save). |
| `observer.apiToken` | empty | Sent as `X-Observer-Token` on requests to the local daemon. Leave empty unless your daemon requires one. |

### Human line counts on save

SuperBased already counts the lines your AI tools write. It cannot see
the lines you type, so the extension measures those and reports the
COUNTS - never the content - to the local daemon each time you save.

Two numbers go out per save:

- **human** - what changed between the file's last clean state (your
  last save, or the moment an agent's write was reloaded from disk) and
  the file as you left it when the save began.
- **system** - what changed between that and the bytes actually written.
  That gap is your formatter's, so a format-on-save reflow is never
  counted as lines you wrote.

In-editor agents (Copilot Chat's agent mode, Cline, Kilo, Cursor) edit the
buffer through a `WorkspaceEdit`, which dirties it exactly like typing
does, so their edits would otherwise land as your own. A shape-only
heuristic (no text inspected - just how many ranges changed and how many
lines were replaced or inserted) flags a save that looks agent-made and
the daemon books it as unclassified rather than human, since there is no
VS Code signal that names who authored a change. The same threshold also
catches a genuine large paste (30+ lines), which books unclassified too;
a small in-editor-agent append under that size can still land as human.

What never leaves the editor is the file itself. The request carries the
workspace-relative path, the workspace folder path, the language, and
the buckets (added / modified / deleted code, added / deleted comments,
whitespace-only, blank, unclassifiable). There is no field for text.
Generated and vendored files - lockfiles, `node_modules`, `dist`,
`*.pb.go`, minified bundles, binaries - are skipped outright, as is
anything that is not a real file on disk.

It posts to `http://127.0.0.1:<dashboard.port>/api/loc/editor-change` on
the workspace host and nowhere else. With no daemon running the post
fails silently: no notification, no retry, no queue.

Two honesty notes. First, these are **editor-reported saves, not a
filesystem measurement**: they exist only while VS Code is running with
this extension active, and only for files you save in VS Code - work in
another editor, in a terminal, or via `git checkout` never appears, which
is why the dashboard labels them "editor-reported". Second, the endpoint
is an unauthenticated loopback POST by default, so any local process
could post counts to it. They are an observability signal only; nothing
in the product uses line counts for enforcement or for rating anybody's
work.

Turn it off with `"observer.loc.reportSaves": false` - it takes effect
immediately, no reload.

### Common configurations

#### "I want zero editor noise"

```jsonc
{
  "observer.statusBar.enabled": false,
  "observer.daemon.mode": "detect"
}
```

The extension is now a passive consumer — no status bar, no
spawned processes. You start `observer start` in a separate
terminal and use the dashboard for everything else.

#### "I want the editor to be the source of truth"

```jsonc
{
  "observer.daemon.mode": "auto",
  "observer.statusBar.enabled": true
}
```

The extension supervises the daemon. Crashes auto-restart with
backoff. The status bar tells you at a glance whether things are
healthy. You can still attach to a daemon started elsewhere
without conflict.

#### "I want a different dashboard port" (8081 is already taken)

```jsonc
{
  "observer.dashboard.port": 9081,
  "observer.proxy.port": 9082
}
```

Both ports follow the configured values, and the webview
`portMapping` follows automatically. The daemon's lockfile records
the port the extension reads, so attach-mode works regardless.

### Disabling specific surfaces

There's no per-surface kill switch beyond `observer.statusBar.enabled`.
If you don't want the activity-bar sidebar, right-click the
**SuperBased** icon in the activity bar and pick **Hide 'SuperBased'**.
If you don't want the dashboard webview, just don't run
**SuperBased: Open Dashboard**.

---

## Troubleshooting

### "SuperBased: binary not found"

`observer.binary.path` is empty + `observer` isn't on your `$PATH`
+ no bundled binary in the VSIX. Two fixes:

1. Install observer via `npm install -g @superbased/observer` or
   `pip install superbased-observer`. Then either restart VS Code
   or run **SuperBased: Doctor** to re-resolve.
2. Set `observer.binary.path` to the absolute path of a working
   binary.

The extension also auto-downloads from GitHub Releases on first
activation. If the download failed (network blocked, permissions
issue under `globalStorageUri`), the Output channel will show the
specific failure mode.

### "SuperBased idle" — the status bar shows the warning state

The lockfile is missing or stale. Three options:

1. Run **SuperBased: Start Daemon** if you're in `managed`/`auto`
   mode.
2. Run `observer start` in a terminal if you're in `detect` mode.
3. Check `~/.observer/observer-*.lock` — if there's a stale file
   with a PID that's no longer running, delete it.

### "SuperBased unreachable" — the status bar shows the error state

The lockfile says a daemon is running but the dashboard port isn't
answering. Usually one of:

- The daemon crashed and the lockfile cleanup hasn't fired yet.
  Run **SuperBased: Start Daemon** in `managed`/`auto` to restart;
  or kill the stale PID + restart manually in `detect`.
- A firewall is blocking `127.0.0.1:<observer.dashboard.port>`.
- You changed `observer.dashboard.port` after the daemon started.
  Restart the daemon to pick up the new value.

### CodeLens "Refresh from SuperBased learnings" failed

The Output channel logs the exact `observer suggest` failure.
Common causes:

- **No workspace folder** — the document isn't inside any workspace
  folder, so `--project` can't be resolved. Open the folder
  containing the instruction file first.
- **Stale daemon** — `observer suggest` reads the same DB the
  daemon writes to. If the daemon is in a broken state (e.g.
  WAL-locked), restart it.
- **Permissions** — SuperBased needs write access to the instruction
  file. Check ownership and the file's permissions bits.

### Dashboard webview shows a blank page

The iframe failed to load `http://127.0.0.1:<port>/`. Check the
Output channel for the daemon's stderr — usually the dashboard
goroutine logged the cause at startup. Common cases:

- The port is bound by another process.
- The watcher panicked at startup and took the dashboard with it.

### "Refresh All Trees" returns "Failed to load"

The `/api/*` endpoint threw. Each tree's specific endpoint and the
error message land in the Output channel; the tree placeholder
also has a hover tooltip with the error text.

If multiple trees show "Failed to load" simultaneously, the daemon
is almost certainly in a broken state. Restart it.

---

## Beyond the extension

### Reference docs

- [`docs/vscode-extension.md`](./vscode-extension.md) — the
  command + settings + surface reference.
- [`docs/vscode-extension-tracker.md`](./vscode-extension-tracker.md)
  — the M0 → M6 implementation log; useful when filing a bug to
  pinpoint when a surface landed.

### CLI parity

Almost everything the extension shows is also available from the
CLI:

- `observer status` — the status bar's data.
- `observer tail` — live-stream every captured action.
- `observer cost --days 7` — the Costs sidebar data.
- `observer discover` — the Discovery sidebar data.
- `observer suggest` — the CodeLens command (with `--target …`).

The extension is a UX shell; the CLI is the canonical surface.

### MCP server

SuperBased exposes thirteen MCP tools (`get_file`, `get_symbols`,
`get_relations`, `retrieve_stashed`, etc.) over stdio. AI tools
that support MCP (Claude Code, Cline, Cursor with MCP, Continue,
etc.) can call them directly. Register via `observer init` —
opt-in because it costs about 1,800 tokens per turn for the
schema.

### Help drawer

Every chart, KPI tile, and column in the dashboard has a
one-liner explanation. Click the `?` icon in the dashboard's top
bar to open the Help drawer; ~160 entries cover tabs, tiles,
charts, columns, filters, metrics, calculations, and a glossary.

---

## Privacy + local-first

The extension is **strictly local-first**:

- **Zero telemetry.** Respects `telemetry.telemetryLevel`. No
  usage analytics, no crash reports, no session-id beacons.
- **No outbound network calls** at runtime. The only network
  traffic the extension ever generates is the first-install
  binary download from
  `github.com/superbasedapp/observer/releases/…` when no
  `observer` binary is found on your machine. After that, all
  communication is to `127.0.0.1:<dashboard.port>` on your
  workspace host.
- **Codespaces / Remote-SSH** — the iframe `portMapping` rewrites
  the webview-side `127.0.0.1` to the workspace host's loopback.
  Data still doesn't cross any wire that wasn't already part of
  your VS Code remote-dev session.
- **No data leaves your machine.** Every byte SuperBased captures is
  written to `~/.observer/observer.db` (or
  `$OBSERVER_HOME/observer.db`) and stays there.
- **Line counts on save are counts, not content.** The one thing the
  extension sends rather than reads is the per-save line count described
  in [Human line counts on save](#human-line-counts-on-save) - how many
  lines changed, in which buckets, for which workspace-relative path. No
  file text is read, sent, or stored, and the destination is the same
  `127.0.0.1:<dashboard.port>` daemon. Disable it with
  `"observer.loc.reportSaves": false`.

The same guarantees apply to the binary itself — SuperBased is
Apache-2.0 and the source for everything captured + computed is in
the [main repository](https://github.com/superbasedapp/observer).

---

## Getting help

- **Issues** — [github.com/superbasedapp/observer/issues](https://github.com/superbasedapp/observer/issues)
- **Discussions** — [github.com/superbasedapp/observer/discussions](https://github.com/superbasedapp/observer/discussions)
- **Output channel** — `View → Output → SuperBased` shows everything
  the extension is doing. Include the relevant excerpt when filing
  bugs.

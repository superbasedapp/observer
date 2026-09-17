# VS Code Extension

> **SuperBased for VS Code** — one local intelligence layer for
> every AI coding tool you use, available without leaving your editor.
>
> _This document is the **reference** — commands, settings, surfaces._
> _Looking for the workflow walkthrough? Try the in-editor_
> _**Get Started** view (Help → Welcome), or read_
> _[`docs/vscode-extension-user-guide.md`](./vscode-extension-user-guide.md)_
> _for the long-form prose version._

The extension wraps the existing observer binary (CLI + dashboard +
proxy + MCP server) with a UX shell that surfaces the most-used
numbers + actions inside VS Code, Cursor, VSCodium, and Windsurf.
Every byte of business logic stays in Go; the extension never sends
data anywhere except to the local daemon on `127.0.0.1`.

## Install

### From the VS Code Marketplace

```bash
code --install-extension superbased.superbased-observer
```

Or search **"SuperBased"** in the Extensions view
(`Ctrl+Shift+X` / `⌘⇧X`).

### From Open VSX (Cursor, VSCodium, Windsurf)

The same VSIX is published to [open-vsx.org](https://open-vsx.org/)
so Cursor and other VS Code forks pick it up via their default
registry.

```bash
cursor --install-extension superbased.superbased-observer
codium --install-extension superbased.superbased-observer
```

### From a `.vsix` (offline / private)

Per-platform `.vsix` archives ride along with every observer release;
grab the matching one from the
[Releases page](https://github.com/superbasedapp/observer/releases)
and install via `code --install-extension <file>.vsix`.

## What it does

| Surface | Description |
|---|---|
| **Status bar** | Today's spend in the bottom-right (`$(graph) ▞ superbased $313.85`), updated every 60 s. Click → open dashboard. Hover for delta vs yesterday, top model, burn rate, month projection. The `▞ superbased` wordmark prefix is on by default; turn it off with `observer.statusBar.wordmark = false`. |
| **Activity bar** | An `observer` view container with four `TreeView`s — **Today**, **Sessions**, **Discovery**, **Costs (7 d)**. Right-click any session row for **Open in Dashboard** / **Copy Session ID**. |
| **Dashboard webview** | `SuperBased: Open Dashboard` opens the full React analytics SPA inside an editor tab. Same surface as the standalone `http://127.0.0.1:8081/` — Remote-SSH / Codespaces work via `portMapping`. |
| **File-freshness decorations** | A small dot in the explorer next to files your AI tools touched in the last 24 h, with a Markdown hover showing last-read-by, edit count, stale re-read count, and the tools that touched it. |
| **Budget + watcher-lag notifications** | When spend hits 80 % of `intelligence.monthly_budget_usd`, a banner suggests review. When the watcher falls behind on a session file by > 10 kB, a banner names the lagging file. Both deduped so they don't nag. |
| **Daemon lifecycle** | The extension can attach to a daemon you started in a terminal (`detect` mode — default), or spawn + supervise its own (`managed` / `auto`). Crash recovery with exponential backoff `[1 s, 2 s, 5 s]`; user-initiated stops are distinguished from crashes. |
| **Terminal profile** | A contributed terminal profile titled **"AI Coding Tool (SuperBased-proxied)"** that pre-exports `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `ENABLE_TOOL_SEARCH=true` so any AI CLI launched from it routes through the observer proxy. |
| **CodeLens on instruction files** | `CLAUDE.md`, `AGENTS.md`, and `.cursorrules` get two lenses at the top: **Refresh from SuperBased learnings** (runs `observer suggest --apply`) and **Preview suggestions** (dry-run, opens stdout beside the original). |
| **Human line-count reporting** | On each save the extension counts how many lines you changed and posts the COUNTS to the local daemon, so the dashboard can show human-written lines next to AI-written ones. See [Human line counts](#human-line-counts). Off with `observer.loc.reportSaves = false`. |

## Human line counts

The daemon already counts the lines your AI tools write, from the
before/after text those tools already record. It has no way to see the
lines *you* type. This is the editor half of that measurement.

**What is captured.** On every save the extension computes two diffs and
sends the line counts:

- `human` — the difference between the file as it stood at the last
  clean point (your last save, or the moment an agent's write was
  reloaded from disk) and the file as you left it when the save started.
- `system` — the difference between what you left and what was actually
  written to disk. That gap is your formatter's work (format-on-save,
  organize-imports, trailing-whitespace trim), reported separately so a
  gofmt reflow never counts as lines you wrote.

Each diff produces the same bucket set the daemon uses for AI edits:
added / modified / deleted code lines, added / deleted comment lines,
whitespace-only lines, blank lines, and lines the classifier could not
place. A one-line replacement is one *modified* line, not one added plus
one deleted; a 200-line reindent is 200 *whitespace* lines and zero
modified.

**In-editor agents are not counted as human.** Copilot Chat's agent mode
and extensions like Cline, Kilo and Cursor apply their edits through a
`WorkspaceEdit`, which dirties the buffer exactly like typing does, so a
save right after one of those would otherwise be booked as the
developer's own work. A small heuristic (`isAgentShapedChange`, no text
inspected, only the shape of the change: how many ranges, how many lines
replaced or inserted) flags a save that looks agent-made and sends
`possible_agent: true`; the daemon books that save as `unknown` rather
than as human or as any specific agent, since VS Code has no API that
names the author of a change. Two honest side effects: a human paste of
30 or more lines is flagged the same way and also lands as `unknown`, and
a small in-editor-agent append under that threshold can still be booked
human.

**What is never captured.** File content. Not a line of it, not an
excerpt, not a hash of one. The request body has no field that can hold
text: only the workspace-relative path, the workspace folder's absolute
path, the language, the category, two count buckets, two confidence
grades and a timestamp. Generated and vendored files (lockfiles,
`node_modules`, `dist`, `*.pb.go`, minified bundles, binaries) are
skipped entirely, and so is anything that is not a real file on disk
(untitled buffers, diff views, `git:` revisions).

**Where it goes.** `POST http://127.0.0.1:<dashboard.port>/api/loc/editor-change`
on the workspace host, and nowhere else. If the daemon is not running the
post fails silently: no notification, no retry. An older daemon without
the endpoint answers 404 and the extension stops posting for the rest of
the session.

**The classifier is shared, on purpose.** The language table and the
per-language comment/string token tables are generated from the daemon's
own Go tables into `vscode/src/loc/classifier-tables.json`, and a test on
each side fails if the two drift. If the editor and the daemon counted
lines with different rulers, "AI vs human" would not be a comparison.

**Honesty caveat — these are editor-reported saves, not a filesystem
measurement.** They only exist while VS Code is running with this
extension active, and only for files you save in VS Code: work done in
another editor, in a terminal, or by `git checkout` is invisible to this
path, and the UI labels human counts "editor-reported" for exactly that
reason. The endpoint is a loopback POST carrying a per-install shared
secret the daemon generates and the extension reads from the observer
home — which stops a local process that is not your editor from forging
saves, but is no barrier at all to anything else running as you, since it
can read the same file. Treat these numbers as observability, never as an
enforcement or performance signal — nothing in the product uses them for
either. The daemon-side keys (`[loc].editor_token_file`,
`[loc].editor_token_required`) are documented in `docs/loc-tracking.md`.

**Turning it off.** `observer.loc.reportSaves = false`. It takes effect
immediately, with no reload.

## Commands

Open the command palette (`Ctrl+Shift+P` / `⌘⇧P`) and search for
**SuperBased:**.

| Command | What it does |
|---|---|
| `SuperBased: Doctor` | Run `observer doctor` against the resolved binary in a new terminal. |
| `SuperBased: Start Daemon` | Spawn `observer start` (only in `managed`/`auto` mode). |
| `SuperBased: Stop Daemon` | SIGTERM the extension-managed daemon (graceful 5 s window before SIGKILL). |
| `SuperBased: Open Dashboard` | Open the dashboard webview panel. |
| `SuperBased: Copy Proxy Env Vars` | Copy the three proxy env vars to the clipboard in your shell's syntax (bash/zsh/fish → `export …`; PowerShell → `$env:…`; cmd → `set …`). |
| `SuperBased: Refresh All Trees` | Force a refresh on all four sidebar trees. |
| `SuperBased: Open Session in Dashboard` | Copy a session ID to clipboard + open the dashboard. (Right-click a session row.) |
| `SuperBased: Copy Session ID` / `Copy Path` | Self-explanatory; right-click context menu. |
| `SuperBased: Refresh Instructions from Learnings` | CodeLens on `CLAUDE.md` etc. — runs `observer suggest --apply --target <…>` for the current workspace. |
| `SuperBased: Preview Instruction Suggestions` | Same as above but dry-run; opens stdout in a new editor beside the original. |

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `observer.daemon.mode` | `detect` | `detect` attaches only; `managed` spawns + kills with the editor; `auto` attaches if a daemon is running, otherwise spawns. |
| `observer.binary.path` | empty | Absolute path to override binary auto-detection. **Machine-scoped and restricted in untrusted workspaces** — see "Workspace trust" below. |
| `observer.binary.preferPathBinary` | `false` | Scan `$PATH` before the bundled binary. **Machine-scoped and restricted in untrusted workspaces**, same reason as `observer.binary.path`. |
| `observer.dashboard.port` | `8081` | Where the dashboard listens. |
| `observer.proxy.port` | `8820` | Where the API proxy listens. |
| `observer.statusBar.enabled` | `true` | Today-spend status bar item. |
| `observer.statusBar.wordmark` | `true` | Show the `▞ superbased` wordmark prefix on the status bar's live-state text. |
| `observer.cacheStatusBar.enabled` | `true` | Cache-expiry status bar item (a countdown when a valuable prompt cache is about to go cold). |
| `observer.loc.reportSaves` | `true` | Report line COUNTS (never content) to the local daemon on each save, so the dashboard can show human-written lines next to AI-written ones. See [Human line counts](#human-line-counts). |
| `observer.loc.editorToken` | empty | Sent as `X-Observer-Token` on the saved-line-count report. **Leave it empty** — the daemon generates a per-install token on first start and the extension reads it from the observer home (`OBSERVER_HOME` if set, else `~/.observer/loc-editor-token`). Set it only when the daemon runs somewhere the extension cannot read that file, or when you moved the file with the daemon's `[loc].editor_token_file` key. |
| `observer.apiToken` | empty | **Deprecated, no longer read.** The saved-line-count report was the only request that ever sent this header; it now uses `observer.loc.editorToken`. |

## Binary management

On first activation the extension resolves a working `observer`
binary via this precedence:

1. `observer.binary.path` setting (if set and the file exists) - always
   wins, regardless of what follows.
2. The binary bundled inside the VSIX (per-platform packages bundle the
   matching architecture's binary at CI time) - checked first by
   default, because it is always present and known-correct for this
   extension version. Set `observer.binary.preferPathBinary` to scan
   `$PATH` before the bundled copy instead.
3. `observer` on your `$PATH` (cross-platform `which`, honours
   `PATHEXT` on Windows) - checked when the bundled copy is unusable, or
   first when `preferPathBinary` is set. **See "Re-probing on activation
   (O7)" below: even when the bundled copy wins here, PATH is checked
   once more before the extension commits to it.**
4. Download from the latest matching observer release on GitHub,
   SHA256-verified against the same release's `SHA256SUMS`, cached
   under VS Code's `globalStorageUri/v<version>/`.

The extension version matches the observer release it was built
against, so the download URL always resolves.

### Re-probing on activation (O7)

`observer` can now update **itself** - a `binary`-install-method daemon can
apply an org-published manifest and swap its own executable
(`docs/enterprise-updates.md`). Without a guard, an extension bundling an
older `observer` build would relaunch its own stale copy over a node that
had just updated, and the two would thrash on every activation: the daemon
updating itself, the extension putting the old one back.

So the extension **never trusts a cached resolution across activations**
and **never lets its bundled copy silently outrank a newer installed
one**:

- Binary resolution re-runs on every activation - nothing about which
  binary to use is cached from a previous VS Code session.
- When the bundled copy would win (step 2 above), the extension probes
  `$PATH` once more and hands back the **installed** binary instead if it
  is **strictly newer** (`isStrictlyNewer`, in
  `vscode/src/binary-internals.ts`) - an equal or unorderable version
  changes nothing, and the bundled copy still wins every tie. `--version`
  reporting `unknown` (unparseable output) never reads as "newer": any
  uncertainty keeps the bundled copy.
- The extension also reports its **own** version to the daemon after
  every reconcile (`Client.postExtensionVersion`, loopback `POST
  /api/update/extension-version`), which is what lets an org's Fleet →
  Versions board show extension/daemon version skew per developer
  (`extension_version` on the update posture row - empty when no
  extension is running, never `"0"`).

The inverse case needs no guard: a `vscode`-owned daemon binary (one
living in the extension's own global-storage cache) is not something the
node updater will ever touch - the install-method table marks it
no-self-apply and the node reports `blocked{install_method:vscode}` if it
somehow tried.

### Workspace trust

`observer.binary.path` and `observer.binary.preferPathBinary` name (or
change how the extension searches for) the executable this extension
resolves and spawns as the long-running daemon. Without a guard, a
cloned repo's checked-in `.vscode/settings.json` could set
`observer.binary.path` to an arbitrary path and have the extension
launch it the moment you opened the folder. Both settings are declared
`"scope": "machine"` (VS Code will not apply a workspace/folder-level
value for them at all) and are additionally listed in
`capabilities.untrustedWorkspaces.restrictedConfigurations`, so they are
ignored from workspace configuration until you grant trust. On top of
that, `activate()` itself checks `vscode.workspace.isTrusted`: in an
untrusted workspace the extension does not resolve or spawn the observer
binary, attach to a running daemon, or wire up any commands/status
bars/tree views at all — it logs to the Output channel, shows a
one-time warning notification explaining why, and resumes full
activation automatically the moment you grant trust (no reload
needed). Every other setting (ports, status bar toggles, the LOC
reporting opt-in) stays workspace-scoped, since none of them choose an
executable or read a secret off disk.

## Local-first guarantees

- **No telemetry.** The extension respects `telemetry.telemetryLevel`
  and never reports usage, crash, or session data.
- **No outbound network calls** except to GitHub Releases on first
  install (for the binary, when none is found locally).
- **No data leaves your machine.** All `/api/*` traffic is to
  `127.0.0.1:<dashboard.port>` on the workspace host. Under
  Remote-SSH / Codespaces the iframe `portMapping` routes the
  webview-side `127.0.0.1` to the same loopback on the host — no
  data crosses the wire except through your existing VS Code
  remote-dev session.

## Compatibility

| Editor | Status |
|---|---|
| Visual Studio Code (≥ 1.90) | First-class |
| Cursor | Supported via Open VSX; the extension uses only stable VS Code APIs (no `proposedApi.*`) |
| VSCodium | Same as Cursor |
| Windsurf | Same as Cursor |
| Codespaces | Works — the extension declares `extensionKind: ["workspace"]` so it runs on the workspace host |
| Remote-SSH / WSL2 / Dev Containers | Same as Codespaces |

## Source

The extension lives at `vscode/` in the
[main repository](https://github.com/superbasedapp/observer).
Build locally with:

```bash
cd vscode
npm install
npm run build         # bundles to out/extension.js
npm test              # runs the unit suite (118 tests at 1.7.26)
npm run package       # produces a local .vsix
```

Press **F5** inside `vscode/` to open the Extension Development
Host with the extension loaded against a dev observer.

## License

Apache-2.0 — same as the observer binary it wraps.

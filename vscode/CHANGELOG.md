# Changelog

All notable changes to the SuperBased Observer VS Code extension are
documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows the observer binary's tag (extension version == observer
release tag).

## [Unreleased]

### Added
- **SuperBased: Sign in and connect** (replaces the "Enroll in Org"
  placeholder). Runs `observer connect --json --no-browser`, opens the
  approval page in your browser and waits with a code and Cancel. You
  choose your personal dashboard, a team, or Not now on that page.
  **SuperBased: Connect to a team...** preselects a team.
- An account item in the status bar: "SuperBased · not signed in" until
  you connect, then the name of your dashboard or team (click opens it).
- A one-time sign-in suggestion on first start, returning once 7 days
  after Later and never shown on a signed-in or connected machine.

### Changed
- The Get Started walkthrough opens with sign-in; no account is still
  needed for anything else.

## [1.8.1] — 2026-06-03

First Marketplace release of the v1.8 line. The v1.8.0 release shipped
the Teams privacy posture rework end-to-end but the Marketplace job
failed because the VSIX manifest version wasn't being stamped in
lockstep with the release tag. v1.8.1 fixes the version-stamp step in
the release pipeline and re-ships the bundled binary with all v1.8.0
agent + org-server features (per-node opt-in for full-content sharing,
hash-only default wire shape, `observer-org quickstart`, `--dev-auth`
bypass, `observer enroll --link`, `observer doctor` org-awareness,
`observer org status` / `backfill` / `preview`, the LF `.gitattributes`,
and the golden-path CI smoke).

### Fixed
- VSIX builds now stamp `vscode/package.json` from the release tag
  before `vsce package` runs.

## [1.7.28] — 2026-06-02

### Fixed
- Marketplace listing showed broken logo images. Relative
  `<picture>` URLs in this README don't get path-rewritten by
  Marketplace when the README lives in a subfolder (`vscode/`, not
  the repo root). Switched to absolute
  `raw.githubusercontent.com/superbasedapp/observer/main/…`
  URLs.

### Changed
- README rewritten as an onboarding-first Marketplace landing page.
  Leads with a 5-minute quick start (install → Doctor → daemon mode
  → Open Dashboard → proxy env routing) instead of descriptive copy.
  A surface-by-surface table now names the exact command or click to
  reach each surface. All cross-doc links use absolute github.com
  URLs so they render as live on the Marketplace listing.

## [1.7.27] — 2026-06-02

First **full** publish — all 5 platforms shipped on the same tag
via the matrix CI flow. (v1.7.26 was the linux-x64-only smoke
publish that validated the publisher accounts + PATs.) The
real SuperBased S-mark brand icon replaces the placeholder used in
v1.7.26's listing.

### Added
- Native **Get Started with SuperBased Observer** walkthrough via
  `contributes.walkthroughs` — surfaces in VS Code's Get Started
  view on first install, with seven completion-tracked steps
  (welcome → doctor → daemon mode → dashboard → proxy →
  instruction files → done). Each step has an action button + an
  explanatory media panel.
- Long-form prose user guide at
  `docs/vscode-extension-user-guide.md` covering quick start,
  daily workflow, per-AI-tool integration (Claude Code, Cursor,
  Codex, Cline, Copilot), customisation recipes, and
  troubleshooting.
- Real SuperBased brand assets at `vscode/media/` (icon.png,
  logo-light.png, logo-dark.png) replacing the M6 placeholder.
  Activity-bar icon rewritten as monochrome S-mark using
  `currentColor` for proper theme tinting.
- 4 additional platform-tagged VSIXes (linux-arm64, darwin-x64,
  darwin-arm64, win32-x64) join linux-x64 on both Marketplace +
  Open VSX.

## [1.7.26] — 2026-06-02

First publishable cut. Covers M0 → M6 of the build-out documented in
[`docs/vscode-extension-tracker.md`](../docs/vscode-extension-tracker.md).

### Added

#### Binary manager (M0)

- `src/binary.ts` resolves a working `observer` binary via four-step
  precedence: `observer.binary.path` setting → `$PATH` → bundled in
  the VSIX → download from GitHub Releases with SHA256 verification,
  cached under `globalStorageUri/v<version>/`.
- `Observer: Doctor` command runs `observer doctor` against the
  resolved binary in a new terminal.

#### Daemon lifecycle + status bar (M1)

- Three-mode daemon manager (`observer.daemon.mode` =
  `detect` / `managed` / `auto`) with lockfile safety so two daemons
  can't fight over the same DB.
- `Observer: Start Daemon` / `Stop Daemon` palette commands.
- Today-spend status bar item polling `/api/analysis/headline` every
  60 s. Click → open dashboard. Hover for delta vs yesterday, top
  model, burn rate, month projection.

#### Dashboard webview (M2)

- `Observer: Open Dashboard` opens a `WebviewPanel` hosting the full
  React analytics SPA inside an editor tab. `portMapping` on the
  configured dashboard port so Remote-SSH / Codespaces work without
  operator intervention.
- Idle state shows a "Start Daemon" button that posts a message back
  to the host instead of leaving the user stranded.

#### Native sidebar (M3)

- Activity-bar `observer` container with four `TreeView`s:
  **Today** (`/api/analysis/headline?days=1`, 60 s refresh),
  **Sessions** (`/api/sessions?limit=20`, 60 s + on save),
  **Discovery** (`/api/discover`, 5 min),
  **Costs (7 d)** (`/api/cost?days=7&group-by=model`, 5 min).
- Per-tool ThemeIcons (`sparkle` / `rocket` / `edit` / `github` /
  `credit-card`); right-click context menus for **Open in
  Dashboard** / **Copy Session ID** / **Copy Path**.

#### Terminal profile + CodeLens on instruction files (M4)

- Contributed terminal profile "AI Coding Tool (Observer-proxied)"
  pre-exports `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`,
  `ENABLE_TOOL_SEARCH=true` against the configured proxy port.
- `Observer: Copy Proxy Env Vars` copies the same triple to the
  clipboard in your shell's syntax (bash/zsh/fish → `export …`;
  PowerShell → `$env:…`; cmd → `set …`).
- `CodeLens` on `CLAUDE.md`, `AGENTS.md`, `.cursorrules`:
  **Refresh from Observer learnings** (runs
  `observer suggest --apply --target <…>`) and
  **Preview suggestions** (dry-run; opens stdout beside the
  original).

#### File decorations + notifications + crash recovery (M5)

- `FileDecorationProvider` puts a small dot in the explorer next to
  files your AI tools touched in the last 24 h, backed by the new
  Go-side `/api/file/state?path=<abs>` endpoint. 5-min TTL cache
  with in-flight dedup so the daemon isn't slammed by explorer scans.
- `HoverProvider` mirrors the same data on line 1 of the active file
  with a richer Markdown body.
- **Budget breach** notification fires once per UTC day when monthly
  spend hits 80 % of `intelligence.monthly_budget_usd`.
- **Watcher-lag** notification fires when the watcher falls behind
  on a session file by > 10 kB. Deduped per worst-file on 5-min
  windows; skips known-misrouted files.
- **Daemon crash recovery**: extension-spawned daemons that exit
  unexpectedly are restarted with backoff `[1 s, 2 s, 5 s]`; on the
  4th failure a toast offers **Open Output Channel** / **Retry**.

#### Local-first guarantees

- Zero telemetry. The extension respects `telemetry.telemetryLevel`
  and never reports anything.
- No outbound network calls except the first-install binary download
  from GitHub Releases when no `observer` is found locally.

### Tested

- 118 unit tests covering binary resolution, lockfile parsing, three-
  mode gating, `/api/*` client + backoff, dashboard webview nonce,
  tree formatters + responses, env-format helper, instruction-target
  classifier, file-freshness cache, notification deciders, and
  crash-recovery backoff. `npm test` runs in ~5.7 s.

### Known limitations

- Marketplace screenshots are placeholder branding; final marketing
  art lands before the first published release.
- The `observer.init` / `observer.initWithMCP` palette commands are
  stubs — they surface a "not yet implemented" message. Use
  `observer init` from a terminal until that work lands in a
  follow-up.
- The session deep-link copies the session ID to your clipboard and
  opens the dashboard; the React SPA does not yet honour a
  `?session=<id>` query param. Tracked as a small `web/src/`
  follow-up; can land without re-cutting the extension.

## [0.1.0] — 2026-06-02

### Added
- Initial scaffold (manifest, esbuild bundler, TypeScript config,
  launch/tasks for the Extension Development Host).
- Binary manager (`src/binary.ts`) with four-step precedence:
  `observer.binary.path` setting → `$PATH` → bundled in VSIX →
  download from GitHub Releases with SHA256 verification, cached
  under `globalStorageUri/v<version>/`.
- `Observer: Doctor` command that runs `observer doctor` in a
  terminal against the resolved binary.
- Unit tests for `parseSha256Sums`, `PLATFORM_TO_ASSET` coverage,
  and `which()` PATH search.

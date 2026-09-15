# SuperBased

> The exact tokens your AI provider billed you — cache splits,
> reasoning tokens, long-context surcharges — reconciled across 29
> coding tools, entirely on your own machine. Nothing you build here
> ever leaves your machine unless you opt a node into it.

[![npm](https://img.shields.io/npm/v/@superbased/observer.svg)](https://www.npmjs.com/package/@superbased/observer)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platforms: Linux • macOS • Windows](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue.svg)](#install)
[![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-blue.svg)](https://go.dev/)
[![⭐ Star this repo](https://img.shields.io/badge/⭐-Star_this_repo-yellow.svg)](https://github.com/superbasedapp/observer)

If SuperBased catches something useful in your next bill, a star helps
other people looking for the same thing find it.

<p align="center">
  <img src="docs/assets/infographics/one-local-path.png" alt="One local path for AI coding activity" width="780">
</p>

## Try it in one command

```bash
npx @superbased/observer
```

On a fresh machine — no `~/.observer/observer.db`, no
`~/.observer/config.toml` — this scans every AI coding tool's own
local session files into a throwaway temp database, prints one cost
table grouped by tool and model, and deletes the database again before
it exits. It's local-only: zero network calls, and nothing is written
outside that temp directory (foreign-mount adapter mirrors — e.g. WSL
reading a Windows-side tool store — are redirected there too; pricing
is embedded in the binary, not fetched at runtime).

Already have SuperBased set up (or want the explicit form)? Run
`observer usage`. Bare `observer` only runs the one-shot on a machine
with no local SuperBased state at all — otherwise it prints the usual
welcome screen (`OBSERVER_ONESHOT=off` to always get the welcome
screen). This is the zero-config sibling of `observer cost`: `usage`
rolls up whatever session files it finds into a throwaway DB; `cost`
queries the DB you've actually been capturing into with `observer
scan` / `observer start` — including any proxy-accurate turns. Full
reference: [`docs/one-shot-usage-report.md`](docs/one-shot-usage-report.md).

---

## Table of contents

- [Try it in one command](#try-it-in-one-command)
- [What it is in 30 seconds](#what-it-is-in-30-seconds)
- [Install](#install)
- [First-run walkthrough](#first-run-walkthrough)
- [Dashboard tour](#dashboard-tour)
- [Terminals — launch, join, and track your AI CLIs](#terminals--launch-join-and-track-your-ai-clis)
- [MCP server — 25 cross-tool intelligence calls](#mcp-server--25-cross-tool-intelligence-calls)
- [Sign in and Cloud Intelligence (beta, experimental)](#sign-in-and-cloud-intelligence-beta-experimental)
- [Integrations — the stable contract to build against](#integrations--the-stable-contract-to-build-against)
- [API proxy — accurate token capture + compression](#api-proxy--accurate-token-capture--compression)
- [Architecture](#architecture)
- [Security & control layer (guard)](#security--control-layer-guard)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Post-upgrade hygiene + recovery](#post-upgrade-hygiene--recovery)
- [Build from source](#build-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## What it is in 30 seconds

A single local Go binary built on three things a hosted usage console
can't give you, in order of how much they matter:

1. **Proxy-accurate, cross-vendor cost attribution.** An optional API
   reverse proxy reads the token counts your provider actually
   billed — net input, 5m/1h cache read/write splits, reasoning
   tokens, long-context repricing — the same math your invoice uses,
   not a JSONL-derived estimate. It's accurate enough that it caught
   its **own** bug: a Codex reasoning-token double-billing regression
   SuperBased found and back-corrected months of history for
   (migration 058, shipped v1.18.0) — the kind of self-audit a vendor
   console has no incentive to run against itself.
2. **Local-first, by construction.** The watcher, proxy, dashboard,
   MCP server, and CLI make zero outbound calls on your behalf — no
   telemetry, no analytics, no remote reporting. Everything SuperBased
   captures is written to your own database and stays there.
   Full details: [`PRIVACY.md`](PRIVACY.md).
3. **One capture layer, every tool you actually use.** 40 adapters —
   Claude Code, Codex, Cursor, Cline + Cline CLI, GitHub Copilot +
   Copilot CLI, Gemini CLI, OpenCode, Google Antigravity, Cowork,
   Hermes Agent, Kilo Code, Aider, Goose, Devin, Qoder, Crush, Grok,
   Kiro CLI, Kimi Code, Qwen Code, OpenClaw, Pi, Factory Droid,
   Open Interpreter, Command Code, and more — parsed into one
   normalized schema, queryable from a local dashboard, an MCP server
   (so the tools themselves can query it), and a CLI. (Five *more*
   `*-web` adapters cover ChatGPT/Claude.ai/Gemini/Copilot/Perplexity
   in the browser — those need the browser-capture extension, which
   today only installs unpacked; every tool listed above works out of
   the box.) Twenty-seven of those are also full CLI launchers you can
   run as real terminals — from the dashboard or your own shell,
   captured through the same pipeline — see
   [Terminals](#terminals--launch-join-and-track-your-ai-clis) below.

Raw token counting across tools is table stakes here — it's the
substrate the accurate-cost layer above is built on, not the pitch.

**One local binary.** SuperBased captures, normalizes, and analyzes AI
coding tool activity on your own machine: proxy-accurate cost,
compression, cache tracking, and session handoff for every AI coding
tool you run.

<p align="center">
  <img src="docs/assets/screenshots/04-cost.png" alt="Cost tab — proxy-accurate per-model token buckets and dollar cost" width="900">
</p>

<p align="center">
  <img src="docs/assets/screenshots/11-session-detail.png" alt="Session detail — cost, token buckets, cost predictor and limit gauge" width="900">
</p>

<p align="center">
  <img src="docs/assets/infographics/intelligence-across-tools.png" alt="Shared local intelligence layer across tools" width="780">
</p>

It answers questions like:

- Where did this week's $147 Claude bill come from — which projects,
  models, sessions, tool calls? And is that number the same one my
  provider's invoice would show?
- Did I spend more on Opus or Sonnet? Are my Sonnet sessions hitting
  the long-context tier and getting repriced at 2×?
- How much did I waste re-reading files that hadn't changed since
  the last read in the same session?
- Could that trivial Opus session have been done by Sonnet for 1/5
  the cost?
- Across Claude Code, Cursor, and Codex working in the same repo,
  what files are touched by all three? Where are they stepping on
  each other?
- What will my next message roughly cost — and how much of my 5-hour
  and weekly subscription limit is left before I hit it?
- Where did my own OpenTelemetry-instrumented agent spend its tokens
  — with the proxy's exact per-span cost where it routed through the
  proxy?

---

## Install

Pick whichever package manager fits your environment — npm and PyPI
ship the same prebuilt binary from the same `v*` tag, version
numbers kept in lock-step.

### Via VS Code (Marketplace or Open VSX)

```bash
code --install-extension superbased.superbased-observer
```

The VS Code extension bundles the observer binary, lifts the
dashboard / sidebar / status bar / file decorations into the editor,
and contributes a terminal profile that pre-exports the proxy env
vars so AI CLIs launched from it route through observer
automatically. Cursor, VSCodium, and Windsurf install the same VSIX
via [Open VSX](https://open-vsx.org).

After install, VS Code's **Get Started** page surfaces an in-editor
walkthrough; the long-form user guide lives at
[`docs/vscode-extension-user-guide.md`](docs/vscode-extension-user-guide.md)
and the command + settings reference is at
[`docs/vscode-extension.md`](docs/vscode-extension.md).

### Via npm (recommended for Node users)

```bash
npm install -g @superbased/observer
observer --version
```

### Via pip / uv / pipx (recommended for Python users)

```bash
pip install superbased-observer            # plain pip
uv tool install superbased-observer        # uv (isolated env, fastest)
pipx install superbased-observer           # pipx (isolated env)
observer --version
```

Wheels ship for `manylinux2014_{x86_64,aarch64}`,
`macosx_*_{x86_64,arm64}`, and `win_amd64`. `uv tool` and `pipx`
keep the install isolated from your project's Python env — generally
what you want for a CLI tool.

### Via go install (latest main, builds locally)

```bash
go install github.com/marmutapp/superbased-observer/cmd/observer@latest
observer --version
```

### Via direct download (pre-built per-platform archive)

Each tagged release attaches per-platform archives to the
[Releases page](https://github.com/superbasedapp/observer/releases),
verifiable against the published `SHA256SUMS`:

| Asset | Platform | Contents |
|---|---|---|
| `observer-vX.Y.Z-linux-x64.tar.gz` | Linux x86_64 | `observer` + `antigravity-bridge.exe` (for WSL2) |
| `observer-vX.Y.Z-linux-arm64.tar.gz` | Linux arm64 | `observer` + `antigravity-bridge.exe` (for WSL2) |
| `observer-vX.Y.Z-darwin-x64.tar.gz` | macOS Intel | `observer` |
| `observer-vX.Y.Z-darwin-arm64.tar.gz` | macOS Apple Silicon | `observer` |
| `observer-vX.Y.Z-win32-x64.zip` | Windows x86_64 | `observer.exe` |
| `SHA256SUMS` | — | sha256 of all five archives |

```bash
# Linux x64 example — substitute your platform + version.
VERSION=v1.6.21
PLAT=linux-x64
curl -L -O https://github.com/superbasedapp/observer/releases/download/$VERSION/observer-$VERSION-$PLAT.tar.gz
curl -L -O https://github.com/superbasedapp/observer/releases/download/$VERSION/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf observer-$VERSION-$PLAT.tar.gz
./observer --version
```

The binary is pure Go — no CGO, no external runtime dependencies.
SQLite storage is pure-Go via `modernc.org/sqlite`. Single static
binary; `scp` it anywhere it runs. Same artifacts ship to npm and to
the Releases page (build-once-ship-everywhere CI), so the npm and
direct-download paths produce byte-identical binaries.

---

## First-run walkthrough

```bash
# 1. Start everything: proxy + watcher + dashboard in one foreground
#    process (ctrl-c to stop). Hooks auto-register for every detected
#    AI tool, and the dashboard opens in your browser
#    (http://localhost:8081; suppress with --no-open).
observer start

# 2. (another shell) Backfill from existing session logs so the
#    dashboard has history immediately rather than starting empty.
observer scan
```

From here the dashboard drives. On an empty database the Overview tab
leads with a three-step onboarding checklist — and a **demo mode**
offer if you'd rather look around first: one click seeds a temporary
synthetic dataset so every chart renders with realistic data (your
real `observer.db` is never read or written; a persistent banner marks
demo state and one click clears it). The two checklist steps that
matter:

3. **Route your AI tool through the proxy** — accurate token counts
   and conversation compression both need it. On the Compression
   tab's **Proxy** banner, click your tool's status pill, then
   **Route through the observer proxy…**: the button previews the
   exact file change (Claude Code: an `env.ANTHROPIC_BASE_URL` entry
   in `~/.claude/settings.json`; Codex: an `observer` model provider
   in `~/.codex/config.toml`) and writes only on confirm. Durable —
   every later session routes automatically. The same section of the
   Settings → Connected tools panel offers a per-tool setup wizard
   (hooks / MCP / routing, one consent click per write) and a Launch
   button. Prefer the terminal? The same routing ships as `observer
   init`, as session-scoped wrappers (`observer claude` / `observer
   codex` — no config writes), or as a plain
   `export ANTHROPIC_BASE_URL=http://localhost:8820` /
   `OPENAI_BASE_URL=http://localhost:8820/v1`.
4. **Use your AI tool as normal.** The checklist tracks the first
   captured session; cost, compression, and cache numbers populate
   within minutes of real activity.

**Optional — MCP registration.** `observer init` additionally writes
MCP server entries (and hook entries) into each AI tool's own config
files (`~/.claude/settings.json`, `~/.claude.json`,
`~/.cursor/mcp.json`, `~/.codex/config.toml`, …). Hooks default ON,
MCP defaults ON; opt out per-side with `--skip-hooks` / `--skip-mcp`.
Idempotent. `observer start` alone never registers the MCP server —
MCP wiring is explicit-only, because it costs ~1,800 schema tokens
per AI-client turn.

**If you route Claude Code while MCP servers are registered, set
`ENABLE_TOOL_SEARCH=true` in the same environment.** Claude Code's
SDK disables `ToolSearch:optimistic` deferred MCP loading whenever
`ANTHROPIC_BASE_URL` is set, eagerly inlining all 17 observer MCP
tool schemas (plus any Google MCPs) into every request prefix —
~+21K tokens/turn. The override re-enables lazy loading; observer's
proxy forwards `tool_reference` blocks byte-identically, satisfying
the SDK's documented safety condition. Empirical: with the override +
v1.7.23 defaults, the proxy is **−6.9% mean cost vs no-proxy** on
Claude Code's reference rig (n=8 lumen refactor task, V7-22 binary).
Without it, ~+9% per-turn overhead. See
[superbased.app/docs/connect/claude-code](https://superbased.app/docs/connect/claude-code#set-enable-tool-search-when-routing-with-mcp)
for the full picture.

The proxy logs every turn with the exact token counts the provider
returned, including cache-tier breakdowns (5m vs 1h ephemeral) and
1h surcharges that JSONL adapters can't always disambiguate.

### Verifying the install

```bash
observer doctor          # health checks: DB integrity, hook
                         # registration, MCP entries, pid bridge
observer status          # row counts + recent activity
observer tail            # live-stream captured actions
```

---

## Dashboard tour

`observer start` opens the dashboard automatically on interactive
launches (suppress with `--no-open`; default URL
<http://localhost:8081>). Twenty-one tabs in four nav groups (Monitor /
Analyze / Optimize / Configure), each designed around one question —
the tour below covers the core surfaces; Live (recent sessions with a
real-time action feed), Search (full-text over captured tool outputs),
Privacy (capture map + scrub tester), and the opt-in Terminals page
(covered in [Terminals](#terminals--launch-join-and-track-your-ai-clis)
below) and Remote page (covered under
[Remote & mobile access](#remote--mobile-access) below) are
self-explanatory once you're in, and the Suggestions tab's advisor
nudges and the Patterns tab's derived habits are covered in their own
docs. Evaluating without data? Start **demo mode** from the empty
Overview — synthetic dataset in a temp DB, real `observer.db`
untouched, one click to clear.

### Overview — what's been happening?

<p align="center">
  <img src="docs/assets/screenshots/01-overview.png" alt="Overview tab" width="900">
</p>

Four headline KPI tiles (sessions, API turns, token rows, stale
re-reads — each filterable by the global Window / Tool / Project
chips), cost-over-time stacked area split by billable token bucket,
actions-over-time stacked by tool, top models by token volume, top
tools by action count.

### Sessions — what did each run actually do?

<p align="center">
  <img src="docs/assets/screenshots/02-sessions.png" alt="Sessions tab" width="900">
</p>

One row per session with cost, token totals (input / cache R /
cache W / output), elapsed time, action count, and a model badge.
Quality / Errors / Redundancy scoring columns light up once
`observer score` has run. Click a row to open the per-session
slide-over (shown below in [Session detail](#session-detail--drill-into-one-session)).

### Actions — the firehose, filtered

<p align="center">
  <img src="docs/assets/screenshots/03-actions.png" alt="Actions tab" width="900">
</p>

Every recorded tool call, normalized across adapters. Filter by
action type (28 categories), tool, effort, permission. Each row
exposes its `target` + status + raw-tool source + truncated content
preview; click to expand to the full event with error context.

### Cost — per-model breakdown with the right math

<p align="center">
  <img src="docs/assets/screenshots/04-cost.png" alt="Cost tab" width="900">
</p>

Eight KPI tiles across the billable token buckets (Net Input, Cache
Read, Cache Write 5m, Cache Write 1h, Output, Reasoning, plus total
USD and turn count). Per-model table shows the full breakdown
including reasoning tokens (billed at output rate) and long-context
surcharges (Sonnet 1M, gpt-5 >272K, Gemini 2.5 Pro >200K). Hover
any column header for its definition + formula.

### Analysis — spending insights & efficiency signals

<p align="center">
  <img src="docs/assets/screenshots/05-analysis.png" alt="Analysis tab" width="900">
</p>

Twelve KPI tiles comparing this period to prior: spend Δ%, MTD vs
budget with projection bar, $/M output rate, cache savings + cache
efficacy %, high-context turn count, $/turn, burn rate ($/active
hour), top model concentration %, Discovery waste $, sessions
total. Daily-spend stacked bars with Model / Project / Tool
dimension toggle, hour-of-day heatmap, period-over-period movers
(top increases / decreases / new entrants), and model right-sizing
hints (trivial Opus sessions that could have used Sonnet).

### Tools — per-AI-client breakdown

<p align="center">
  <img src="docs/assets/screenshots/06-tools.png" alt="Tools tab" width="900">
</p>

Four KPIs (total actions, distinct tools, overall success rate,
busiest tool), activity-over-time stacked area, and per-tool
action-type-mix horizontal bars (100% normalized, colored by action
category). Surfaces which AI client owned which kind of work.

### Compression — what the proxy saved

<p align="center">
  <img src="docs/assets/screenshots/07-compression.png" alt="Compression tab" width="900">
</p>

Five KPIs: total $ saved (priced at your input rate), tokens saved,
bytes trimmed, turns compressed. Savings-per-day stacked bar by
mechanism (drop, trim, summary), savings-by-mechanism donut, recent
events table with original→compressed→saved + dollar impact per
event.

### Cache — prompt-cache observation & forecasting

<p align="center">
  <img src="docs/assets/screenshots/08-cache.png" alt="Cache tab" width="900">
</p>

Headline cache-ratio hero (cache_read ÷ cache_write tokens) and three
sibling KPIs: Cache read, Cache write, and Avoidable spend / Event
count. Avoidable spend renders in warn tone — it's the dollar overhead
of rewrites that wouldn't have happened on a perfectly cache-friendly
session. By-model and By-project tables with R%/W% mix bars + absolute
Read/Write/Events + cache Ratio + Avoidable $. Proportional Top
causes histogram (suffix_growth + hit dominate a healthy session;
real invalidations render in warn tone; tools_changed on MCP toggles
renders neutral). Worst sessions table sorted by rewrite count;
click-through opens the per-turn Cache panel.

**How it's captured.** Two paths feed the same engine, both writing
to NODE-LOCAL `cache_segments` / `cache_entries` / `cache_events`
tables (migrations 036+037, node-local only, never leaving the machine):

- **Tier-1 (proxy)** — point your AI client at `127.0.0.1:8820` and
  the cachetrack engine reads each turn's `cache_read_input_tokens` +
  `cache_creation_input_tokens` envelope live. Default capture path
  for Claude Code.
- **Tier-2 (transcript watcher)** — feeds the same engine from
  on-disk claude-code JSONL transcripts for sessions that didn't
  route through the proxy. Run `observer backfill --cache-rescan`
  to retrofit history.

**Enable / disable.** Default-on per spec §11 (the loader merges
`[cachetrack].enabled = true` if the section is absent). To turn off:
`[cachetrack].enabled = false` in `~/.observer/config.toml`, then
restart `observer start`. Inspect engine health with
`observer cache-health --json`. Operator reference:
[superbased.app/docs/guides/cache-tracking](https://superbased.app/docs/guides/cache-tracking)
(or [docs/cache-tracking.md](docs/cache-tracking.md) in the repo).

### Suggestions — the advisor's quantified nudges

Default-on, fully local suggestions engine (zero LLM cost, zero
network): 19 detectors turn the window's captured activity into
ranked, dollar- or minute-quantified recommendations — session
balloons, idle re-cache, long-context tier crossings, trivial
sessions on expensive models, cache hit-rate / cache-write waste /
prefix thrash, read-heavy expensive-model sessions, effort
overprovisioning, fast-tier premium, unrecovered failures, quality
regressions, MCP schema overhead, compression off, capture without
proxy routing, cross-session stale reads, web-search spend, spend
spikes, plus a posture nudge (guard observing idle, pointing at the
surface that owns the workflow). Every
card carries its arithmetic ("show math"), a confidence score,
snooze/dismiss with a 7-day cooldown, and — where a dashboard
control can fix the finding — a one-click action that navigates to
the right surface (writes stay behind that surface's own consent
flow). CLI twin: `observer advise`. Config: Settings → Advisor
(`[advisor]` — evidence window, confidence/savings floors, opt-in
≤400-token session-start digest).

### Discovery — the waste detector

<p align="center">
  <img src="docs/assets/screenshots/09-discovery.png" alt="Discovery tab" width="900">
</p>

Waste $ hero (stale-read tokens × your blended input rate). Four
KPIs: stale re-reads count, tokens wasted, affected files, repeated
commands. Top files re-read table with cross-thread highlighting
(when the same file was re-read from a subagent that didn't see the
parent's read). Repeated-commands table with no-change-rerun
detection.

### Security — the guard, operable end to end

Posture tiles + a filterable verdict timeline (rule IDs resolve to
their full definitions), then the routine workflows: a consent-gated
mode control that shows the simulate evidence before you flip
enforce, the enforce-readiness replay over your real history, the
approvals register (scoped, expiring — live immediately), a
lint-gated user-policy editor with `.bak` undo, budget guardrails
suggested from your own observed spend with a daily burn-down meter,
MCP pin approvals, and one-click compliance evidence downloads.

### Settings — every config knob, editable

<p align="center">
  <img src="docs/assets/screenshots/10-settings.png" alt="Settings tab" width="900">
</p>

Schema-driven forms for every config section — Watcher, Freshness,
Retention, Hooks, Proxy, Compression, Intelligence, Advisor, Cache
tracking, Secrets scrubbing, MCP, Profiles, Org share, OTel — with
honest reload semantics per section: pricing and profile changes
apply hot, MCP applies to the next AI session, restart-gated
sections raise a persistent restart-pending banner that names the
exact command and clears only when the daemon actually restarts.
Alongside the forms: a **Connected tools** panel (per-tool status
matrix, consent-gated setup wizard, Launch button), a **Health**
panel (the `observer doctor` checks + recent failures), the
**Backfill** panel (every mode click-to-run with streamed output +
full rescan), a **Storage** panel (per-table DB size breakdown with
index/FTS bytes folded in, vacuum + online backup as click-to-run
jobs, documented manual restore — CLI twin `observer db
stats|vacuum|backup`), and a config-file card with one-click `.bak`
restore.
182 baked-in default models; pricing "Override" prompts auto-fill
from the default.

### Live — what's running right now

<p align="center">
  <img src="docs/assets/screenshots/12-live.png" alt="Live tab — sessions active in the last 15 minutes" width="900">
</p>

Every session with activity in the last 15 minutes, refreshing on a
5-second tick: lifetime cost, tokens, turns, and a streaming action
feed per session. The fastest way to confirm the proxy is capturing
while you work.

### Session detail — drill into one session

<p align="center">
  <img src="docs/assets/screenshots/11-session-detail.png" alt="Session detail slide-over panel — cost, token buckets, cost predictor and limit gauge" width="900">
</p>

Click any session row → slide-over with an action-type breakdown
donut, a token-bucket bar (net input / cache R / cache W / output),
and the models used. It also carries the **next-message cost
predictor** (a low / typical / high band over the session's likely
turn fan-out) and, for proxied subscription sessions, the **5-hour /
weekly limit gauge** read from the provider's own rate-limit headers.

<p align="center">
  <img src="docs/assets/screenshots/11-session-detail-2.png" alt="Session detail — per-message timeline of every upstream API turn" width="900">
</p>

Scroll down for the full **per-message timeline** — every upstream
API turn with its model, token buckets, per-turn cost, and the tool
calls nested inside it, each row expandable. The same panel surfaces
from Actions when you click a session pill.

### Remote & mobile access

The dashboard reads fine from a phone (the layout adapts to small
screens), and you can drive a node from another device over your
**tailnet** — nothing is exposed to the public internet. Pair a second
device from the **Remote** tab, then view sessions, cost, and the live
feed from anywhere on your tailnet. Bind the dashboard to a tailnet
interface with `[dashboard].addr` (or the `OBSERVER_DASHBOARD_ADDR`
env override) instead of the default loopback.

The same tailnet pairing is also what lets a remote device join a live
terminal, not just view charts — the launch dock, joinable sessions,
Session Cockpit, and the execute-is-gated posture (**default off**,
`[remote].allow_terminal`) are covered in
[Terminals](#terminals--launch-join-and-track-your-ai-clis) below.
Full remote setup: [`docs/remote-access.md`](docs/remote-access.md).

---

## Terminals — launch, join, and track your AI CLIs

The dashboard doesn't just watch your AI tools after the fact — it
can launch them, and any paired device can join a session that's
already running.

- **Launch from the dashboard or any shell.** All 27 CLI launchers
  (claude, codex, opencode, cursor, copilot-cli, kilo, cline-cli,
  hermes, gemini, openclaw, pi, antigravity, qwen, kiro, grok, kimi,
  devin, qoder, goose, droid, open-interpreter, command-code, muse,
  prime-agent, zcode, vibe, freebuff) launch
  as real PTY terminals from the
  dashboard ("Launch here") or via `observer <verb>`; Linux/macOS +
  native Windows (ConPTY, Win10 1809+). Guided one-click install when
  the tool binary isn't found.
- **Attach-by-default (v1.25.0).** `observer <verb>` runs
  daemon-owned so the dashboard can join; the native terminal stays
  fully interactive as seat #1. `--no-attach` for a bare run;
  scripted/piped invocations never attach. The attach client also
  forwards your shell's values for each tool's registry-documented
  credential env keys (claude-code, codex, hermes, pi, copilot-cli,
  gemini-cli, grok, and others with registry-documented key envs) via
  `[terminal.attach].forward_auth_env` (default `true`), so a
  shell-exported API key works exactly as it would bare. Honest
  caveat: tools without a registry-documented credential env, and
  dashboard-launched terminals, still see only the daemon's env
  (config-file/OAuth auth is unaffected; export where `observer start`
  runs, or use `--no-attach`).
- **Jump in from anywhere.** Every live daemon-owned terminal is
  joinable from any dashboard tab — local or paired remote — as an
  extra seat. Many read-only viewers (cap 8), exactly one writer;
  control moves seamlessly native → local dashboard → remote
  dashboard by taking the writer lease (type in the native terminal
  to reclaim it; remote takeover is available only to
  fully-authenticated paired tailnet devices, and the seat that loses
  the lease stays read-only with take-back available). Fresh runs
  link to their observer session in roughly 10–30 seconds.
- **Per-terminal Files & Git panels.** Read-only file tree + viewer
  rooted at the terminal's project root; a Git panel with
  branch/upstream/ahead-behind/status plus a 100-commit log; copy
  path / paste into the terminal. Read-only v1 — no edits and no git
  mutations from the panel.
- **Session Cockpit.** A draggable live panel on any AI-tool
  terminal: tokens/sec (measured vs estimated badge), cost with
  AI/tool split, the next-message cost band, context fill vs the
  model's budget, the 5h/7d rate-limit gauge (proxy-routed sessions),
  prompt-cache expiry countdowns, CPU/mem/disk plus the spawned
  process tree, and the last five turns deep-linked to session
  detail.
- **Workspace grid.** Up to 9 live terminal tiles at once, drag to
  resize, layouts persist server-side; read-only when viewed from a
  remote device.
- **Restarts & continuity.** On a daemon restart, 26 of the 27
  launchers auto-resume the same transcript (native resume) —
  openclaw is the sole holdout, because its resume is picker-only.
  Fork any tool's session forward with
  `observer <verb> --continue-from <id>` — a new session id seeded
  with a distilled handover as the first prompt.
- **Remote posture.** Remote access is opt-in, tailnet-only
  (Tailscale serve), off by default; viewing and execute are separate
  tiers, and execute is default-off. See
  [Remote & mobile access](#remote--mobile-access) above, plus
  [`docs/remote-access.md`](docs/remote-access.md) and
  [`docs/session-handoff.md`](docs/session-handoff.md).

---

## MCP server — 25 cross-tool intelligence calls

**Opt-in.** The MCP server is not active until you run
`observer init` (or `observer init --claude-code` / `--cursor` /
`--codex`). That command writes entries pointing at the observer
binary into each AI tool's own MCP config file
(`~/.claude.json`, `~/.cursor/mcp.json`, `~/.codex/config.toml`).
The MCP server then runs as a **stdio subprocess spawned by your AI
tool** — its lifecycle matches the AI tool's, and it never opens a
network port. `observer start` alone does NOT register or launch
the MCP server; it can be skipped entirely via
`observer init --skip-mcp` if you want hooks-only capture.

Once registered, every connected AI tool can query the observer
over MCP/stdio: **21 tools are always registered**, and **4 more
register conditionally** (only when the capability they depend on —
the proxy stash, or the codeintel index — is actually configured):

| MCP tool | What it answers |
|---|---|
| `check_file_freshness` | Has this file changed since I last read it? |
| `check_command_freshness` | Did this exact command already run? With what result? |
| `get_file_history` | Every read/edit of this file across every tool + session (with codeintel enrichment when available). |
| `get_session_summary` | What did session X actually do? AI-generated 2–4 sentence summaries. |
| `get_session_recovery_context` | For resuming an interrupted session. |
| `get_project_patterns` | Derived behaviours: hot files, co-changes, edit→test pairs. |
| `get_last_test_result` | Without re-running. |
| `get_failure_context` | Error correlation + retry detection. |
| `get_action_details` | The raw row, scrubbed of secrets. |
| `get_cost_summary` | Per-window spend rollup. |
| `get_redundancy_report` | What would Discovery flag for this project? |
| `search_symbols` | Fuzzy symbol search across the project's codeintel index (Tier-C). |
| `list_actions_around` | Chronological ±N actions around an `action_id`. |
| `search_past_outputs` | Full-text search of past tool-call outputs (FTS5 over excerpts). |
| `get_output_composition` | Code vs. explanation split of a session's output, by bytes, with the code:explanation ratio and languages used. |
| `get_suggestions` | Top dollar/time-quantified cost & quality suggestions from the local advisor. |
| `cache_status` | Live prompt-cache health: which caches are warm, expiring, or cold, with value-at-risk. |
| `get_model_recommendation` | Evidence-backed model suggestion per turn-kind, from the local Model Value Report. |
| `get_routing_status` | Model-routing layer state: phase, available policy templates, tier-table size, decision-log counters. |
| `continue_session` | A distilled, scrubbed handover of a session from another AI tool, so you can continue its work here. |
| `get_session_message` | One full, un-excerpted message from a session's transcript — pulls the complete body a handover excerpt truncated. |
| `get_file` _(conditional)_ | The file's current bytes (or at a given commit), with path-safety gate + audit. |
| `get_symbols` _(conditional)_ | Resolve symbol name + range to file path + body (codeintel-backed). |
| `get_relations` _(conditional)_ | Codeintel BFS — who calls / is called by this symbol. |
| `retrieve_stashed` _(conditional)_ | Pulls original bytes of a tool_result the proxy stashed (only registered when CCR is enabled). |

**Operator note for Claude Code via observer's proxy.** When you set
`ANTHROPIC_BASE_URL=http://localhost:8820`, Claude Code's SDK
disables `ToolSearch:optimistic` deferred MCP loading — observer's
tool schemas (plus any Google MCPs you've registered) end up
eagerly inlined into every request prefix, ~+21K tokens/turn. **Set
`ENABLE_TOOL_SEARCH=true` in the same shell** to recover lazy
loading; observer's proxy forwards `tool_reference` blocks
byte-identically, satisfying the SDK's documented safety condition
for the override. See
[superbased.app/docs/connect/claude-code](https://superbased.app/docs/connect/claude-code#set-enable-tool-search-when-routing-with-mcp)
for the full picture.

Knowledge captured from one tool benefits all the others working on
the same project — data is organized by git root, not by tool. A
read by Claude Code becomes a freshness signal for Codex; a Cursor
compaction is visible from Cline.

---

## Sign in and Cloud Intelligence (beta, experimental)

Optional, opt-in, and **beta (experimental)**. Nothing is sent
anywhere unless you run `observer cloud login` and enrol a session
yourself - the `observer cloud` CLI is the only outbound trigger, and
it touches the network only while one of its commands is running.
**Signed-in Free** gives up to 20 session enrichments per day (100 per
month) on GPT-5.6 Luna (xhigh reasoning). **Plus (beta)** runs
enrichments on GPT-5.6 Sol (xhigh reasoning), capped at 120 per month,
USD 15/month with a 7-day trial. An enrichment returns a narrative
summary of the session: what was done, which plans were implemented,
which issues or bugs were found, what failed, and what to do next.
Behaviour, allowances, and pricing may change. The local daemon -
proxy, watcher, dashboard, MCP - needs no account and is unaffected by
any of it. Full detail: [docs/cloud-intelligence.md](docs/cloud-intelligence.md).

---

## Integrations — the stable contract to build against

The MCP server is the **supported integration surface** for
third-party tooling — the one place observer publishes a stability
promise you can build against: three published tiers
(**stable** / **conditional** / **experimental**), a tier for every
one of the 25 tools, and five server-level invariants (a single
pretty-JSON `text` block per call, in-band `isError`, silent limit
clamping, alphabetical `tools/list`, and the pinned server name
`observer`).

**The contract:** [`docs/mcp-contract.md`](docs/mcp-contract.md) —
what each tier promises under semver, and what is explicitly *out*
of contract (the dashboard HTTP API and the SQLite schema are both
internal and unversioned; integrate over MCP instead).

**Machine-readable, diffable in CI:**

```bash
observer contract --json   # {"contract_version":1,"mcp":{…},"adapters":[…]}
```

The tiers come from one Go table shared by the doc and the emitter,
and conformance tests fail the build if a stable tool is renamed or
if a newly registered tool ships unlisted — so the contract can't
silently drift from the binary.

### Wiring the MCP server by hand

`observer init --claude-code` (or `--cursor` / `--codex`, or bare
`observer init`) writes the entry for you. For a client observer
doesn't know about, register it yourself — it's a plain stdio
subprocess with no network port:

```json
{
  "mcpServers": {
    "observer": {
      "command": "/absolute/path/to/observer",
      "args": ["serve"]
    }
  }
}
```

Then call it like any MCP server:

```jsonc
// tools/call
{ "name": "get_cost_summary", "arguments": { "group_by": "model", "days": 7 } }
```

The server reads `~/.observer/config.toml` unless you pass
`--config <path>`. Its lifecycle matches the AI tool that spawned it.

### Community integrations

None listed yet — this list is PR-curated and starts empty rather
than seeded with aspirational entries.

To add yours, open a PR appending one row to the table below.
Criteria:

- **Verifiable artifact.** A public repo, package, or extension
  anyone can install and run. Not a blog post, not a screenshot, not
  a waitlist.
- **Actually uses the contract.** It talks to the MCP server (or
  consumes `observer contract --json`). An integration built on the
  dashboard HTTP API or by reading `observer.db` directly can't be
  listed — those surfaces are internal and will break you.
- **Honesty rules apply**, the same ones this repo holds itself to:
  claims in your description must be things a reader can check.
  No unmeasured savings percentages, no capability the artifact
  doesn't have today, and "planned" is not "does".
- **One row, plain description.** Name, link, one sentence on what
  it does. Maintenance status is welcome; marketing copy isn't.

| Integration | What it does | Maintainer |
|---|---|---|
| _(none yet — [open a PR](CONTRIBUTING.md))_ | | |

---

## API proxy — accurate tokens, compression, stash

The proxy is the home of three features that only exist when your AI
client routes through it. None of them run on the watcher / `observer
start` ingestion path — compression and stash live in the request
path because that's the only place where bytes can be rewritten
before they reach the upstream provider.

When you point your AI tool at `http://localhost:8820`, the proxy:

1. **Forwards your request to your chosen upstream** (Anthropic or
   OpenAI). The destination is the same provider URL your AI client
   would have called directly; no data leaves your machine that
   wasn't already going to that provider. Your API key is yours —
   the proxy reads it from the inflight headers, never stores it.
2. **Records the exact token counts** the provider returned (cache
   5m vs 1h split, long-context tier triggers, reasoning tokens)
   into the `api_turns` table — more accurate than parsing the
   JSONL the AI tool wrote.
3. **Compresses the conversation** before forwarding
   (importance-scored, prefix-stable for cache alignment) — the
   biggest lever for keeping long sessions inside rate-limit
   windows. **Opt-in**: flip `[compression.conversation].enabled =
   true` (or the Settings → Compression toggle); once enabled, tuned
   per-tool profiles apply automatically (see below), with the safe
   per-type set (`compress_types = ["json","logs","code"]`) on
   Anthropic traffic. Compressed events land in the
   `compression_events` table and surface on the Compression
   dashboard tab. Empirical on Claude Code lumen rig (n=8, V7-22):
   **−6.9% mean cost vs no-proxy**, CV 7.6%, zero tail outliers.
4. **Stashes large tool outputs** the compressor hides, so the
   originals stay retrievable via the `retrieve_stashed` MCP tool
   (only registered when stash is configured). **Off by default —
   stash markers break Anthropic's prefix cache** (V7-25 n=1
   measurement: +25% cost, `cache_creation_input_tokens` doubled).
   Operators who want stash on a workload should A/B before
   committing.

Three compression layers, each independently toggleable:

- **Shell output filters** — RTK-style truncation of large `bash` /
  `git` / `go test` / `docker` / `kubectl` / `cargo` / `pytest`
  outputs inline before they hit the LLM context. Runs on hook /
  `observer run` paths; does not require the proxy.
- **Tool output indexing** — every tool call's output indexed into
  FTS5; large outputs trimmed to a 2KB excerpt cap so the index
  stays compact and `search_past_outputs` stays fast. Runs on the
  watcher path; does not require the proxy.
- **Conversation compression** — proxy rewrites large `tool_result`
  blocks before forwarding upstream. **Proxy-only** — there is no
  non-proxy path for this layer, and the stash that backs
  `retrieve_stashed` is wired here too.

**Trade-off if you skip the proxy:** you still get full hook + JSONL
ingestion, the dashboard, MCP (if registered), and shell+indexing
compression. You lose proxy-grade token accuracy, conversation
compression, and the stash. For rate-limited plans (Claude Teams 5h/7d
windows), conversation compression is usually the difference between
"finishes the task" and "hits the limit."

### Choosing a compression mode (Anthropic vs Codex)

`mode` is a profile parameter — each shipped profile (next section)
already pins the right one, so most users never set it by hand; the
matrix below is the why. It behaves differently per provider. Per-type
`tool_result` compression runs in every mode; `mode` only changes how messages
are dropped and whether an Anthropic `cache_control` marker is injected.

| `mode` | What it does | Claude Code (Anthropic) | Codex / OpenAI |
|---|---|---|---|
| `token` | Per-type compress, then drop lowest-scored messages to hit `target_ratio`. | ✅ Works. | ✅ Clearest choice for Codex/OpenAI. |
| `cache` | Restrict drops to the tail half + inject a `cache_control` marker at the prefix boundary. | ✅ Anthropic-specific. | ⚠️ No effect beyond `token`. |
| `cache_aware` *(default)* | Skip drops, narrow compression to `tool_result` blocks, no marker injection; keep history byte-stable across turns so Anthropic's prefix cache keeps hitting (`cache_creation` falls on later turns). | ✅ **Recommended for Anthropic Pro/Max** — and the shipped default. | ⚠️ No effect beyond `token`, so the default is harmless for Codex. |

The shipped default is `cache_aware` (`token` is just the internal fallback when
`mode` is empty). The `cache`/`cache_aware` strategies exist for **Anthropic's
content-hash prefix cache** (`cache_control` is an Anthropic Messages API
concept). OpenAI/Codex prompt caching is **automatic and server-side** — there
is nothing to mark or tune, so the proxy's OpenAI path is mode-agnostic (the
default `cache_aware` simply behaves like `token` there).

### Profiles — the right parameters per tool, automatically

Compression parameters ship as **profiles**: named parameter sets
resolved per traffic class at the proxy boundary (formerly "recipes",
which had to be hand-picked per daemon — and applied to *all* traffic,
mis-tuning whichever tool the recipe wasn't written for). Enable
compression once and the tuned parameters apply per tool
simultaneously:

| Profile | Auto-assigned to | Headline params | Measured |
|---|---|---|---|
| **`claude-code`** | Anthropic-path traffic (`claude-sonnet-4-6`, `claude-opus-4-8`, any `claude-*` via Claude Code) | `cache_aware`, ratio 0.85, json+logs+code+tools, stash off (V7-25: stash breaks Anthropic's prefix cache) | **−6.9% mean cost vs OFF** (n=8 lumen refactor, CV 7.6%, zero tail outliers; requires `ENABLE_TOOL_SEARCH=true` when MCP servers are registered). The A2 run (2026-06-11, n=8 Opus 4.8) added the tools-defs trim: **−12.5%** vs the pre-A2 set with zero `tools_changed` cache events. |
| **`codex-safe`** | OpenAI-path traffic (plain GPT under the codex CLI: `gpt-5.4`, `gpt-5.5`, any non-`-codex`) | `token` mode, ratio 0.95, logs-only (JSON sentinel substitution corrupts codex tool data) | −22% to −56% on gpt-5.4-mini (V7-21, n=10); **inconclusive** on an `apply_patch`-only workload (V7-26 — no logs-shaped output, so the proxy was a no-op; A/B your own traffic shape) |
| **`codex-variant`** | manual — `observer profile assign openai codex-variant` | ratio 0.99, preserve 50, **no per-type compression** (V7-2: `-codex` models re-derive when tool_results change) | **−10%** ($0.270 vs $0.300, n=10, gpt-5.3-codex) |
| **`default`** | escape hatch | master-config `[compression.conversation]` params, unchanged | — |

"variant" in `codex-variant` means the `-codex` *model variant*
(`gpt-5.3-codex`, anything `*-codex*`), not a variant of the codex
CLI — both codex profiles are for the codex CLI.

Working with profiles:

- **Inspect**: `observer profile list` (assignments + sources),
  `observer profile show codex-safe` (the resolved TOML).
- **Reassign** per traffic class or per tool: `observer profile
  assign openai codex-variant`, `observer profile assign tool:cline
  codex-safe` — or Settings → Profiles in the dashboard.
- **Custom profiles**: `observer profile create mine --from
  claude-code`, then `observer profile set mine
  compression.conversation.target_ratio 0.9` — or the Settings →
  Profiles editor.
- **Per-project overrides**: a repo-level `.observer/config.toml`
  (`[profiles]` + `[compression]` keys only) picks different profiles
  or turns compression OFF for that repo's traffic — never on
  (untrusted-repo guard).
- **Hot for new sessions**: profile edits and assignment changes
  apply without a daemon restart. The master `enabled` switch itself
  is restart-gated — the dashboard banner says so honestly.
- `observer start --recipe <name>` survives as a deprecated alias
  that pins one profile for all traffic.

**Measured effects vary by traffic shape and workload** — from the
double-digit savings above to a since-fixed configuration that once
regressed cost on a different binary. Historic marketing claims of a
flat savings percentage are retracted; compression ships opt-in and
default-off precisely because the right call depends on your own
traffic — A/B it before relying on any number here. Full knob
reference (stash, rolling-summary's per-provider model
split, compaction):
[`docs/compression-modes.md`](docs/compression-modes.md). Then route
your client through the proxy — the one-click button path in the
[First-run walkthrough](#first-run-walkthrough) — and restart it.

---

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│ Claude Code  │     │    Cursor    │     │    Codex     │    ... 40 adapters total
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │ JSONL              │ hook events        │ rollout files
       ▼                    ▼                    ▼
┌────────────────────────────────────────────────────────┐
│              fsnotify Watcher + Adapters               │
│      (one parser per platform, normalized output)      │
└───────────────────────────┬────────────────────────────┘
                            │ ToolEvent / Action / Session
                            ▼
┌────────────────────────────────────────────────────────┐
│   SQLite (WAL, pure-Go via modernc.org/sqlite)         │
│   actions · sessions · projects · file_state ·         │
│   api_turns · token_usage · failure_context ·          │
│   compaction_events · action_excerpts (FTS5)           │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Dashboard   │     │  MCP Server  │     │  API Proxy   │
│ HTTP+/api/*  │     │  stdio · 25  │     │ Anthropic +  │
│   21 tabs    │     │    tools     │     │    OpenAI    │
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                                                 ▼
                                           upstream API
                                           (traffic passes
                                           through verbatim,
                                           with token tracking
                                           + optional compression)
```

Adapters parse each platform's session format into a unified
`Action` row. The cost engine reads `api_turns` (proxy, accurate)
and `token_usage` (JSONL adapters, approximate) and deduplicates
per-turn via the upstream `request_id` ↔ `source_event_id` match —
and, for Codex, skips replayed fork/subagent turns and tracks
parent/child session lineage so a forked session never double-counts
its parent's tokens. The MCP server exposes the same database. The
dashboard pulls JSON from the same `/api/*` endpoints the MCP tools
use.

---

## Security & control layer (guard)

The guard evaluates every captured agent action against a table-driven policy
— built-in rules (destructive commands, project boundaries, secrets egress,
MCP pinning, taint/dataflow, budgets) plus your own TOML rules — records each
verdict in a hash-chained tamper-evident audit table, and blocks
pre-execution on the channels that support it (Claude Code and Cursor hooks,
the proxy egress path, plus native permission rules it compiles into each
client's own config). It ships **observe-only by default**: nothing blocks
until you flip enforce, and `observer guard simulate --since 168h` replays
your real history against current policy first so you know exactly what
enforce would have done.

Guard policy is entirely local: built-in rules plus your own TOML rules, a
hash-chained audit table, and pre-execution blocking on the channels that
support it. Audit rows export as JSONL/CEF for SIEM ingestion, and
`observer guard report` renders a compliance evidence pack mapped to
SOC 2 / NIST 800-53. The no-network invariant holds: nothing leaves the
machine unless you opt into the OTel feed or the cloud alerting tier
individually.

Optional **process observability** (`[observer.process]`, opt-in, off by
default) attaches the OS-level process tree — Linux eBPF or Windows ETW —
beneath each captured session, for the runtime side effects hooks alone
can't see (a spawned binary, an unexpected child process).

**Alerting.** Guard verdicts and budget/obs-alert crossings can push out
through desktop toast notifications (`[guard.alerts] desktop = true`) and
outbound webhooks — generic, Slack, Discord, or PagerDuty
(`[[guard.cloud.webhooks]]` for guard events) — each behind its own
opt-in, routed through one egress worker with an endpoint allowlist
and a payload cap. Nothing fires until you configure it.

Every routine guard workflow also runs from the dashboard's Security page
(mode control with simulate evidence, enforce-readiness replay, approvals,
lint-gated policy editor, budget guardrails, evidence downloads) — see the
[Dashboard tour](#dashboard-tour) above.

- **[Operator guide](https://superbased.app/docs/guides/security-guard)** —
  concepts, modes, the observe→enforce path, and the honest "what guard
  does NOT do" list.
- **Rule catalog, policy authoring, enforce runbook, compliance mapping** —
  every built-in rule ID, the TOML matcher vocabulary with a worked
  7-recipe cookbook, the observe→enforce rollout runbook, and the SOC 2
  CC-series + NIST 800-53 AU-2/AU-3/AU-9/AC-6 evidence-pack mapping ship
  as `docs/guard-rules.md`, `docs/guard-policy-authoring.md`,
  `docs/guard-enforce-runbook.md`, and `docs/guard-compliance.md` for
  anyone building from source.

---

## CLI reference

| Command | Purpose |
|---|---|
| `observer usage [--since 30d] [--json]` | Zero-config one-shot: scans every detected tool's own session files into a throwaway temp DB, prints a tool × model cost table, deletes the DB. No daemon, no config read by default, no network. Bare `observer` runs this too, on a machine with no local SuperBased state (`OBSERVER_ONESHOT=off` to disable). See [`docs/one-shot-usage-report.md`](docs/one-shot-usage-report.md). |
| `observer statusline` | One-line cost status for your terminal prompt (or a compatible editor status bar): wordmarked, fail-open, zero network calls beyond your own local daemon. Opt-in registration via `observer init --statusline`. See [`docs/observer-statusline.md`](docs/observer-statusline.md). |
| `observer init [--all]` | Register hooks + MCP server + durable proxy routes with every detected AI tool (each side defaults on; `--skip-hooks` / `--skip-mcp` / `--skip-proxy-route` opt out). Zero flags on a terminal → an interactive checklist: preview + consent per write, MCP never pre-selected. Any flag keeps batch mode. |
| `observer uninstall [--all] [--purge]` | Reverse of `init`. Refuses to touch drifted configs unless `--force`. `--purge` also deletes `~/.observer/`. |
| `observer scan [--force]` | One-time backfill — parse all known session files into the DB. `--force` re-walks from offset 0. |
| `observer watch` | Live fsnotify-based watcher daemon. |
| `observer start` | Proxy + watcher + dashboard in one foreground process. Auto-opens the dashboard on interactive launches (`--no-open` to skip). |
| `observer claude [-- args…]` | Launch Claude Code routed through the proxy for that session only — no config writes; re-exports a fresh Pro/Max OAuth token so the SDK can't bypass the proxy. `--verify` = pre-flight checks only. See [superbased.app/docs/reference/cli](https://superbased.app/docs/reference/cli#routed-launchers). |
| `observer codex [-- args…]` | Launch Codex routed through the proxy for that session only (argv `openai_base_url` injection, no config writes). |
| `observer profile list\|show\|assign\|create\|delete\|set` | Compression profiles: inspect, reassign per traffic class / per tool, create + edit custom ones. Hot for new sessions. |
| `observer config set <key> <value> [--project <root>]` | Dotted-key config setter through the shared validated write path; `--project` writes the repo-level override file. |
| `observer proxy start` | Run only the API reverse proxy. |
| `observer dashboard [--port N]` | Embedded dashboard + `/api/*` JSON on http://localhost:N (default 8081). |
| `observer cost [--days N] [--group-by …]` | Token + USD rollup from the CLI, against the DB you've been capturing into with `observer scan` / `observer start` (includes proxy-accurate turns) — the persistent sibling of `observer usage`'s throwaway one-shot. |
| `observer discover` | Stale re-reads + redundant-commands report. |
| `observer patterns` | Derive hot files, co-changes, common commands, edit→test pairs. |
| `observer learn` | Derive correction rules from failure→recovery pairs. |
| `observer suggest` | Compose patterns + corrections into CLAUDE.md / AGENTS.md / .cursorrules. |
| `observer summarize` | Generate AI session summaries (uses Anthropic Haiku). |
| `observer score` | Session quality scoring (error rate, redundancy, onboarding cost, retry cost). |
| `observer status` | Row counts + recent activity. |
| `observer tail` | Live-stream captured actions. |
| `observer advise` | Prescriptive cost/quality suggestions (the Suggestions tab, in the CLI). |
| `observer cache-health` | Prompt-cache engine health: grading gate, read:write consistency, cause concentration. |
| `observer doctor` | Health checks: DB integrity, hook checksums, MCP drift, pid bridge, proxy routing gaps. |
| `observer contract [--json]` | The published stability contract: every MCP tool with its tier (stable / conditional / experimental) plus each adapter's public capability row. `--json` emits the `contract_version`-stamped artifact an integrator pins. Prose: [`docs/mcp-contract.md`](docs/mcp-contract.md). |
| `observer adapters [--json]` | The full adapter capability matrix (proxy / surface / hook / MCP / native / token / handoff / attach / resume), generated from the capability registry. |
| `observer prune` | Run retention now. |
| `observer db stats\|vacuum\|backup` | Storage manager: per-table size breakdown (index + FTS5 shadow bytes folded in), reclaim free pages with bytes-freed report, online snapshot via `VACUUM INTO` (safe while the daemon runs; refuses overwrite). |
| `observer db import <path> [--dry-run]` | Merge another `observer.db` (a stranded install from another OS / home dir) into this node's. Idempotent single-transaction merge; `--dry-run` rolls the same transaction back for exact counts. Migrates the source first — point it at a copy. |
| `observer metrics [--port N]` | Prometheus `/metrics` endpoint. |
| `observer export {json\|csv\|xlsx}` | Dump tables for external analysis. |
| `observer backfill --<mode>` | Re-populate columns added by later migrations. `--all` runs every mode. |
| `observer run <command>` | Run a command with its stdout streamed through the shell filter. |
| `observer hook <tool> <event>` | Hook entrypoint (called by the AI tools after `init`). |
| `observer serve` | MCP stdio server (spawned by AI tools). |
| `observer completion <shell>` | Shell completions (bash / zsh / fish / powershell), e.g. `observer completion zsh > "${fpath[1]}/_observer"`. |

`observer <command> --help` for full flag listings. Bare `observer`
prints a status welcome (daemon up? dashboard URL? next step) instead
of the help wall; `observer --help` keeps the complete list.

---

## Configuration

Default location: `~/.observer/config.toml`. Override with
`--config`. A minimal config:

```toml
[observer]
db_path = "~/.observer/observer.db"
log_level = "info"

[proxy]
enabled = true
port = 8820
anthropic_upstream = "https://api.anthropic.com"
openai_upstream = "https://api.openai.com"

[intelligence]
monthly_budget_usd = 100   # surfaces on Analysis tab; 0 hides

[compression.shell]
enabled = true
exclude_commands = ["curl", "playwright"]

[compression.indexing]
enabled = true
max_excerpt_bytes = 2048

[compression.conversation]
enabled = false            # opt-in; modifies request bodies in flight
mode = "cache_aware"       # "token" | "cache" | "cache_aware" — see "Choosing a compression mode" below
target_ratio = 0.85
preserve_last_n = 5
compress_types = ["json", "logs", "code"]

# Per-model pricing overrides. Only specify what differs from baked-in.
[intelligence.pricing.models."claude-sonnet-4-6"]
input = 3.0
output = 15.0
cache_read = 0.30
cache_creation = 3.75
cache_creation_1h = 6.00

# Long-context tier example (Anthropic Sonnet 1M, gpt-5 >272K,
# Gemini 2.5 Pro >200K). When prompt exceeds the threshold, every
# rate is replaced with its long_context_* counterpart for that turn.
[intelligence.pricing.models."claude-sonnet-4-5"]
input = 3.0
output = 15.0
cache_read = 0.30
cache_creation = 3.75
cache_creation_1h = 6.00
long_context_threshold = 200000
long_context_input = 6.0
long_context_output = 22.50
long_context_cache_read = 0.60
long_context_cache_creation = 7.50
long_context_cache_creation_1h = 12.00
```

Every key has a TOML environment-variable override:
`OBSERVER_<SECTION>_<KEY>` (uppercased, underscores). Nested
sections join with extra underscores:
`OBSERVER_COMPRESSION_CONVERSATION_ENABLED=true`.

The Settings tab in the dashboard provides a fully-editable visual
editor for everything in `config.toml` — pricing and profile changes
apply hot, MCP settings apply to the next AI session, and
restart-gated sections raise a persistent banner that names the
exact restart command and clears itself once the daemon actually
restarts (the daemon never restarts itself).

---

## Post-upgrade hygiene + recovery

After upgrading the binary, or whenever the Actions tab looks
gappy (watcher fell behind, daemon restart with stale state,
fsnotify event drops):

```bash
observer backfill --all
```

Re-walks every JSONL the adapters know about from offset 0, then
runs the surgical column-update backfills (cache-tier, message-id,
etc.) on top. The `(source_file, source_event_id)` UNIQUE index
keeps the pass idempotent.

The dashboard surfaces a top-of-page banner whenever the watcher's
parse cursor for any session file is more than 10 KB behind the
on-disk size, so silent data loss has a visible signal.
`observer backfill --help` lists every supported flag.

---

## Build from source

```bash
git clone https://github.com/superbasedapp/observer
cd observer
make build        # builds bin/observer + bin/antigravity-bridge.exe
make test         # full test suite (race detector enabled)
make all          # fmt + vet + lint + test + build
```

Requirements: **Go 1.22+**. No CGO. SQLite via `modernc.org/sqlite`
(pure Go). golangci-lint optional for `make lint`. Dashboard
source under `web/` (React + TypeScript + Vite + Tailwind); the
compiled bundle is committed to
`internal/intelligence/dashboard/webapp/dist/` so a contributor
who only touches Go can `make build` without Node.

If you edit `web/src/`:

```bash
# Hot-reload dev loop (Vite serves :5173, proxies /api/* to observer)
./bin/observer dashboard --addr 127.0.0.1:8081 &
cd web && npm install && npm run dev

# When done, rebuild the embedded bundle and commit
make web-build
git add internal/intelligence/dashboard/webapp/dist web/dist
```

`make web-build` regenerates both `web/dist` and the embedded copy.
Requires **Node 22 LTS**.

### CI gates

Every PR + push to `main` runs `.github/workflows/ci.yml`:

- **`frontend`** — `npm ci` → typecheck → build → dist-consistency
  check (asserts the committed embedded bundle matches a fresh build).
- **`go`** — `go vet` → `go test -race` → cross-compile.

Tag pushes (`v*`) trigger `.github/workflows/npm-release.yml`:
builds the frontend once, cross-compiles five platform binaries,
ships them to npm, and creates a GitHub Release.

---

## Contributing

PRs welcome. Table-driven tests in every package; >80% coverage on
core packages (cost, freshness, adapters, store). Run `make test`
before submitting; `make all` locally to catch fmt/vet/lint issues.
Conventional commits (`feat:` / `fix:` / `chore:` / `docs:` /
`test:` / `refactor:` / `perf:`).

For larger changes, open an issue first to align on scope. Adapter
contributions (a new AI coding tool to support) are particularly
welcome — see existing adapters in `internal/adapter/` for the
pattern.

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

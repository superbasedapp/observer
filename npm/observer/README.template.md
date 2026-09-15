# @superbased/observer

[![npm](https://img.shields.io/npm/v/@superbased/observer.svg)](https://www.npmjs.com/package/@superbased/observer)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Platforms: Linux • macOS • Windows](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue.svg)](https://github.com/superbasedapp/observer)
[![Website](https://img.shields.io/badge/homepage-superbased.app-2EC4B6.svg)](https://superbased.app/)

**Homepage:** [https://superbased.app/](https://superbased.app/)

**Claude Code cost tracking. Cursor token usage. Codex spend.
AI coding agent observability — one local tool, proxy-accurate.**
SuperBased captures, normalizes, and analyzes every AI
coding tool call across **40 adapters** — Claude Code, Codex, Cursor,
Cline + Cline CLI, GitHub Copilot (VS Code) + Copilot CLI, Gemini CLI,
OpenCode, Google Antigravity, Cowork, Nous Research's Hermes Agent,
Kilo Code (legacy IDE extension + CLI), Aider, Goose, Devin, OpenClaw,
Pi, Factory Droid, Open Interpreter, Command Code, and more — in one
local single-binary tool. An optional API proxy
reconciles the *exact* tokens your provider billed (net input, cache
5m/1h splits, reasoning tokens, long-context surcharges) instead of a
JSONL-derived estimate. No telemetry and no cloud by default - nothing
leaves your machine unless you explicitly opt in to the sign-in beta.

**One local binary.** SuperBased captures, normalizes, and analyzes
every AI coding tool call on your machine: proxy-accurate cost,
compression, cache tracking, and session handoff.

<p align="center">
  <img src="https://github.com/superbasedapp/observer/raw/main/docs/assets/infographics/one-local-path.png" alt="One local path for AI coding activity" width="780">
</p>

# Table of contents

- [Install](#install)
- [Five-minute quickstart](#five-minute-quickstart)
- [Zero-setup cost report: `observer usage`](#zero-setup-cost-report-observer-usage)
- [One local binary](#one-local-binary)
- [Per-AI-client setup](#per-ai-client-setup)
- [Architecture in detail](#architecture-in-detail)
- [Dashboard tour](#dashboard-tour)
- [Terminals — launch, join, and track your AI CLIs](#terminals--launch-join-and-track-your-ai-clis)
- [MCP tools reference](#mcp-tools-reference)
- [Compression mechanisms](#compression-mechanisms)
- [Cost and token math](#cost-and-token-math)
- [Terminology and glossary](#terminology-and-glossary)
- [CLI reference](#cli-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Security and privacy](#security-and-privacy)
- [Source, contributing, license](#source-contributing-license)


## Install

**Use a global install** (`-g`) so the `observer` command is available
on your `$PATH` from any directory:

```bash
npm install -g @superbased/observer
observer --version
```

If you install locally (without `-g`) the binary lives at
`./node_modules/.bin/observer` and isn't on your `$PATH`. Run it
with `npx`:

```bash
npm install @superbased/observer    # local install
npx observer --version              # ↑ what to use everywhere `observer` is shown below
```

A note for shared / CI machines where `npm install -g` may need
`sudo`: see [Troubleshooting → EACCES](#npm-install--g-fails-with-eacces-permission-denied)
for user-writable-prefix and version-manager fixes.

> **Python users:** `pip install superbased-observer` ships the
> same binary; version numbers are kept in lock-step. See
> [the PyPI page](https://pypi.org/project/superbased-observer/).
> Don't install both globally — whichever directory comes first on
> `$PATH` wins, which gets confusing if their versions drift.

Pre-built binaries ship for:

| Platform              | Architecture |
|-----------------------|--------------|
| Linux                 | x64, arm64   |
| macOS (Intel)         | x64          |
| macOS (Apple Silicon) | arm64        |
| Windows               | x64          |

The package uses the `optionalDependencies`-per-platform pattern (same
shape as `esbuild` / `swc` / `@biomejs/biome`) — only the binary
matching your machine downloads. No postinstall network calls, no
compile step.

If your platform isn't listed, build from source — instructions in
the [main repo](https://github.com/superbasedapp/observer).


## Five-minute quickstart

**No install at all, just a cost table:**

```bash
npx @superbased/observer            # a 30-day cost table, right now
npx @superbased/observer usage      # the explicit, same-thing form
```

On a fresh machine with no SuperBased state yet, bare `npx
@superbased/observer` scans each detected AI tool's own local session
files into a throwaway temp database, prints one tool × model cost
table, and deletes the database again — no daemon, no config written,
no network call. See [Zero-setup cost report](#zero-setup-cost-report-observer-usage)
below for what it does and doesn't do.

**For the full local tool** — proxy-accurate tokens, live dashboard,
conversation compression, cache tracking:

```bash
# 1) Install.
npm install -g @superbased/observer

# 2) Start everything: proxy + watcher + dashboard in one process.
#    Hooks auto-register for every detected AI tool, and the
#    dashboard opens in your browser (suppress with --no-open).
observer start
```

From here the dashboard drives:

3. **Route your AI client through the proxy** — on the Compression
   tab's **Proxy** banner, click your tool's status pill, then
   **Route through the observer proxy…**. The button previews the
   exact file change and writes only on confirm. (Every other
   routing mechanism — `observer init`, the `observer claude` /
   `observer codex` wrappers, plain env vars — is listed in
   [Per-AI-client setup](#per-ai-client-setup).)
4. **Use your AI tool as normal.** The Overview tab's onboarding
   checklist tracks your first captured session; cost, compression,
   and cache numbers populate within minutes of real activity.

`observer init` is OPTIONAL — run it only if you want the MCP server
registered with your AI clients (gives them on-demand tools like
`check_file_freshness` / `get_cost_summary`, at the cost of ~1,800
tokens of schema per turn). Skip it for an MCP-free install.

**What `start` does vs what `init` adds:**

| Step | Hooks | Proxy listening | Watcher | Dashboard | MCP in AI clients | Codex proxy route |
|---|---|---|---|---|---|---|
| `observer start` alone | auto-registers ✓ | ✓ | ✓ | ✓ | — | — |
| `observer init` + `observer start` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `observer init --skip-mcp` + `start` | ✓ | ✓ | ✓ | ✓ | — | ✓ |

MCP and codex routing are explicit-only because both write per-client
config files. Hooks self-heal on every `start`.


<!-- @@INCLUDE:docs/distribution/README-body.md@@ -->


## Troubleshooting

### `npm install -g` fails with `EACCES: permission denied`

Default npm puts globals under `/usr/local/lib/node_modules` which
Homebrew-managed Node owns as root on macOS. Three fixes; pick one:

```bash
# 1) RECOMMENDED — point npm at a user-writable prefix.
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.zshrc
source ~/.zshrc
npm install -g @superbased/observer

# 2) Use a Node version manager — fnm / nvm install Node into your
#    home directory and dodge the permission issue entirely.
brew install fnm
fnm install --lts
npm install -g @superbased/observer

# 3) sudo (works but you'll fight permissions on every update).
sudo npm install -g @superbased/observer
```

### `observer: command not found` after install

The shim binary is at `~/.npm-global/bin/observer` (or wherever your
npm prefix points). Make sure that directory is on `$PATH`:

```bash
echo $PATH | tr ':' '\n' | grep -E 'npm|node'
# add the prefix's bin/ to PATH if missing — see fix above
```

If you installed only a platform package (e.g. `@superbased/observer-darwin-x64`)
without the main `@superbased/observer`, the shim doesn't get created
— there's no `bin` field. Install the main package; npm picks up the
right platform binary automatically via `optionalDependencies`.

### `observer init` says "no tools selected and none auto-detected"

Auto-detection looks for the AI clients' default session-log dirs
(`~/.claude/projects/`, `~/.codex/sessions/`, `~/.cursor/`, etc.).
On a fresh machine where no client has run yet, those dirs don't
exist. Pass the flag explicitly:

```bash
observer init --claude-code     # or --codex / --cursor / --cline / --all
```

This registers hooks regardless — the next time the client runs,
its dirs get created and the watcher picks them up.

### Empty dashboard / "No proxy traffic"

Session/action data populates passively whenever `observer start` is
running, but ground-truth cost / compression numbers require the
proxy. Route your tool through it — the quickest way is the
dashboard's Compression tab → **Proxy** banner → **Route through the
observer proxy…** button; every other mechanism (wrappers, env vars,
`observer init`) is listed under
[Per-AI-client setup](#per-ai-client-setup).

Verify with `observer status | grep api_turns` — count should
climb during AI-client activity.

### `observer --version` says `dev`

You're on a non-released build. Reinstall with `npm install -g @superbased/observer` or rebuild with the workflow's `-X main.version=$VERSION` ldflag.

### `tool_result block must have a corresponding tool_use block`

Anthropic 400. Means the conversation-compression pipeline dropped
a `tool_use` while keeping its matching `tool_result`. Versions
prior to 1.3.2 had this bug; upgrade. If you're on 1.3.2+ and still
see it, file an issue with the conversation prefix.

### `tool use concurrency issues`

Anthropic 400 surfaced in Claude Code as this message. Means the
parallel-tool-use case (multiple `tool_use` blocks in one assistant
message) isn't paired correctly with the multi-block tool_result
that follows. Versions prior to 1.3.2 had this bug; upgrade.

### Cross-thread numbers are 0

Pre-migration data was ingested without the `is_sidechain` flag.
Run `observer backfill --is-sidechain` once to re-walk JSONL and
populate the flag on existing rows.

### Migration error: `duplicate column name`

Race condition between concurrent daemon startups, fixed in 1.4.1.
Upgrade. If you still see it, run daemons serially: `observer
watch`, wait, then `observer dashboard`, then `observer proxy
start` (or just use `observer start` which runs all three in one
process — proxy + watcher + dashboard).

### `observer start` log says only `proxy + observer` — no `:8081`

You're on a pre-1.4.7 build. Earlier versions ran only proxy +
watcher under `observer start`; the dashboard had to be started
separately via `observer dashboard --addr 127.0.0.1:8081`. Upgrade
to 1.4.7+ — the dashboard goroutine is now part of `observer start`
and the log line confirms all three: `proxy <addr> + watcher +
dashboard http://127.0.0.1:8081`. Pass `--no-dashboard` to opt out.

### "address already in use" on port 8820

Another `observer proxy start` or `observer start` is still running.
Find it with `pgrep -af 'observer (proxy|start)'` and `kill <pid>`.
On macOS:

```bash
lsof -nP -iTCP:8820 -sTCP:LISTEN
kill <pid>
```

### Dashboard port already in use

```bash
observer dashboard --addr 127.0.0.1:8082    # pick a different port
# or
[dashboard]
port = 8082                                  # in config.toml
```


## Security and privacy

**Local-only. No telemetry. No remote anything.** The watcher, hook
handler, dashboard, MCP server, and CLI never make an outbound network
call on observer's behalf. The only code paths that touch the network
are the optional API proxy (which forwards **your** requests unchanged
to the AI provider you already use) and a handful of explicit opt-in
features (message-summary LLM, codeintel MCP).

The full privacy statement — what observer stores, what it reads,
what it never stores, the explicit list of outbound-network call sites
gated behind config, and how to verify "no telemetry" yourself with
`grep`, `strings`, and a network-namespaced shell — lives in
[`PRIVACY.md`](https://github.com/superbasedapp/observer/blob/main/PRIVACY.md).

Operational shorthand:

- **Local-only HTTP.** The proxy and dashboard bind to `127.0.0.1`
  by default. Don't bind to `0.0.0.0` unless you've thought about
  it — there's no auth.
- **Secrets scrubbing.** Tool inputs and outputs pass through
  `internal/scrub/` before persistence; review the regex set if your
  secrets follow non-default formats.
- **Database.** `~/.observer/observer.db` is a SQLite file with the
  same security posture as your `~/.claude/` and `~/.codex/` session
  logs (which already hold the same content). Encrypt the disk if
  your threat model needs that.
- **Full delete.** `rm -rf ~/.observer/` removes everything observer
  ever stored — no traces elsewhere on your system.


## Source, contributing, license

- **Source**: https://github.com/superbasedapp/observer
- **Specification**: `superbased-final-spec-v2.md` in the repo
- **Issues**: https://github.com/superbasedapp/observer/issues
- **License**: [Apache 2.0](https://github.com/superbasedapp/observer/blob/main/LICENSE)
- **Author**: Santosh Kathira <contact@superbased.app>

This npm package is a thin Node.js shim that resolves the right
pre-built binary at runtime and spawns it. Same shape as `esbuild` /
`swc` / `@biomejs/biome`. The Go source lives in the main repo;
binaries are cross-compiled per release tag via GitHub Actions and
published as `@superbased/observer-<platform>-<arch>` per-platform
packages.

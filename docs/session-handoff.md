# Session Handoff (continue-anywhere)

Move a session from one AI tool to another: `observer handoff` re-reads
the conversation from the source tool's own files, distills it into a
handover document, prices every carry option, and writes
`HANDOFF-<id>.md` into the project root for the target tool to read.

Plan of record: `docs/plans/session-handoff-plan-2026-07-03.md` (+ the
Phase 0 findings doc). The feature is complete through P4: P1 shipped the
core + CLI; P2 the dashboard fork picker + MCP `continue_session` + the
reader tranche; P3 the hook/prompt injection lanes + best-effort
target-session linking + `handoff_rehydration` cache accounting; P4 the
`handoffs` retention sweep + `observer doctor` handoff probe. The
target-model default is routing-tier-matched (see "Target model").

## The honest premise

**The provider cache cannot move.** Prompt caches are server-side and
prefix-exact; a new tool's system prompt diverges at byte zero, and
verbatim replay breaks on signed thinking blocks and foreign tool ids.
What moves is the *context*, distilled — and the estimate table shows
exactly what rehydrating it costs at the target model. That framing is
load-bearing: never describe this feature as cache migration.

## Quick start

```bash
# What would moving this session to codex cost?
observer handoff <session-id> --to codex --dry-run

# Do it (writes <project-root>/HANDOFF-<shortid>.md)
observer handoff <session-id> --to codex

# Fork from message 35 instead of the end
observer handoff <session-id> --to codex --from-message 35

# History
observer handoff list
```

Then open the target tool in the same project and ask it to read the
`HANDOFF-*.md` file. Add `HANDOFF-*.md` to `.gitignore` — the doc
carries conversation excerpts (the CLI reminds you).

## Carry modes (`--carry`, default `distilled_tail`)

| Mode | Contents |
|---|---|
| `metadata` | Action-derived facts only: files touched, commands + outcomes, unresolved errors. Works for every adapter. |
| `distilled` | Facts + the first user message (the mission), quoted verbatim. |
| `distilled_tail` | Distilled + a verbatim flattened tail of the last K messages before the fork (default 6, `[handoff] tail_messages`). |
| `full` | The whole flattened conversation through the fork, with tool results EXCERPTED (the ≤300-char `ResultCap` snippet). Every message carries a `[msg <id>]` tag and the doc emits an MCP-hint line, so a target with the SuperBased MCP pulls any full body **on demand** via `get_session_message` — `full` never needs to carry the raw bodies itself. Inlined into the first prompt (pointer-degrades to the on-disk doc only past the ~100 KB inline bound). |
| `full_cache` | Like `full`, but the actual read/tool bodies are written **un-excerpted into the handover doc** — the target loads the source session's whole read cache by READING that doc, so it starts warm with zero MCP round-trips. Requires an adapter with an un-excerpted (`FullTranscriptReader`) reader — currently **claude-code** and **codex**; every other tool degrades to `full` with a stated reason. The doc is size-capped by `[handoff] max_cache_bytes` (default 8 MB; truncates past it with a note). |

The dry-run table prices all five at `--target-model` (default: the
source session's model).

**Delivery note.** The injected launch prompt (`observer <tool>
--continue-from`, e.g. `agy -i "<prompt>"`) is a single argv string, so
it is bounded by the OS per-argument limit (Linux `MAX_ARG_STRLEN` =
128 KB) — a larger prompt fails `exec` with E2BIG. Any doc past
`continueFromMaxPromptBytes` (~100 KB) therefore degrades to a pointer:
the full content stays in the on-disk `HANDOFF-*.md` and the prompt
tells the tool to read it first. A `full_cache` doc is routinely
hundreds of KB, so it is *always* delivered this way — the target reads
the doc and loads the cache all the same. (`observer handoff` writes the
doc as the deliverable directly, no argv involved.)

Use `full` when the target has the SuperBased MCP (the lean default —
ids + hint + on-demand pull); use `full_cache` when you want the source
read cache loaded into the new session up front, or when the target has
no SuperBased MCP to pull from. Because `full_cache` ships raw read
bodies, it is local-to-local by nature — the handover doc lives in the
project folder; nothing goes on the org push wire.

## Fork points (default: last message)

`--from-message N` (1-based over the normalized transcript) or
`--from-time <RFC3339>`. A fork must land on a *stable boundary* — the
end of an assistant exchange with no unresolved tool calls. Unstable
requests snap BACKWARD deterministically and the output reports
`requested message 37, snapped to 35 — inside an unresolved tool chain`.
Everything (facts, tail, pricing) is computed as of the fork, so
mid-history forks price cheaper.

The "normalized transcript" merges each run of assistant records between
two user prompts into ONE assistant exchange; tool results attach to the
exchange that made the call; thinking/reasoning blocks are dropped;
harness-injected wrapper records (`<local-command-caveat>` etc.) don't
count as user messages.

## Which tools can hand off what

Transcript readability per adapter lives in the integration registry
(the Phase 0 findings doc has the full table). Shipped transcript
readers: **claude-code**, **codex** (P1) + **cursor**, **cline**,
**cline-cli**, **hermes**, **opencode** (P2 tranche 2 — all
live-verified against real sessions). The remaining FULL-classified
adapters (cowork, copilot-cli, gemini-cli, kilo-code-cli, openclaw, pi)
get readers in a later tranche. Tools without a readable transcript
degrade honestly to `metadata` carry with a message naming the gap.
Transcript paths are DERIVED from the session id (hook-fed sessions
have no stored path), so handoffs work for hook-captured sessions too.
Format notes: cursor's agent transcripts record neither tool-call ids
nor results — calls settle on turn markers with empty result excerpts,
and messages carry no timestamps (fork by time errors honestly).

## Surfaces beyond the CLI (P2)

- **Dashboard** — the session detail panel's "Continue in another tool"
  card opens the Continue-in… modal: registry-derived target picker,
  carry selector, priced carry table, and a fork picker over the message
  timeline (stable snap-table boundaries selectable; unstable rows shown
  disabled with the exact rule reason; cumulative-weight column).
  Endpoints: `GET /api/session/<id>/handoff/estimate?to=&fork=&carry=`
  (always a dry run) and `POST /api/session/<id>/handoff`.
- **MCP** — the `continue_session` tool serves the handover to the
  TARGET tool's model on demand (pull model), addressed by `session_id`
  or `latest` (+ `tool` / `project_root` filters). Read-only by default;
  `write_file: true` also writes the doc. See `docs/mcp-tools.md`.

## Launch here (embedded web terminal)

The Continue-in… modal can also **start the target tool in the browser**,
not just write a handover file. For a launchable target the modal shows a
**"Launch `<tool>` here"** button beside "Write handover doc". Clicking it
spawns `observer <tool> --continue-from <id>` in a pseudo-terminal **inside
the daemon's own OS** and streams the tool's TUI into an xterm.js panel over
a websocket — so it works uniformly whether the daemon is local, on a remote
host, or in WSL while your browser is on Windows (no `wt.exe`/interop, no
cross-OS shell).

- **Launchable set** — **twenty-seven** launchers, declared as
  `HandoffCapability.Launch` in `internal/integration` (the button is hidden
  for every other target, and for all targets when the feature is disabled).
  Two launch **modes** (dispatched on `LaunchSpec.Mode`, never a tool name):
  - **Seeded** (twenty-four): the handover is injected as the tool's first
    interactive prompt — **claude-code, codex, gemini-cli, pi, opencode,
    copilot-cli, cline-cli, kilo-code-cli, cursor, openclaw, antigravity-cli,
    qwen-code, kiro-cli, grok, qoder, goose, devin, droid, open-interpreter,
    command-code, muse, prime-agent, zcode, mistral-code**.
    See the per-adapter seed-contract table below for the exact
    flag/positional each uses.
  - **DocAssisted** (three): **hermes**, **kimi-code**, and **freebuff** —
    their TUIs take no initial-prompt seed (upstream gaps), so the launcher
    writes the handover doc and opens the TUI for you to reference/paste
    (details below).

  `kilo-code-cli` (`observer kilo`), `cursor` (`observer cursor`),
  `openclaw` (`observer openclaw --continue-from`), `antigravity-cli`
  (`observer antigravity-cli --continue-from`, aliases `observer antigravity`
  / `observer agy`; seeds `agy -i "<h>"`), `qwen-code` (`observer qwen`;
  seeds `qwen -i "<h>"` — the documented base-URL lane stays unprobed), and
  `kiro-cli` (`observer kiro`, alias `observer kiro-cli`; seeds
  `kiro-cli chat "<h>"` — SigV4, nothing to route), `grok`
  (`observer grok`; seeds the trailing positional — the /up upstream lane
  stays unprobed), `qoder` (`observer qoder`; seeds `qodercli -i "<h>"` —
  no base-URL knob exists, nothing to route), `goose` (`observer goose`;
  seeds `goose run -t "<h>" -s` — OPENAI_HOST, not OPENAI_BASE_URL, stays
  unprobed), and `kimi-code`
  (`observer kimi`, alias `observer kimi-code`; DocAssisted, non-proxied)
  are pure seeding launchers with **no proxy routing** (they talk to their own
  backend, or — for openclaw — the seed is launched non-proxied to dodge the
  `--local` stall);
  token capture stays on their watcher/SQLite/trajectory adapters. Seeding is
  orthogonal to token capture.
- **Endpoints** — `POST /api/session/<id>/launch` (body `{to, carry,
  fork_message}`) mints an opaque session handle; the browser opens
  `GET /ws/launch/<handle>` to drive the PTY. `GET /api/launch/sessions`
  lists live terminals (metadata only) and `DELETE /api/launch/<handle>`
  reaps one.
- **Enable / disable** — on by default, gated by
  `[handoff].allow_dashboard_launch` (default `true`). Set it `false` to
  remove the surface entirely: the endpoints return 503 and the button
  hides. It lives entirely within the dashboard's loopback + `browserGuard`
  trust boundary.
- **Security** — the argv is built **server-side** from the validated
  target (never client argv or paths). The handle is a 256-bit
  `crypto/rand` value minted **only** by the Origin-checked POST, and the
  websocket upgrade rejects cross-origin requests by default — so a
  malicious page can neither mint a handle nor attach to one. Concurrent
  sessions are capped; closing the browser tab reaps the child process tree.
  Live sessions are NOT idle-reaped by default — an agent sitting at its
  prompt stays available (terminal + dashboard) indefinitely; set
  `[terminal].idle_timeout` to a positive duration (e.g. `"30m"`) to opt back
  into idle reaping. Remote writer leases keep their §4.α.2c idle/hard-cap
  lifetimes; the local seat's lease never expires.
- **Platform** — the embedded terminal has a real PTY backend on **every
  shipped OS**: unix (Linux + macOS) via creack/pty, and **native Windows via
  ConPTY** (`CreatePseudoConsole`, Win10 1809+) with a job object
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) reaping the child tree — the Windows
  analog of the unix `kill(-pgid)`. Both backends are CGO-free. `termsession.PTYSupported()`
  gates the launch seam: it is true on unix and on ConPTY-capable Windows, so
  the **"Launch `<tool>` here" button appears natively — no WSL required**. The
  only residual is **Windows older than 10 1809** (no `CreatePseudoConsole`):
  there `PTYSupported()` is false, cmd leaves the seam unwired, and the button
  is hidden (the honest fallback). In that fallback case cross-tool
  **migration still works** — "Continue in… → Write handover doc" runs through
  the platform-independent `BuildHandoff` path (writes `HANDOFF-*.md` with pure
  file I/O, no PTY), so a user continues a session in another tool *in the same
  environment* by writing the doc and opening the target tool on it. The
  spawned launcher still needs the proxy for routed capture — run it under
  `observer start`; a standalone `observer dashboard` launches the tool but it
  warns that the proxy is unreachable.
- **Binary resolution & guided install (2026-07-23).** Every launcher resolves
  its tool binary through a shared ladder — process PATH, then a memoized
  login-shell PATH capture, then native probe dirs (`.local/bin`,
  `.volta/bin`, `.hermes/node/bin`, …), then (WSL only) foreign Windows homes
  under `/mnt` — and classifies the result into one of five verdicts:
  `ok`, `ok_off_path`/`shadowed` (launchable, with a hygiene note — e.g. a
  native binary shadowed on PATH by a Windows npm interop shim), or
  `foreign_only`/`not_found` (not launchable). Because every launch is a
  fresh `observer <tool>` process, the ladder re-resolves every time — a
  binary installed a minute ago is launchable on the very next attempt, no
  daemon restart required. When a tool is `foreign_only` (a Windows-only
  install seen from a WSL daemon) or `not_found`, the New Terminal dialog
  shows a verified install command and an **"Install in terminal"** button
  that runs it in a visible, Ctrl-C-able PTY (`POST /api/terminal/install`,
  gated by `[terminal.launch].allow_install`, default on). Cross-OS launch —
  actually running a Windows-only binary from a WSL daemon — is explicitly
  out of scope; the guided fix is always a native install. Custom project
  paths typed as `C:\Users\…` are translated to the `/mnt/c/Users/…`
  equivalent before validation. Design of record:
  [`docs/plans/tool-binary-resolution-and-guided-install-plan-2026-07-23.md`](plans/tool-binary-resolution-and-guided-install-plan-2026-07-23.md).
- **`--config` inheritance (2026-09-03).** A dashboard-launched child now
  runs with the same `--config <path>` the daemon itself was started with
  (`setDaemonConfigPath` in `cmd/observer/start.go`; the launch manager
  prefixes it onto every one of the 27 launcher subcommands — `shell` and
  `ssh` runs are excluded by construction, since they have no `observer
  <tool>` subcommand to prefix). Before this fix a dashboard-launched child
  always re-derived config from the **default** path, so an operator running
  the daemon with a non-default `[proxy].port` or `db_path` got a child that
  silently pointed at the wrong proxy port and wrote attribution to the
  wrong (or a nonexistent) database, while printing a message that misnamed
  the cause ("start it with `observer start`" when the daemon was already
  running). See
  [`docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md`](plans/dashboard-install-gap-remediation-research-2026-09-02.md)
  §9 (Q1 plumbing bug P1) for the finding and fix.
- **`allowed_project_roots` asymmetry (DI-18).** With
  `[terminal.launch].allowed_project_roots = []`, an explicit `project_root`
  passed on a launch request is **refused**, but an *omitted* `project_root`
  **succeeds** — the child simply inherits the daemon's own working
  directory (`has_project_root:false`, `dir_set:false` in the launch log).
  This is a real inconsistency, left as documented behaviour rather than
  changed (see the audit's DI-18 finding,
  `docs/audits/dashboard-install-audit-2026-09-02.md`): a caller that wants
  a specific project root must add it to the allow-list, but a caller
  willing to accept "wherever the daemon happens to be running from" needs
  no allow-list entry at all. Note that the daemon's cwd as an implicit
  project root is itself a surprising default worth knowing about — a
  daemon started from a git worktree hands every rootless launch that
  worktree as its project (observed in the 2026-09-02 first-launch probe:
  `pi` picked up the worktree's own `AGENTS.md`).

**GUI launches (IDE / desktop apps) are a different shape — none of this
section applies to them.** The New Terminal picker's "IDE / desktop app"
group (`docs/plans/ide-desktop-launch-plan-2026-09-03.md`) launches a
DETACHED GUI process (`kind:"gui"` on `POST /api/terminal/launch`), and a
detached GUI process has no PTY: no bytes stream into a browser panel, so
there is nothing to "launch here" in the sense this section means. Concretely
that means no `--continue-from` handover seed, no resume, no attach, no
Jump-in, and no terminal tab docked in the dashboard — a successful GUI
launch returns a receipt (pid + whether the routing wrap actually reached
the child) rather than a session token. See `docs/adapters.md` "IDE /
desktop-app launch rows" for the launch-row shape and
`docs/plans/ide-desktop-launch-plan-2026-09-03.md` §9 for what shipped.

## Session attach — default-on, and the Terminal Workspace

Interactive `observer <verb>` launches — all 22 CLI launchers (claude, codex,
opencode, cursor, copilot-cli, kilo, cline-cli, hermes, gemini, openclaw, pi,
antigravity-cli, qwen, kiro, grok, kimi, devin, qoder, goose, droid,
open-interpreter, command-code) — ATTACH by
default when the daemon is reachable: the daemon owns the PTY (so the
dashboard can join it), while your native terminal stays fully interactive as
viewer #1.

- **What "Jump in" offers.** The dashboard's Jump-in list surfaces EVERY live
  daemon-owned run, not just `--attach` sessions: dashboard-launched new
  terminals (fresh), handoffs, native resumes, and CLI `observer <tool>
  --attach` sessions alike — each is a real daemon-owned PTY a dashboard tab
  (local or remote) can join as an extra seat. A fresh run's Jump-in button
  stays disabled until correlation links its session id (~10–30 s). A handoff
  terminal's Jump-in row keys by the FORKED session (not the source it
  continued from) once correlation links it — empty until then — so it is
  joined from the fork's session detail, never the source session's. A BARE
  external session (launched `--no-attach`, or any process not owned by the
  daemon) never appears — its stdio belongs to your own shell and is not
  re-parentable; `--attach` is specifically how you make a session running in
  YOUR OWN terminal daemon-owned and therefore joinable.
- **Proxy env forwarding is claude/codex-scoped; credential env now forwards
  for registry-documented tools.** When the daemon spawns the attached child,
  it forwards its own proxy route (`ANTHROPIC_BASE_URL` and friends) only for
  `claude` and `codex`; every other launcher's daemon-spawned inner process
  applies its own routing itself — attach doesn't change how a self-routing
  tool decides its upstream. `[terminal.attach].route_proxy` / `--no-proxy`
  remain claude/codex-scoped knobs, not general ones. Separately, an attached
  child no longer simply inherits the **daemon's** environment for
  credentials: the attach client also forwards the launching shell's values
  for each tool's registry-documented credential env keys
  (`integration.Capability.AuthEnv`) across the owner-only attach socket,
  applied last-wins at spawn — so a shell-exported key works under attach
  exactly as it would bare. Covered today: `claude-code` (`ANTHROPIC_API_KEY`,
  `ANTHROPIC_AUTH_TOKEN`), `codex` (`OPENAI_API_KEY`), `hermes`
  (`OPENROUTER_API_KEY`, plus a non-default `--key-env NAME` forwarded too),
  `pi` (`OPENAI_API_KEY`), `copilot-cli` (`COPILOT_PROVIDER_API_KEY`, and the
  GitHub-auth chain `COPILOT_GITHUB_TOKEN`/`GH_TOKEN`/`GITHUB_TOKEN` in that
  precedence), `gemini-cli` (`GEMINI_API_KEY` in AI-Studio mode;
  `GOOGLE_API_KEY` plus `GOOGLE_APPLICATION_CREDENTIALS`/
  `GOOGLE_CLOUD_PROJECT`/`GOOGLE_CLOUD_PROJECT_ID`/`GOOGLE_CLOUD_LOCATION` in
  Vertex mode), and `grok` (`XAI_API_KEY`). Gated by
  `[terminal.attach].forward_auth_env` (default `true`) — values are never
  logged or persisted, and transit the socket once per launch.
  Dashboard-launched terminals are unaffected either way: there's no client
  shell to forward from, so they still run under the daemon's env exactly as
  before. Every other tool has no grounded `AuthEnv` registry row yet
  (file/OAuth/keychain auth, or simply unverified — `kiro-cli`'s AWS
  credential family is a deliberate exclusion for blast-radius reasons), so
  the old caveat still applies to them: a credential exported only in the
  shell you typed `observer <verb>` in, and not present where `observer
  start` was launched, will be invisible to the attached child. Workaround
  for those tools: export the credential in the shell that starts the
  daemon, or launch with `--no-attach` to run bare under your own shell's
  env.
- **Opting out / forcing.** `--no-attach` launches bare for one run;
  `--attach` forces attach; `[terminal.attach].default_on = false` (or the
  Settings → terminal toggle, no restart) turns default-on off entirely.
  Scripted invocations (`--print`, piped stdio, headless subcommands) never
  attach and never gain new output.
- **Honest skip notices.** Whenever a default attach is skipped for a
  surprising reason (inside a daemon-owned terminal, daemon unreachable,
  attach disabled while default_on is set) the launcher prints ONE stderr
  line saying why. Explicit opt-outs stay silent.
- **Daemon down ≠ broken claude.** A bare fallback launch neutralizes an
  `observer init`-baked proxy route with a one-shot CLI-scope `--settings`
  override so the session goes direct to the provider (with a "turns are NOT
  captured" notice). Routes the launcher cannot override (managed settings,
  your own `--settings`, codex's config-file route) refuse with the exact fix
  named. Third-party gateway routes are honored untouched.
- **Daemon restarts.** A graceful restart stamps every live attach run
  `daemon_shutdown`. For any launcher whose tool grounds a **native resume**,
  the attach client then offers prompt-with-timeout auto-resume ("resuming
  session <id> in 5s — Enter now, Ctrl-C skip") onto the SAME transcript via
  the tool's own resume mechanism. As of 2026-08-27 that is **26 of the 27
  launchers**: the flagships `claude` (`--resume`) and `codex` (`resume`), plus
  the live-verified wave `opencode` / `kilo` / `cline-cli` / `gemini` /
  `copilot-cli` / `pi` / `qwen` / `grok` / `kimi` / `devin` / `hermes` /
  `kiro` / `qoder` / `antigravity-cli` / `goose`, plus `cursor`
  (`--resume=<chatId>`, grounded 2026-07-25 — see below), plus the 2026-07-29
  wave `droid` (`--resume=<sessionId>`, joined for the same optional-value
  reason as cursor), `open-interpreter` (`resume <SESSION_ID>` — the codex
  subcommand shape) and `command-code` (`--session <id>`; its `-r/--resume`
  sibling is optional-value AND name-resolving, so the required-value
  `--session` is the one used), plus the 2026-08-06 wave `muse` (`resume
  <session-uuid>`, subcommand shape) and `prime-agent` (`--resume <path|id>`,
  required-value flag), plus `zcode` (`--resume`), `mistral-code`'s `vibe`
  (`--resume <8hex>`, required-value flag on the session dir's 8-hex
  suffix), and `freebuff` (`--continue`). Each observer launcher
  exposes a uniform `--resume <id>` flag and translates it to the tool's own
  argv (e.g. `opencode --session <id>`, `kiro-cli chat --resume-id <id>`,
  `goose session --resume --session-id <id>`); the registry declares the
  contract per tool and the launcher owns the translation, so no caller
  branches on tool name. Two id nuances are handled at the boundary and are
  operator-invisible: **goose** stores a store-scoped session id
  (`<id>@<hash8>`) and the launcher strips the `@…` suffix before composing the
  native argv; **kimi** requires the prefixed `session_<uuid>` id (a bare uuid
  hard-fails) and the launcher ensures the prefix (our adapter already stores
  the prefixed form, so it is idempotent). A native resume is mutually
  exclusive with the `--continue-from` handoff-fork family and refused loudly if
  both are given.
  `cursor` was grounded on **2026-07-25** once the operator authenticated
  `cursor-agent`, taking the set to 18 of 19 *at that time* (the current count
  is the 26 of 27 above). It takes `cursor-agent
  --resume=<chatId>` and the chatId **is our SessionID verbatim** — no
  transform — because Cursor names its on-disk chat directories with the same
  uuid our adapter stores. **Pass the id JOINED with `=`.** The flag takes an
  optional value (`--resume [chatId]`, help reports `default: false`), so the
  `=` form is the unambiguous spelling; the space-separated form depends on the
  parser electing to consume the next token rather than leaving the flag bare
  and treating the id as a positional. The live confirm was content-level:
  resuming a chat and asking it to quote the conversation's first user message
  returned that message verbatim, so the prior transcript really is loaded —
  and structurally, `meta.json` kept its original `createdAtMs` and `title`
  while `store.db` grew, whereas the identical run WITHOUT `--resume` created a
  brand-new chat. Caveat worth knowing operationally: the
  resume call is flaky over some networks — several attempts died with
  `RetriableError: WritableIterable is closed` against
  `agentn.global.api5.cursor.sh` before succeeding. That is transport
  flakiness, not a broken mechanism (the host is reachable and non-resume
  calls reconnect too), but a resume prompt may need a retry.
  The remaining **1 launcher — `openclaw` — is honest degraded-mortality**:
  the restart ends the attached session outright with a notice, and the manual
  fallback is `observer <verb> --continue-from <session-id>` (a
  distilled-handover fork onto a NEW session id, not a resume of the same
  transcript). `openclaw` exposes only a picker-only `sessions` command with
  no non-interactive resume surface.
- **Reclaiming control after a dashboard Jump-in.** When a dashboard tab takes
  over a session you launched with `--attach`, your native terminal is demoted
  to a viewer and prints one "control was taken over" line. To take it back,
  **press any printable key or Enter in the native terminal** — the daemon
  re-acquires the writer, delivers that keystroke, restores your terminal's
  geometry (healing any TUI the dashboard left at foreign dimensions), and the
  dashboard tab sees control return. Arrow keys and a bare ESC alone will NOT
  reclaim, by design: TUI apps answer terminal queries (cursor-position,
  Device-Attributes) with ESC-prefixed bytes on stdin, and reclaiming on those
  machine bytes would steal the dashboard's control with nobody typing. The
  same fence covers 8-bit C1-prefixed replies and, for a short window
  (~300 ms) after any such machine reply, its split continuation bytes — so a
  keystroke landing inside that window is simply dropped; press again. Known
  narrow residuals: a VT answerback (ENQ) string configured to plain text, or
  a large bracketed paste whose body spans past the window, can still read as
  typing — both stay one explicit gesture away from correct (the dashboard
  can take control back the same way). Turn the gesture off with
  `[terminal.attach].reclaim_on_input = false` (default true; then a revoked
  native terminal stays fenced with one notice, as before).

**The Terminal Workspace** (`/terminals`, Workspace tab) shows any number of
embedded terminals on one auto-compacting grid: drag tiles by their header,
resize from the edges, add running sessions from the tray. Docking is always
an explicit gesture — "⊞ Add to grid" on any floating terminal window, "⬈
Open as window" on any tile to undock back into the floating window (which is
itself drag-resizable; its size persists). "▭ Remove from grid" keeps the
session running in the tray; "✕ Stop & close" ends the process (confirmed).
Layouts persist server-side (node-local, never pushed) and render read-only
on paired remote devices. `[terminal].max_concurrent` (default 9) caps live
terminals. The former Terminals-page content (launch policy, remote control,
standing access — including the opt-in `revoke_standing_on_takeover`
hardening — live status, run history) lives under the Settings tab. Authenticated
remote writer handoff is default-on: after the unchanged credential gate, a
remote may supersede the native/local seat or another remote, and the losing
seat stays connected read-only with take-back. The owner can opt out live with
`[remote].allow_remote_terminal_takeover = false` or the Settings checkbox.
Remote reading of attach/resume PTYs is independently gated by the named
`[remote].allow_terminal_view` flag, which now defaults `true` (a paired device
sees those PTYs read-only, mirroring the takeover default-true precedent); the
WRITE/drive path is unchanged, and setting it `false` restores the deny-read
posture. Takeover never bypasses this gate.

## Hook delivery (`--deliver hook`, claude-code only)

`observer handoff <id> --to claude-code --deliver hook` still writes the
`HANDOFF-*.md` file, but ALSO *arms* it: the next claude-code session
started **in this project** boots with the handover already in context,
injected as SessionStart `additionalContext` (the same seam the advisor
digest rides). No copy/paste, no "read that file" step.

```bash
# Arm the next claude-code session in this project with a distilled handover
observer handoff <session-id> --to claude-code --deliver hook
# → hook armed for claude-code until 2026-07-04 16:00 — the next claude-code
#   session in this project starts with the handover in context (one-shot).
```

Semantics (all deliberate):

- **claude-code only.** Only claude-code declares the `inject_hook`
  lane in the integration registry; asking for `--deliver hook` against a
  tool that doesn't support it errors honestly, naming the grounded lanes.
  Delivery dispatches on capability shape, never a tool-name branch.
- **One-shot.** The first matching session claims the armed handoff and
  marks it delivered; it never fires again. The claim is a single guarded
  `UPDATE … RETURNING`, so two sessions starting at once can't both get it.
- **TTL.** An armed handoff expires after `[handoff] hook_ttl_minutes`
  (default 240 = 4h). A stale handoff never surfaces days later.
- **Project-scoped.** The arming records the source project root; the
  claim matches on it (the hook resolves the new session's project via its
  git root), so an armed handoff only fires for the same project.
- **8KB budget.** SessionStart `additionalContext` delivers intact only to
  ~8KB (Phase 0 D-P0.2); larger payloads Claude Code truncates to a ~1.9KB
  preview. So the payload is hard-budgeted to `[handoff] hook_max_bytes`
  (default 8192): the compact doc when it fits, otherwise the document head
  truncated on a line boundary plus an explicit pointer to read the
  on-disk `HANDOFF-*.md` for the rest. The doc content stays on disk — the
  `handoffs` row records only the arming window and the file path.
- **Precedence.** When a handoff is armed, it takes the whole hook budget
  for that one session and the advisor digest is skipped; otherwise the
  advisor digest injects as before. A hook failure always fails open to a
  plain approve — it can never block the session.

## Prompt delivery (`--continue-from` on the launchers)

The launcher subcommands can run the handoff for you and seed the handover
as the tool's **first user prompt** — no copy/paste, no "read that file"
step. This is the `inject_prompt` delivery lane (plan §10):

```bash
# Distil a handover from a claude-code session and start claude seeded with it
observer claude --continue-from <session-id>

# Same for codex; fork earlier and choose a carry mode
observer codex --continue-from <session-id> --carry distilled --from-message 40

# gemini seeds via its -i/--prompt-interactive flag; pi via a trailing message
observer gemini --continue-from <session-id>
observer pi --continue-from <session-id>

# opencode/kilo seed the TUI via --prompt; cursor via a trailing positional
observer opencode --continue-from <session-id>
observer kilo --continue-from <session-id>
observer cursor --continue-from <session-id>

# copilot/cline seed interactive mode via -i; openclaw via chat --message
observer copilot-cli --continue-from <session-id>
observer cline-cli --continue-from <session-id>
observer openclaw --continue-from <session-id>   # launched non-proxied

# antigravity-cli seeds Google's `agy` via -i/--prompt-interactive (non-proxied)
observer antigravity-cli --continue-from <session-id>

# qwen seeds Qwen Code via -i/--prompt-interactive; kiro seeds `kiro-cli chat`
# via the chat subcommand's positional prompt (both launched non-proxied)
observer qwen --continue-from <session-id>
observer kiro --continue-from <session-id>

# grok seeds its trailing positional prompt (non-proxied)
observer grok --continue-from <session-id>

# hermes + kimi-code have no TUI seed → doc-assisted: write the doc + open the TUI
observer hermes --continue-from <session-id>
observer kimi --continue-from <session-id>

# zcode seeds via its interactive --prompt/-p flag; mistral-code (vibe) via
# its bare positional [PROMPT] (both launched non-proxied)
observer zcode --continue-from <session-id>
observer vibe --continue-from <session-id>

# freebuff has no seed lane → doc-assisted, like hermes/kimi-code
observer freebuff --continue-from <session-id>
```

Under the hood `--continue-from` runs the exact same handoff as
`observer handoff` (delivery `prompt`): it writes the `HANDOFF-*.md`, records
a `handoffs` row (`delivery='prompt'`), and injects the rendered doc as the
launcher's positional prompt before exec'ing the tool. The doc keeps its
`<!-- superbased-handoff <shortid> -->` marker so the P3 linker can later
find the continued session.

Flags mirror `observer handoff`: `--carry`, `--from-message N`,
`--from-time <RFC3339>` (default fork = last message).

### Per-adapter interactive-seed contracts (canonical)

This is the authoritative table of **how each AI CLI accepts an initial
prompt into an interactive session** — the contract the launcher's
`promptInjection` descriptor encodes. It was established by reading each
tool's own `--help` (+ its docs) and an argv-construction smoke, live on
2026-07-04/05. **Read this before assuming a tool's seed mechanism** — a
truncated top-level `--help` once hid opencode's `--prompt` and led to a
wrong "not seedable" conclusion; the fix was to check the TUI/default
command's own flags, not just the top-level help.

| Tool (registry) | `observer` launcher | Interactive-seed contract | Injection kind | Headless one-shot (NOT used for launch) |
|---|---|---|---|---|
| claude-code | `claude` | leading positional: `claude "<h>"` | leading positional | `claude -p` |
| codex | `codex` | trailing positional (TUI + `exec`): `codex "<h>"` | trailing positional | `codex exec "<h>"` |
| gemini-cli | `gemini` | `-i`/`--prompt-interactive "<h>"` (bare positional `query` is also a prompt) | flag value (`BarePositionalIsPrompt`) | `-p`/`--prompt` |
| pi | `pi` | trailing positional `[messages...]` | trailing positional | — |
| opencode | `opencode` | `--prompt "<h>"` opens the **TUI** seeded (bare positional is a project **path**) | flag value | `opencode run "<h>"` |
| kilo-code-cli | `kilo` | `--prompt "<h>"` opens the **TUI** seeded (bare positional is a project **path**) | flag value | `kilo run "<h>"` |
| copilot-cli | `copilot-cli` | `-i`/`--interactive "<h>"` opens interactive + auto-executes | flag value | `-p`/`--prompt` |
| cline-cli | `cline-cli` | `-i`/`--tui` (boolean) + positional `<h>` → TUI auto-submits the seed | flag value (`-i` boolean, positional follows) | bare positional w/o `-i` = headless act-mode |
| cursor | `cursor` | trailing positional `[prompt...]` (interactive is the default) | trailing positional | `-p`/`--print` |
| openclaw | `openclaw` | `chat --message "<h>"` (chat ≡ `tui --local`); **launched non-proxied** | flag value (`--message`, `chat` prepended) | `openclaw agent --message "<h>"` |
| antigravity-cli | `antigravity-cli` (aliases `antigravity` / `agy`) | `-i`/`--prompt-interactive "<h>"` (Gemini-family; bare positional is also a prompt); **launched non-proxied** (no base-URL knob) | flag value (`BarePositionalIsPrompt`) | — |
| qwen-code | `qwen` | `-i`/`--prompt-interactive "<h>"` (Gemini-CLI fork; bare positional is also a prompt); **launched non-proxied** (base-URL lane unprobed) | flag value (`BarePositionalIsPrompt`) | `-p`/`--prompt` |
| kiro-cli | `kiro` (alias `kiro-cli`) | `chat "<h>"` — the chat subcommand's positional INPUT (`chat` prepended); **launched non-proxied** (SigV4, no base-URL knob) | trailing positional (`--no-interactive` conflicts) | `chat "<h>" --no-interactive` |
| grok | `grok` | trailing positional `grok "<h>"` opens a seeded interactive session; **launched non-proxied** (/up upstream lane unprobed) | trailing positional (`-p/--prompt` conflict) | `-p "<h>"` (plan-agent default — read-only) |
| qoder | `qoder` | `-i`/`--prompt-interactive "<h>"` executes the prompt then stays interactive (binary is `qodercli`; bare positional `[query...]` is also a prompt); **launched non-proxied** (no base-URL knob) | flag value (`BarePositionalIsPrompt`, subcommand map) | `-p`/`--print` |
| goose | `goose` | `run -t "<h>" -s` — the run subcommand's `--text` value, kept interactive by `-s` (`run` prepended, `-s` appended unless forwarded); **launched non-proxied** (OPENAI_HOST lane unprobed) | flag value (`run` subcommand + `-s`; `-i`/`--instructions`/`--recipe` conflict; `--no-session` errors — it would skip capture) | `run -t "<h>"` (exits after the turn) |
| devin | `devin` | trailing positional after `--`: `devin -- "<h>"` opens a seeded interactive session; **launched non-proxied** (Cognition backend, no base-URL knob) | trailing positional after `--` (`-p`/`--print`, `--prompt-file` conflict) | `-p "<h>"` |
| kimi-code | `kimi` (alias `kimi-code`) | **none** — `-p` prints and EXITS; the TUI takes no seed flag → **DocAssisted** (write doc + open the TUI); **launched non-proxied** | n/a (doc-assisted) | `-p "<h>"` |
| hermes | `hermes` | **none** — `--tui` takes no initial-message flag → **DocAssisted** (write doc + open `hermes --tui`) | n/a (doc-assisted) | `-z`/`--oneshot "<h>"`, `chat -q "<h>"` |
| droid | `droid` | trailing positional `droid "<h>"` — `--help` states `Usage: droid [options] [command] [prompt...]` with the worked example `droid "review app.tsx"   Start with an initial prompt`; **launched non-proxied** (built-in-model path has no base-URL knob, BYOK lane unprobed) | trailing positional (a leading `exec`/management verb is refused, not seeded) | `droid exec "<h>"` |
| open-interpreter | `open-interpreter` (alias `interpreter`) | trailing positional `interpreter "<h>"` — this fork's OWN help: `Usage: interpreter [OPTIONS] [PROMPT]`, `[PROMPT]  Optional user prompt to start the session`; **launched non-proxied** (it is codex, but its base-URL lane is unprobed — the launcher injects NO `-c openai_base_url`) | trailing positional (codex-shaped subcommand map) | `interpreter exec "<h>"` |
| command-code | `command-code` (alias `commandcode`) | trailing positional `commandcode "<h>"` — `--help` lists `commandcode "message"   Start with initial message`; **launched non-proxied** (its API-URL knob points at Command Code's own closed gateway) | trailing positional (`-p`/`--print` and `--no-session` refused) | `commandcode -p "<h>"` |
| zcode | `zcode` | `--prompt`/`-p "<h>"` — zcode's own docs describe this as the interactive seed lane (`zcode --help`); the bare command with no prompt opens the TUI unseeded; **launched non-proxied** (Z.AI OAuth, no base-URL knob) | flag value (`--prompt`, conflicts with `-p`/`--print`) | — |
| mistral-code | `vibe` | trailing positional `vibe "<h>"` (bare `[PROMPT]`) opens a seeded interactive session; **launched non-proxied** (API-key auth, `vibe_base_url`/`api_base` lane unprobed) | trailing positional | `-p`/`--prompt` |
| freebuff | `freebuff` | **none** — `freebuff --help` (2026-08-18) exposes only `login` and `--continue`, no positional prompt or one-shot flag → **DocAssisted** (write doc + open the TUI); **launched non-proxied** (CodebuffAI backend, no base-URL knob) | n/a (doc-assisted) | — |

**Absent by convention:** this table lists ONLY tools with a grounded
`Handoff.Launch` row, so an adapter appears here the moment (and only when) its
launcher is wired. Adding one = ground the seed contract against the tool's own
`--help` (including the DEFAULT/TUI command's flags) + an argv smoke → add the
registry `Launch` row + the `continueFromLauncher` verb → add the row here.

Notes that bit us / matter:

- **opencode / kilo-code-cli** (OpenCode-family): `--prompt` is a flag on the
  **default TUI command**, NOT shown in the top-level `--help` command list;
  the bare positional is a project path. The headless `run` subcommand is a
  different run mode, not the seed.
- **cline-cli**: `-i/--tui` is a *boolean*; the prompt is a separate
  positional the TUI auto-submits on mount. A bare positional *without* `-i`
  runs a **headless** act-mode one-shot — so the launcher must emit `-i`.
  `-p` here is `--plan`, NOT a prompt flag.
- **cursor**: talks to its own backend → the `observer cursor` launcher does
  **not** proxy-route; token capture is via the cursor hook + `store.db`
  adapter.
- **openclaw**: has a real `--message` seed, but `chat` ≡ `tui --local` and
  `--local` **stalls when proxy-routed** (`project_openclaw_runtime_block`).
  So `--continue-from` launches openclaw **non-proxied** (like a pure seeding
  wrapper); token capture stays on the trajectory adapter. Do not re-probe the
  proxied path.
- **hermes**: no TUI initial-prompt flag exists (upstream gap,
  NousResearch/hermes-agent Issue #19675 `--initial`). Its only prompt entry
  points (`-z/--oneshot`, `chat -q`) are **headless one-shots** that answer
  and exit — a different run mode, not an interactive continue. So hermes is
  wired **DocAssisted**: `observer hermes --continue-from` writes the handover
  doc, prints its path, and opens `hermes --tui` for you to reference or
  paste. For a fully headless continue you can also run
  `hermes -z "$(cat HANDOFF-<id>.md)"`.
- **freebuff**: `freebuff --help` (2026-08-18) exposes only a `login`
  subcommand and `--continue` — no positional prompt, no one-shot flag, no
  TUI initial-message flag at all. So like hermes/kimi-code it is wired
  **DocAssisted**: `observer freebuff --continue-from` writes the handover
  doc, prints its path, and opens the bare `freebuff` TUI for you to
  reference or paste in yourself.

Semantics (all deliberate):

- **Which launchers.** Twenty-five, one per interactive CLI harness (see the
  seed-contract table below for the exact per-adapter mechanism; this list is
  not yet extended for the 2026-08-06 `muse`/`prime-agent` wave, tracked
  separately). Twenty-two are **Seeded** (`observer claude|codex|gemini|pi|
  opencode|copilot-cli|cline-cli|kilo|cursor|openclaw|antigravity-cli|qwen|
  kiro|grok|qoder|goose|devin|droid|open-interpreter|command-code|zcode|vibe
  --continue-from`) — they declare the `inject_prompt` lane and inject the
  handover as the first prompt. Three are **DocAssisted**
  (`observer hermes|kimi|freebuff --continue-from`) — they write the doc +
  open the TUI (none of the three has a seed flag). Each launcher passes its own tool as the handoff
  TARGET, and the svc validates the delivery lane against that tool's grounded
  capability, so the wiring dispatches on capability shape, never a tool-name
  branch. The injection STRATEGY is declared data — a `promptInjection`
  descriptor (leading positional / trailing positional / flag value) each
  Seeded launcher hands to the shared `injectPrompt` helper — not a per-tool
  code branch.
- **Placement + conflict.** The `promptInjection` descriptor per launcher:
  `observer claude` prepends the handover as claude's **leading positional**;
  `observer codex`, `observer pi` and `observer cursor` append it as the
  **trailing positional** (codex reads a positional in both TUI and `exec`
  forms; pi's `[messages...]` and cursor-agent's `[prompt...]` seed an
  interactive session); `observer gemini` (`-i`), `observer copilot-cli`
  (`-i/--interactive`) and `observer cline-cli` (`-i/--tui`) pass it as a
  **flag value** that opens interactive mode seeded; `observer opencode` and
  `observer kilo` pass it as **`--prompt`** (the TUI-command flag — distinct
  from the headless `run` subcommand); `observer openclaw` passes it as
  **`--message`** on the `chat` subcommand (≡ `tui --local`), launched
  **non-proxied** to dodge the `--local` stall; `observer qwen` passes it as
  **`-i`** (Gemini-CLI fork, non-proxied — the base-URL lane is unprobed);
  `observer kiro` appends it as the **positional INPUT of the `chat`
  subcommand** (`chat` prepended, non-proxied — SigV4; a forwarded
  `--no-interactive` errors, since it would run headless and exit instead of
  opening the seeded session). `observer hermes` is the lone
  **DocAssisted** launcher — no prompt is injected; it writes the doc and
  opens `hermes --tui`. If you *also* forward your own prompt
  — a competing positional, or the tool's own seed/headless flag — the
  launcher errors honestly (two prompts) rather than silently dropping one.
  The conflict check is grammar-light: **forward value-flags in
  `--flag=value` form** (e.g. `--model=opus`, not `--model opus`) so their
  value is not mistaken for a prompt. For the flag-value launchers whose bare
  positional is a project **path** (opencode/kilo) rather than a prompt, a
  forwarded path is *not* treated as a competing prompt
  (`promptInjection.BarePositionalIsPrompt` is false for them, true for
  gemini whose positional is a query).
- **Pointer degrade.** A `full` carry can be tens of KB; past a 100KB bound
  the launcher injects a short pointer prompt ("read `HANDOFF-….md` …",
  keeping the marker line for the linker) instead of inlining the whole doc.
  The full doc is on disk regardless.
- **No proxy needed.** `--continue-from` only reads the DB + the source
  tool's transcript and writes the doc/row; it works whether or not the
  proxy is running (the tool still launches routed as usual).

`observer handoff … --to claude-code|codex` prints a tip line pointing at the
matching `observer <tool> --continue-from <id>` command when the target
declares the prompt lane. `--deliver` itself stays `file|hook` — from
`observer handoff` there is no session to prepend into, so the prompt lane is
reached through the launchers, not a `--deliver prompt` flag.

## Config — `[handoff]` (LOCAL-ONLY, default-on)

```toml
[handoff]
enabled          = true
tail_messages    = 6
max_doc_tokens   = 12000              # file-lane budget; tail degrades first
default_carry    = "distilled_tail"
file_name        = "HANDOFF-{shortid}.md"
hook_max_bytes   = 8192               # hook lane budget (Phase 0: 8KB intact cap)
hook_ttl_minutes = 240                # armed --deliver hook expiry (one-shot; 4h)
retention_days   = 180                # handoffs-table prune horizon (0 = keep forever)
max_cache_bytes  = 8388608            # full_cache doc byte cap (8MB; 0 = uncapped)
```

`retention_days` bounds how long the node-local `handoffs` records live.
The rows are tiny content-free metadata (hashes/enums/paths), so the
default is generous — 180 days keeps roughly six months of handoff history
for the target-session linker while still bounding growth. `0` keeps them
forever. The sweep runs through the shared retention runner
(`observer prune`, and `prune_on_startup` on `observer start` / `watch`),
alongside the cache / router / guard / process prunes — the `prune`
summary line reports `handoff_rows=<n>`.

## Privacy

Node-local end to end. The `handoffs` table (migration 055) stores
counts/enums/hashes only and is pinned out of the org push by the
privacy sentinel; the rendered doc is never stored — it is written once,
scrubbed (structure-safe secret redaction), to your own disk. Cross-
machine handoff does not exist; if ever built it will be a separate
opt-in behind `shipsRawContent()`.

## The stay option

Every estimate carries the other side of the plan §9 comparison: what
staying in the source tool looks like. Two independently grounded
halves, each omitted honestly when there's no data: the source
session's next-message cost band (the same low/typical/high math as
`observer predict`) and the live cache value-at-risk a move abandons
(cachewarm's write−read delta summed over the session's warm windows).
Shown on the CLI table footer, the modal's estimate footer, and the
`stay` object in the API/MCP payloads.

## Target-session linking

Every rendered handover leads with a marker —
`<!-- superbased-handoff <shortid> -->` — that rides into the target
session on whichever lane delivered it: the injected first prompt
(`--continue-from`), the SessionStart context block (`--deliver hook`),
or the model reading the `HANDOFF-<shortid>.md` file (the file/MCP lanes,
where the file's content enters the transcript as a tool result). Because
the marker only becomes observable once the target session's first turn
has been captured to disk, linking necessarily lags that first turn.

`observer handoff list` runs a **best-effort** sweep before it prints: for
each delivered handoff of the last 7 days that still has no target, it
lists candidate sessions of the target tool in the same project started
after the handoff, re-reads each candidate's transcript through the same
reader the source side uses, and stamps `handoffs.target_session_id` on
the first candidate whose transcript carries the handoff's short-id. The
`TARGET` column then shows the linked session (`-` when none). The stamp
is written once and never overwritten; a candidate whose transcript can't
be read is skipped silently, and one handoff's failure never aborts the
sweep. Each candidate's transcript is re-read with the source hints the
store recorded for it (its distinct `source_file` paths), so the reader
opens the exact store the session was captured from — load-bearing on
foreign-mount installs where several stores of one tool coexist.

The short-id is persisted on the `handoffs` row (`short_id`, migration
057), so a handoff written to a custom `--out` path is linkable going
forward. Rows created before migration 057 have no stored short-id and
fall back to recovering it from the delivered doc's `HANDOFF-<shortid>.md`
file name — so a pre-057 custom `--out` handoff (or any handoff without
`--to`) remains unlinkable.

## Post-injection accounting

A target session's first turn is a large cold cache write BY DESIGN — the
whole handover doc arrives as the first prompt / context / file read.
SuperBased annotates that write as `cause=handoff_rehydration` instead of a
plain `reanchor` so it does not read as cache-write waste or a session
balloon. Two layers cooperate: the cache tracker fires
`handoff_rehydration` live when the `superbased-handoff` marker is present
on the first observed turn — on BOTH the Anthropic lane and the implicit /
OpenAI-Codex lane (§15.3), and across the proxy + Tier-2 transcript lanes.
The one live-coverage gap is a non-proxied **codex** target: its Tier-2
observation carries no reconstructed block bodies to scan, so the marker
never reaches the tracker there. The cost advisor is the belt for that gap
(and any non-proxied target): it retroactively exempts a stamped handoff
target's leading turn / first cache event from the balloon + write-waste
detectors. See
[cache-tracking.md → Session-handoff accounting](cache-tracking.md#session-handoff-accounting).

## Doctor probe

`observer doctor` (and `observer doctor handoff`) runs a **handoff
readers** check: for every registered adapter it reports the declared
transcript tier (`full` / `partial` / actions-only) and the grounded
delivery lanes, and — where the tool has a session in the DB from the last
30 days and its adapter implements the transcript reader — it runs a
lightweight, read-only, time-boxed (2s) readability probe against that
latest session. A successful read of ≥1 message is `read OK`; a tool with
no reader says `metadata handover only`, and a tool classified readable
whose latest session can't be re-read is a WARN (the reader is declared but
not delivering), never a fabricated OK. The probe never writes and never
restarts anything, so it is safe to run against a live install. Dispatch is
on capability shape (registry `HandoffCapability` + a structural reader
interface), so a new adapter is covered automatically.

## Target model

When `--target-model` is not given, the estimate no longer just reuses
the source model — it maps the source model's routing tier onto a
model appropriate for the target tool. A codex (`gpt-5.5`-tier) session
handed off `--to claude-code` prices at the Anthropic opus-class
representative of that tier, not `gpt-5.5`; `--to gemini-cli` prices at
the Google representative. The resolution is honest and fails safe: a
same-provider target (e.g. `--to cline` from claude-code), an unknown
source tier, or a target tool whose provider family isn't grounded
(router-fronted tools like opencode, hermes, pi) all fall back to the
source model. An explicit `--target-model` always wins.

## STT / dictation into terminals (supported — fixed 2026-07-23)

Push-to-talk dictation apps that inject text by **momentarily writing the
clipboard, sending Ctrl+V, then restoring the previous clipboard** — Wispr
Flow is the canonical example — work in the dashboard web terminal.

They didn't always: for three sessions the terminal pasted the user's OLD
clipboard instead of the transcription, and two recovery bridges (a
`beforeinput`/`dataTransfer` reader, then an inserted-delta reader, then a
server-side relay) were built and reverted chasing a phantom "clipboard
restore race". The actual root cause was **xterm.js swallowing plain Ctrl+V**:
xterm maps it to the control byte `\x16` and CANCELS the keydown
(`Keyboard.ts` keyCode 86 → `_keyDown` cancel), so the browser paste never
fired at all. The dictation tool, seeing its primary paste not land,
eventually issued a fallback paste — *after* it had already restored the
previous clipboard — which is why a stale clipboard (and never the
transcription) reached the PTY, and why the 2026-07-22 DOM trace saw the old
clipboard in the paste event's own snapshot: that event was the LATE fallback
paste, not a lost race.

**The fix** (`web/src/components/LaunchTerminal.tsx`, custom key handler):
return `false` for the paste combos (`v`/`V` with Ctrl/Cmd) so xterm skips its
key processing and the browser's native paste fires immediately — while the
transcription is still on the clipboard — and xterm's own paste handler
forwards it to the PTY. No bridge, no field styling, no delta forwarding.
Trade-off: a literal `^V` control byte can no longer be typed into the TUI
(nano's Ctrl+V page-down etc.) — the same trade VS Code's integrated terminal
makes on Windows.

**Diagnostics:** a passive input-event trace overlay lives at
`web/src/lib/sttdebug.ts` — **dev builds only** (compile-gated behind
`import.meta.env.DEV` in `main.tsx`, so the shipped dashboard bundle carries
no input-capture surface). Run the Vite dev server (`cd web &&
VITE_API_PROXY=http://localhost:8081 npm run dev` — the dev proxy rewrites its
own Origin so the daemon's same-origin terminal surface works from :5174),
open it with `?sttdebug=1` (or `localStorage.sbo_sttdebug = "1"`), and a
bottom-left panel logs keydown/paste/beforeinput/input/composition events
with timestamps, all client-side. It is the tool that cracked this bug; reach
for it first if a dictation app update ever regresses terminal paste
behavior. History of the failed bridge attempts:
`docs/handovers/session-parking-2026-07-22-stt-terminal-paste-revert.md`.

## Known limitations

- Cross-OS sessions captured through the WSL bridge can carry
  `[external]//…`-prefixed file paths in the Files section — an artifact
  of how those actions were recorded, echoed honestly.
- Target-session linking is best-effort and lagged (see above): it needs
  a known target tool, a recoverable short-id (stored on the `handoffs`
  row from migration 057, or parsed from a `HANDOFF-<shortid>.md` doc
  name for pre-057 rows), and a candidate session with a readable
  transcript in the same project.
- `--continue-from` is wired on **twenty-seven** launchers (see the per-adapter
  seed-contract table above). Twenty-four are **Seeded** (claude, codex, gemini,
  pi, opencode, copilot-cli, cline-cli, kilo, cursor, openclaw,
  antigravity-cli, qwen, kiro, grok, qoder, goose, devin, droid,
  open-interpreter, command-code, muse, prime-agent, zcode, vibe);
  **hermes**, **kimi-code**, and **freebuff** are
  **DocAssisted** (no TUI seed flag exists — upstream gaps — so the launcher
  writes the doc + opens the TUI). openclaw's `--continue-from` launches
  **non-proxied** to avoid the known `--local` proxy stall
  (`project_openclaw_runtime_block`); its seeded TUI has not been live-run
  from this environment (do-not-reprobe), so treat the interactive path as
  best-effort with the written doc as the guaranteed fallback.
- **Minimize / dock (dismiss ≠ kill).** A live terminal is owned by an
  app-level dock (`web/src/components/LaunchDock.tsx`), not the modal, so
  dismissing it does NOT reap the process. Clicking outside the panel (or
  Escape when the terminal is not focused, or `Cmd/Ctrl-.`) **minimizes** it
  to a status pill bottom-right; click the pill to restore. The websocket +
  child process stay alive across minimize/restore (the `LaunchTerminal` stays
  mounted — only its wrapper is parked off-screen), so nothing is lost. Escape
  **while the live TUI is focused** goes to the tool (never hijacked). Killing
  the process is only the explicit "Stop & close" / pill `✕`, which confirms
  while the session is live; a `beforeunload` guard warns before a tab-close/
  refresh kills a running session.
- **Survives tab-close / refresh (Tier 2, shipped 2026-07-05).** A websocket
  disconnect now **detaches** rather than reaps: each session runs an always-on
  pump goroutine (`internal/termsession/manager.go::pump`) that continuously
  drains the PTY into a bounded per-session replay ring (`outbuf.go`, 256 KiB)
  whether or not a client is attached, so a clientless PTY never blocks.
  `Session.Read` serves the attached client from the ring — a fresh `Attach`
  resets the offset to 0, so a reconnecting client **replays recent scrollback
  then tails live**. `Detach` closes a per-attach cancel channel to unblock
  `Read` without killing the PTY; the dashboard `LaunchSession` seam is
  unchanged (the offset protocol stays inside `termsession`). On the frontend,
  `LaunchDock` fetches `GET /api/launch/sessions` on mount and re-creates a
  minimized pill per live session, each reconnecting `/ws/launch/<handle>`.
  Cleanup stays with the explicit "Stop & close" (`DELETE /api/launch/<handle>`)
  + the 30-s exit-linger reaper (idle reaping is off by default; opt in via
  `[terminal].idle_timeout`). The PTY backend spans every
  shipped OS (unix creack/pty + native-Windows ConPTY); only Windows older than
  10 1809 (no `CreatePseudoConsole`) falls back to the hidden-button state,
  where handoff-doc migration still works. **Native-Windows ConPTY is still
  owed an operator run-pass on real Windows** (compile/vet-verified only).

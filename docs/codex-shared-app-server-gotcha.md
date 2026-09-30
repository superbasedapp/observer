# Codex shared app-server gotcha (V5-1)

Codex's global `\\.\pipe\codex-ipc` named pipe (Windows) /
`app-server-control.sock` Unix socket (POSIX) lets one long-running
`codex.exe app-server` process intercept every subsequent
`codex exec` call on the host. When that holder process was launched
without observer's `-c openai_base_url=…` override (e.g., the VS Code
Codex extension or Codex Desktop spawned it), the calls bypass
observer's proxy entirely — no `api_turns` row is inserted, no
compression telemetry is captured. See
[`observer-platform-issues-v5.md`](observer-platform-issues-v5.md)
§V5-1 for the full mechanism and reproducer.

## TL;DR (benchmark operators)

```bash
# Inspect: is a shared codex app-server running on this host?
observer codex --detect-only
# exit code 1 → shared app-server detected; capture WILL be incomplete

# Mitigate: kill the shared app-server(s), then run codex normally.
observer codex --exclusive -- exec --json -m gpt-5-codex "..."

# After the run: re-launch your VS Code Codex extension / Codex
# Desktop manually (e.g., reload the VS Code window).
```

That's the entire workflow. Everything else in this doc is "why" and
"corner cases".

## How observer detects shared app-servers

The detection logic lives in
[`internal/codexipc/`](../internal/codexipc/). On every
`observer codex` invocation (unless `--no-app-server-check` is set):

- **POSIX**: stat `${CODEX_HOME:-~/.codex}/app-server-control.sock`.
  If absent, no holder is bound — fast path. If present, run
  `ps -A -o pid,comm,args` and match processes whose comm contains
  `codex` and args contains `app-server` (but not `--type=` Electron
  child markers).
- **Windows**: run a PowerShell CIM query against `Win32_Process` for
  `codex.exe` / `Codex.exe` entries, filtered to command lines
  containing `app-server` and not containing `--type=`.

Each detected process is classified by path heuristic into
`vscode-extension`, `codex-desktop`, or `unknown` so the
operator-facing warning can name the responsible app.

## The `--exclusive` flag

Opt-in. Terminates every detected shared app-server before exec'ing
codex. Operator-hostile but bounded:

- **POSIX**: `syscall.Kill(pid, SIGKILL)`.
- **Windows**: `taskkill /F /PID <pid>`.

What dies: the VS Code Codex extension's persistent `app-server`
process, and/or Codex Desktop's. What does NOT die: your editor
itself, your shell, or any unrelated codex processes. Per-PID
outcome is printed verbatim:

```
observer codex: terminating 2 shared codex app-server(s) per --exclusive:
  PID 10072  vscode-extension  — terminated
  PID 35388  vscode-extension  — terminated
observer codex: re-launch your VS Code Codex extension / Codex Desktop manually after this run.
```

If termination fails (typical on Windows when the codex.exe belongs
to an elevated session and observer is running unelevated), the
per-PID line surfaces the OS error so you can fall back to manual
kill (Task Manager / `kill -9`).

## The `--detect-only` flag

Inspection only — runs pre-flight detection, prints a multi-line
summary, exits without launching codex. Exit code 1 when any shared
app-server is detected, 0 otherwise. CI-gate-friendly:

```bash
if observer codex --detect-only; then
    echo "host is clean — proceeding with batch"
    observer codex -- exec ...
else
    echo "shared app-server detected — aborting batch or use --exclusive"
    exit 1
fi
```

Mutually exclusive with `--exclusive`. Passing both errors out
before doing anything.

## The post-flight capture check

After `child.Run()` completes (success or failure), observer cross-
references the codex rollout JSONL touched in this run against the
`api_turns` rows the proxy actually recorded. The check is silent on
the happy path. On mismatch it emits one of three single-line
warnings:

- **Full bypass with pre-flight context**:
  `0 of N codex turn(s) reached observer's proxy in this run — confirms V5-1 bypass from the shared app-server(s) above.`
- **Full bypass without pre-flight signal**:
  `0 of N codex turn(s) reached observer's proxy in this run — capture failed but no shared app-server was detected at pre-flight; please report at docs/observer-platform-issues-v5.md as a V5 follow-up.`
- **Partial bypass**:
  `only X of N codex turn(s) captured by proxy; partial V5-1 bypass.`

These warnings are stderr-only and never change the wrapper's exit
code — your CI scripts continue to trust the codex exit code, the
warning is operator signal only.

## `--no-app-server-check`

Universal escape hatch. Skips both pre- and post-flight detection
silently. Use when:

- Your script has verified the host is clean by some other means.
- You're profiling and don't want detection latency (~10 ms POSIX,
  ~100-300 ms Windows for the PowerShell CIM query).
- You explicitly accept the V5-1 bypass risk (e.g., a one-off
  diagnostic where capture is irrelevant).

## Manual termination (when `--exclusive` can't)

If the shared app-server runs as a different user / elevated session
and `--exclusive` fails, terminate manually:

**Windows (PowerShell, run as the owning user or elevated):**

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'codex.exe' OR Name = 'Codex.exe'" |
  Where-Object { $_.CommandLine -like '*app-server*' -and $_.CommandLine -notlike '*--type=*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

**POSIX:**

```bash
ps -A -o pid,comm,args | awk '/codex/ && /app-server/ && !/--type=/{print $1}' | xargs -r kill -9
```

Then re-launch your VS Code Codex extension / Codex Desktop manually.

## V6-2: codex's `-c openai_base_url` doesn't reach the inner app-server

`docs/observer-platform-issues-v6.md` §V6-2 documents a second
codex-cli design quirk: `codex exec` is a thin outer process that
parses `-c openai_base_url=…` argv overrides into its own TOML
state, but **does NOT forward them to the inner `codex app-server`
child** that actually makes the HTTP call. The inner reads its own
config from `$CODEX_HOME/config.toml`, so only the file value reaches
the HTTP client.

Symptom: `observer codex` reports `routing via http://127.0.0.1:8820
(-c openai_base_url injected; auth shape detected by proxy)`,
codex completes cleanly with exit 0, and ZERO turns land in
`api_turns`. Even after `--exclusive` cleans up the V5-1 shared
app-server case.

**v1.7.5 mitigation**: pre-flight reads `$CODEX_HOME/config.toml`
and warns when `openai_base_url` is missing or doesn't point at the
proxy. The warning is a single stderr line per misconfigured CODEX_
HOME root, naming the exact `openai_base_url = "…"` line to add.
Honored by the same `--no-app-server-check` escape hatch as the
other pre-flight checks.

**Operator fix (manual, one-time per host)**:

```toml
# ~/.codex/config.toml  (POSIX)
# %USERPROFILE%\.codex\config.toml  (Windows)
openai_base_url = "http://127.0.0.1:8820/v1"
```

After this line is added, codex's inner app-server reads it on every
spawn and the proxy is correctly hit. The warning silences and
capture works on the next `observer codex` run.

**Upstream fix (codex side)**: codex 0.131+ should forward
per-invocation `-c` overrides to the inner spawned app-server
(either via argv pass-through or IPC handshake). Filed under the v6
doc's "Suggested upstream fixes" §V6-2.

## Codex 0.157.x routing re-check (2026-09-27, backlog item 14)

Re-verified against codex 0.157.1 (npm `@openai/codex@0.157.1`, run in a
throwaway `CODEX_HOME` against a local listener, no model call):

- **Both route knobs still work.** Top-level `openai_base_url` (built-in
  `openai` provider) and the `observer init` shape (`model_provider =
  "openai-observer"` + `[model_providers.openai-observer] base_url`) both sent
  `POST /v1/responses` to the loopback listener.
- **The built-in provider tries a WebSocket first.** With `openai_base_url`,
  codex (0.154.0 and 0.157.1 alike) opens `GET /v1/responses` WebSocket
  upgrades before falling back to HTTPS POST. The proxy passes a WebSocket
  upgrade straight through and records no `api_turns` row for it, so turns
  that stay on a WebSocket are session-log capture only. The `openai-observer`
  custom provider made no WebSocket attempt (POST only), which is one more
  reason `observer init` writes that shape.
- **Application network policy (new in 0.157.0, PRs #47389 / #47407).** A
  managed requirements file with an enabled `[application.network]` block
  (`/etc/codex/requirements.toml`, `%ProgramData%\OpenAI\Codex\requirements.toml`,
  macOS MDM, or ChatGPT-workspace cloud requirements) restricts codex's own
  HTTP/WebSocket traffic to "HTTPS or WSS to that exact host"
  (`codex-rs/http-client/src/network_policy.rs`). The observer proxy is plain
  http on loopback, so no allow entry admits it: a routed codex is expected to
  fail under such a policy. `observer doctor codex` warns when the system file
  enables it (MDM and cloud requirements are not visible to it). Not
  live-verified: it needs a root-owned requirements file.
- **Bedrock leaves the proxy.** `model_provider = "amazon-bedrock"` (codex's
  built-in provider, configured by `aws.profile` / `aws.region`, no
  `base_url`) signs requests with SigV4 and sends them to AWS. The observer
  route cannot cover it; those turns are session-log capture only.
  `observer doctor codex` (`codex.proxy_route`) and the `observer codex`
  launch notice say so instead of implying proxy-exact capture, and name any
  profile (`[profiles.<name>]` or `<name>.config.toml`) that selects it.

## V6-3: proxy TLS handshake adds TTFB on the first request

`docs/observer-platform-issues-v6.md` §V6-3: even when V5-1 +
V6-2 are both resolved (no shared app-servers, `openai_base_url` set
in config.toml), the FIRST codex request through the proxy can fail
because the proxy pays a 500ms–1.5s TLS handshake to chatgpt.com on
a cold connection pool, pushing total TTFB past codex's ~15s inner-
pipe timeout. Same `Reconnecting... N/5` pattern as V4-1.

**v1.7.5 mitigation**: at `observer start`, the proxy fires a HEAD
request against every URL in `[proxy].prewarm_targets` (defaults:
`https://chatgpt.com/`, `https://api.openai.com/`). This warms the
`http.Transport` connection pool, so the first real codex request
reuses an established TCP+TLS session and TTFB drops to roughly
direct-call territory.

Plus a defense-in-depth `flusher.Flush()` call after the proxy
copies upstream status+headers to the client, so codex's inner pipe
sees the `HTTP/1.1 200 OK` line within RTT instead of waiting for
the first body byte.

**Disabling pre-warm**: set `[proxy].prewarm_targets = []` in
`~/.observer/config.toml` to disable. Useful when observer is on a
network that blocks outbound to one of the targets, or when you're
benchmarking the cold-start path explicitly.

**Limitations of the mitigation**: pre-warm helps only for the
upstream URLs you've warmed. If chatgpt.com goes through a CDN that
doesn't pool by hostname, the warm session may not be reused. The
fundamental fix is still upstream — codex 0.131+ should raise the
inner-pipe TTFB timeout from ~15s to ~60s and/or expose it as a
`request_first_byte_timeout` config knob.

## Limitations

- **Cross-mount wrapping isn't detected.** Observer running in WSL2
  wrapping `/mnt/c/Users/<u>/codex.exe` calls the POSIX detector,
  which won't see the Windows-side `codex.exe app-server` processes.
  Pre-flight will be silent, and only the post-flight check will
  catch the bypass after the fact. Track as a v1.7.5+ follow-up if
  this hits you in practice — file under V5-2.
- **Detection is a snapshot.** A shared app-server spawned mid-run
  (e.g., the VS Code Codex extension wakes up while codex is
  executing) won't be caught by pre-flight, only post-flight.
- **`--exclusive` doesn't auto-restart what it kills.** Observer
  can't know how the operator wants the VS Code extension or Codex
  Desktop relaunched — you'll need to reload the VS Code window or
  re-open Codex Desktop manually.

## Why isn't this fixed upstream?

V5-1 is fundamentally a codex-cli design choice. The fix has to
happen there. `observer-platform-issues-v5.md` §V5-1 ("Suggested
upstream fixes") lists the four options ranked by complexity:

1. `--exclusive` / `--no-shared-app-server` flag on `codex exec`.
2. Per-`CODEX_HOME` pipe naming.
3. Per-request propagation of `-c openai_base_url` from the outer
   codex to the shared app-server's HTTP client.
4. Documentation in `codex exec --help`.

Until one of those ships, observer's wrapper-side mitigation is the
best we can do.

## See also

- [`observer-platform-issues-v5.md`](observer-platform-issues-v5.md)
  §V5-1 — full mechanism, reproducer, suggested upstream fixes.
- [`proxy-live-test-recipe.md`](proxy-live-test-recipe.md) — Linux/WSL
  baseline for verifying observer captures codex turns end-to-end.
- [`adapter-audit-playbook.md`](adapter-audit-playbook.md) §"Fixed-name
  IPC discovery" — the generalized red-flag pattern this gotcha
  represents.

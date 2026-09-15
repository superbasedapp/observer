# Remote dashboard access (Tailscale HTTPS, view tier)

Observer's dashboard is loopback-only by default (`127.0.0.1`) — the security
model is *single user + loopback*. **Remote access is opt-in and off by
default.** This page covers the v1 remote transport: **viewing** the dashboard
over your private [Tailscale](https://tailscale.com/) tailnet, with real HTTPS
and application authentication.

Scope of v1 (operator decision 2026-07-12):

- **Tailnet-HTTPS only.** Native LAN TLS (binding a LAN IP directly) is a
  tracked future feature, not shipped.
- **View tier by default.** You can read the dashboard remotely. The execute
  tier (remote terminal / launches) is a **separate**, default-off opt-in
  (`[remote].allow_terminal`) with its own security review — enabling remote
  *view* never turns it on. Remote viewing of attach/resume PTYs is separately
  gated by `[remote].allow_terminal_view` (**default true**, mirroring the
  `allow_remote_terminal_takeover` default-true precedent): a paired device sees
  those PTYs read-only — including their rows in the dashboard's Jump-in list.
  Fresh/handoff dashboard terminals are the non-sensitive floor a remote caller
  always sees; only the attach/resume PTYs (whose TUI can echo secrets) are
  gated. This is a READ-only relaxation — driving them is unchanged and still
  requires `allow_terminal` plus the full writer conjunction. Terminal output
  may contain secrets, so set `allow_terminal_view = false` to keep the
  attach/resume sessions (and their Jump-in rows) hidden from remote callers.
- **`tailscale serve` (private), never `tailscale funnel` (public).** Funnel
  exposes to the public internet; Observer refuses execute routes over funnel
  and the whole feature is designed around the private tailnet only.

See `docs/plans/remote-dashboard-access-plan-2026-07-12.md` for the full design
and threat model, and `docs/security.md` for the ledger entry.

## Managing it from the dashboard (recommended)

Everything below can be driven from the **Remote** page of the local dashboard
(`Configure → Remote`) — you rarely need the CLI. The page is owner-local: the
management actions are `CapabilityLocal`, so they only work from the machine
running Observer (a paired remote viewer sees state but cannot arm/pair/reset).

- **Turn on remote access** — mints the pairing secret + reserves the loopback
  backend + writes `[remote]`. Binds on the next daemon restart (there's a
  **Restart daemon** button in `Settings → Health`, and a "Restart now" button on
  the restart-pending banner — no CLI jump needed).
- **Pair a device** — the everyday action. Shows a **one-time QR + link** for a
  new phone/laptop. **Devices you've already paired stay connected** — pairing a
  new device never disconnects the others. You can pair up to `max_sessions`
  devices (default 5). Takes effect immediately (the running controller
  hot-reloads the fresh secret — no restart).

  **Pairing is gated on tailnet reachability** so you never mint a QR that
  can't connect. The button reflects the same `tailscale status` the Tailscale
  card reads:
  - **Reachable** (Tailscale up + serve confirmed exposing the backend) → the
    button is live, as normal.
  - **Known-unreachable** (Tailscale absent, logged out, or serve not
    configured) → the button is **visible but disabled**, with an inline hint
    naming the exact missing step (*install Tailscale* / *log in to Tailscale* /
    *start Tailscale serve*) and a link that scrolls to the **Tailscale** card
    to finish it.
  - **Indeterminate** (an older `tailscale` CLI can't report serve state, or
    the status probe failed) → the button **stays enabled** — remote never
    hard-blocks on a signal it can't read — with a caution line: if the pairing
    link doesn't load on the device, finish the Tailscale serve step.

  **On the device itself:** the phone/laptop you scan from must have Tailscale
  **installed** and be **signed into the same tailnet account** as this machine
  — otherwise the `https://<host>/#pair=…` URL won't resolve at all. The
  reachable Tailscale card and the pairing-QR reveal both show the app links:
  [iOS](https://apps.apple.com/app/tailscale/id1470499037) ·
  [Android](https://play.google.com/store/apps/details?id=com.tailscale.ipn) ·
  [other platforms](https://tailscale.com/download).
- **Reset & unpair all devices** — the rare, destructive control. Mints a new
  secret and **disconnects every paired device** (each must scan a new QR). Use
  it only if a secret leaked. Confirmed with a device-count warning.
- **Turn off remote access** — reverts to loopback-only and removes the secret
  (needs a restart to unbind the listener).

The **Tailscale** card on the Remote page walks the whole tailnet setup as a
guided state machine — **install → log in → arm → serve → pair** — with each
manual step now runnable from an in-dashboard terminal (you never leave the
dashboard):

- **Not installed** → **Install in a terminal** runs Tailscale's official
  `install.sh` under `sudo` in an embedded xterm (Linux only; refused if
  tailscale is already present). The download link remains as a fallback.
- **Installed, logged out** → **Log in in a terminal** runs `tailscale up` in an
  embedded xterm and shows the authentication link it prints — open it on your
  phone/browser to approve the machine. (`sudo`-prefixed unless the daemon runs
  as root; a user who already holds Tailscale operator rights could run it
  unprivileged.) Copy-the-command remains as a fallback.
- **Armed, serve not set** → **Set up serve for me** (and, if the unprivileged
  daemon needs it, a one-time **operator grant** terminal). If your tailnet
  hasn't approved HTTPS/Serve yet, this surfaces a one-time **enable Serve**
  consent link to your Tailscale admin console. **Approval alone does not start
  serving** — after you approve, come back and click **Set up Tailscale serve
  for me** again (a **Retry serve** button sits right beside the consent link;
  it re-fires the same request and refetches status when it completes).

Each of these terminals is **owner-local only**: the spawned command is a fixed,
server-derived argv (never request input), the route is `CapabilityLocal` +
confirm-token, and the PTY is a local-writer-only setup session — a paired remote
device can never drive it. The `sudo`/auth flow happens interactively in the
xterm; Observer never stores or handles your password.

**Paired device sessions persist across daemon restarts** (node-local
`remote_sessions`, migration 066) — restarting the daemon (e.g. via the dashboard
button) no longer logs your phone out. The raw session token lives only in the
device's cookie; a leaked `observer.db` yields no usable cookie.

Because the secret is stored **hashed-only** (§ *Security notes*), the same QR
can never be re-shown — "Pair a device" always mints a fresh one. That's why
adding a device and resetting are different actions: adding keeps existing
devices, resetting replaces the secret for everyone.

## How it works

`tailscale serve` terminates TLS on your tailnet and forwards **plaintext to a
loopback backend**. Observer therefore does **not** embed Tailscale — the
operator runs `tailscale serve`, and Observer serves a dedicated **loopback**
listener behind it:

```
 phone/laptop (tailnet)  --HTTPS-->  tailscale serve  --plaintext-->  127.0.0.1:<backend>  (Observer)
```

The backend listener is a **separate** listener from the owner-trusted direct
dashboard listener. It is classified *remote-exposed at construction*: it
requires authentication for **every** request — even though the peer is
loopback — so there is no "it came from 127.0.0.1, therefore trusted" bypass
(the tailnet-serve-to-loopback trap). It is also the only place forwarded
identity headers (`Tailscale-User-Login`, …) are read; they are stripped before
any handler runs so a spoofed copy can never be trusted. In v1 those headers
are recorded for audit only — authentication is the pairing device session, not
the tailnet identity.

## Bring-up

1. **Install Tailscale** and join your tailnet on the machine running Observer.
   Confirm the machine's HTTPS host with `tailscale status` (it looks like
   `my-machine.your-tailnet.ts.net`). HTTPS certs require [MagicDNS + HTTPS
   enabled](https://tailscale.com/kb/1153/enabling-https) in your tailnet.
   (On Linux you can do both the install and the `tailscale up` login from the
   dashboard's **Tailscale** card instead — see *Managing it from the
   dashboard* above.)

2. **Arm remote access:**

   ```
   observer remote enable --tailscale
   ```

   This is an atomic transaction: it mints a 128-bit pairing secret (stored
   **hashed** at rest, argon2id, `0600`), reserves a dedicated loopback backend
   port, adds your tailnet host to the Host allow-list, and writes `[remote]`.
   It auto-detects the tailnet host via `tailscale status`; pass it explicitly
   if detection fails:

   ```
   observer remote enable --tailscale --host my-machine.your-tailnet.ts.net
   ```

   The command prints a **pairing URL** with the secret in the URL *fragment*
   (after `#`) — the fragment is never sent to or logged by the server — plus
   the `tailscale serve` command to run and a restart reminder.

3. **Point Tailscale at the backend** (once, on this machine). The `enable`
   output prints the exact command, e.g.:

   ```
   tailscale serve --bg :<backend-port>
   ```

4. **Restart the observer daemon** so the backend listener binds. Follow the
   daemon-restart order (route OFF → stop → `observer start` → route ON) from
   `docs/daemon-restart-runbook.md` — the running daemon is not hot-restarted
   by `enable` (that would break live proxied sessions).

5. **Pair from your device** (on the same tailnet): open the printed
   `https://<host>/#pair=<secret>` URL. The dashboard reads the fragment, pairs,
   receives a short-lived HttpOnly session cookie, and strips the hash from the
   URL. You now have **view-tier** access.

## Managing it from the CLI

```
observer remote status     # mode, backend, trusted hosts, TLS, recent access events
observer remote rotate      # RESET: mint a fresh secret; invalidates EVERY paired device
observer remote disable     # revert to loopback-only AND remove the pairing secret
```

CLI `rotate`/`disable` run in a separate process, so they take effect on the next
daemon restart (the running process loaded the previous secret at startup).
`disable` removes the secret file (true revocation) and reverts `[remote]` to
`off`.

> The CLI has no "add a device" equivalent — `observer remote rotate` is the
> reset-everyone control. To **add a device without disconnecting the others**,
> use the dashboard's **Pair a device** button (it hot-reloads the fresh secret
> on the running controller, so it takes effect immediately — no restart). The
> dashboard "Reset & unpair all devices" is the equivalent of CLI `rotate`.

## Configuration (`[remote]`, LOCAL-ONLY)

`[remote]` is node-local — it is never distributed via `[org_client.share]` and
there is no server-side/remote toggle for it (mirrors the org-push posture: the
node operator owns exposure entirely). `observer remote enable` manages these;
you rarely edit them by hand.

```toml
[remote]
enabled                = true              # master switch (default false)
mode                   = "tailscale"       # off | tailscale   (lan is deferred)
tailscale_backend_addr = "127.0.0.1:PORT"  # loopback backend tailscale serve forwards to
trusted_hosts          = ["my-machine.your-tailnet.ts.net"]  # Host allow-list (no "allow any")
require_tls            = true              # TLS required for all remote access
allow_terminal         = false            # execute-tier terminal (Phase 4; separate opt-in)
allow_terminal_view    = true             # read attach/resume PTYs remotely (independent, default true; set false to hide)
allow_remote_terminal_takeover = true     # authenticated remote may supersede local/remote writer
rate_limit_per_min     = 6                 # pairing-attempt rate limit
```

`allow_remote_terminal_takeover` is a post-authentication lease policy, not an
authentication bypass. With its default `true`, a remote device that has already
passed the full writer conjunction (Tailscale HTTPS, paired live device session,
`allow_terminal`, launch/session policy, and a valid single-use
capability+confirm or standing secret) may take control from the native/local
seat or another remote device. The losing seat stays connected read-only and is
offered take-back. Set it to `false` (or turn off “Allow remote devices to take
over control” under Terminals → Settings) to require the current writer to yield.
A valid one-time capability is consumed before that lease-policy refusal, so a
fresh approval is required for the next attempt; a standing secret is not
cleared. The credential gate itself is unchanged.

The pairing secret is **not** in config — it lives hashed in a `0600`
`remote-secret` file beside the DB.

**Fresh-launch default directory.** When a fresh terminal launch has **no
project root** (none allow-listed, or the operator picks "Agent's default
directory"), the agent runs in the **Observer daemon's own working directory** —
the directory `observer start` / `observer dashboard` was launched from — not a
guessed project. Allow-list a root under `[terminal.launch].allowed_project_roots`
(Terminals page → launch policy) to launch elsewhere.

Such a launch still **correlates to its agent session**: run→session discovery
matches on the directory the child actually runs in (the daemon's cwd), not on
the authorized project root, so the Session panel links and the live vitals fill
in exactly as they do for an allow-listed launch.

It also gets the **Files / Git** panel. Since **2026-08-28** (operator ruling,
reversing the earlier conservative gating) those buttons are **enabled by
default** for any dashboard-launched terminal that has a directory on this
machine: they follow the run's *factual* working directory when the launch
requested no root, and the allow-listed project root when it did. The launch
allow-list governs which roots a dashboard client may **request at launch time**;
it was never a statement about which directory an already-running, owner-local
terminal may browse. Nothing about *who* may browse changed: the panel is still
token-scoped and server-resolved (the browser never sends a path), still applies
its per-request traversal/symlink containment checks, and a remote-exposed viewer
still needs `[remote].allow_terminal_view`.

The panel says which kind of directory it is showing. When it is serving the
terminal's working directory rather than an allow-listed project root, the header
reads `<tool> · working dir` and the path is labelled **working directory**.

Files/Git stay disabled only when there is genuinely nothing local to browse:
an **SSH remote-system terminal** (its files live on the remote host, and the
local directory its `ssh` client runs in is not the terminal's working
directory), or a daemon whose own working directory could not be read. If a
terminal shows a live session but greyed-out Files/Git buttons, that is one of
those two states, not a failure.

## Security notes & residuals

- A paired remote viewer sees the **full, unscrubbed local `observer.db`** —
  they are trusted as the machine owner. A lower-trust remote viewer is a
  separate scrubbing project, not this feature.
- Attach/resume terminal subscription is governed by its own gate,
  `[remote].allow_terminal_view`, independent of `allow_terminal`. It now
  **defaults `true`** (a paired device sees those PTYs read-only), mirroring the
  `allow_remote_terminal_takeover` default-true precedent; the WRITE/drive path
  is unchanged. The gate covers BOTH the live PTY subscription AND those PTYs'
  rows in the dashboard's Jump-in list; fresh/handoff dashboard terminals are
  the non-sensitive floor a remote caller always sees, so with the gate off a
  remote Jump-in list shows only fresh/handoff. Set `allow_terminal_view =
  false` to restore the deny-read posture for the attach/resume PTYs. Now that
  every `observer <verb>` launcher attaches by default, more sessions are
  `KindAttach` and therefore fall under this gate — intended, not a
  regression: fresh/handoff dashboard terminals remain the non-sensitive floor
  regardless.
- The `remote_audit` log is metadata-only (session ids and enums, never
  secrets) and is **not** compliance-grade immutable — a local owner can mutate
  the SQLite file. It is a best-effort operational record, not tamper-evident.
- On Windows, the `0600` secret-file permission is advisory; file ACLs are the
  real control (documented residual).
- `enable` reserves a free loopback port at arm time and the daemon rebinds it
  on start; if that port is taken at start, the backend listener logs a clear
  error and the local dashboard is unaffected.

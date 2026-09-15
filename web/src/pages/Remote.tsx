import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { ChartShell, Pill } from "@/components/primitives";
import { HelpInd, TitleWithHelp } from "@/components/HelpInd";
import { useApi } from "@/lib/useApi";
import { fetchJSON } from "@/lib/api";
import { markRestartPending } from "@/lib/restartPending";
import { fmtClock, fmtDateTime, fmtShortId } from "@/lib/format";
import {
  LaunchTerminal,
  type Status as LaunchTerminalStatus,
} from "@/components/LaunchTerminal";
import { useLaunchDock, type DockSession } from "@/components/LaunchDock";

// Remote page (dashboard-management-surface plan §9-§11). Arms/disarms tailnet
// remote access, reveals the one-time pairing URL + QR, and manages live device
// sessions + the audit tail — all from the owner-trusted LOCAL dashboard. The
// enable/disable/rotate + session-revoke routes are CapabilityLocal server-side,
// so this panel only works from loopback; a remote viewer sees state but cannot
// arm/disarm.

type RemoteConfig = {
  confirm_token: string;
  config_writable: boolean;
  controller_live: boolean;
  enabled: boolean;
  mode: string;
  require_tls: boolean;
  allow_terminal: boolean;
  allow_terminal_view: boolean;
  trusted_hosts: string[];
  backend_addr?: string;
  rate_limit_per_min?: number;
  max_sessions?: number;
  secret_present: boolean;
  secret_fingerprint: string;
  ready: boolean;
};

type EnableResponse = {
  ok: boolean;
  restart_required: boolean;
  host?: string;
  backend_addr?: string;
  allow_terminal?: boolean;
  allow_terminal_view?: boolean;
  tailscale_serve?: string;
  pairing_url?: string;
  pairing_secret?: string;
};

type SessionRow = {
  fingerprint: string;
  created_at: string;
  last_seen: string;
  age_seconds: number;
};

type AuditRow = {
  ts: string;
  kind: string;
  principal: string;
  remote_addr: string;
  route: string;
  decision: string;
  detail: string;
};

type TailscaleStatus = {
  present: boolean;
  logged_in: boolean;
  host: string;
  state: string;
  install_url: string;
  daemon_runs_serve: boolean;
  armed?: boolean;
  backend_addr?: string;
  serve_command?: string;
  serve_configured?: boolean;
  serve_detectable?: boolean;
};

// ServeResult mirrors the POST /api/remote/tailscale/serve response — Observer
// runs `tailscale serve` for the operator; enable_url is the one control-plane
// consent it cannot perform (the user opens it once, approves, re-runs);
// needs_privilege is set when the non-root daemon lacks the operator grant (the
// remedy is the in-dashboard operator-grant terminal, not a raw error).
type ServeResult = {
  ok?: boolean;
  enable_url?: string;
  needs_privilege?: boolean;
  output?: string;
  error?: string;
};

// GrantResult mirrors POST /api/remote/tailscale/operator-grant — it returns the
// PTY handle the embedded terminal attaches to so the user types their sudo
// password once, in the dashboard.
type GrantResult = {
  handle?: string;
  user?: string;
  command?: string;
  error?: string;
};

const REVEAL_MS = 60_000;

// LaunchInfoWire mirrors dashboard.LaunchInfo (GET /api/launch/sessions). The
// terminal-control surface reads writer_holder ("local" | a remote device
// fingerprint | "") and the viewer count to show who currently drives each
// live terminal.
type LaunchInfoWire = {
  token: string;
  subcommand?: string;
  session_id?: string;
  viewers?: number;
  writer_holder?: string;
  exited?: boolean;
  has_project_root?: boolean;
};

type RemoteSessionRow = { fingerprint: string };

// ApproveReveal holds a one-time grant-control result. Like the pairing QR it
// is kept ONLY in memory, masked after a timeout, and never re-fetched. It is
// keyed by the terminal token (its `handle`) so the reveal renders beside the
// exact row the operator granted control on.
type ApproveReveal = {
  handle: string;
  device: string;
  capability: string;
  confirm: string;
};

const APPROVE_REVEAL_MS = 60_000;

// StandingStatus mirrors GET /api/remote/standing-terminal — the opt-in durable
// terminal-control secret + the two lease-policy toggles.
type StandingStatus = {
  enabled: boolean;
  secret_present: boolean;
  secret_fingerprint: string;
  allow_terminal: boolean;
  remote_enabled: boolean;
  config_writable: boolean;
  warning: string;
  revoke_on_takeover: boolean;
  allow_remote_terminal_takeover: boolean;
};

async function postJSON<T>(path: string, confirmToken: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Observer-Confirm": confirmToken,
    },
    body: JSON.stringify(body ?? {}),
  });
}

export function RemotePage() {
  const cfg = useApi<RemoteConfig>("/api/remote/config", undefined, [], { refreshMs: 15_000 });
  const sessions = useApi<{ sessions: SessionRow[]; controller_live: boolean }>(
    "/api/remote/sessions",
    undefined,
    [],
    { refreshMs: 15_000 },
  );
  const audit = useApi<{ events: AuditRow[]; immutable: boolean }>("/api/remote/audit");
  const tailscale = useApi<TailscaleStatus>("/api/remote/tailscale/status", undefined, [], {
    refreshMs: 20_000,
  });
  // Live terminals (GET /api/launch/sessions) power the terminal-control surface
  // moved here from the Terminals page — grant control of a live terminal to a
  // paired device, revoke it, or take control back locally.
  const launchSessions = useApi<{ sessions: LaunchInfoWire[] }>(
    "/api/launch/sessions",
    undefined,
    [],
    { refreshMs: 8_000 },
  );
  const dock = useLaunchDock();

  const [host, setHost] = useState("");
  const [hostEdited, setHostEdited] = useState(false);
  const [allowTerminal, setAllowTerminal] = useState(false);
  const [serveBusy, setServeBusy] = useState(false);
  const [serveResult, setServeResult] = useState<ServeResult | null>(null);
  // Operator-grant terminal: the PTY handle the embedded xterm attaches to so
  // the user types their sudo password ONCE, in the dashboard.
  const [grantHandle, setGrantHandle] = useState<string | null>(null);
  const [grantBusy, setGrantBusy] = useState(false);
  const [grantErr, setGrantErr] = useState<string | null>(null);
  // Guided login (`tailscale up`) + install (install.sh) terminals — the SAME
  // local-only SpecSetup PTY seam as the operator grant (server-derived argv,
  // local-writer-only). Each spawns its own xterm handle; on child exit we
  // refresh tailnet status so the card advances along the ladder.
  const [loginHandle, setLoginHandle] = useState<string | null>(null);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginErr, setLoginErr] = useState<string | null>(null);
  const [installHandle, setInstallHandle] = useState<string | null>(null);
  const [installBusy, setInstallBusy] = useState(false);
  const [installErr, setInstallErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Allow-terminal toggle (enabled state). It shares the SAME `busy` mutual
  // exclusion as the other manage verbs (pair/disable/rotate) so two config
  // read-modify-writes can't race from this panel. termOverride renders the
  // POST response's saved value immediately (cfg.reload() is fire-and-forget);
  // it clears itself once the fetched config catches up — the fetched config
  // stays the single source of truth. termMsg is the honest restart notice.
  const [termOverride, setTermOverride] = useState<boolean | null>(null);
  const [termMsg, setTermMsg] = useState<string | null>(null);
  // Allow-terminal-VIEW toggle (§3.2 Phase 4): the independent READ opt-in that
  // lets a paired device SEE attach/resume terminals. Strictly weaker than
  // allow_terminal (write). Same optimistic-override + honest-message pattern as
  // the allow_terminal toggle above; hot-reloads (no restart).
  const [termViewOverride, setTermViewOverride] = useState<boolean | null>(null);
  const [termViewMsg, setTermViewMsg] = useState<string | null>(null);
  // One-time pairing reveal — held ONLY in memory, never localStorage/URL (§11).
  const [pairing, setPairing] = useState<EnableResponse | null>(null);
  const [masked, setMasked] = useState(false);
  const [qr, setQr] = useState<string | null>(null);
  const maskTimer = useRef<number | null>(null);

  const c = cfg.data;

  // Pairing reachability gate. The everyday "Pair a device" button used to
  // appear the moment remote was armed, ignoring whether the dashboard is
  // actually reachable over the tailnet — so users minted QR codes that could
  // never connect. Compute reachability from the SAME tailscale status the
  // Tailscale card consumes (one shared fetch at this level, `tailscale.data`):
  //   - reachable      → serve is confirmed exposing the backend over HTTPS.
  //   - indeterminate  → we CANNOT read serve state (fetch failed, or an older
  //                      tailscale CLI can't report serve). Never hard-block on
  //                      a signal we can't read — keep pairing enabled, warn.
  //   - known-unreachable → we CAN read the state and it says not-yet-reachable
  //                      (tailscale absent / logged out / serve not configured).
  const ts = tailscale.data;
  const serveReachable = Boolean(ts?.present && ts?.logged_in && ts?.serve_configured);
  const serveIndeterminate =
    !ts ||
    (Boolean(ts.present) &&
      Boolean(ts.logged_in) &&
      (ts.serve_detectable === false ||
        (ts.serve_configured === undefined && ts.serve_detectable === undefined)));
  // The exact missing step, named honestly (house rule: the disabled-control
  // copy names the precise missing dependency).
  const pairMissingStep = !ts?.present
    ? "install Tailscale"
    : !ts?.logged_in
      ? "log in to Tailscale"
      : "start Tailscale serve";
  const pairKnownUnreachable = !serveReachable && !serveIndeterminate;
  const confirmToken = c?.confirm_token ?? "";

  const reloadAll = useCallback(() => {
    cfg.reload();
    sessions.reload();
    audit.reload();
  }, [cfg, sessions, audit]);

  // Seed the host input from the detected tailnet host so "Arm" just works when
  // Tailscale is up — the Tailscale card already resolved it; don't force a
  // re-type. Only until the operator edits the field (then their value wins).
  useEffect(() => {
    const detected = tailscale.data?.host;
    if (detected && !hostEdited && host === "") {
      setHost(detected);
    }
  }, [tailscale.data?.host, hostEdited, host]);

  // Render the QR client-side from the pairing URL fragment (lazy chunk).
  useEffect(() => {
    let cancelled = false;
    if (pairing?.pairing_url) {
      import("qrcode")
        .then((m) => m.toDataURL(pairing.pairing_url as string, { margin: 1, width: 220 }))
        .then((url) => {
          if (!cancelled) setQr(url);
        })
        .catch(() => {
          if (!cancelled) setQr(null);
        });
    } else {
      setQr(null);
    }
    return () => {
      cancelled = true;
    };
  }, [pairing]);

  // Mask the pairing reveal after REVEAL_MS; the value survives in memory so
  // "reveal" re-shows it without any server round-trip.
  useEffect(() => {
    if (pairing) {
      setMasked(false);
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
      maskTimer.current = window.setTimeout(() => setMasked(true), REVEAL_MS);
    }
    return () => {
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
    };
  }, [pairing]);

  async function arm(action: "enable" | "disable" | "rotate" | "add-device") {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy(action);
    setErr(null);
    try {
      const body = action === "enable" ? { host: host.trim(), allow_terminal: allowTerminal } : {};
      const res = await postJSON<EnableResponse>(`/api/remote/${action}`, confirmToken, body);
      if (action === "disable") {
        setPairing(null);
      } else {
        // enable / rotate / add-device all mint a fresh secret + QR to reveal.
        setPairing(res);
      }
      if (res.restart_required) markRestartPending(`remote-${action}`);
      reloadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  // setAllowTerminal flips [remote].allow_terminal on the armed controller via a
  // dedicated endpoint that does NOT rotate the pairing secret or drop paired
  // devices (unlike a re-arm). allow_terminal now hot-reloads onto the live gate
  // + standing verifier, so the flip takes effect IMMEDIATELY in BOTH directions
  // with no daemon restart (restart_required is false); the →false case also
  // revokes any live remote terminal writer immediately.
  async function saveAllowTerminal(next: boolean) {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("allow-terminal");
    setErr(null);
    setTermMsg(null);
    try {
      const res = await postJSON<EnableResponse>("/api/remote/allow-terminal", confirmToken, {
        allow_terminal: next,
      });
      const saved = res.allow_terminal ?? next;
      // Render the saved value immediately — cfg.reload() is fire-and-forget,
      // so without this the checkbox would re-enable showing the stale value
      // until the next /api/remote/config GET lands.
      setTermOverride(saved);
      if (res.restart_required) markRestartPending("remote-allow-terminal");
      setTermMsg(
        saved
          ? "Allow terminal is now on. Live now - no restart needed; this expands the remote execution authority."
          : "Allow terminal is now off. Live now - no restart needed. Any live remote terminal was revoked immediately and new control is refused.",
      );
      cfg.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  // Drop the optimistic override once the fetched config agrees with it, so the
  // fetched config goes back to being the single source of truth.
  useEffect(() => {
    if (termOverride !== null && c?.allow_terminal === termOverride) {
      setTermOverride(null);
    }
  }, [c?.allow_terminal, termOverride]);

  // saveAllowTerminalView flips [remote].allow_terminal_view on the armed
  // controller via a dedicated endpoint (does NOT rotate the secret or drop
  // devices). It hot-reloads onto the live VIEW gate — the flip takes effect
  // IMMEDIATELY in both directions with no restart; the →false case also closes
  // any already-open remote view of an attach/resume terminal at once.
  async function saveAllowTerminalView(next: boolean) {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("allow-terminal-view");
    setErr(null);
    setTermViewMsg(null);
    try {
      const res = await postJSON<{ allow_terminal_view?: boolean; restart_required?: boolean }>(
        "/api/remote/allow-terminal-view",
        confirmToken,
        { allow_terminal_view: next },
      );
      const saved = res.allow_terminal_view ?? next;
      setTermViewOverride(saved);
      if (res.restart_required) markRestartPending("remote-allow-terminal-view");
      setTermViewMsg(
        saved
          ? "Allow terminal view is now on (this is the default). Live now - no restart needed. Paired devices can SEE attach/resume terminals like Claude Code and Codex (read-only); driving them still needs Allow terminal + a per-terminal Grant."
          : "Allow terminal view is now off. Live now - no restart needed. Any open remote view of an attach/resume terminal was closed immediately.",
      );
      cfg.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  // Drop the view override once the fetched config agrees with it.
  useEffect(() => {
    if (termViewOverride !== null && c?.allow_terminal_view === termViewOverride) {
      setTermViewOverride(null);
    }
  }, [c?.allow_terminal_view, termViewOverride]);

  // pairDevice is THE everyday action: mint a fresh one-time QR for a new device
  // WITHOUT disconnecting devices already paired, then scroll the reveal into
  // view so the QR is actually visible (the panel sits above the controls).
  async function pairDevice() {
    await arm("add-device");
    setTimeout(
      () =>
        document
          .getElementById("pairing-reveal")
          ?.scrollIntoView({ behavior: "smooth", block: "start" }),
      120,
    );
  }

  // resetAndUnpair is the RARE, destructive reset — a new secret that
  // disconnects EVERY device (use it only if a secret leaked). Gated behind an
  // explicit count-aware confirm that points at "Pair a device" for the normal
  // case.
  function resetAndUnpair() {
    const n = sessions.data?.sessions.length ?? 0;
    const msg =
      n > 0
        ? `Reset the pairing secret and unpair all devices?\n\nThis DISCONNECTS all ${n} currently-paired device${n === 1 ? "" : "s"} - each must scan a new QR to reconnect.\n\nOnly do this if a secret leaked. To pair another device WITHOUT disconnecting these, use "Pair a device" instead.`
        : `Reset the pairing secret?\n\nThe previous QR stops working and a fresh one is minted.`;
    if (!window.confirm(msg)) return;
    void arm("rotate");
  }

  async function setupServe() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setServeBusy(true);
    setServeResult(null);
    try {
      const res = await postJSON<ServeResult>("/api/remote/tailscale/serve", confirmToken, {});
      setServeResult(res);
      tailscale.reload();
    } catch (e) {
      setServeResult({ error: e instanceof Error ? e.message : String(e) });
    } finally {
      setServeBusy(false);
    }
  }

  // runOperatorGrant spawns `sudo tailscale set --operator=<you>` in an embedded
  // terminal (local-writer-only server-side). The user types their password once;
  // on exit we auto-retry serve, which then works unprivileged.
  async function runOperatorGrant() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setGrantBusy(true);
    setGrantErr(null);
    try {
      const res = await postJSON<GrantResult>(
        "/api/remote/tailscale/operator-grant",
        confirmToken,
        {},
      );
      if (res.handle) {
        setGrantHandle(res.handle);
      } else {
        setGrantErr(res.error ?? "could not start the permission terminal");
      }
    } catch (e) {
      setGrantErr(e instanceof Error ? e.message : String(e));
    } finally {
      setGrantBusy(false);
    }
  }

  // When the operator-grant terminal exits, tear it down and auto-retry serve —
  // which now succeeds unprivileged.
  function onGrantTerminalStatus(s: LaunchTerminalStatus) {
    if (s === "exited") {
      setGrantHandle(null);
      void setupServe();
    }
  }

  // runLogin spawns `tailscale up` in an embedded local-only terminal (server
  // decides sudo-vs-not) so the auth URL it prints is shown right here — the
  // user opens it on their phone/browser to finish login.
  async function runLogin() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setLoginBusy(true);
    setLoginErr(null);
    try {
      const res = await postJSON<GrantResult>("/api/remote/tailscale/login", confirmToken, {});
      if (res.handle) {
        setLoginHandle(res.handle);
      } else {
        setLoginErr(res.error ?? "could not start the login terminal");
      }
    } catch (e) {
      setLoginErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoginBusy(false);
    }
  }

  // On login-terminal exit, tear it down and re-detect — a successful
  // `tailscale up` flips the card to the "up" state.
  function onLoginTerminalStatus(s: LaunchTerminalStatus) {
    if (s === "exited") {
      setLoginHandle(null);
      tailscale.reload();
    }
  }

  // runInstall spawns the official Tailscale Linux install script in an
  // embedded local-only terminal (sudo password typed here). Server refuses
  // off-Linux or when tailscale is already present.
  async function runInstall() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setInstallBusy(true);
    setInstallErr(null);
    try {
      const res = await postJSON<GrantResult>("/api/remote/tailscale/install", confirmToken, {});
      if (res.handle) {
        setInstallHandle(res.handle);
      } else {
        setInstallErr(res.error ?? "could not start the install terminal");
      }
    } catch (e) {
      setInstallErr(e instanceof Error ? e.message : String(e));
    } finally {
      setInstallBusy(false);
    }
  }

  // On install-terminal exit, tear it down and re-detect — a successful install
  // flips the card from "not installed" to "installed, log in next".
  function onInstallTerminalStatus(s: LaunchTerminalStatus) {
    if (s === "exited") {
      setInstallHandle(null);
      tailscale.reload();
    }
  }

  // cancelSetupTerminal actually TERMINATES a running setup PTY (sudo login /
  // install / operator-grant). Dropping React state alone only unmounts the
  // xterm/ws — the server deliberately keeps the child alive for reconnect, so a
  // bare state-drop would orphan a root process (the sudo prompt keeps running).
  // DELETE /api/launch/<handle> reaps the process group. These are owner-loopback
  // (Local) routes, so the DELETE is never blocked by the remote
  // setup-termination guard. Best-effort: on failure the idle sweep still reaps
  // the child, and a wedged DELETE must not freeze the button.
  async function cancelSetupTerminal(handle: string | null, clear: () => void) {
    clear();
    if (!handle) return;
    try {
      await fetchJSON(`/api/launch/${encodeURIComponent(handle)}`, undefined, { method: "DELETE" });
    } catch {
      /* reaped by the idle sweep as a fallback */
    }
  }

  function goToPairing() {
    document.getElementById("remote-arm")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Scroll to the Tailscale setup card — the destination for the "finish the
  // Tailscale step" hint under a gated "Pair a device" button.
  function goToTailscaleSetup() {
    document
      .getElementById("tailscale-setup")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function revoke(fingerprint: string) {
    if (
      !window.confirm(
        "Revoke this device now? It ends any live remote session and unpairs the device (it must scan a new QR to reconnect).",
      )
    ) {
      return;
    }
    try {
      await fetchJSON(`/api/remote/sessions/${fingerprint}`, undefined, { method: "DELETE" });
      sessions.reload();
      audit.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function revokeAll() {
    if (!confirmToken) return;
    try {
      await postJSON("/api/remote/sessions/revoke-all", confirmToken, {});
      sessions.reload();
      audit.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="space-y-4 p-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="inline-flex items-center text-[15px] font-semibold text-fg-1">
            Remote access
            <HelpInd id="glossary.connect_a_device" />
          </h1>
          <p className="mt-0.5 text-[12px] text-fg-3">
            Open this dashboard on your phone or laptop over your tailnet (Tailscale HTTPS, read-only).
            Turning it on/off and pairing devices are owner actions - they only work from this machine.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Pill variant={c?.enabled ? "success" : "neutral"}>{c?.enabled ? "armed" : "off"}</Pill>
          {c?.enabled && (
            <Pill variant={c?.ready ? "success" : "warn"}>{c?.ready ? "listener ready" : "restart to bind"}</Pill>
          )}
        </div>
      </div>

      {err && (
        <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
          {err}
        </div>
      )}

      {/* Honest disabled state: what enabling does + the restart requirement. */}
      {!c?.config_writable && (
        <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-[12px] text-fg-3">
          This dashboard was started without a writable config path, so remote access can't be armed from
          here. Use <code className="text-fg-2">observer remote enable --tailscale --host …</code> instead.
        </div>
      )}

      {/* Pairing reveal (§11) - one-time, in-memory, masked after ~60s. */}
      {pairing?.pairing_url && (
        <div id="pairing-reveal">
        <ChartShell
          title="Scan to pair this device"
          sub="Open this on the new phone or laptop - scan the QR, or copy the link and open it there. It works once and isn’t shown again (click “Pair a device” for a fresh one). Devices you’ve already paired are unaffected."
        >
          <div className="flex flex-col gap-4 p-1 sm:flex-row sm:items-start">
            <div className="flex-1 space-y-2">
              <div className="break-all rounded-2 border border-line-2 bg-bg-1 px-3 py-2 font-mono text-[12px] text-fg-2">
                {masked ? "•••••••••••••• (hidden - click Reveal)" : pairing.pairing_url}
              </div>
              <div className="flex gap-2">
                {masked ? (
                  <button
                    type="button"
                    onClick={() => setMasked(false)}
                    className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
                  >
                    Reveal
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => navigator.clipboard?.writeText(pairing.pairing_url ?? "")}
                    className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
                  >
                    Copy link
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setPairing(null)}
                  className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-3 hover:bg-bg-3"
                >
                  Done
                </button>
              </div>
              {/* Device-side prerequisite reminder - the QR is useless unless
                  the scanning device is on the same tailnet. */}
              <p className="text-[11px] leading-relaxed text-fg-3">
                Scan from a device that has Tailscale installed and is signed
                into the same tailnet - otherwise this link won’t load. Get the
                app: <DeviceTailscaleLinks />.
              </p>
              {pairing.tailscale_serve && (
                <div className="pt-2">
                  <div className="mb-1 text-[11px] text-fg-3">
                    Point Tailscale at the backend (run once on this machine), then restart the daemon:
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 break-all rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
                      {pairing.tailscale_serve}
                    </code>
                    <button
                      type="button"
                      onClick={() => navigator.clipboard?.writeText(pairing.tailscale_serve ?? "")}
                      className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              )}
            </div>
            {qr && !masked && (
              <img
                src={qr}
                alt="Pairing QR code"
                className="h-[180px] w-[180px] shrink-0 rounded-2 border border-line-2 bg-white p-1"
              />
            )}
          </div>
        </ChartShell>
        </div>
      )}

      {/* Arm / disarm controls. */}
      <div id="remote-arm">
      <ChartShell
        title={<TitleWithHelp text="Configuration" helpId="card.remote_config" />}
        sub={
          c?.enabled
            ? "Remote access is on. Pair a device to connect a phone or laptop - that takes effect immediately. Turning remote access off needs a daemon restart to unbind the listener."
            : "Turn on tailnet remote access. This mints a pairing secret and writes [remote] config; the listener binds on the next daemon restart."
        }
      >
        <div className="space-y-3 p-1 text-[12px]">
          {c?.enabled ? (
            <>
              <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                <Field label="mode" value={c.mode} />
                <Field label="backend" value={c.backend_addr || "-"} />
                <Field label="require TLS" value={String(c.require_tls)} />
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-fg-3">allow terminal</div>
                  <label
                    className="mt-0.5 inline-flex items-center gap-1.5"
                    title="Enables the execute-tier remote terminal - expands the remote execution authority. Takes effect after a daemon restart."
                  >
                    <input
                      type="checkbox"
                      checked={termOverride ?? c.allow_terminal}
                      disabled={busy !== null || !c.config_writable}
                      onChange={(e) => saveAllowTerminal(e.target.checked)}
                      className="h-3.5 w-3.5 disabled:opacity-50"
                    />
                    <span className="font-mono text-[12px] text-fg-2">
                      {busy === "allow-terminal"
                        ? "saving…"
                        : (termOverride ?? c.allow_terminal)
                          ? "on"
                          : "off"}
                    </span>
                  </label>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-fg-3">allow terminal view</div>
                  <label
                    className="mt-0.5 inline-flex items-center gap-1.5"
                    title="On by default - a switch you can turn OFF. Lets a paired device SEE (read-only) attach/resume terminals like Claude Code and Codex. Strictly weaker than Allow terminal: driving still needs Allow terminal + a per-terminal Grant. Hot-reloads; no restart."
                  >
                    <input
                      type="checkbox"
                      checked={termViewOverride ?? c.allow_terminal_view}
                      disabled={busy !== null || !c.config_writable}
                      onChange={(e) => saveAllowTerminalView(e.target.checked)}
                      className="h-3.5 w-3.5 disabled:opacity-50"
                    />
                    <span className="font-mono text-[12px] text-fg-2">
                      {busy === "allow-terminal-view"
                        ? "saving…"
                        : (termViewOverride ?? c.allow_terminal_view)
                          ? "on"
                          : "off"}
                    </span>
                  </label>
                </div>
                <Field label="rate limit/min" value={String(c.rate_limit_per_min ?? "-")} />
                <Field label="secret" value={c.secret_present ? c.secret_fingerprint : "none"} />
              </dl>
              {termMsg && (
                <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-fg-2">
                  {termMsg}
                </div>
              )}
              {termViewMsg && (
                <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-fg-2">
                  {termViewMsg}
                </div>
              )}
              <div>
                <div className="mb-1 text-[11px] text-fg-3">trusted hosts</div>
                <div className="flex flex-wrap gap-1">
                  {(c.trusted_hosts ?? []).map((h) => (
                    <Pill key={h} variant="neutral">
                      {h}
                    </Pill>
                  ))}
                  {(c.trusted_hosts ?? []).length === 0 && <span className="text-fg-3">none</span>}
                </div>
              </div>
              <div className="flex flex-wrap gap-2 pt-1">
                <button
                  type="button"
                  disabled={busy !== null || pairKnownUnreachable}
                  onClick={pairDevice}
                  title={
                    pairKnownUnreachable
                      ? `Pairing is unavailable until you ${pairMissingStep} - this dashboard isn't reachable over your tailnet yet.`
                      : undefined
                  }
                  className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50"
                >
                  {busy === "add-device" ? "generating QR…" : "Pair a device"}
                </button>
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => arm("disable")}
                  className="rounded-2 border border-line-2 bg-bg-2 px-3 py-1 text-[12px] text-fg-2 hover:bg-bg-3 disabled:opacity-50"
                >
                  {busy === "disable" ? "turning off…" : "Turn off remote access"}
                </button>
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={resetAndUnpair}
                  className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-1 text-[12px] text-danger hover:bg-danger/20 disabled:opacity-50"
                >
                  {busy === "rotate" ? "resetting…" : "Reset & unpair all devices"}
                </button>
              </div>
              {/* Honest pair-gating hint: name the exact missing Tailscale step
                  (known-unreachable → button disabled above) or warn that serve
                  status can't be verified (indeterminate → button stays live). */}
              {pairKnownUnreachable && (
                <p className="text-[11px] leading-relaxed text-warn">
                  Pairing is unavailable until this dashboard is reachable over
                  your tailnet - finish the Tailscale step:{" "}
                  <span className="font-medium">{pairMissingStep}</span>.{" "}
                  <button
                    type="button"
                    onClick={goToTailscaleSetup}
                    className="text-accent underline"
                  >
                    Go to Tailscale setup →
                  </button>
                </p>
              )}
              {!serveReachable && serveIndeterminate && (
                <p className="text-[11px] leading-relaxed text-fg-3">
                  Serve status can’t be verified on this Tailscale version - if
                  the pairing link doesn’t load on the device, finish the
                  Tailscale serve step.{" "}
                  <button
                    type="button"
                    onClick={goToTailscaleSetup}
                    className="text-accent underline"
                  >
                    Go to Tailscale setup →
                  </button>
                </p>
              )}
              <p className="text-[11px] leading-relaxed text-fg-3">
                <span className="font-medium text-fg-2">Pair a device</span> shows
                a one-time QR to connect a new phone or laptop - devices you’ve
                already paired stay connected (up to {c.max_sessions ?? 5} at
                once).{" "}
                <span className="font-medium text-fg-2">
                  Reset &amp; unpair all devices
                </span>{" "}
                disconnects everything and mints a new secret; only use it if a
                secret leaked.
              </p>
            </>
          ) : (
            <>
              <label className="block">
                <span className="mb-1 block text-[11px] text-fg-3">tailnet host (e.g. box.tailnet.ts.net)</span>
                <input
                  value={host}
                  onChange={(e) => {
                    setHost(e.target.value);
                    setHostEdited(true);
                  }}
                  placeholder="my-machine.tailnet-name.ts.net"
                  className="w-full rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[12px] text-fg-1 outline-none focus:border-accent"
                />
                {!host.trim() && (
                  <span className="mt-1 block text-[11px] text-warn">
                    {tailscale.data?.present
                      ? "No tailnet host detected - run `tailscale up`, or type the HTTPS host tailscale serve exposes."
                      : "Tailscale not detected - install it and run `tailscale up`, or type the HTTPS host manually."}
                  </span>
                )}
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={allowTerminal}
                  onChange={(e) => setAllowTerminal(e.target.checked)}
                />
                <span className="text-[12px] text-fg-2">
                  Also enable the execute-tier remote terminal (expands execution authority - leave off unless
                  you need it)
                </span>
              </label>
              <button
                type="button"
                disabled={busy !== null || !c?.config_writable || !host.trim()}
                onClick={() => arm("enable")}
                className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
              >
                {busy === "enable" ? "turning on…" : "Turn on remote access"}
              </button>
              <p className="text-[11px] text-fg-3">
                Turning on remote access writes config and mints a secret, but the listener binds only on
                the next daemon restart. After that, pairing a device takes effect instantly - no restart.
              </p>
            </>
          )}
        </div>
      </ChartShell>
      </div>

      {/* Terminal control for paired devices - grant a paired device control of
          a live terminal (mints a one-time capability + confirm code scoped to
          ONE device AND ONE terminal), revoke it, or take control back. Depends
          on the "allow terminal" enablement in Configuration above. Owner-local
          only. Moved here from the Terminals page so enablement → grant →
          standing reads as one flow. */}
      <RemoteTerminalControl
        sessions={(launchSessions.data?.sessions ?? []).filter((s) => s.token && !s.exited)}
        devices={sessions.data?.sessions ?? []}
        controllerLive={sessions.data?.controller_live ?? false}
        confirmToken={confirmToken}
        configWritable={c?.config_writable ?? false}
        onReload={() => {
          launchSessions.reload();
          sessions.reload();
        }}
        onTakeOver={(handle, tool, sessionId, hasProjectRoot) => {
          const arg = { tool, sessionId, hasProjectRoot } as unknown as DockSession;
          arg.token = handle;
          dock.launch(arg);
        }}
      />

      {/* Standing terminal-control access - opt-in, off by default, owner-local.
          Rendered below the single-use grant flow so the safer per-terminal path
          reads as the primary one. */}
      <StandingTerminalAccess confirmToken={confirmToken} />

      {/* Tailscale setup + detection (§D) - a guided state machine: install →
          log in → arm → serve → pair, each step naming what's next + the
          expected outcome. When serve needs the operator grant it runs in an
          embedded terminal (the sudo password is typed here, not in a bounced
          shell). */}
      <div id="tailscale-setup">
      <TailscaleCard
        data={tailscale.data}
        onServe={setupServe}
        serveBusy={serveBusy}
        serveResult={serveResult}
        onRunGrant={runOperatorGrant}
        grantBusy={grantBusy}
        grantHandle={grantHandle}
        grantErr={grantErr}
        onGrantStatus={onGrantTerminalStatus}
        onCancelGrant={() => void cancelSetupTerminal(grantHandle, () => setGrantHandle(null))}
        onRunLogin={runLogin}
        loginBusy={loginBusy}
        loginHandle={loginHandle}
        loginErr={loginErr}
        onLoginStatus={onLoginTerminalStatus}
        onCancelLogin={() => void cancelSetupTerminal(loginHandle, () => setLoginHandle(null))}
        onRunInstall={runInstall}
        installBusy={installBusy}
        installHandle={installHandle}
        installErr={installErr}
        onInstallStatus={onInstallTerminalStatus}
        onCancelInstall={() => void cancelSetupTerminal(installHandle, () => setInstallHandle(null))}
        onGoToPairing={goToPairing}
        onPairDevice={pairDevice}
      />
      </div>

      {/* Live device sessions. */}
      <ChartShell
        title="Paired devices"
        sub="Live device sessions. Revoke takes effect instantly - no restart."
        right={
          <button
            type="button"
            onClick={revokeAll}
            disabled={!sessions.data?.controller_live || (sessions.data?.sessions.length ?? 0) === 0}
            className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-40"
          >
            Revoke all
          </button>
        }
      >
        <div className="p-1 text-[12px]">
          {!sessions.data?.controller_live ? (
            <div className="text-fg-3">
              No live controller - the remote listener binds on the next daemon restart. Existing sessions
              will appear here once it is running.
            </div>
          ) : (sessions.data?.sessions.length ?? 0) === 0 ? (
            <div className="text-fg-3">No paired devices.</div>
          ) : (
            <table className="w-full text-left">
              <thead className="text-[11px] text-fg-3">
                <tr>
                  <th className="py-1">fingerprint</th>
                  <th className="py-1">created</th>
                  <th className="py-1">last seen</th>
                  <th className="py-1"></th>
                </tr>
              </thead>
              <tbody className="font-mono text-fg-2">
                {sessions.data?.sessions.map((s) => (
                  <tr key={s.fingerprint} className="border-t border-line-1">
                    <td className="py-1">{s.fingerprint}…</td>
                    <td className="py-1">{fmtDateTime(s.created_at)}</td>
                    <td className="py-1">{fmtDateTime(s.last_seen)}</td>
                    <td className="py-1 text-right">
                      <button
                        type="button"
                        onClick={() => revoke(s.fingerprint)}
                        className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3"
                      >
                        revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </ChartShell>

      {/* Audit tail. */}
      <ChartShell
        title="Access audit"
        sub="Recent remote-access + management events (metadata only). Not compliance-immutable - a local owner can edit the underlying SQLite."
      >
        <div className="max-h-[280px] overflow-auto p-1 text-[11px]">
          {(audit.data?.events.length ?? 0) === 0 ? (
            <div className="text-fg-3">No events yet.</div>
          ) : (
            <table className="w-full text-left font-mono">
              <thead className="text-fg-3">
                <tr>
                  <th className="py-1">ts</th>
                  <th className="py-1">kind</th>
                  <th className="py-1">principal</th>
                  <th className="py-1">decision</th>
                  <th className="py-1">route</th>
                  <th className="py-1">detail</th>
                </tr>
              </thead>
              <tbody className="text-fg-2">
                {audit.data?.events.map((e, i) => (
                  <tr key={i} className="border-t border-line-1">
                    <td className="py-1 pr-2">{fmtClock(e.ts)}</td>
                    <td className="py-1 pr-2">{e.kind}</td>
                    <td className="py-1 pr-2">{e.principal}</td>
                    <td className="py-1 pr-2">{e.decision}</td>
                    <td className="py-1 pr-2">{e.route}</td>
                    <td className="py-1">{e.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </ChartShell>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-fg-3">{label}</div>
      <div className="font-mono text-[12px] text-fg-2">{value}</div>
    </div>
  );
}

// TailscaleCard is the §D detect + guide surface. It is honest about the three
// first-class states (not installed / installed-but-logged-out / up) and about
// the fact that Observer never runs `tailscale up` or `tailscale serve` itself
// (daemon privileged-exec + the WSL-vs-Windows tailscaled split) - it only
// generates the command for the operator to run.
function TailscaleCard({
  data,
  onServe,
  serveBusy,
  serveResult,
  onRunGrant,
  grantBusy,
  grantHandle,
  grantErr,
  onGrantStatus,
  onCancelGrant,
  onRunLogin,
  loginBusy,
  loginHandle,
  loginErr,
  onLoginStatus,
  onCancelLogin,
  onRunInstall,
  installBusy,
  installHandle,
  installErr,
  onInstallStatus,
  onCancelInstall,
  onGoToPairing,
  onPairDevice,
}: {
  data: TailscaleStatus | null;
  onServe: () => void;
  serveBusy: boolean;
  serveResult: ServeResult | null;
  onRunGrant: () => void;
  grantBusy: boolean;
  grantHandle: string | null;
  grantErr: string | null;
  onGrantStatus: (s: LaunchTerminalStatus) => void;
  onCancelGrant: () => void;
  // Guided login (`tailscale up`) terminal (state 2).
  onRunLogin: () => void;
  loginBusy: boolean;
  loginHandle: string | null;
  loginErr: string | null;
  onLoginStatus: (s: LaunchTerminalStatus) => void;
  onCancelLogin: () => void;
  // Guided install (install.sh) terminal, Linux only (state 1).
  onRunInstall: () => void;
  installBusy: boolean;
  installHandle: string | null;
  installErr: string | null;
  onInstallStatus: (s: LaunchTerminalStatus) => void;
  onCancelInstall: () => void;
  // Scroll to the arm/config section (used before remote is on).
  onGoToPairing: () => void;
  // Actually mint a fresh QR (used once remote is on + reachable).
  onPairDevice: () => void;
}) {
  if (!data) {
    return (
      <ChartShell title="Tailscale" sub="Detecting…">
        <div className="p-1 text-[12px] text-fg-3">Checking `tailscale status`…</div>
      </ChartShell>
    );
  }

  // State 1: not installed.
  if (!data.present) {
    return (
      <ChartShell
        title="Tailscale"
        sub="Tailscale is how this dashboard reaches you over an encrypted tailnet (no ports opened to the public internet)."
        right={<Pill variant="warn">not installed</Pill>}
      >
        <div className="space-y-2 p-1 text-[12px] text-fg-3">
          <p>The `tailscale` CLI wasn't found on this machine.</p>

          {/* Primary (Linux): run the official install script in an embedded
              local-only terminal - the sudo password is typed here, not in a
              bounced shell. */}
          {!installHandle && (
            <div className="space-y-2 rounded-2 border border-accent/40 bg-accent/10 px-3 py-2">
              <p className="text-[11px] text-fg-2">
                Install it here: this opens a terminal and runs Tailscale's{" "}
                <a
                  href="https://tailscale.com/install.sh"
                  target="_blank"
                  rel="noreferrer"
                  className="text-accent underline"
                >
                  official install script
                </a>{" "}
                with <code>sudo</code> - enter your password when prompted. The command is fixed
                (<code>curl -fsSL https://tailscale.com/install.sh | sh</code>); SuperBased never runs a
                command you didn't start.
              </p>
              <button
                type="button"
                disabled={installBusy}
                onClick={onRunInstall}
                className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50"
              >
                {installBusy ? "opening terminal…" : "Install in a terminal"}
              </button>
              {installErr && <p className="text-[11px] text-danger">{installErr}</p>}
            </div>
          )}

          {/* The embedded install terminal (local-writer-only server-side). */}
          {installHandle && (
            <SetupTerminalEmbed
              handle={installHandle}
              label="tailscale install"
              hint="Enter your sudo password below. This terminal runs only the Tailscale install script and closes itself when done - the card then re-detects."
              onStatus={onInstallStatus}
              onCancel={onCancelInstall}
            />
          )}

          {/* Fallback: the manual download page. */}
          <a
            href={data.install_url}
            target="_blank"
            rel="noreferrer"
            className="inline-block rounded-2 border border-line-2 bg-bg-2 px-3 py-1 text-[12px] text-fg-2 hover:bg-bg-3"
          >
            …or download it yourself →
          </a>
          <p className="text-[11px] text-fg-3">
            On WSL2 the tailnet may be owned by a Windows-side Tailscale, but SuperBased needs the Linux binary
            the daemon itself lives beside - so installing here (in Linux) is still what SuperBased needs.
          </p>
        </div>
      </ChartShell>
    );
  }

  // State 2: installed but not logged in.
  if (!data.logged_in) {
    return (
      <ChartShell
        title="Tailscale"
        sub="Tailscale is installed but this node is not up. Log in from a terminal, then this card will show your tailnet host."
        right={<Pill variant="warn">{data.state || "not up"}</Pill>}
      >
        <div className="space-y-2 p-1 text-[12px]">
          {/* Primary: run `tailscale up` in an embedded local-only terminal.
              The auth URL it prints appears right here - open it on your phone
              to finish login. */}
          {!loginHandle && (
            <div className="space-y-2 rounded-2 border border-accent/40 bg-accent/10 px-3 py-2">
              <p className="text-[11px] text-fg-2">
                Log in here: this opens a terminal and runs <code>tailscale up</code>. It prints an
                authentication link - open it on your phone or browser to approve this machine. (The
                daemon runs it with <code>sudo</code> unless it is already root; enter your password if
                prompted.)
              </p>
              <button
                type="button"
                disabled={loginBusy}
                onClick={onRunLogin}
                className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50"
              >
                {loginBusy ? "opening terminal…" : "Log in in a terminal"}
              </button>
              {loginErr && <p className="text-[11px] text-danger">{loginErr}</p>}
            </div>
          )}

          {/* The embedded login terminal (local-writer-only server-side). */}
          {loginHandle && (
            <SetupTerminalEmbed
              handle={loginHandle}
              label="tailscale login"
              hint="This terminal runs `tailscale up`. When it prints an authentication link, open it on your phone/browser to approve - the card then re-detects."
              onStatus={onLoginStatus}
              onCancel={onCancelLogin}
            />
          )}

          {/* Fallback: run it yourself. */}
          <details className="text-[11px] text-fg-3">
            <summary className="cursor-pointer">…or run it yourself</summary>
            <div className="mt-1 flex items-center gap-2">
              <code className="flex-1 rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
                tailscale up
              </code>
              <CopyButton text="tailscale up" />
            </div>
            <p className="mt-1 text-[11px] text-fg-3">
              On WSL2 the tailnet may be owned by a Windows-side Tailscale - run it on the side that owns
              your tailnet if the embedded login doesn't apply.
            </p>
          </details>
        </div>
      </ChartShell>
    );
  }

  // State 3: up. A guided serve → pair flow. serveActive is the terminal
  // success state; hasBackend (serve_command present) means remote is armed and
  // a loopback backend port exists; needsPriv routes to the operator grant.
  const serveActive = Boolean(data.serve_configured);
  const hasBackend = Boolean(data.serve_command);
  const needsPriv = Boolean(serveResult?.needs_privilege);
  const tailnetURL = data.host ? `https://${data.host}/` : "";

  // Step pill: where you are on the ladder.
  const stepPill = serveActive ? (
    <Pill variant="success">reachable</Pill>
  ) : hasBackend ? (
    <Pill variant="neutral">serve not set</Pill>
  ) : (
    <Pill variant="warn">turn on first</Pill>
  );

  return (
    <ChartShell
      title="Tailscale"
      sub="This node is on your tailnet. Expose the dashboard over tailnet HTTPS, then pair a device."
      right={stepPill}
    >
      <div className="space-y-3 p-1 text-[12px]">
        <dl className="grid grid-cols-2 gap-2">
          <Field label="tailnet host" value={data.host || "-"} />
          <Field label="backend" value={data.backend_addr || "(turn on first)"} />
        </dl>

        {/* Terminal success: reachable → next step is pairing. */}
        {serveActive && (
          <div className="space-y-2 rounded-2 border border-success/40 bg-success/10 px-3 py-2">
            <p className="text-[12px] text-success">
              ✅ Serve is active - the dashboard is reachable over your tailnet at{" "}
              <a href={tailnetURL} target="_blank" rel="noreferrer" className="font-mono underline">
                {tailnetURL || "your tailnet host"}
              </a>
              .
            </p>
            <p className="text-[11px] text-fg-3">
              <strong className="text-fg-2">Next:</strong> click{" "}
              <span className="font-medium text-fg-2">Pair a device</span> to
              generate a one-time QR, then scan it on your phone - you’ll land on
              the read-only view of this dashboard. It takes effect immediately;
              devices you’ve already paired stay connected.
            </p>
            {/* Device-side prerequisite: the phone/other device must have
                Tailscale installed AND be signed into the SAME tailnet, or the
                pairing URL won't resolve at all. */}
            <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
              <p className="text-[11px] font-medium text-fg-2">On your phone or other device</p>
              <p className="mt-0.5 text-[11px] leading-relaxed text-fg-3">
                Install Tailscale on that device and sign in to the same tailnet
                {data.host ? (
                  <>
                    {" "}
                    as this machine (<span className="font-mono text-fg-2">{data.host}</span>)
                  </>
                ) : (
                  " account as this machine"
                )}{" "}
                - otherwise the dashboard URL simply won’t load. Get the app:{" "}
                <DeviceTailscaleLinks />.
              </p>
            </div>
            <button
              type="button"
              onClick={onPairDevice}
              className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25"
            >
              Pair a device →
            </button>
          </div>
        )}

        {/* Not yet serving: guide to arm (no backend) or run serve. */}
        {!serveActive && !hasBackend && (
          <p className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-fg-2">
            <strong>Step 1:</strong> arm remote access below to reserve a loopback backend port. Then this
            card can set up <code>tailscale serve</code> for you.{" "}
            <button type="button" onClick={onGoToPairing} className="text-accent underline">
              Go to arm →
            </button>
          </p>
        )}

        {!serveActive && hasBackend && (
          <div className="space-y-2">
            <p className="text-[11px] text-fg-3">
              <strong className="text-fg-2">Step:</strong> expose SuperBased over tailnet HTTPS. This runs{" "}
              <code>tailscale serve</code> for you - no terminal needed if the daemon has permission.
            </p>
            <button
              type="button"
              disabled={serveBusy}
              onClick={onServe}
              className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
            >
              {serveBusy ? "setting up serve…" : "Set up Tailscale serve for me"}
            </button>

            {/* Privilege wall → the one-time operator grant, run in-dashboard. */}
            {needsPriv && !grantHandle && (
              <div className="space-y-2 rounded-2 border border-warn/40 bg-warn/10 px-3 py-2">
                <p className="text-[11px] text-fg-2">
                  One-time permission needed. The daemon runs unprivileged, so Tailscale needs a{" "}
                  <em>one-time operator grant</em>. Click below to open a terminal right here and run{" "}
                  <code>sudo tailscale set --operator</code> - enter your password when prompted. After that,
                  serve works with no sudo, forever.
                </p>
                <button
                  type="button"
                  disabled={grantBusy}
                  onClick={onRunGrant}
                  className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
                >
                  {grantBusy ? "opening terminal…" : "Grant permission in a terminal"}
                </button>
                {grantErr && <p className="text-[11px] text-danger">{grantErr}</p>}
              </div>
            )}

            {/* The embedded operator-grant terminal (local-writer-only server-side). */}
            {grantHandle && (
              <SetupTerminalEmbed
                handle={grantHandle}
                label="tailscale setup"
                hint="Type your sudo password below. This terminal runs only the operator grant, and closes itself when done - serve then retries automatically."
                onStatus={onGrantStatus}
                onCancel={onCancelGrant}
              />
            )}

            {/* Control-plane consent Observer cannot perform. Approving HTTPS in
                the Tailscale admin console does NOT start serving — the user must
                come back and re-fire serve, so we say so explicitly and put a
                Retry button right here (re-runs the same serve POST, which also
                refetches status on completion). */}
            {serveResult?.enable_url && (
              <div className="space-y-1.5 rounded-2 border border-warn/40 bg-warn/10 px-3 py-2">
                <p className="text-[11px] text-warn">
                  One-time step SuperBased can't do for you - enable Serve in your Tailscale account:{" "}
                  <a
                    href={serveResult.enable_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-accent underline"
                  >
                    enable Serve →
                  </a>
                </p>
                <p className="text-[11px] text-fg-2">
                  After you approve HTTPS in the Tailscale admin console, click{" "}
                  <span className="font-medium">Set up Tailscale serve for me</span> again -
                  approval alone does not start serving.
                </p>
                <button
                  type="button"
                  disabled={serveBusy}
                  onClick={onServe}
                  className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-50"
                >
                  {serveBusy ? "retrying serve…" : "Retry serve"}
                </button>
              </div>
            )}
            {serveResult?.ok && (
              <p className="text-[11px] text-success">Serve is set - reachable over your tailnet.</p>
            )}
            {serveResult?.error && !needsPriv && (
              <p className="text-[11px] text-danger">serve failed: {serveResult.error}</p>
            )}

            {/* Fallback: the exact command, for platforms where daemon-run serve
                is unreliable (e.g. WSL2 ↔ Windows tailscaled). */}
            <details className="text-[11px] text-fg-3">
              <summary className="cursor-pointer">…or run it yourself</summary>
              <div className="mt-1 flex items-center gap-2">
                <code className="flex-1 break-all rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
                  {data.serve_command}
                </code>
                <CopyButton text={data.serve_command ?? ""} />
              </div>
            </details>
          </div>
        )}
      </div>
    </ChartShell>
  );
}

// SetupTerminalEmbed renders the shared in-dashboard xterm for a local-only
// setup PTY - the operator grant, `tailscale up` login, or the Tailscale
// install script. All three spawn a SpecSetup session server-side, which is
// local-writer-only: a paired remote principal can never acquire its writer
// lease, so the sudo password / auth flow is driven only from the owner-trusted
// loopback dashboard. Factored out of the operator-grant embed so login +
// install reuse the exact same widget rather than duplicating it.
function SetupTerminalEmbed({
  handle,
  label,
  hint,
  onStatus,
  onCancel,
}: {
  handle: string;
  label: string;
  hint: string;
  // Widened to the full LaunchTerminal Status union so the added
  // "reconnecting" state flows through unchanged (a setup PTY drops its socket
  // like any other; the terminal reconnects rather than tombstoning).
  onStatus: (s: LaunchTerminalStatus) => void;
  onCancel: () => void;
}) {
  return (
    <div className="space-y-1">
      <p className="text-[11px] text-fg-3">{hint}</p>
      <div className="h-[280px] overflow-hidden rounded-2 border border-line-2">
        <LaunchTerminal
          token={handle}
          tool={label}
          expanded
          onStatus={onStatus}
          onClose={onCancel}
          onMinimize={onCancel}
        />
      </div>
    </div>
  );
}

// DeviceTailscaleLinks renders the three Tailscale-app install links (the phone
// or other remote device must have Tailscale installed AND be signed into the
// SAME tailnet, or the dashboard URL simply won't resolve). Shared by the
// reachable Tailscale card and the pairing-QR reveal so the device-side
// prerequisite is stated in both places a user might act.
function DeviceTailscaleLinks() {
  return (
    <span className="inline-flex flex-wrap gap-x-2 gap-y-0.5">
      <a
        href="https://apps.apple.com/app/tailscale/id1470499037"
        target="_blank"
        rel="noreferrer"
        className="text-accent underline"
      >
        iOS
      </a>
      <a
        href="https://play.google.com/store/apps/details?id=com.tailscale.ipn"
        target="_blank"
        rel="noreferrer"
        className="text-accent underline"
      >
        Android
      </a>
      <a
        href="https://tailscale.com/download"
        target="_blank"
        rel="noreferrer"
        className="text-accent underline"
      >
        other platforms
      </a>
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard?.writeText(text)}
      className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
    >
      Copy
    </button>
  );
}

// RemoteTerminalControl is the owner-local terminal-control surface (moved here
// from the Terminals page). For each live terminal it shows the current
// controller (writer_holder) + viewer count and offers: Grant control (POST
// /api/remote/approve-execute → a one-time capability + confirm code, scoped to
// ONE device AND ONE terminal, masked/copied to convey), emergency Revoke
// control (DELETE the remote controller's device session), and Take over (open
// the terminal locally, which the backend treats as a local takeover that
// demotes the remote writer). Granting depends on the "allow terminal"
// enablement in Configuration above. All routes are owner-loopback-only, so this
// panel works only from the local dashboard.
function RemoteTerminalControl({
  sessions,
  devices,
  controllerLive,
  confirmToken,
  configWritable,
  onReload,
  onTakeOver,
}: {
  sessions: LaunchInfoWire[];
  devices: RemoteSessionRow[];
  controllerLive: boolean;
  configWritable: boolean;
  confirmToken: string;
  onReload: () => void;
  onTakeOver: (handle: string, tool: string, sessionId: string, hasProjectRoot: boolean) => void;
}) {
  const [pickDevice, setPickDevice] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Single active reveal (only one grant can be minted at a time), but rendered
  // PER-ROW: the panel appears under the terminal row whose token matches
  // reveal.handle, so the capability/confirm codes sit beside the exact terminal
  // the operator granted control on. Masked after ~60s; "shown once" semantics.
  const [reveal, setReveal] = useState<ApproveReveal | null>(null);
  const [masked, setMasked] = useState(false);
  const maskTimer = useRef<number | null>(null);

  // Mask the one-time capability + confirm after a timeout, like the pairing
  // reveal. The value survives in memory so "Reveal" re-shows it with no
  // server round-trip.
  useEffect(() => {
    if (reveal) {
      setMasked(false);
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
      maskTimer.current = window.setTimeout(() => setMasked(true), APPROVE_REVEAL_MS);
    }
    return () => {
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
    };
  }, [reveal]);

  async function approve(handle: string) {
    const device = pickDevice[handle] || devices[0]?.fingerprint || "";
    if (!device) {
      setErr("No paired device to grant - pair one in Configuration above first.");
      return;
    }
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("approve:" + handle);
    setErr(null);
    try {
      const res = await postJSON<{
        capability: string;
        confirm: string;
        device: string;
        handle: string;
      }>("/api/remote/approve-execute", confirmToken, { device, handle });
      setReveal({
        handle,
        device: res.device || device,
        capability: res.capability,
        confirm: res.confirm,
      });
      onReload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function revoke(fingerprint: string) {
    if (!fingerprint || fingerprint === "local") return;
    if (
      !window.confirm(
        "Revoke this device's control now? It ends the remote writer immediately and unpairs the device (it must scan a new QR to reconnect).",
      )
    ) {
      return;
    }
    setBusy("revoke:" + fingerprint);
    setErr(null);
    try {
      await fetchJSON(`/api/remote/sessions/${fingerprint}`, undefined, { method: "DELETE" });
      onReload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  function holderLabel(h?: string) {
    if (!h) return { text: "no controller", variant: "neutral" as const };
    if (h === "local") return { text: "you (local)", variant: "success" as const };
    return { text: `remote ${h}`, variant: "warn" as const };
  }

  return (
    <ChartShell
      title={<TitleWithHelp text="Terminal control for paired devices" helpId="card.terminal_control" />}
      sub="Grant a paired remote device control of a live terminal, revoke it, or take control back. Granting mints a ONE-TIME capability + confirm code scoped to ONE device AND ONE terminal (execute tier) - shown once; held only in memory (never written to disk) until it is consumed or expires. Depends on “allow terminal” enablement in Configuration above. Owner-local only."
      right={
        <Pill variant={controllerLive ? "success" : "neutral"}>
          {controllerLive ? "remote live" : "remote off"}
        </Pill>
      }
    >
      <div className="space-y-3 p-1 text-[12px]">
        {err && (
          <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-danger">
            {err}
          </div>
        )}

        {!configWritable && (
          <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">
            This dashboard has no writable config path, so terminal-control grants aren't available here.
          </div>
        )}
        {!controllerLive && (
          <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-warn">
            Remote access isn't live. Arm it and pair a device in <span className="font-medium">Configuration</span> above
            before you can grant terminal control.
          </div>
        )}

        {sessions.length === 0 ? (
          <div className="text-fg-3">No live terminals. Launch or continue a session to manage terminal control.</div>
        ) : (
          <table className="w-full text-left">
            <thead className="text-[11px] text-fg-3">
              <tr>
                <th className="py-1">terminal</th>
                <th className="py-1">controller</th>
                <th className="py-1">viewers</th>
                <th className="py-1">grant device</th>
                <th className="py-1"></th>
              </tr>
            </thead>
            <tbody className="text-fg-2">
              {sessions.map((s) => {
                const holder = holderLabel(s.writer_holder);
                const remoteHeld = !!s.writer_holder && s.writer_holder !== "local";
                return (
                  <Fragment key={s.token}>
                  <tr className="border-t border-line-1 align-top">
                    <td className="py-1.5">
                      <span className="font-mono text-fg-1">{s.subcommand || "terminal"}</span>
                      <span className="ml-1 font-mono text-[10.5px] text-fg-3" title={s.token}>
                        {fmtShortId(s.token, 8)}
                      </span>
                    </td>
                    <td className="py-1.5">
                      <Pill variant={holder.variant}>{holder.text}</Pill>
                    </td>
                    <td className="py-1.5">{s.viewers ?? 0}</td>
                    <td className="py-1.5">
                      <select
                        value={pickDevice[s.token] ?? ""}
                        disabled={!controllerLive || devices.length === 0}
                        onChange={(e) =>
                          setPickDevice((cur) => ({ ...cur, [s.token]: e.target.value }))
                        }
                        className="w-full rounded-2 border border-line-2 bg-bg-0 px-1.5 py-1 text-[11px] text-fg-1 disabled:opacity-40"
                      >
                        {devices.length === 0 && <option value="">no paired devices</option>}
                        {devices.length > 0 && <option value="">choose device…</option>}
                        {devices.map((d) => (
                          <option key={d.fingerprint} value={d.fingerprint}>
                            {d.fingerprint}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="py-1.5">
                      <div className="flex flex-wrap justify-end gap-1.5">
                        <button
                          type="button"
                          disabled={
                            !controllerLive ||
                            !configWritable ||
                            devices.length === 0 ||
                            busy !== null
                          }
                          onClick={() => approve(s.token)}
                          className="rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-[11px] font-medium text-accent hover:bg-accent/25 disabled:opacity-40"
                        >
                          {busy === "approve:" + s.token ? "granting…" : "Grant control"}
                        </button>
                        <button
                          type="button"
                          disabled={!remoteHeld || busy !== null}
                          title={
                            remoteHeld
                              ? "Revoke this device's control of this terminal now"
                              : "No remote device is currently controlling this terminal - writer control is single-use and ends when the device's socket closes (e.g. a phone refresh). To revoke a device entirely, use “Paired devices” below."
                          }
                          onClick={() => revoke(s.writer_holder as string)}
                          className="rounded-2 border border-danger/40 bg-danger/10 px-2 py-0.5 text-[11px] text-danger hover:bg-danger/20 disabled:opacity-40"
                        >
                          {busy === "revoke:" + s.writer_holder ? "revoking…" : "Revoke"}
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            onTakeOver(s.token, s.subcommand || "terminal", s.session_id || "", !!s.has_project_root)
                          }
                          title="Open this terminal locally - you take control back (demotes any remote writer)"
                          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-0.5 text-[11px] text-fg-2 hover:bg-bg-3"
                        >
                          Take over
                        </button>
                      </div>
                    </td>
                  </tr>
                  {/* Per-row one-time reveal — rendered under the exact terminal
                      the operator granted control on. Masked after ~60s. */}
                  {reveal?.handle === s.token && (
                    <tr className="border-t border-line-1">
                      <td colSpan={5} className="py-2">
                        <div className="space-y-2 rounded-2 border border-accent/40 bg-accent/10 p-3">
                          <div className="text-[11px] text-fg-2">
                            Convey BOTH values to device <span className="font-mono">{reveal.device}</span> -
                            they grant that ONE device control of THIS terminal{" "}
                            <span className="font-mono" title={reveal.handle}>{fmtShortId(reveal.handle, 8)}</span> (execute tier),
                            once. Shown only now.
                          </div>
                          <CopyField label="capability" value={reveal.capability} masked={masked} />
                          <CopyField label="confirm code" value={reveal.confirm} masked={masked} />
                          <div className="flex gap-2">
                            {masked ? (
                              <button
                                type="button"
                                onClick={() => setMasked(false)}
                                className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
                              >
                                Reveal
                              </button>
                            ) : null}
                            <button
                              type="button"
                              onClick={() => setReveal(null)}
                              className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-3 hover:bg-bg-3"
                            >
                              Done
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}

        {/* Paired devices. A device is revocable whenever it is paired — NOT
            only while it happens to hold a live writer lease (writer leases are
            single-use and die on a phone refresh, so the per-terminal Revoke
            above is disabled most of the time). Revoking a device here ends any
            control it holds AND unpairs it. */}
        <div className="rounded-2 border border-line-2 bg-bg-1 p-3">
          <div className="mb-1 text-[11px] font-medium text-fg-2">Paired devices</div>
          <div className="mb-2 text-[11px] text-fg-3">
            Revoke a device to unpair it and immediately end any terminal control it holds. A revoked
            device must scan a new QR to reconnect.
          </div>
          {devices.length === 0 ? (
            <div className="text-[11px] text-fg-3">No paired devices.</div>
          ) : (
            <div className="space-y-1">
              {devices.map((d) => (
                <div key={d.fingerprint} className="flex items-center gap-2">
                  <code className="flex-1 rounded-2 border border-line-2 bg-bg-0 px-2 py-1 font-mono text-[11px] text-fg-2">
                    {d.fingerprint}
                  </code>
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => revoke(d.fingerprint)}
                    title="Unpair this device and end any control it holds now"
                    className="rounded-2 border border-danger/40 bg-danger/10 px-2 py-1 text-[11px] text-danger hover:bg-danger/20 disabled:opacity-40"
                  >
                    {busy === "revoke:" + d.fingerprint ? "revoking…" : "Revoke device"}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </ChartShell>
  );
}

// StandingTerminalAccess is the OPT-IN standing terminal-control surface: mint a
// single durable, hashed-at-rest secret that lets a paired device re-acquire
// writer control across websocket refreshes WITHOUT a fresh per-terminal Grant
// each time. DEFAULT OFF, with a firm security warning: standing access is a
// strict superset of risk over the single-use grant flow (anyone with the secret
// + a paired session controls EVERY terminal). Owner-local only. The raw secret
// is shown ONCE on mint and stored hashed at rest; revoke kills the secret AND
// every writer holding through it.
function StandingTerminalAccess({
  confirmToken,
}: {
  confirmToken: string;
}) {
  const status = useApi<StandingStatus>("/api/remote/standing-terminal", undefined, [], {
    refreshMs: 20_000,
  });
  const st = status.data;
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [masked, setMasked] = useState(false);
  const maskTimer = useRef<number | null>(null);

  // Mask the one-time secret after a timeout (like the pairing reveal). The
  // value survives in memory so "Reveal" re-shows it with no round-trip.
  useEffect(() => {
    if (secret) {
      setMasked(false);
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
      maskTimer.current = window.setTimeout(() => setMasked(true), APPROVE_REVEAL_MS);
    }
    return () => {
      if (maskTimer.current) window.clearTimeout(maskTimer.current);
    };
  }, [secret]);

  const canManage = !!st?.config_writable;
  const prereqOK = !!st?.remote_enabled && !!st?.allow_terminal;
  // Honest disabled copy: name the exact missing dependency. Both prerequisites
  // now live on THIS page (Configuration above), so point there.
  const disabledReason = !canManage
    ? "This dashboard has no writable config path, so standing access can't be managed here."
    : !st?.remote_enabled
      ? "Remote access is off. Arm it in Configuration above first."
      : !st?.allow_terminal
        ? "“Allow terminal” is off. Turn it on in Configuration above first - standing access only grants what allow terminal permits."
        : "";

  async function mint() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("mint");
    setErr(null);
    try {
      const res = await postJSON<{ secret: string }>(
        "/api/remote/standing-terminal/mint",
        confirmToken,
        {},
      );
      setSecret(res.secret);
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    if (
      !window.confirm(
        "Revoke standing terminal-control access? This deletes the secret and immediately drops every remote writer that acquired control through it.",
      )
    ) {
      return;
    }
    setBusy("revoke");
    setErr(null);
    try {
      await postJSON("/api/remote/standing-terminal/revoke", confirmToken, {});
      setSecret(null);
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  // saveRevokeOnTakeover flips [remote].revoke_standing_on_takeover — the opt-in
  // hardening that makes a desktop takeover of a standing-secret writer also
  // revoke the standing secret. Default off (seamless). Live immediately.
  async function saveRevokeOnTakeover(next: boolean) {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("revoke-on-takeover");
    setErr(null);
    try {
      await postJSON("/api/remote/standing-revoke-on-takeover", confirmToken, {
        revoke_standing_on_takeover: next,
      });
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  // saveAllowRemoteTakeover flips the default-on post-authentication lease
  // policy. Credential validation is unchanged; the live controller hot-reloads.
  async function saveAllowRemoteTakeover(next: boolean) {
    if (!confirmToken) {
      setErr("No confirm token - reload the page.");
      return;
    }
    setBusy("allow-remote-takeover");
    setErr(null);
    try {
      await postJSON("/api/remote/allow-remote-takeover", confirmToken, {
        allow_remote_terminal_takeover: next,
      });
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  return (
    <ChartShell
      title={<TitleWithHelp text="Standing terminal-control access (advanced)" helpId="card.standing_terminal" />}
      sub="Opt-in: a single durable secret that lets a paired device keep terminal control across page refreshes, without re-granting each terminal. Off by default - the per-terminal single-use grants above are the safer path. Owner-local only."
      right={
        <Pill variant={st?.enabled ? "warn" : "neutral"}>
          {st?.enabled ? "standing access ON" : "standing access off"}
        </Pill>
      }
    >
      <div className="space-y-3 p-1 text-[12px]">
        {err && (
          <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-danger">{err}</div>
        )}

        {/* The firm security warning — shown verbatim from the server. */}
        <div className="rounded-2 border border-warn/40 bg-warn/10 px-3 py-2 text-[11px] text-warn">
          <span className="font-medium">Security warning. </span>
          {st?.warning ??
            "Standing access means anyone who has this secret AND a paired remote session can control EVERY live terminal, across refreshes, until you revoke it. Per-terminal single-use grants are safer."}
        </div>

        {disabledReason && (
          <div className="rounded-2 border border-line-2 bg-bg-2 px-3 py-2 text-fg-3">{disabledReason}</div>
        )}

        {/* One-time secret reveal — masked after ~60s. */}
        {secret && (
          <div className="space-y-2 rounded-2 border border-accent/40 bg-accent/10 p-3">
            <div className="text-[11px] text-fg-2">
              Standing secret - shown ONCE. Convey it to the device you want to grant standing control. A
              device may store it in its browser localStorage so control survives a refresh; that means the
              secret lives on that device - treat it like a password and revoke it if the device is lost.
            </div>
            <CopyField label="standing secret" value={secret} masked={masked} />
            <div className="flex gap-2">
              {masked && (
                <button
                  type="button"
                  onClick={() => setMasked(false)}
                  className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
                >
                  Reveal
                </button>
              )}
              <button
                type="button"
                onClick={() => setSecret(null)}
                className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-3 hover:bg-bg-3"
              >
                Done
              </button>
            </div>
          </div>
        )}

        {st?.enabled && st?.secret_present && (
          <div className="text-[11px] text-fg-3">
            A standing secret is provisioned (<span className="font-mono">{st.secret_fingerprint}</span>). The
            raw secret is never re-shown - rotate to issue a fresh one, or revoke to turn standing access off.
          </div>
        )}

        {st?.remote_enabled && (
          <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
            <input
              type="checkbox"
              className="mt-[2px]"
              checked={st?.allow_remote_terminal_takeover ?? true}
              disabled={!canManage || busy !== null}
              onChange={(e) => void saveAllowRemoteTakeover(e.target.checked)}
            />
            <span>
              <span className="font-medium text-fg-2">Allow remote devices to take over control</span>
              <span className="block text-[11px] text-fg-3">
                On (default): an authenticated remote device with a valid one-time grant or standing secret
                can take control from the native/local seat or another remote device; the losing seat stays
                connected read-only and can take control back. Off: a held terminal refuses the remote
                acquire. A refused one-time grant is consumed, so a fresh grant is required. Live
                immediately; no restart.
              </span>
            </span>
          </label>
        )}

        {st?.remote_enabled && (
          <label className="flex items-start gap-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
            <input
              type="checkbox"
              className="mt-[2px]"
              checked={!!st?.revoke_on_takeover}
              disabled={!canManage || busy !== null}
              onChange={(e) => void saveRevokeOnTakeover(e.target.checked)}
            />
            <span>
              <span className="font-medium text-fg-2">Revoke standing access when this desktop takes over</span>
              <span className="block text-[11px] text-fg-3">
                Off (default): taking over a remote writer only revokes its live control - the paired device
                can re-take control later (seamless). On: a desktop takeover of a writer that held control
                through the standing secret ALSO revokes the secret itself - the device must be granted a
                fresh secret to regain standing control. Live immediately; no restart.
              </span>
            </span>
          </label>
        )}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button
            type="button"
            disabled={!prereqOK || !canManage || busy !== null}
            onClick={mint}
            className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] text-accent hover:bg-accent/25 disabled:opacity-40"
          >
            {busy === "mint"
              ? st?.enabled
                ? "rotating…"
                : "enabling…"
              : st?.enabled
                ? "Rotate standing secret"
                : "Enable standing access"}
          </button>
          {st?.enabled && (
            <button
              type="button"
              disabled={!canManage || busy !== null}
              onClick={revoke}
              className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-1 text-[12px] text-danger hover:bg-danger/20 disabled:opacity-40"
            >
              {busy === "revoke" ? "revoking…" : "Revoke standing access"}
            </button>
          )}
        </div>
      </div>
    </ChartShell>
  );
}

// CopyField renders a masked-or-shown secret with a copy button — the same
// convey-once discipline as the pairing reveal.
function CopyField({
  label,
  value,
  masked,
}: {
  label: string;
  value: string;
  masked: boolean;
}) {
  return (
    <div>
      <div className="mb-0.5 text-[10px] uppercase tracking-wide text-fg-3">{label}</div>
      <div className="flex items-center gap-2">
        <code className="flex-1 break-all rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
          {masked ? "•••••••••••••• (hidden - click Reveal)" : value}
        </code>
        <button
          type="button"
          onClick={() => navigator.clipboard?.writeText(value)}
          className="rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
        >
          Copy
        </button>
      </div>
    </div>
  );
}

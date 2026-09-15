import { useState } from "react";
import { Pill } from "@/components/primitives";
import {
  LaunchTerminal,
  type Status as LaunchTerminalStatus,
} from "@/components/LaunchTerminal";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { markRestartPending } from "@/lib/restartPending";

// ETWCapturerCard — the dashboard-driven setup surface for the ELEVATED
// Windows ETW process capturer (docs/plans/etw-dashboard-setup-plan-2026-07-27.md
// §E5). It is the third instance of the Tailscale guided-setup pattern, after
// the tailnet card and "Install in terminal": one detection endpoint returning
// first-class STATES, one card with N mutually exclusive states, a primary
// "do it for me" button, and a copyable fallback behind <details>.
//
// What it is setting up: a Windows Scheduled Task that runs
// `observer process-bridge --etw --connect …` at logon with /RL HIGHEST. ETW
// session control (StartTraceW) always requires elevation, so without that task
// the per-process NETWORK BYTE totals are simply absent — network accounting
// reports "off" rather than fabricating numbers.
//
// THE ONE THING THIS CARD CANNOT DO FOR YOU is approve the Windows User Account
// Control prompt. Nothing suppresses UAC; the prompt IS the security boundary.
// The button brokers it — the daemon spawns a fixed PowerShell
// `Start-Process … -Verb RunAs` in a local-only terminal — and the copyable
// command stays available for a host where no one is sitting at the console.
// That is the same shape as the Tailscale card's `sudo tailscale set --operator`
// step, which also cannot be taken silently.

const STATUS_ENDPOINT = "/api/process/etw/status";
// ~20s, the Tailscale card's cadence. The status probe shells out to
// `schtasks /Query`, so a tighter poll would spend a Windows interop exec every
// few seconds for a value that changes about once ever.
const POLL_MS = 20_000;

type Probe = "unknown" | "absent" | "present";

type CapturerDecode = {
  dropped: number;
  unsupported_version: number;
  // The positive half. `decoded` is the only number that says the decoder
  // measured anything; a large `ignored` is normal and is NOT a fault.
  decoded: number;
  ignored: number;
  // `healthy` means "refused nothing" — it is not a pass on its own, because a
  // decoder that accepted nothing also refused nothing.
  healthy: boolean;
  // The renumbered-provider suspicion: events arrived, none was classified as
  // data, none was refused. Derived daemon-side so this card and /metrics and
  // `observer doctor` cannot disagree.
  nothing_classified: boolean;
  reported_at: string;
  line?: string;
};

type Transport = {
  addr?: string;
  connections: number;
  auth_failures: number;
  last_auth_error?: string;
  last_auth_error_class?: string;
  connected: boolean;
  last_connect_at?: string;
  last_disconnect_at?: string;
  capturer_decode: CapturerDecode | null;
};

type Health = {
  pid: number;
  reported_at: string;
  age_seconds: number;
  stale: boolean;
  backend: string;
  backend_up: boolean;
  network_accounting_mode: string;
  network_accounting_reason?: string;
  transport_state: string;
  transport_unavailable_reason?: string;
  transport: Transport | null;
  transport_line?: string;
};

// ETWStatus mirrors dashboard.etwStatusResponse exactly. The five states are
// the planner's own vocabulary; `plan_detectable: false` is the separate
// "no plan could be produced" signal, kept out of the state enum so a config
// we could not read never masquerades as a probe result.
type ETWStatus = {
  task_name: string;
  // Does this host have a Windows Task Scheduler at all — independent of
  // whether the feature is on. It is what decides whether this card renders,
  // because `state` cannot answer it: the planner reports the DISABLED skip
  // first, so the default install looks identical on Windows and on Linux.
  schtasks_present: boolean;
  plan_detectable: boolean;
  plan_undetectable_reason?: string;
  state?: "skip" | "present" | "manual" | "unknown" | "blocked";
  skip_reason?: "etw_disabled" | "no_schtasks";
  enabled: boolean;
  listen_addr?: string;
  probe: Probe;
  probe_error?: string;
  command?: string;
  command_cmd_shell_only: boolean;
  reason?: string;
  notes?: string[];
  // True when this response was served to a REMOTELY-EXPOSED caller and the
  // fields that describe the machine — the command, the notes, and every
  // reason that quotes a filesystem path — were withheld. It is stated rather
  // than left implicit so the card can say WHY it is showing less, instead of
  // rendering an empty panel.
  local_detail_withheld?: boolean;
  health: Health | null;
  health_reason?: string;
};

type RegisterResult = {
  handle: string;
  task_name: string;
  command: string;
  notes?: string[];
  uac_required: boolean;
  plan_state: string;
  // True when this POST started NOTHING: an elevated registration terminal was
  // already live and the daemon handed back that one. Every other field then
  // describes THAT run — the command it is actually running, which may differ
  // from the plan this click computed if config changed in between.
  already_running?: boolean;
};

export function ETWCapturerCard() {
  const status = useApi<ETWStatus>(STATUS_ENDPOINT, undefined, [], {
    refreshMs: POLL_MS,
  });
  const [handle, setHandle] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [enableMsg, setEnableMsg] = useState<string | null>(null);
  const [reattached, setReattached] = useState(false);

  const data = status.data;

  // register spawns the elevation broker. The server owns every byte of the
  // argv; this request carries only the confirm token, exactly like the
  // Tailscale setup POSTs and /api/terminal/install.
  async function register() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      const cfg = await fetchJSON<{ confirm_token?: string }>("/api/remote/config");
      const ctok = cfg.confirm_token ?? "";
      if (!ctok) {
        setErr("No confirm token - reload the page.");
        return;
      }
      const res = await fetchJSON<RegisterResult>("/api/process/etw/register", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Observer-Confirm": ctok },
        body: "{}",
      });
      // already_running means the daemon handed back a registration terminal
      // that was ALREADY live (its labelled setup ops are idempotent), so this
      // click started nothing and the terminal below is the earlier run — very
      // likely still sitting on its UAC prompt. Say so rather than let the
      // operator think a second prompt is coming.
      setReattached(Boolean(res.already_running));
      setHandle(res.handle);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // enableETW writes through the ordinary config-section seam — the ONE owner
  // of config writes — with a PARTIAL body, so every key it does not name
  // (listen address, token path, handshake timeout, backend, poll rate) is
  // preserved rather than zeroed.
  //
  // It sets BOTH switches, and the button copy says so. [observer.process.etw]
  // alone is not enough: runProcessObserver returns early when
  // [observer.process].enabled is false, so the whole subsystem — the accept
  // listener included — is never constructed. Setting only the ETW key would
  // produce a card that reports "registered, waiting for a capturer" forever
  // while nothing was ever listening. Both assignments are idempotent.
  //
  // The listener binds at daemon start, so this honestly reports that a restart
  // is needed and feeds the global restart-pending banner.
  async function enableETW() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    setEnableMsg(null);
    try {
      const res = await fetchJSON<{ restart_required?: boolean }>(
        "/api/config/section/process",
        undefined,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ Enabled: true, ETW: { Enabled: true } }),
        },
      );
      if (res.restart_required) markRestartPending("process");
      setEnableMsg(
        res.restart_required
          ? "Saved. Restart the observer daemon - the accept listener binds at start - then come back here to register the task."
          : "Saved.",
      );
      status.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  // On child exit, drop the terminal and RE-DETECT. A successful run flips the
  // card to "present"; a dismissed UAC prompt leaves it exactly where it was,
  // with the copyable command intact — which is the honest outcome, not an
  // error state.
  function onTerminalStatus(s: LaunchTerminalStatus) {
    if (s === "exited") {
      setHandle(null);
      setReattached(false);
      status.reload();
    }
  }

  // cancel TERMINATES the setup PTY. Dropping React state alone would only
  // detach the viewer — the daemon deliberately keeps a setup child alive for
  // reconnect — orphaning a PowerShell sitting on an unanswered UAC prompt.
  async function cancel() {
    const h = handle;
    setHandle(null);
    setReattached(false);
    if (!h) return;
    try {
      await fetchJSON(`/api/launch/${encodeURIComponent(h)}`, undefined, { method: "DELETE" });
    } catch {
      /* the idle sweep reaps it as a fallback */
    }
    status.reload();
  }

  // Nothing known yet: render nothing rather than a "checking…" strip. On the
  // overwhelmingly common host (Linux/macOS, no Task Scheduler) the settled
  // answer is ALSO nothing, so a skeleton would only ever be a flash of a card
  // that does not apply.
  if (!data) return null;

  // THE RENDER GATE. No Task Scheduler on this host ⇒ this whole feature does
  // not apply, so the card renders nothing at all. This is checked BEFORE the
  // state switch on purpose: the planner reports the "feature is off" skip
  // first (correctly — that is the actionable reason on Windows), so a
  // default-config Linux laptop and a default-config Windows box arrive here
  // with the identical state, and only this flag tells them apart. Gating on
  // the state alone would put a "Turn on Windows process telemetry" button in
  // front of every Linux and macOS user.
  if (!data.schtasks_present) return null;

  // No plan could be produced at all. This is not "unknown" — that word is
  // reserved for a schtasks probe that ran and could not answer — so it gets
  // its own honest panel naming what stopped us.
  if (!data.plan_detectable) {
    return (
      <Shell
        badge={<Pill variant="warn">not determined</Pill>}
        subtitle="The setup plan could not be composed, so this card cannot say whether the elevated capturer applies to this machine."
      >
        <Note tone="warn">{data.plan_undetectable_reason}</Note>
        <HealthBlock data={data} />
      </Shell>
    );
  }

  // Belt and braces: the planner's own "not a Windows host" skip. Unreachable
  // past the render gate above (it implies schtasks_present is false), kept
  // because the two facts are computed on different paths and this state must
  // never render even if they ever disagree.
  if (data.state === "skip" && data.skip_reason === "no_schtasks") return null;

  // The feed is switched off. Explain what it buys, then offer the toggle.
  if (data.state === "skip") {
    return (
      <Shell badge={<Pill variant="neutral">off</Pill>} subtitle={SUBTITLE}>
        <p className="text-[11.5px] leading-relaxed text-fg-2">
          Windows process telemetry is off. With it on, SuperBased can attribute{" "}
          <strong className="text-fg-0">per-process network bytes</strong> to the AI-tool
          session that caused them - the one thing the zero-privilege poll backend cannot
          see, because reading it needs an ETW trace session and ETW session control always
          requires elevation. Without it, network accounting reports{" "}
          <code className={CODE}>off</code> rather than guessing.
        </p>
        <p className="text-[11px] leading-relaxed text-fg-3">
          The button writes two keys:{" "}
          <code className={CODE}>[observer.process].enabled</code> (the master switch - the
          whole subsystem, listener included, is skipped without it) and{" "}
          <code className={CODE}>[observer.process.etw].enabled</code>, which opens the
          loopback listener the elevated capturer dials into. Nothing else changes: existing
          capture keeps running exactly as it does now, and an install where no capturer ever
          connects behaves identically to one without the feature. Leave the{" "}
          <strong className="text-fg-1">Backend</strong> selector above on{" "}
          <code className={CODE}>auto</code> unless you know otherwise -{" "}
          <code className={CODE}>off</code> disables capture regardless of these keys.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          {data.local_detail_withheld ? (
            <WithheldNote data={data} />
          ) : (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={enableETW}
                className={PRIMARY_BTN}
              >
                {busy ? "saving…" : "Turn on Windows process telemetry"}
              </button>
              {enableMsg && <span className="text-[11.5px] text-success">{enableMsg}</span>}
              {err && <span className="text-[11.5px] text-danger">{err}</span>}
            </>
          )}
        </div>
      </Shell>
    );
  }

  // Blocked: a dependency is missing and no command can be composed with
  // everything resolved. Deliberately NO command — a copyable line with a
  // placeholder in it is worse than none.
  if (data.state === "blocked") {
    return (
      <Shell
        badge={<Pill variant="warn">blocked</Pill>}
        subtitle="The elevated capturer cannot be set up yet - one dependency is missing."
      >
        {data.reason ? <Note tone="warn">{data.reason}</Note> : <WithheldNote data={data} />}
        <p className="text-[11px] leading-relaxed text-fg-3">
          Nothing was registered and nothing is broken: process capture keeps running
          without the ETW feed, and its absence shows up as{" "}
          <code className={CODE}>network_accounting_mode=off</code> rather than as invented
          byte counters. Fix the item above and this card will offer the one-click setup.
        </p>
        <HealthBlock data={data} />
      </Shell>
    );
  }

  // Registered. Report on the LINK, not on the registration — a task that
  // exists and a capturer that is streaming are two different facts.
  if (data.state === "present") {
    return (
      <Shell
        badge={<Pill variant="success">task registered</Pill>}
        subtitle={`Scheduled Task "${data.task_name}" exists and was left untouched.`}
      >
        <HealthBlock data={data} />
        <details className="group text-[11px] text-fg-3">
          <summary className="cursor-pointer">Manage the task yourself</summary>
          <div className="mt-2 space-y-2">
            <CommandRow label="verify" text={`schtasks.exe /Query /TN "${data.task_name}" /V /FO LIST`} />
            <CommandRow label="start now" text={`schtasks.exe /Run /TN "${data.task_name}"`} />
            <CommandRow label="remove" text={`schtasks.exe /Delete /TN "${data.task_name}" /F`} />
            <p className="text-[11px] text-fg-3">
              Delete and remove both need an elevated Windows shell. SuperBased never
              reconfigures or replaces a task you already have.
            </p>
          </div>
        </details>
      </Shell>
    );
  }

  // manual / unknown — the actionable state. `unknown` keeps its hedge: the
  // read-only probe could not tell us either way, so the copy says "run it if
  // the task is absent" and never claims the task is missing.
  const hedged = data.state === "unknown";
  return (
    <Shell
      badge={<Pill variant={hedged ? "warn" : "info"}>{hedged ? "not confirmed" : "not registered"}</Pill>}
      subtitle={SUBTITLE}
    >
      {hedged ? (
        <Note tone="warn">
          <span>
            The read-only <code className={CODE}>schtasks /Query</code> probe could not tell
            us whether the task exists
            {data.probe_error ? <> - {data.probe_error}</> : null}. Treat the step below as
            &ldquo;do it if the task is absent&rdquo;: the command carries no{" "}
            <code className={CODE}>/F</code>, so schtasks refuses to overwrite a task that
            already exists rather than clobbering it.
          </span>
        </Note>
      ) : (
        <p className="text-[11.5px] leading-relaxed text-fg-2">
          Scheduled Task <code className={CODE}>{data.task_name}</code> is not registered, so
          the elevated capturer never starts and per-process network bytes are unavailable.
          One step fixes it.
        </p>
      )}

      {!handle && !data.local_detail_withheld && (
        <div className="space-y-2 rounded-2 border border-accent/40 bg-accent/10 px-3 py-2">
          <p className="text-[11px] leading-relaxed text-fg-2">
            <strong className="text-fg-0">What happens:</strong> SuperBased opens a terminal
            below and runs a fixed command that asks Windows to elevate. Windows shows a{" "}
            <strong className="text-fg-0">User Account Control prompt</strong> - that prompt
            cannot be suppressed and must be approved{" "}
            <strong className="text-fg-0">on this machine</strong>, at its console. Approve
            it and the task is registered; dismiss it and nothing is registered and this card
            comes straight back with the command below.
          </p>
          <button type="button" disabled={busy} onClick={register} className={PRIMARY_BTN}>
            {busy ? "opening terminal…" : "Set it up for me"}
          </button>
          {err && <p className="text-[11px] text-danger">{err}</p>}
          <p className="text-[10.5px] text-fg-3">
            No UAC prompt can be answered on a headless machine or over a remote session -
            this button is owner-local only. Use the command below there.
          </p>
        </div>
      )}

      {!handle && data.local_detail_withheld && <WithheldNote data={data} />}

      {handle && (
        <div className="space-y-1">
          {reattached && (
            <Note tone="info">
              A registration terminal was <strong className="text-fg-0">already running</strong>,
              so nothing new was started - this is that run, and its Windows UAC prompt is
              probably still waiting. Approve or dismiss it there.
            </Note>
          )}
          <p className="text-[11px] text-fg-3">
            Approve the Windows UAC prompt to continue. This terminal runs only the elevated{" "}
            <code className={CODE}>schtasks /Create</code> and reports its exit code - it
            cannot show the elevated window&rsquo;s own output, because an elevated process
            does not share this console.
          </p>
          <div className="h-[240px] overflow-hidden rounded-2 border border-line-2">
            <LaunchTerminal
              token={handle}
              tool="etw task registration"
              expanded
              onStatus={onTerminalStatus}
              onClose={() => void cancel()}
              onMinimize={() => void cancel()}
            />
          </div>
        </div>
      )}

      {data.command && (
        <details className="group text-[11px] text-fg-3">
          <summary className="cursor-pointer">…or run it yourself, once, in an elevated Windows shell</summary>
          <div className="mt-2 space-y-2">
            <p className="text-[11px] leading-relaxed text-fg-3">
              {data.command_cmd_shell_only ? (
                <>
                  Run this in an elevated <strong className="text-fg-1">Command Prompt</strong>{" "}
                  - not PowerShell. Your token path contains a space, which forces the{" "}
                  <code className={CODE}>\&quot;</code> escaping PowerShell rejects.
                </>
              ) : (
                <>
                  Either an elevated Command Prompt or PowerShell (right-click → Run as
                  administrator). The single quotes are load-bearing: schtasks normalises them
                  into the correct quoted action, and they are the only form that parses in
                  both shells. Paste it as-is.
                </>
              )}
            </p>
            <CommandRow label="register" text={data.command} />
            {data.notes && data.notes.length > 0 && (
              <ul className="list-disc space-y-1 pl-4 text-[11px] leading-relaxed text-fg-3">
                {data.notes.map((n) => (
                  <li key={n} className="whitespace-pre-wrap">
                    {n}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </details>
      )}

      <HealthBlock data={data} />
    </Shell>
  );
}

const SUBTITLE =
  "An elevated Windows Scheduled Task runs the ETW capturer at logon. It is what makes per-process network bytes available; everything else captures without it.";

const CODE = "rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1";
const PRIMARY_BTN =
  "rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50";

// Shell is the card chrome, shared by every state so they cannot drift apart.
function Shell({
  badge,
  subtitle,
  children,
}: {
  badge: React.ReactNode;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-1 p-4">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">Elevated ETW capturer (Windows)</h4>
        {badge}
      </header>
      <p className="text-[11px] leading-relaxed text-fg-3">{subtitle}</p>
      {children}
    </section>
  );
}

// WithheldNote explains an intentionally thinner card. The status endpoint
// withholds the command, the notes and every path-bearing reason from a
// REMOTELY-EXPOSED caller — those name the operator's filesystem layout and
// Windows account — and the setup itself is owner-local anyway, because a UAC
// prompt can only be approved at the machine's own console.
function WithheldNote({ data }: { data: ETWStatus }) {
  return (
    <Note tone="info">
      Setup runs only on the dashboard running{" "}
      <strong className="text-fg-0">on that machine</strong>. The command and its notes
      contain its file paths and Windows account name, so they are not sent here, and the
      registration itself raises a Windows UAC prompt that can only be approved at that
      console - the buttons that do it are owner-local. The capturer-link health below is
      live either way.
      {data.state === "skip" && (
        <>
          {" "}
          Windows process telemetry is <strong className="text-fg-0">off</strong> on that
          machine; turning it on is a config write, also owner-local.
        </>
      )}
      {data.state === "blocked" && (
        <>
          {" "}
          This install is <strong className="text-fg-0">blocked</strong> on a missing
          dependency; open the dashboard there to see which.
        </>
      )}
    </Note>
  );
}

function Note({ tone, children }: { tone: "warn" | "danger" | "info"; children: React.ReactNode }) {
  const cls =
    tone === "danger"
      ? "border-danger/40 bg-danger-soft/40"
      : tone === "warn"
        ? "border-warn/40 bg-warn-soft/40"
        : "border-info/30 bg-info-soft/40";
  return (
    <div className={`rounded-2 border px-3 py-2 text-[11.5px] leading-relaxed text-fg-1 ${cls}`}>
      {children}
    </div>
  );
}

function CommandRow({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-1">
      <div className="text-[10px] font-semibold uppercase tracking-[0.06em] text-fg-3">{label}</div>
      <div className="flex items-start gap-2">
        <code className="flex-1 overflow-x-auto whitespace-pre rounded-2 border border-line-2 bg-bg-1 px-2 py-1 font-mono text-[11px] text-fg-2">
          {text}
        </code>
        <button
          type="button"
          className="shrink-0 rounded-2 border border-line-2 bg-bg-2 px-2 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
          onClick={() => {
            navigator.clipboard?.writeText(text);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          }}
        >
          {copied ? "copied" : "copy"}
        </button>
      </div>
    </div>
  );
}

// HealthBlock renders what the RUNNING daemon last published about the capturer
// link. Every present-tense fact is staleness-qualified: the record is a REPORT,
// and a daemon that stopped refreshing minutes ago can only support "a capturer
// WAS connected as of its last report".
//
// It NEVER asserts a cause for a refused handshake. auth_failures counts every
// refusal for any reason — a wrong token, a protocol version this daemon does
// not speak, a malformed opening line, or an unrelated Windows-host process
// probing the port, which WSL2's localhostForwarding exposes to the whole host.
// Only last_auth_error_class and the verbatim last_auth_error carry a cause, and
// both come from what the daemon actually recorded.
function HealthBlock({ data }: { data: ETWStatus }) {
  const h = data.health;
  if (!h) {
    return (
      <p className="text-[11px] leading-relaxed text-fg-3">
        {data.health_reason ??
          "No running daemon has published a process-observability health record."}
      </p>
    );
  }
  const asOf = h.stale
    ? `as of the daemon's last report ${fmtAge(h.age_seconds)} ago (STALE)`
    : `as of ${fmtAge(h.age_seconds)} ago`;

  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-2 px-3 py-2">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
          Capturer link
        </span>
        <span className="text-[10.5px] text-fg-3">{asOf}</span>
      </div>

      {/* diag owns this sentence and already staleness-qualifies it; re-deriving
          it here would make a second owner of the same prose. */}
      {h.transport_line && (
        <p className="text-[11.5px] leading-relaxed text-fg-1">{h.transport_line}</p>
      )}

      {h.transport_state === "none" && (
        <p className="text-[11px] leading-relaxed text-fg-3">
          No dial-in transport was requested on this daemon - the normal state when the ETW
          listener is not configured. This is absence, not failure.
        </p>
      )}
      {h.transport_state === "unavailable" && (
        <Note tone="warn">
          The listener could not be created
          {h.transport_unavailable_reason ? <> - {h.transport_unavailable_reason}</> : null}.
        </Note>
      )}

      {h.transport && (
        <>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] sm:grid-cols-4">
            <Stat label="listening on" value={h.transport.addr || "-"} />
            <Stat
              label="streaming"
              value={h.transport.connected ? "yes" : "no"}
              tone={h.transport.connected ? "good" : "muted"}
            />
            <Stat label="connections" value={String(h.transport.connections)} />
            <Stat
              label="handshakes refused"
              value={String(h.transport.auth_failures)}
              tone={h.transport.auth_failures > 0 ? "warn" : "muted"}
            />
          </dl>

          {h.transport.connections === 0 && h.transport.auth_failures === 0 && (
            <p className="text-[11px] leading-relaxed text-fg-3">
              Waiting for a capturer to dial in. If the task is registered, it starts at your
              next logon - or start it now (elevated):{" "}
              <code className={CODE}>schtasks.exe /Run /TN &quot;{data.task_name}&quot;</code>
            </p>
          )}

          {h.transport.auth_failures > 0 && (
            <Note tone="warn">
              <span>
                {h.transport.auth_failures} connection
                {h.transport.auth_failures === 1 ? " was" : "s were"} refused at the
                handshake. That count names <strong className="text-fg-0">no cause</strong>:
                it includes a wrong shared token, a protocol version this daemon does not
                speak, a malformed opening line, and any unrelated Windows-host process
                probing the port. What the daemon actually recorded:
                <span className="mt-1 block font-mono text-[10.5px] text-fg-2">
                  class: {h.transport.last_auth_error_class || "not recorded"}
                  {h.transport.last_auth_error ? (
                    <>
                      <br />
                      {h.transport.last_auth_error}
                    </>
                  ) : null}
                </span>
              </span>
            </Note>
          )}

          {/* The single most important validation signal the ETW feed has.
              Four states, not two: never reported / refusing events / decoding
              NOTHING (refuses nothing, accepts nothing — the renumbered-provider
              shape, which every refusal-shaped check reads as healthy) / healthy
              and actually decoding. */}
          {!h.transport.capturer_decode ? (
            <p className="text-[11px] leading-relaxed text-fg-3">
              The capturer has not reported decoder health. That is not a clean zero - a
              capturer with no running network decoder (every non-elevated run) reports
              nothing at all, and showing it as zero would claim the payload assumptions had
              been exercised and held.
            </p>
          ) : !h.transport.capturer_decode.healthy ? (
            <Note tone="danger">
              <span>
                <strong className="text-fg-0">
                  {h.transport.capturer_decode.dropped} network event
                  {h.transport.capturer_decode.dropped === 1 ? "" : "s"} dropped
                </strong>
                {h.transport.capturer_decode.unsupported_version > 0 && (
                  <>
                    {" "}
                    and {h.transport.capturer_decode.unsupported_version} refused for an
                    unsupported event version
                  </>
                )}
                . A non-zero drop count means the capturer&rsquo;s payload-length assumption
                does not hold on this host - the per-process byte totals are{" "}
                <strong className="text-fg-0">wrong</strong>, not merely incomplete. Please
                report it with your Windows build.
                {h.transport.capturer_decode.line && (
                  <span className="mt-1 block font-mono text-[10.5px] text-fg-2">
                    {h.transport.capturer_decode.line}
                  </span>
                )}
              </span>
            </Note>
          ) : h.transport.capturer_decode.nothing_classified ? (
            <Note tone="warn">
              <span>
                <strong className="text-fg-0">No data events classified.</strong> The decoder
                refused nothing - but it accepted nothing either:{" "}
                {h.transport.capturer_decode.ignored} event
                {h.transport.capturer_decode.ignored === 1 ? " was" : "s were"} classified as
                not-a-data-event and {h.transport.capturer_decode.decoded} as data. Ignoring
                events is normal on its own (control-plane, connect/disconnect, retransmit,
                UDP); ignoring <strong className="text-fg-0">all</strong> of them is not, and
                it means the byte totals from this host are a flat zero that every
                drop-counter check reads as healthy. If this host was moving TCP traffic, the
                provider&rsquo;s event ids no longer match this build&rsquo;s layout table.
                If it was idle, this is not yet evidence either way - drive some TCP traffic
                and re-read.
                {h.transport.capturer_decode.line && (
                  <span className="mt-1 block font-mono text-[10.5px] text-fg-2">
                    {h.transport.capturer_decode.line}
                  </span>
                )}
              </span>
            </Note>
          ) : (
            <p className="text-[11px] leading-relaxed text-success">
              Decoder healthy: {h.transport.capturer_decode.decoded} data event
              {h.transport.capturer_decode.decoded === 1 ? "" : "s"} decoded, 0 dropped, 0
              refused for an unsupported event version (
              {h.transport.capturer_decode.ignored} non-data event
              {h.transport.capturer_decode.ignored === 1 ? "" : "s"} ignored, which is
              normal). The capturer&rsquo;s fixed-offset payload assumptions hold on this
              host, so the per-process byte totals are trustworthy.
            </p>
          )}
        </>
      )}

      <p className="text-[10.5px] text-fg-3">
        network accounting: <span className="font-mono">{h.network_accounting_mode}</span>
        {h.network_accounting_reason ? ` - ${h.network_accounting_reason}` : ""}
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "good" | "warn" | "muted";
}) {
  const cls =
    tone === "good" ? "text-success" : tone === "warn" ? "text-warn" : "text-fg-1";
  return (
    <div>
      <dt className="text-[10px] uppercase tracking-[0.06em] text-fg-3">{label}</dt>
      <dd className={`font-mono text-[11px] ${cls}`}>{value}</dd>
    </div>
  );
}

function fmtAge(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "an unknown time";
  if (seconds < 90) return `${Math.round(seconds)}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

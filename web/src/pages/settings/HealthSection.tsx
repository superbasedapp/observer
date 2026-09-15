import clsx from "clsx";
import { Info } from "lucide-react";
import { Link } from "react-router-dom";
import {
  ChartShell,
  Pill,
  Tooltip,
  TruncatedPath,
} from "@/components/primitives";
import { ChartState } from "@/components/ChartState";
import { RestartOverlay } from "@/components/RestartOverlay";
import { useApi } from "@/lib/useApi";
import { useDaemonRestart } from "@/lib/useDaemonRestart";
import { isUpdateAvailable, useUpdateCheck } from "@/lib/version";
import { fmtDateTime } from "@/lib/format";
import type {
  DoctorReport,
  HealthFailuresResponse,
  StatusSnapshot,
  UpdateStatusResponse,
} from "@/lib/types";

// HealthSection — the `observer doctor` checks in the dashboard
// (usability arc P4.8 / review row D1). Read-only; the Details lines
// carry each check's remediation hint, exactly as the CLI prints
// them. Runs on open and on Re-run only (the DB integrity check is
// not free on a large observer.db).
export function HealthSection() {
  return (
    <>
      <DaemonCard />
      <div className="mt-4">
        <UpdateCard />
      </div>
      <div className="mt-4">
        <DoctorCard />
      </div>
      <div className="mt-4">
        <FailuresCard />
      </div>
    </>
  );
}

// DaemonCard — on-demand "Restart daemon" control (usability follow-up). The
// same graceful shutdown + self re-exec the pending-config banner uses, always
// reachable so the operator can load a freshly-built binary without dropping to
// the CLI. Honest about the cost + the standalone-dashboard 501.
function DaemonCard() {
  const { restarting, error, restart } = useDaemonRestart();
  if (restarting) {
    return (
      <RestartOverlay
        title="Restarting the daemon…"
        body="Applying your changes and reconnecting. This page reloads automatically when the new process is up."
      />
    );
  }
  return (
    <ChartShell
      title="Daemon"
      sub="Restart the running daemon to load a freshly-built binary or apply saved config - without dropping to the CLI."
    >
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() =>
            restart(
              "Restart the daemon now?\n\nReconnecting takes ~1s; an active proxied coding session may drop one in-flight request.",
            )
          }
          className="rounded-2 border border-accent/50 bg-accent/15 px-3 py-1.5 text-[12px] font-medium text-accent hover:bg-accent/25"
        >
          Restart daemon
        </button>
        <span className="text-[11.5px] text-fg-3">
          Graceful shutdown + self re-exec (~1s). One in-flight proxied request
          may drop.
        </span>
      </div>
      {error && (
        <p className="mt-2 text-[11.5px] text-danger">
          {/http|501|not\s|unavailable/i.test(error)
            ? "Restart isn’t available on this dashboard - it needs the full daemon started with `observer start` (the standalone `observer dashboard` can’t re-exec itself)."
            : `Restart failed - ${error}`}
        </p>
      )}
    </ChartShell>
  );
}

// UpdateCard — the user-initiated update check (zero-network hardening
// pass, 2026-07-30). Nothing here fetches on mount: the "Check for
// updates" button is the only thing that ever contacts npm, and it
// does so exactly once per click. See web/src/lib/version.ts and
// `observer privacy` for the same claim verified from the CLI side.
function UpdateCard() {
  const status = useApi<StatusSnapshot>("/api/status");
  const current = status.data?.version;
  const { latest, checking, error, lastCheckedAt, checkNow } =
    useUpdateCheck();
  const updateAvailable = isUpdateAvailable(current, latest);
  return (
    <ChartShell
      title="Updates"
      sub="Checks npmjs.org only when you click below - never automatically, never in the background. No other page or timer triggers this request."
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[11.5px] text-fg-3">
          Running{" "}
          <span className="font-mono text-fg-1">
            v{current || "dev"}
          </span>
        </span>
        <button
          type="button"
          onClick={() => void checkNow()}
          disabled={checking}
          className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3 disabled:opacity-60"
        >
          {checking ? "Checking npm…" : "Check for updates"}
        </button>
        {lastCheckedAt && !checking && (
          <span className="text-[11px] text-fg-4">
            last checked {fmtDateTime(new Date(lastCheckedAt).toISOString())}
          </span>
        )}
      </div>
      {error && (
        <p className="mt-2 text-[11.5px] text-danger">
          Couldn’t reach registry.npmjs.org - check your network and try
          again.
        </p>
      )}
      {!error && latest && (
        <p className="mt-2 text-[11.5px]">
          {updateAvailable ? (
            <>
              <span className="text-accent">v{latest} is available</span> -
              update with <kbd>npm i -g @superbased/observer</kbd> or{" "}
              <kbd>pipx upgrade superbased-observer</kbd>, or read the{" "}
              <a
                href={`https://github.com/superbasedapp/observer/releases/tag/v${latest}`}
                target="_blank"
                rel="noreferrer"
                className="text-accent hover:underline"
              >
                release notes
              </a>
              .
            </>
          ) : (
            <span className="text-fg-3">
              You’re on the latest published version.
            </span>
          )}
        </p>
      )}
      <OrgUpdatePosture />
    </ChartShell>
  );
}

// OrgUpdatePosture renders the ORG-SERVED half of the update answer, beside
// the click-gated npm probe above (enterprise update management §3.10, W5).
//
// The two answers are different questions and the card shows both rather than
// picking one: npm says what the public registry has published, the org says
// what THIS fleet is allowed to run and how far this node has got. On an
// enrolled node the org answer is the one that decides.
//
// It reads GET /api/update/status, a LOOPBACK read of state the daemon already
// holds from the push cycle - it adds no outbound request and no timer.
function OrgUpdatePosture() {
  const st = useApi<UpdateStatusResponse>("/api/update/status");
  const d = st.data;
  if (!d) return null;
  if (!d.enabled) {
    return (
      <p className="mt-3 border-t border-line-1 pt-3 text-[11.5px] text-fg-3">
        Org-managed updates are turned off on this node ([update].enabled =
        false), so nothing here is checked against an org server. The npm check
        above is the only update signal.
      </p>
    );
  }
  const refusal = d.org_refusal;
  return (
    <div className="mt-3 border-t border-line-1 pt-3 text-[11.5px]">
      {refusal && (
        <p className="mb-2 rounded-2 border border-danger/30 bg-danger-soft px-2 py-1.5 text-danger">
          Your org is not accepting this node's data:{" "}
          {refusal.message}
          {refusal.min_version ? (
            <>
              {" "}
              Update to{" "}
              <span className="font-mono">v{refusal.min_version.replace(/^v/, "")}</span>{" "}
              or newer to start sharing again.
            </>
          ) : null}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-fg-3">
        <span>
          Org update state{" "}
          <span className="font-mono text-fg-1">
            {d.state === "unknown" || !d.state ? "not reported" : d.state}
          </span>
        </span>
        {d.channel && (
          <span>
            channel <span className="font-mono text-fg-1">{d.channel}</span>
          </span>
        )}
        {d.target_version && (
          <span>
            target <span className="font-mono text-fg-1">{d.target_version}</span>
          </span>
        )}
        {d.install_method && (
          <span>
            installed via{" "}
            <span className="font-mono text-fg-1">{d.install_method}</span>
          </span>
        )}
        <span>auto-apply {d.auto_apply ? "on" : "off"}</span>
        {d.window && <span>window {d.window}</span>}
      </div>
      {d.auto_apply_reason && (
        <p className="mt-1 text-fg-4">{d.auto_apply_reason}</p>
      )}
      {!d.self_apply && d.advice && (
        <p className="mt-1 text-warn">
          This node cannot replace its own binary. {d.advice}
        </p>
      )}
      {d.error_class && (
        <p className="mt-1 text-danger">
          Last update attempt failed at the {d.error_class} step. Run{" "}
          <kbd>observer update history</kbd> for the local ledger.
        </p>
      )}
    </div>
  );
}

function DoctorCard() {
  const report = useApi<DoctorReport>("/api/health/doctor");
  const d = report.data;
  return (
    <ChartShell
      title="Health"
      sub="The `observer doctor` checks: database integrity, hook checksums and binary paths, MCP registrations, pidbridge, concurrent daemons, codex hook trust, org enrolment."
    >
      <ChartState
        loading={report.loading}
        error={report.error}
        empty={!report.loading && (d?.checks ?? []).length === 0}
        emptyHint="No checks returned."
      >
        {/* `=== true` on purpose: the field is absent on the local
            projection (Go `omitempty`) and on any daemon older than the
            feature, and `undefined` must render exactly like `false`. */}
        {d?.local_detail_withheld === true && <RedactionNotice />}
        <div className="space-y-1.5">
          {(d?.checks ?? []).map((c) => (
            <div
              key={c.name}
              className="rounded-2 border border-line-1 bg-bg-2 px-3 py-2"
            >
              <div className="flex items-baseline gap-2">
                <span
                  className={clsx(
                    "w-4 text-center text-[12px] font-bold",
                    c.status === "ok"
                      ? "text-success"
                      : c.status === "warn"
                        ? "text-warn"
                        : "text-danger",
                  )}
                >
                  {c.status === "ok" ? "✓" : c.status === "warn" ? "⚠" : "✗"}
                </span>
                <span className="font-mono text-[11.5px] text-fg-1">
                  {c.name}
                </span>
                <span className="flex-1 text-[11.5px] text-fg-2">
                  {c.message}
                </span>
              </div>
              {c.details && c.details.length > 0 && (
                <ul className="ml-6 mt-1 list-disc space-y-0.5 text-[11px] text-fg-3">
                  {c.details.map((line, i) => (
                    <li key={i} className="whitespace-pre-wrap">
                      {line}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-line-1 pt-3">
          <button
            type="button"
            onClick={report.reload}
            className="rounded-2 border border-line-2 bg-bg-2 px-2.5 py-1 text-[11px] text-fg-2 hover:bg-bg-3"
          >
            Re-run checks
          </button>
          {d && (
            <span className="text-[11.5px] text-fg-3">
              {d.ok} ok · {d.warn} warn · {d.fail} fail
              {d.all_ok && (
                <span className="ml-2 text-success">all checks passed ★</span>
              )}
            </span>
          )}
        </div>
      </ChartState>
    </ChartShell>
  );
}

// RedactionNotice — shown only when GET /api/health/doctor came back as the
// REMOTE-FACING PROJECTION (local_detail_withheld). This is a privacy filter
// working as designed, not a problem with the install, so it wears the same
// neutral chrome as the check rows above it (line-1 / bg-2 / fg-3) with an Info
// glyph — never the warn/danger colours or the ⚠ / ✗ status glyphs the list
// uses, which would read as one more failed check in a list of checks.
//
// The copy deliberately does NOT say the report is fully sanitised. The
// server's own residue note (pathRedactor, health_doctor_redact.go) lists what
// survives: a path under no root this daemon holds, OS-convention paths like
// /etc/codex/*.toml left readable on purpose, and the org enrolment check's
// user email, which substitution cannot touch at all. "some machine detail can
// still come through" is the honest form of that; the reassuring form would be
// false.
function RedactionNotice() {
  const ph = "font-mono text-fg-2";
  return (
    <div
      data-testid="doctor-redaction-notice"
      className="mb-2 flex items-start gap-2 rounded-2 border border-line-1 bg-bg-2 px-3 py-2 text-[11.5px] leading-relaxed text-fg-3"
    >
      <Info className="mt-[2px] h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <p>
        This device is connected remotely, so machine-specific paths and user
        names appear as placeholders - <code className={ph}>~</code>,{" "}
        <code className={ph}>&lt;config&gt;</code>,{" "}
        <code className={ph}>&lt;other-home&gt;</code> - standing in for real
        locations on the host, and some machine detail can still come through.
        The checks and their results are unchanged; for the unredacted report,
        open this dashboard locally on the host or run{" "}
        <code className={ph}>observer doctor</code> in a terminal there.
      </p>
    </div>
  );
}

// FailuresCard — the failure_context table surfaced (P4.11): recent
// failed commands grouped, recovered-vs-not, deep-link to the session
// where the latest failure happened. Closes the quality loop the data
// has supported since v1 with zero UI.
function FailuresCard() {
  const failures = useApi<HealthFailuresResponse>("/api/health/failures");
  const f = failures.data;
  return (
    <ChartShell
      title="Recent failures"
      sub="Failed commands from the last 7 days, grouped. Recovered = a later attempt of the same command succeeded; unrecovered groups are the time sinks worth a root-cause fix."
    >
      <ChartState
        loading={failures.loading}
        error={failures.error}
        empty={!failures.loading && (f?.failures ?? []).length === 0}
        emptyHint="No failures captured in the last 7 days."
      >
        <table className="w-full border-collapse text-[11.5px]">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-[0.06em] text-fg-3">
              <th className="pb-1.5 pr-3 font-semibold">Command</th>
              <th className="pb-1.5 pr-3 font-semibold">Fails</th>
              <th className="pb-1.5 pr-3 font-semibold">Outcome</th>
              <th className="pb-1.5 pr-3 font-semibold">Project</th>
              <th className="pb-1.5 font-semibold">Last session</th>
            </tr>
          </thead>
          <tbody>
            {(f?.failures ?? []).map((g) => (
              <tr key={g.command + g.last_at} className="border-t border-line-1">
                <td className="max-w-[280px] py-1.5 pr-3">
                  <Tooltip
                    content={
                      <span className="whitespace-pre-wrap break-all">
                        {g.error_message
                          ? `${g.command}\n\n${g.error_category || "error"}: ${g.error_message}`
                          : g.command}
                      </span>
                    }
                    maxWidth={460}
                  >
                    <code className="block cursor-help truncate font-mono text-fg-1">
                      {g.command}
                    </code>
                  </Tooltip>
                </td>
                <td className="py-1.5 pr-3 text-fg-2">
                  {g.fails}
                  {g.retries > 0 && (
                    <span className="text-fg-4"> (+{g.retries} retries)</span>
                  )}
                </td>
                <td className="py-1.5 pr-3">
                  {g.recovered ? (
                    <Pill variant="success">recovered</Pill>
                  ) : (
                    <Pill variant="warn">unrecovered</Pill>
                  )}
                </td>
                <td className="max-w-[200px] py-1.5 pr-3 text-fg-3">
                  {g.project ? (
                    <TruncatedPath value={g.project} className="text-[11px]" />
                  ) : (
                    "-"
                  )}
                </td>
                <td className="py-1.5">
                  <Link
                    to={`/sessions?session=${encodeURIComponent(g.session_id)}`}
                    className="text-accent hover:underline"
                  >
                    open
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {f && f.total > f.failures.length && (
          <p className="mt-2 text-[11px] text-fg-3">
            {f.total} failure events total in the window; showing the{" "}
            {f.failures.length} most recent command groups.
          </p>
        )}
      </ChartState>
    </ChartShell>
  );
}

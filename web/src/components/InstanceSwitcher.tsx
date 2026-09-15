import { useCallback, useEffect, useRef, useState } from "react";
import clsx from "clsx";
import {
  apiReason,
  connectInstance,
  disconnectInstance,
  testInstance,
} from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type {
  InstanceInfo,
  InstancesResponse,
  InstanceTestResult,
} from "@/lib/types";
import { Tooltip } from "@/components/primitives";

// InstanceSwitcher lets the operator view the dashboard of a REMOTE developer
// machine that runs its own Observer install, without leaving this one.
//
// WHAT IT ACTUALLY DOES, stated plainly because the honest version is smaller
// than it sounds: selecting a remote instance asks the daemon to open an
// `ssh -N -L 127.0.0.1:<free>:127.0.0.1:<dashboard_port>` forward, and then
// opens that loopback address in a new tab. The page you are reading does NOT
// re-point its own API base at the remote daemon — this dashboard keeps showing
// LOCAL data, and the remote one renders in its own tab under its own auth.
// That is why the trigger reads "Local" while you are here rather than pretending
// to be a mode switch. (Swapping the running app's API base in place is a much
// bigger arc; see the plan's §12 follow-up.)
//
// It renders NOTHING when the feature is off or no instances are configured, so
// a solo install's header is unchanged.

export function InstanceSwitcher() {
  const res = useApi<InstancesResponse>("/api/instances", undefined, [], {
    refreshMs: 15000,
  });
  const [open, setOpen] = useState(false);
  // pending is the name currently being connected/disconnected. It is what
  // makes the "Connecting…" state real rather than optimistic: it is set before
  // the POST and cleared when it settles.
  const [pending, setPending] = useState<string | null>(null);
  // local overrides the polled row for an instance we just acted on, so the UI
  // updates immediately instead of waiting up to 15s for the next poll.
  const [local, setLocal] = useState<Record<string, InstanceInfo>>({});
  // failures holds a client-side reason for an instance whose POST threw. The
  // server's own message is used verbatim.
  const [failures, setFailures] = useState<Record<string, string>>({});
  // testPending is the name currently running the "Test" probe. Tracked
  // separately from `pending` because a test opens no forward and changes no
  // state, so it never needs to block (or be blocked by) connect/disconnect.
  const [testPending, setTestPending] = useState<string | null>(null);
  // testResults holds the last probe result per instance, cleared whenever a
  // new test starts so a stale check/x never lingers past the request.
  const [testResults, setTestResults] = useState<
    Record<string, InstanceTestResult>
  >({});
  // testFailures holds the server's own reason when the test request itself
  // could not run (disabled, unknown profile, etc.) — distinct from a
  // completed probe reporting auth_ok:false, which lands in testResults.
  const [testFailures, setTestFailures] = useState<Record<string, string>>(
    {},
  );
  const rootRef = useRef<HTMLDivElement>(null);

  // Close on outside click / Escape, the same affordance the other header menus
  // use.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const rows = (res.data?.instances ?? []).map((r) => local[r.name] ?? r);
  const enabled = res.data?.enabled ?? false;

  const onConnect = useCallback(
    async (name: string) => {
      setPending(name);
      setFailures((f) => ({ ...f, [name]: "" }));
      try {
        const info = await connectInstance(name);
        setLocal((l) => ({ ...l, [name]: info }));
        if (info.url) {
          // Open the REMOTE dashboard in its own tab. noreferrer so this
          // dashboard's URL is never disclosed to the forwarded page.
          window.open(info.url, "_blank", "noreferrer");
        }
      } catch (e) {
        setFailures((f) => ({ ...f, [name]: apiReason(e) }));
      } finally {
        setPending(null);
      }
    },
    [],
  );

  const onDisconnect = useCallback(async (name: string) => {
    setPending(name);
    setFailures((f) => ({ ...f, [name]: "" }));
    try {
      const info = await disconnectInstance(name);
      setLocal((l) => ({ ...l, [name]: info }));
    } catch (e) {
      setFailures((f) => ({ ...f, [name]: apiReason(e) }));
    } finally {
      setPending(null);
    }
  }, []);

  const onTest = useCallback(async (name: string) => {
    setTestPending(name);
    setTestFailures((f) => ({ ...f, [name]: "" }));
    setTestResults((r) => {
      const next = { ...r };
      delete next[name];
      return next;
    });
    try {
      const result = await testInstance(name);
      setTestResults((r) => ({ ...r, [name]: result }));
    } catch (e) {
      setTestFailures((f) => ({ ...f, [name]: apiReason(e) }));
    } finally {
      setTestPending(null);
    }
  }, []);

  // Nothing to switch to: no surface at all, rather than a control that
  // explains an absence the operator never asked about.
  if (!enabled || rows.length === 0) return null;

  const connected = rows.filter((r) => r.state === "connected");

  return (
    <div ref={rootRef} className="relative">
      <Tooltip
        content={
          connected.length > 0
            ? `${connected.length} remote instance${connected.length === 1 ? "" : "s"} forwarded. This page still shows LOCAL data; each remote dashboard opens in its own tab.`
            : "Viewing this machine's own Observer data. Connect to a remote instance to open its dashboard."
        }
      >
        <button
          type="button"
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={() => setOpen((o) => !o)}
          className="flex h-6 items-center gap-1.5 rounded-pill border border-line-2 bg-bg-2 px-2 text-[10.5px] font-medium text-fg-2 hover:bg-bg-3 hover:text-fg-0"
        >
          <span
            className={clsx(
              "h-1.5 w-1.5 rounded-full",
              connected.length > 0 ? "bg-accent" : "bg-fg-4",
            )}
          />
          Local
          {connected.length > 0 && (
            <span className="text-accent">+{connected.length}</span>
          )}
          <ChevronIcon />
        </button>
      </Tooltip>

      {open && (
        <div
          role="menu"
          className="absolute right-0 z-50 mt-1.5 w-[300px] rounded-2 border border-line-2 bg-bg-1 p-1 shadow-lg"
        >
          <div className="px-2 py-1.5 text-[10px] uppercase tracking-wide text-fg-4">
            Instance
          </div>

          {/* "Local" is a state, not an action: you are already here. */}
          <div className="flex items-center gap-2 rounded-1 bg-bg-3 px-2 py-1.5 text-[11px] text-fg-0">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" />
            <span className="font-medium">Local</span>
            <span className="ml-auto text-[10px] text-fg-3">this machine</span>
          </div>

          <div className="my-1 h-px bg-line-2" />

          {rows.map((r) => (
            <InstanceRow
              key={r.name}
              info={r}
              busy={pending === r.name}
              // Any pending request disables the others so two forwards cannot
              // be opened from one impatient burst of clicks.
              blocked={pending !== null && pending !== r.name}
              failure={failures[r.name] || ""}
              onConnect={() => void onConnect(r.name)}
              onDisconnect={() => void onDisconnect(r.name)}
              testBusy={testPending === r.name}
              testBlocked={testPending !== null && testPending !== r.name}
              testResult={testResults[r.name]}
              testFailure={testFailures[r.name] || ""}
              onTest={() => void onTest(r.name)}
            />
          ))}

          <div className="px-2 pb-1 pt-1.5 text-[10px] leading-snug text-fg-4">
            A remote dashboard opens in its own tab over a loopback SSH forward.
            It uses that install's own sign-in, not this one's.
          </div>
        </div>
      )}
    </div>
  );
}

// InstanceRow renders one configured remote instance and its state.
function InstanceRow({
  info,
  busy,
  blocked,
  failure,
  onConnect,
  onDisconnect,
  testBusy,
  testBlocked,
  testResult,
  testFailure,
  onTest,
}: {
  info: InstanceInfo;
  busy: boolean;
  blocked: boolean;
  failure: string;
  onConnect: () => void;
  onDisconnect: () => void;
  testBusy: boolean;
  testBlocked: boolean;
  testResult: InstanceTestResult | undefined;
  testFailure: string;
  onTest: () => void;
}) {
  const connected = info.state === "connected";
  const connecting = busy || info.state === "connecting";
  // The row's reason, in precedence order: the failure this tab just saw, then
  // the daemon's recorded reason for a forward that died on its own.
  const reason = failure || (info.state === "error" ? info.error || "" : "");
  const disabled = blocked || connecting;
  const disabledReason = blocked
    ? "Another instance request is in flight"
    : connecting
      ? "Opening the SSH port forward"
      : "";

  // The test's own state line: the server's own reason when the request
  // itself could not run, otherwise the probe's verdict. A probe that ran but
  // did not pass (known_hosts unresolved or auth failed) is a RESULT, not an
  // error — it renders in the same amber the "connecting" state uses, not red,
  // since nothing about the request itself failed.
  const testPassed = testResult ? testResult.auth_ok : undefined;
  const testTooltip = testResult
    ? [
        testResult.known_hosts_checked
          ? `known_hosts: ${testResult.known_hosts_ok ? "trusted" : "not trusted"}`
          : "known_hosts: could not check",
        `auth: ${testResult.auth_ok ? "OK" : "failed"}`,
        `latency: ${testResult.latency_ms}ms`,
        testResult.stderr ? testResult.stderr : "",
      ]
        .filter(Boolean)
        .join("\n")
    : testFailure || "Run a bounded, read-only connectivity check";

  return (
    <div className="rounded-1 px-2 py-1.5 hover:bg-bg-2">
      <div className="flex items-center gap-2">
        <span
          className={clsx(
            "h-1.5 w-1.5 shrink-0 rounded-full",
            connected
              ? "bg-success"
              : connecting
                ? "bg-warn"
                : reason
                  ? "bg-danger"
                  : "bg-fg-4",
          )}
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[11px] font-medium text-fg-1">
            {info.label}
          </div>
          <div className="truncate text-[10px] text-fg-4">{info.target}</div>
        </div>
        <Tooltip
          content={<span className="whitespace-pre-line">{testTooltip}</span>}
        >
          <button
            type="button"
            onClick={onTest}
            disabled={testBusy || testBlocked}
            aria-label="Test connection"
            className={clsx(
              "flex h-5 w-5 shrink-0 items-center justify-center rounded-1 border border-line-2",
              testBusy || testBlocked
                ? "cursor-not-allowed bg-bg-2"
                : "bg-bg-2 hover:bg-bg-3",
            )}
          >
            {testBusy ? (
              <span className="inline-block h-2.5 w-2.5 animate-spin rounded-full border border-line-3 border-t-accent" />
            ) : testPassed === true ? (
              <CheckIcon className="text-success" />
            ) : testPassed === false ? (
              <XIcon className="text-danger" />
            ) : (
              <TestIcon className="text-fg-4" />
            )}
          </button>
        </Tooltip>
        {connected ? (
          <div className="flex shrink-0 items-center gap-1">
            <a
              href={info.url}
              target="_blank"
              rel="noreferrer"
              className="rounded-1 border border-line-2 bg-bg-2 px-1.5 py-1 text-[10px] text-fg-2 hover:bg-bg-3 hover:text-fg-0"
            >
              Open
            </a>
            <button
              type="button"
              onClick={onDisconnect}
              disabled={blocked}
              title={blocked ? disabledReason : "Close the port forward"}
              className={clsx(
                "rounded-1 border border-line-2 px-1.5 py-1 text-[10px]",
                blocked
                  ? "cursor-not-allowed bg-bg-2 text-fg-4"
                  : "bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-0",
              )}
            >
              Disconnect
            </button>
          </div>
        ) : (
          <button
            type="button"
            onClick={onConnect}
            disabled={disabled}
            title={disabled ? disabledReason : `Open an SSH forward to ${info.target}`}
            className={clsx(
              "shrink-0 rounded-1 border border-line-2 px-1.5 py-1 text-[10px]",
              disabled
                ? "cursor-not-allowed bg-bg-2 text-fg-4"
                : "bg-bg-2 text-fg-2 hover:bg-bg-3 hover:text-fg-0",
            )}
          >
            {connecting ? "Connecting…" : "Connect"}
          </button>
        )}
      </div>

      {/* State line. Every branch says something true and specific — the
          forwarded port when it is up, and the daemon's own reason when it is
          not. Nothing here is inferred from a status code. */}
      {connected && info.local_port ? (
        <div className="mt-1 pl-3.5 text-[10px] text-success">
          Forwarded on 127.0.0.1:{info.local_port} to its port{" "}
          {info.dashboard_port}
        </div>
      ) : null}
      {connecting && !connected ? (
        <div className="mt-1 pl-3.5 text-[10px] text-warn">
          Connecting over SSH…
        </div>
      ) : null}
      {reason && !connecting ? (
        <div className="mt-1 pl-3.5 text-[10px] leading-snug text-danger">
          {reason}
        </div>
      ) : null}
      {!reason && !connecting && (testFailure || testPassed === false) ? (
        <div className="mt-1 pl-3.5 text-[10px] leading-snug text-warn">
          {testFailure || "Test failed - hover the test button for details"}
        </div>
      ) : null}
    </div>
  );
}

function ChevronIcon() {
  return (
    <svg width="9" height="9" viewBox="0 0 12 12" fill="none" aria-hidden>
      <path
        d="M3 4.5 6 8l3-3.5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// CheckIcon marks a passed connectivity test.
function CheckIcon({ className }: { className?: string }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 12 12"
      fill="none"
      aria-hidden
      className={className}
    >
      <path
        d="M2.5 6.2 5 8.7l4.5-5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

// XIcon marks a failed connectivity test.
function XIcon({ className }: { className?: string }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 12 12"
      fill="none"
      aria-hidden
      className={className}
    >
      <path
        d="M3 3l6 6M9 3l-6 6"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

// TestIcon is the idle "Test connection" affordance: a small plug/pulse
// glyph, distinct from the state dot so it reads as an action, not a status.
function TestIcon({ className }: { className?: string }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 12 12"
      fill="none"
      aria-hidden
      className={className}
    >
      <path
        d="M6 1v3M2 6h2.2M9.8 6H8M6 8v3M4 4l1.4 1.4M8 4 6.6 5.4M4 8l1.4-1.4M8 8 6.6 6.6"
        stroke="currentColor"
        strokeWidth="1.3"
        strokeLinecap="round"
      />
      <circle cx="6" cy="6" r="1.3" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  );
}

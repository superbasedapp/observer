import { loginStartBadge, loginStartButtons, loginStartNote, type LoginStartStatus } from "@/lib/setupExtras";
import { CODE, OutcomeView, PreviewActions, SetupCardShell, useSetupFlow } from "./SetupCardParts";

// StartAtLoginCard - Settings > Health "Start at login".
//
// Installs or removes the per-user entry that starts the Observer daemon when
// you log in: a systemd user unit on Linux, a launchd LaunchAgent on macOS,
// the sign-in entry on Windows. It uses the same code as `observer service
// install` / `observer setup autostart`, with these differences on purpose:
//   - it never starts, stops or restarts the daemon (this page may be served
//     by the very daemon the entry would start), so there is no --now here;
//   - it never overwrites an entry that already exists;
//   - a machine-wide (--system) unit needs root and stays on the command line.

export function StartAtLoginCard({ readOnly = false }: { readOnly?: boolean }) {
  const flow = useSetupFlow<LoginStartStatus>("/api/setup/login-start");
  const { res, status: st, preview, result } = flow;

  if (res.error) {
    return (
      <SetupCardShell title="Start at login" badge={{ text: "unavailable", tone: "neutral" }}>
        <p className="text-[11px] text-fg-3">
          Start at login is managed from this machine only (it writes a user-level service entry).{" "}
          {res.error.message}
        </p>
      </SetupCardShell>
    );
  }
  if (!st) return null;

  const buttons = loginStartButtons(st).map((b) => ({
    label: b.label,
    onClick: () => void flow.doPreview(b.label, { action: b.action }),
  }));

  return (
    <SetupCardShell title="Start at login" badge={loginStartBadge(st)}>
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Start the Observer daemon (proxy, watcher and this dashboard) automatically when you log in
        {st.manager_label ? `, using ${st.manager_label}` : ""}. Nothing is written until you preview and confirm.
        The same control exists on the command line as <code className={CODE}>observer service install</code>.
      </p>
      {st.supported ? (
        <>
          {st.path && (
            <p className="text-[11px] text-fg-3">
              Entry: <code className={CODE}>{st.path}</code>
            </p>
          )}
          {st.installed && st.command && (
            <p className="text-[11px] text-fg-3">
              Runs: <code className={CODE}>{st.command}</code>
            </p>
          )}
          <p className="text-[11px] text-fg-3">{loginStartNote(st)}</p>
          <PreviewActions buttons={buttons} flow={flow} readOnly={readOnly && preview?.request.action !== "remove"} />
          {preview && <OutcomeView out={preview.out} />}
          {result && <OutcomeView out={result} />}
          <p className="text-[10.5px] text-fg-3">
            A machine-wide service for all users (<code className={CODE}>--system</code>) needs administrator
            rights, so it is set up from a terminal with <code className={CODE}>sudo observer service install --system</code>
            .
          </p>
        </>
      ) : (
        <p className="text-[11.5px] text-fg-3">{st.reason}</p>
      )}
    </SetupCardShell>
  );
}

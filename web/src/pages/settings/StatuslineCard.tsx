import {
  statuslineBadge,
  statuslineButtons,
  type StatuslineStatus,
} from "@/lib/setupExtras";
import { CODE, OutcomeView, PreviewActions, SetupCardShell, useSetupFlow } from "./SetupCardParts";

// StatuslineCard - Settings > Connected tools "Claude Code status line".
//
// Installs or removes the "statusLine" entry in Claude Code's settings.json so
// Claude Code shows Observer's one-line cost and session summary. The daemon
// writes it through the same code as `observer init --statusline`; this card
// previews the exact change, then confirms. Removal is byte-exact and only
// ever removes an entry Observer wrote.

export function StatuslineCard({ readOnly = false }: { readOnly?: boolean }) {
  const flow = useSetupFlow<StatuslineStatus>("/api/setup/statusline");
  const { res, status: st, preview, result } = flow;

  if (res.error) {
    return (
      <SetupCardShell title="Claude Code status line" badge={{ text: "unavailable", tone: "neutral" }}>
        <p className="text-[11px] text-fg-3">
          The status line is managed from this machine only (it edits Claude Code&rsquo;s settings file).{" "}
          {res.error.message}
        </p>
      </SetupCardShell>
    );
  }
  if (!st) return null;

  const buttons = statuslineButtons(st).map((b) => ({
    label: b.label,
    onClick: () => void flow.doPreview(b.label, { action: b.action, force: b.force ?? false }),
  }));

  return (
    <SetupCardShell title="Claude Code status line" badge={statuslineBadge(st)}>
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Show Observer&rsquo;s one-line cost and session summary in Claude Code&rsquo;s own status line. Off by
        default. Nothing is written until you preview and confirm. Removing it deletes only the entry Observer
        wrote and leaves the rest of the file as it is. The same control exists on the command line as{" "}
        <code className={CODE}>observer init --statusline</code>.
      </p>
      {st.supported ? (
        <>
          {st.config_path && (
            <p className="text-[11px] text-fg-3">
              Settings file: <code className={CODE}>{st.config_path}</code>
            </p>
          )}
          {st.command && (
            <p className="text-[11px] text-fg-3">
              Runs: <code className={CODE}>{st.command}</code>
            </p>
          )}
          {st.state === "foreign" && (
            <p className="text-[11px] text-fg-3">
              Claude Code already has a status line you set up yourself. Observer leaves it alone unless you choose
              to replace it.
            </p>
          )}
          <PreviewActions buttons={buttons} flow={flow} readOnly={readOnly && preview?.request.action !== "remove"} />
          {preview && <OutcomeView out={preview.out} />}
          {result && <OutcomeView out={result} />}
        </>
      ) : (
        <p className="text-[11.5px] text-fg-3">{st.reason}</p>
      )}
    </SetupCardShell>
  );
}

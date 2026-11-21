import { useState } from "react";
import clsx from "clsx";
import { Button, ConfirmButton, Pill } from "@/components/primitives";
import { fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import {
  cliEquivalent,
  defaultHome,
  needsChoice,
  previewLines,
  windowsHomesVisible,
  type WindowsHomeApplyReply,
  type WindowsHomeTarget,
  type WindowsHomesResponse,
} from "@/lib/windowsHomes";

// WindowsHomesCard - Connected tools' Windows-home control (T-421 item 4):
// `observer init --windows-claude-home | --windows-codex-home |
// --windows-cursor-home <path>` for a daemon running inside WSL while the AI
// tools run on Windows. Lists the Windows homes that carry each tool's
// config, previews the exact writes for the chosen home (a dry run of the
// same init code path), then applies them on a separate confirm. Renders
// nothing on a native daemon (the server reports wsl=false) or when the
// route is refused here (remote viewer, not wired).
export function WindowsHomesCard({ focusTarget }: { focusTarget?: string | null }) {
  const res = useApi<WindowsHomesResponse>("/api/setup/windows-homes");
  if (!windowsHomesVisible(res.data)) return null;
  const targets = res.data!.targets;
  return (
    <div className="mt-3 rounded-2 border border-line-2 bg-bg-3/40 px-3 py-2" data-testid="windows-homes-card">
      <div className="text-[11.5px] font-semibold text-fg-1">Windows-side homes (this daemon runs in WSL)</div>
      <p className="mt-0.5 text-[11px] leading-snug text-fg-3">
        AI tools installed on Windows keep their config in a Windows user home. When several homes carry it, or
        the one found cannot be verified as yours, setup will not pick one on its own: choose it here. Each write
        previews first and runs on its own confirm, through the same code as{" "}
        <code className="font-mono text-fg-2">observer init --windows-*-home</code>.
      </p>
      <div className="mt-2 space-y-2">
        {targets.map((t) => (
          <WindowsHomeRow key={t.target} target={t} focused={focusTarget === t.target} onChanged={res.reload} />
        ))}
      </div>
    </div>
  );
}

function WindowsHomeRow({
  target: t,
  focused,
  onChanged,
}: {
  target: WindowsHomeTarget;
  focused: boolean;
  onChanged: () => void;
}) {
  const [home, setHome] = useState(defaultHome(t));
  const [preview, setPreview] = useState<WindowsHomeApplyReply | null>(null);
  const [result, setResult] = useState<WindowsHomeApplyReply | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function post(dryRun: boolean, force: boolean): Promise<WindowsHomeApplyReply> {
    return fetchJSON<WindowsHomeApplyReply>("/api/setup/windows-homes/apply", undefined, {
      method: "POST",
      headers: await localConfirmHeaders(),
      body: JSON.stringify({ target: t.target, home, dry_run: dryRun, force }),
    });
  }

  async function run(dryRun: boolean, force = false) {
    if (busy || !home) return;
    setBusy(true);
    setErr(null);
    try {
      const out = await post(dryRun, force);
      if (dryRun) {
        setPreview(out);
        setResult(null);
      } else {
        setResult(out);
        setPreview(null);
        onChanged();
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const previewed = preview !== null && preview.home === home;
  return (
    <div
      className={clsx("rounded-2 border bg-bg-2 px-3 py-2", focused ? "border-accent/60" : "border-line-1")}
      data-testid={`windows-home-${t.target}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[11.5px] text-fg-1">{t.target}</span>
        {needsChoice(t) ? (
          <Pill variant="warn">choose a home</Pill>
        ) : (
          <Pill variant="success">picked automatically</Pill>
        )}
      </div>
      <fieldset className="mt-1.5 space-y-1">
        <legend className="sr-only">Windows home for {t.target}</legend>
        {t.candidates.map((c) => (
          <label key={c.home} className="flex min-w-0 items-center gap-2 text-[11px] text-fg-2">
            <input
              type="radio"
              name={`winhome-${t.target}`}
              value={c.home}
              checked={home === c.home}
              onChange={() => {
                setHome(c.home);
                setPreview(null);
                setResult(null);
              }}
            />
            <span className="min-w-0 break-all font-mono">
              {c.home}/{t.subdir}
            </span>
            {c.owned && <span className="text-success">yours</span>}
          </label>
        ))}
      </fieldset>
      <div className="mt-1.5 flex flex-wrap items-center gap-2">
        <Button variant="secondary" size="sm" onClick={() => void run(true)} disabled={!home || busy}>
          Preview
        </Button>
        {previewed && (
          <ConfirmButton
            size="sm"
            variant="primary"
            armedVariant="primary"
            onConfirm={() => void run(false)}
            disabled={busy}
            confirmLabel="Write these changes?"
            armedNote="Writes only the lines previewed below."
            armedNoteSide="top"
          >
            Apply
          </ConfirmButton>
        )}
        {err && previewed && (
          <ConfirmButton
            size="sm"
            onConfirm={() => void run(false, true)}
            confirmLabel="Overwrite?"
            armedNote="Replaces an entry you or another tool configured there."
          >
            Force apply
          </ConfirmButton>
        )}
      </div>
      <p className="mt-1 break-all font-mono text-[10.5px] text-fg-4">CLI: {cliEquivalent(t, home)}</p>
      {(preview || result) && (
        <ul className="mt-1 space-y-0.5 font-mono text-[10.5px] text-fg-3">
          {previewLines(result ?? preview).map((l, i) => (
            <li key={i} className="whitespace-pre-wrap break-all">
              {result ? l : `preview: ${l}`}
            </li>
          ))}
        </ul>
      )}
      {err && <p className="mt-1 text-[11px] text-danger">{err}</p>}
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import { Pill, SegmentedControl } from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import {
  HONESTY_TONE,
  selectionKey,
  sideLabel,
  stateLabel,
  statusParams,
  targetApiId,
  targetOptions,
  unavailableRows,
  type ShellWrapTargetChoice,
} from "@/lib/shellWrap";
import type {
  ShellWrapOutcome,
  ShellWrapShell,
  ShellWrapStatus,
  ShellWrapStatusResponse,
  ShellWrapTool,
} from "@/lib/types";

// ShellWrapCard - Settings -> Terminal "Command wrapping" (backlog item 7).
//
// Makes typing a tool's own command run its observer-wrapped form (`claude`
// -> `observer claude`, `code` -> `observer ide vscode`). The daemon writes
// small shims into an observer-owned directory and a marked, removable PATH
// block into the chosen shells' start-up files; everything is written by ONE
// server-side applier (internal/shellwrapsvc) - this card only chooses,
// previews and confirms.
//
// Low-friction rules the card keeps:
//   - OFF by default; nothing is written until "Apply" after a preview.
//   - Apply is only offered for the EXACT selection just previewed, and the
//     preview shows every file and the exact block it adds.
//   - Undo is one click and restores each start-up file byte-for-byte.
//   - Each row says honestly what wrapping buys (from the registry's
//     WrappedCommandFor seam, never a per-tool guess).
//   - Inside WSL a second target appears: the Windows shells of the same
//     machine (T-419). Each target keeps its own recorded choice; switching
//     drops the selection and any preview, so Apply never crosses targets.

const STATUS = "/api/shell-wrap/status";

const CODE = "rounded-1 bg-bg-3 px-1 py-0.5 font-mono text-[11px] text-fg-1";
const BTN =
  "rounded-2 border border-line-2 bg-bg-3 px-3 py-1 text-small font-medium text-fg-1 hover:bg-bg-4 disabled:opacity-50";
const PRIMARY_BTN =
  "rounded-2 border border-accent/50 bg-accent/15 px-3 py-1 text-[12px] font-medium text-accent hover:bg-accent/25 disabled:opacity-50";

export function ShellWrapCard({ readOnly = false }: { readOnly?: boolean }) {
  const [target, setTarget] = useState<ShellWrapTargetChoice>("native");
  const res = useApi<ShellWrapStatusResponse>(STATUS, statusParams(target));
  const st = res.data?.status ?? null;
  const token = res.data?.confirm_token ?? "";
  const targets = useMemo(() => targetOptions(res.data?.targets), [res.data?.targets]);

  const [tools, setTools] = useState<string[]>([]);
  const [shells, setShells] = useState<string[]>([]);
  const [seeded, setSeeded] = useState(false);
  const [preview, setPreview] = useState<{ key: string; out: ShellWrapOutcome } | null>(null);
  const [result, setResult] = useState<ShellWrapOutcome | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // The response on screen may still be the previous target's while the new
  // one loads (the cache keeps the previous data for the same path).
  const forTarget = (res.data?.target ?? "") === targetApiId(target);

  // Seed the checkboxes once per target from its RECORDED choice.
  useEffect(() => {
    if (!st || seeded || !forTarget) return;
    setTools((st.tools ?? []).filter((t) => t.selected).map((t) => t.id));
    setShells(st.enabled ? (st.planned_shells ?? []) : []);
    setSeeded(true);
  }, [st, seeded, forTarget]);

  const key = target + "|" + selectionKey(tools, shells);
  const previewCurrent = preview !== null && preview.key === key;

  const cli = useMemo(() => (st?.tools ?? []).filter((t) => t.kind === "terminal"), [st]);
  const gui = useMemo(() => (st?.tools ?? []).filter((t) => t.kind === "gui"), [st]);

  function switchTarget(t: ShellWrapTargetChoice) {
    if (t === target || busy) return;
    setTarget(t);
    setTools([]);
    setShells([]);
    setSeeded(false);
    setPreview(null);
    setResult(null);
    setErr(null);
  }

  const switcher =
    targets.length > 0 ? (
      <SegmentedControl<ShellWrapTargetChoice> options={targets} value={target} onChange={switchTarget} size="sm" />
    ) : null;

  if (res.error) {
    return (
      <Shell badge={<Pill variant="neutral">unavailable</Pill>}>
        {switcher}
        <p className="text-[11px] text-fg-3">
          Command wrapping is managed from this machine only (it edits your shell start-up
          files). {res.error.message}
        </p>
      </Shell>
    );
  }
  if (!st) return null;

  const badge = stateLabel(st);

  function toggle(list: string[], set: (v: string[]) => void, id: string) {
    set(list.includes(id) ? list.filter((x) => x !== id) : [...list, id]);
    setResult(null);
  }

  async function post(path: string, body: unknown): Promise<ShellWrapOutcome> {
    return fetchJSON<ShellWrapOutcome>(path, undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Observer-Confirm": token },
      body: JSON.stringify(body),
    });
  }

  async function run(fn: () => Promise<void>) {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const doPreview = () =>
    run(async () => {
      const out = await post("/api/shell-wrap/apply", { target: targetApiId(target), tools, shells, dry_run: true });
      setPreview({ key, out });
      setResult(null);
    });

  const doApply = () =>
    run(async () => {
      const out = await post("/api/shell-wrap/apply", { target: targetApiId(target), tools, shells, dry_run: false });
      setResult(out);
      setPreview(null);
      res.reload();
    });

  const doDisable = () =>
    run(async () => {
      const out = await post("/api/shell-wrap/disable", { target: targetApiId(target), dry_run: false });
      setResult(out);
      setPreview(null);
      res.reload();
    });

  const selectInstalled = () => {
    setTools(cli.filter((t) => t.installed !== false).map((t) => t.id));
    setResult(null);
  };

  return (
    <Shell badge={<Pill variant={badge.tone}>{badge.text}</Pill>}>
      {switcher}
      {st.bridge && <BridgeNote st={st} />}
      <p className="text-[11.5px] leading-relaxed text-fg-2">
        Make typing a tool&rsquo;s own command run its observer-wrapped form - for example{" "}
        <code className={CODE}>claude</code> runs <code className={CODE}>observer claude</code>.
        Observer writes one small shim per command into{" "}
        <code className={CODE}>{st.shim_dir}</code> and puts that folder first on{" "}
        <code className={CODE}>PATH</code> through a marked block in your shell start-up files.
        Off by default. Nothing is written until you preview and apply.
      </p>
      <p className="text-[11px] leading-relaxed text-fg-3">
        You are never locked out: if observer is missing a shim runs the real command, and{" "}
        <code className={CODE}>SBO_SHIM_BYPASS=1 claude</code> always does. Turning it off
        removes every shim and restores each start-up file byte-for-byte. The same controls
        exist on the command line as <code className={CODE}>observer shell-wrap</code>.
      </p>

      <ToolList
        title="Command-line tools"
        st={st}
        tools={cli}
        selected={tools}
        onToggle={(id) => toggle(tools, setTools, id)}
        extra={
          <button type="button" className={BTN} onClick={selectInstalled} disabled={busy}>
            Select all installed
          </button>
        }
      />
      {gui.length > 0 && (
        <ToolList
          title="IDEs and desktop apps"
          note="Only a bare launch or a single folder is wrapped (code, code .). Anything else - a file, a flag - runs the real command, and so does the command inside the app's own terminal."
          st={st}
          tools={gui}
          selected={tools}
          onToggle={(id) => toggle(tools, setTools, id)}
        />
      )}

      <UnavailableList st={st} />

      <div className="space-y-1">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">Shells</div>
        <div className="flex flex-wrap gap-3">
          {(st.shells ?? []).map((sh) => (
            <label key={sh} className="flex items-center gap-1.5 text-[12px] text-fg-1">
              <input
                type="checkbox"
                checked={shells.includes(sh)}
                onChange={() => toggle(shells, setShells, sh)}
                disabled={busy}
              />
              {sh}
              {(st.detected_shells ?? []).includes(sh as ShellWrapShell) && (
                <span className="text-[10.5px] text-fg-3">(detected)</span>
              )}
            </label>
          ))}
        </div>
        <p className="text-[10.5px] text-fg-3">
          None ticked = the shells detected in use (
          {(st.detected_shells ?? []).join(", ") || "none detected"}).
          {st.goos === "windows" &&
            " On Windows only PowerShell profiles are managed; for cmd.exe add the shim folder to PATH yourself."}
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BTN} onClick={doPreview} disabled={busy || !forTarget}>
          {busy && !previewCurrent ? "working…" : "Preview changes"}
        </button>
        <button
          type="button"
          className={PRIMARY_BTN}
          onClick={doApply}
          disabled={busy || readOnly || !previewCurrent || !forTarget}
          title={previewCurrent ? undefined : "Preview this selection first"}
        >
          Apply
        </button>
        {(st.active || st.enabled) && (
          <button type="button" className={BTN} onClick={doDisable} disabled={busy}>
            Turn off and restore files
          </button>
        )}
        {err && <span className="text-[11.5px] text-danger">{err}</span>}
        {readOnly && (
          <span className="text-[11px] text-fg-3">
            Pinned by your organization - you can still turn it off.
          </span>
        )}
      </div>

      {previewCurrent && preview && <OutcomeView out={preview.out} />}
      {result && <OutcomeView out={result} />}

      {(st.rc ?? []).length > 0 && (
        <div className="space-y-1 text-[11px] text-fg-3">
          <div className="font-semibold uppercase tracking-[0.06em]">Start-up files</div>
          {(st.rc ?? []).map((r) => (
            <div key={r.path} className="font-mono">
              {r.shell || "?"} {r.path} -{" "}
              {r.error ? r.error : r.has_block ? (r.wanted && !r.current ? "block outdated" : "block installed") : "block missing"}
            </div>
          ))}
        </div>
      )}
      {(st.warnings ?? []).map((w) => (
        <p key={w} className="text-[11px] text-warn">
          {w}
        </p>
      ))}
    </Shell>
  );
}

// UnavailableList shows the advertised tools that have no command to wrap on
// this target, each with the server's reason and, when one exists, the
// wrapped launch that still works. Nothing is dropped silently (T-492).
function UnavailableList({ st }: { st: ShellWrapStatus }) {
  const rows = unavailableRows(st);
  if (rows.length === 0) return null;
  return (
    <details className="space-y-1.5">
      <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Not wrappable here ({rows.length})
      </summary>
      <ul className="mt-1.5 divide-y divide-line-1 rounded-2 border border-line-1">
        {rows.map((u) => (
          <li key={`${u.kind}/${u.id}`} className="space-y-0.5 px-3 py-1.5 text-[12px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-fg-1">{u.label}</span>
              <Pill variant="neutral">{u.kind === "gui" ? "IDE or desktop app" : "command line"}</Pill>
            </div>
            <div className="text-[11px] text-fg-3">{u.reason}</div>
            {u.hint && (
              <div className="text-[11px] text-fg-3">
                Still works: <code className={CODE}>{u.hint}</code>
              </div>
            )}
          </li>
        ))}
      </ul>
    </details>
  );
}

// BridgeNote explains the Windows target: what runs where, and how the shims
// reach the daemon.
function BridgeNote({ st }: { st: ShellWrapStatus }) {
  const distro = st.bridge?.distro ?? "";
  return (
    <p className="rounded-2 border border-line-2 bg-bg-3/40 px-3 py-2 text-[11px] leading-relaxed text-fg-2">
      These are the commands you type in <strong>Windows</strong> PowerShell. A tool with a Windows
      build keeps running as Windows: its shim asks observer in WSL ({distro}) for the routing it
      applies, through <code className={CODE}>wsl.exe</code>, then runs the Windows program. A tool
      with no Windows build runs inside WSL. If the daemon does not answer, the Windows program runs
      unrouted. For cmd.exe, add <code className={CODE}>{st.shim_dir}</code> to your PATH yourself.
    </p>
  );
}

function ToolList({
  title,
  note,
  st,
  tools,
  selected,
  onToggle,
  extra,
}: {
  title: string;
  note?: string;
  st: ShellWrapStatus;
  tools: ShellWrapTool[];
  selected: string[];
  onToggle: (id: string) => void;
  extra?: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">{title}</div>
        {extra}
      </div>
      {note && <p className="text-[10.5px] text-fg-3">{note}</p>}
      <ul className="divide-y divide-line-1 rounded-2 border border-line-1">
        {tools.map((t) => {
          const active = (t.active ?? []).length > 0;
          const stale = (t.stale ?? []).length > 0;
          return (
            <li key={t.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5 text-[12px]">
              <label className="flex min-w-[180px] items-center gap-1.5 text-fg-1">
                <input type="checkbox" checked={selected.includes(t.id)} onChange={() => onToggle(t.id)} />
                <span className="font-mono">{(t.commands ?? []).join(", ")}</span>
              </label>
              <span className="text-fg-3">
                runs <code className={CODE}>{t.wrapped}</code>
              </span>
              <Pill variant={HONESTY_TONE[t.honesty]}>{t.honesty_text}</Pill>
              {t.route_flag && (
                <span className="text-[10.5px] text-fg-3">
                  route with <code className={CODE}>{t.route_flag}</code>
                </span>
              )}
              {sideLabel(st, t) && (
                <span title={t.where} className="text-[10.5px] text-fg-3">
                  {sideLabel(st, t)}
                </span>
              )}
              {t.installed === false && <Pill variant="neutral">not installed</Pill>}
              {active && <Pill variant={stale ? "warn" : "info"}>{stale ? "active - stale" : "active"}</Pill>}
              {!active && t.selected && <Pill variant="warn">chosen, not applied</Pill>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function OutcomeView({ out }: { out: ShellWrapOutcome }) {
  const changes = (out.changes ?? []).filter((c) => c.action !== "unchanged");
  return (
    <div className="space-y-2 rounded-2 border border-line-2 bg-bg-3/40 p-3 text-[11.5px]">
      <div className="font-semibold text-fg-1">
        {out.dry_run ? "Preview - nothing written yet" : "Applied"}
      </div>
      {changes.length === 0 && <div className="text-fg-3">Nothing to change.</div>}
      {changes.map((c) => (
        <div key={c.kind + c.path} className="space-y-1">
          <div className="font-mono text-fg-2">
            {c.action} {c.shell || c.kind} {c.path}
            {c.target ? ` -> ${c.target}` : ""}
          </div>
          {out.dry_run && c.kind === "rc" && c.detail && (
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-2 border border-line-2 bg-bg-3 px-2 py-1 font-mono text-[10.5px] text-fg-3">
              {c.detail}
            </pre>
          )}
        </div>
      ))}
      {(out.plan.warnings ?? []).map((w) => (
        <p key={w} className="text-[11px] text-warn">
          {w}
        </p>
      ))}
      {(out.notes ?? []).map((n) => (
        <p key={n} className="text-[11px] text-fg-3">
          {n}
        </p>
      ))}
    </div>
  );
}

function Shell({ badge, children }: { badge: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="mt-6 space-y-3 rounded-3 border border-line-2 bg-bg-2 p-4">
      <header className="flex items-baseline justify-between gap-3">
        <h4 className="text-[13px] font-semibold text-fg-0">Command wrapping</h4>
        {badge}
      </header>
      {children}
    </section>
  );
}

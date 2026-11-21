// SandboxReturnsPanel is the Terminals page's "Changes from sandboxed runs"
// (lane RETURNS): the work sandboxed runs brought back, and the person's
// choices for it. A hosted run's changes come home as a saved diff: the panel
// shows its files and a read-only preview, and offers "Open as a branch"
// (a new branch of the folder's repository; the folder itself is not
// touched) when the diff's starting point is a commit, else the file and the
// command to apply it by hand. A local copy run's commits come back on their
// own when the run ends; the panel says where, and offers "Remove the copy"
// (the server removes it only when everything in it is known to be safe
// elsewhere, and says why not otherwise). Every action is the person's click:
// the routes are owner-local, need the confirm token, and refuse an agent.
// The pure half (words, tones, choices) is lib/sandboxReturns.ts.

import { useState } from "react";
import { ChartShell, ConfirmButton, EmptyState, HelpTooltip, InlineLoading, Pill, SuccessCheck } from "@/components/primitives";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { fmtBytes, fmtRelative, fmtShortId } from "@/lib/format";
import { writeClipboard } from "@/lib/clipboard";
import {
  actionError,
  bulkResultLines,
  copyTotals,
  diffPreviewLines,
  fileStatsLabel,
  hasAnything,
  hostedDiffOffer,
  localReturnStatus,
  removeSafeLabel,
  sizeLabel,
  sourceLabel,
  type CopyBulkResult,
  type DiffLineKind,
  type DiffPreview,
  type HostedDiff,
  type LocalReturn,
  type ReturnsPage,
} from "@/lib/sandboxReturns";

const RETURNS = "/api/terminal/sandbox/returns";

const LINE_CLASS: Record<DiffLineKind, string> = {
  file: "text-fg-1 font-semibold",
  hunk: "text-info",
  add: "text-success",
  del: "text-danger",
  meta: "text-fg-3",
  context: "text-fg-2",
};

const btn =
  "rounded-2 border border-line-2 px-2 py-0.5 text-[11px] text-fg-1 hover:bg-bg-2 disabled:opacity-50 disabled:cursor-not-allowed";
const btnAccent =
  "rounded-2 border border-accent/50 bg-accent/15 px-2 py-0.5 text-[11px] text-accent hover:bg-accent/25 disabled:opacity-50";

async function post<T>(path: string, run: string): Promise<T> {
  try {
    return await fetchJSON<T>(path, undefined, {
      method: "POST",
      headers: await localConfirmHeaders(),
      body: JSON.stringify({ run }),
    });
  } catch (e) {
    if (e instanceof ApiError) throw new Error(actionError(e.body, e.message));
    throw e;
  }
}

export function SandboxReturnsPanel() {
  const res = useApi<ReturnsPage>(RETURNS);
  // A build or a machine without the sandbox module answers 404: no panel.
  if (res.error instanceof ApiError && res.error.status === 404) return null;
  const page = res.data;
  return (
    <div id="sandbox-returns" className="scroll-mt-6">
      <ChartShell
        title="Changes from sandboxed runs"
        sub="Work your sandboxed runs brought back. Nothing is applied to your folders; you choose what to keep."
        right={res.loading && !page ? <InlineLoading label="Loading" /> : undefined}
      >
        {res.error && !page && (
          <div className="rounded-2 border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">
            {res.error.message}
          </div>
        )}
        {page && !hasAnything(page) && (
          <EmptyState title="Nothing brought back yet" body="When a sandboxed run that worked on a copy ends, its changes show here." />
        )}
        {page && page.hosted.length > 0 && (
          <section className="space-y-2" aria-label="Changes from hosted sandboxes">
            <h3 className="text-[12px] font-semibold text-fg-1">From hosted sandboxes</h3>
            {page.hosted.map((d) => (
              <HostedDiffRow key={d.run} d={d} onChanged={res.reload} />
            ))}
          </section>
        )}
        {page && page.local.length > 0 && (
          <section className="mt-4 space-y-2" aria-label="Changes from local sandboxes">
            <h3 className="text-[12px] font-semibold text-fg-1">From local sandboxes</h3>
            <RemoveSafeCopies local={page.local} onChanged={res.reload} />
            {page.local.map((v) => (
              <LocalReturnRow key={v.id} v={v} onChanged={res.reload} />
            ))}
          </section>
        )}
      </ChartShell>
    </div>
  );
}

// RemoveSafeCopies (decision SBXD-2) is the copies' total size and the one
// click that removes every copy the removal rules allow: the server checks
// each copy again and keeps any that holds work that did not come back,
// saying why.
function RemoveSafeCopies({ local, onChanged }: { local: LocalReturn[]; onChanged: () => void }) {
  const totals = copyTotals(local);
  const [busy, setBusy] = useState(false);
  const [lines, setLines] = useState<string[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (totals.count === 0) return null;

  async function run() {
    setBusy(true);
    setErr(null);
    setLines(null);
    try {
      const out = await fetchJSON<CopyBulkResult>(`${RETURNS}/remove-safe-copies`, undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: "{}",
      });
      setLines(bulkResultLines(out));
      onChanged();
    } catch (e) {
      setErr(e instanceof ApiError ? actionError(e.body, e.message) : e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-2 border border-line-2 bg-bg-3 px-3 py-2 text-[12px]" data-remove-safe-copies>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg-2">
          {totals.count} cop{totals.count === 1 ? "y" : "ies"} on this machine, {sizeLabel(totals.bytes)} in all.
        </span>
        <ConfirmButton
          variant="soft"
          armedVariant="danger"
          size="sm"
          disabled={busy || totals.candidates === 0}
          loading={busy}
          onConfirm={() => void run()}
          confirmLabel="Remove them now?"
          armedNote="Each copy is checked again first. A copy whose commits did not come back, or that holds files not in its last commit, is kept and the reason is shown."
        >
          {removeSafeLabel(totals)}
        </ConfirmButton>
        <HelpTooltip
          technical
          subject="removing copies"
          content="POST /api/terminal/sandbox/returns/remove-safe-copies walks the same removal rules as Remove the copy, at most 50 copies a click. Copies are also removed by age after [terminal.sandbox].returned_copy_retention_days (default 30, 0 turns it off) under the same rules."
        />
      </div>
      {lines && (
        <ul className="mt-2 space-y-0.5 text-fg-2" role="status">
          {lines.map((l, i) => (
            <li key={i}>{l}</li>
          ))}
        </ul>
      )}
      {err && (
        <div className="mt-2 rounded-2 border border-danger/40 bg-danger/10 px-2 py-1 text-danger" role="alert">
          {err}
        </div>
      )}
    </div>
  );
}

function HostedDiffRow({ d, onChanged }: { d: HostedDiff; onChanged: () => void }) {
  const offer = hostedDiffOffer(d);
  const [preview, setPreview] = useState<DiffPreview | null>(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [made, setMade] = useState<string | null>(null);
  const [armed, setArmed] = useState(false);
  const [copied, setCopied] = useState(false);

  async function toggle() {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (!preview) {
      try {
        setPreview(await fetchJSON<DiffPreview>(`${RETURNS}/diff`, { run: d.run }));
      } catch (e) {
        setErr(e instanceof Error ? e.message : String(e));
      }
    }
  }
  async function branch() {
    setBusy(true);
    setErr(null);
    try {
      const out = await post<{ branch: string }>(`${RETURNS}/branch`, d.run);
      setMade(out.branch);
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  async function remove() {
    if (!armed) {
      setArmed(true);
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await post(`${RETURNS}/remove-diff`, d.run);
      onChanged();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setArmed(false);
    }
  }
  async function copyCommand() {
    const r = await writeClipboard(offer.copy?.text ?? d.apply_command);
    setCopied(r !== "failed");
  }

  const lines = preview ? diffPreviewLines(preview.text) : null;
  return (
    <div className="rounded-2 border border-line-2 px-3 py-2 text-[12px]" data-hosted-run={d.run}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-fg-1">Run {fmtShortId(d.run, 10)}</span>
        <span className="text-fg-3">{fmtRelative(d.saved_at)}</span>
        <span className="text-fg-3">{fmtBytes(d.bytes)}</span>
        <Pill variant={offer.status.tone}>{offer.status.label}</Pill>
        <HelpTooltip
          technical
          subject="this saved diff"
          content={
            <>
              {d.path}
              {d.root ? ` · folder ${d.root}` : ""}
              {d.base_commit ? ` · commit ${d.base_commit}` : ""}
            </>
          }
        />
      </div>
      {d.root && <div className="mt-1 text-fg-2">From {d.root}</div>}
      {offer.status.detail && <div className="mt-1 text-fg-2">{offer.status.detail}</div>}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <button type="button" className={btn} onClick={toggle} aria-expanded={open}>
          {open ? "Hide changes" : "Show changes"}
        </button>
        {offer.canBranch && (
          <button type="button" className={btnAccent} disabled={busy} onClick={branch}>
            {busy ? "Opening…" : "Open as a branch"}
          </button>
        )}
        {offer.canBranch && offer.branch && !made && (
          <span className="text-fg-3">
            Creates <span className="font-mono">{offer.branch}</span>
          </span>
        )}
        {!offer.canBranch && !d.branch_exists && (
          <button type="button" className={btn} onClick={copyCommand}>
            {offer.copy?.label ?? "Copy the apply command"}
          </button>
        )}
        {copied && <SuccessCheck label="Copied" className="!text-[11px]" />}
        <button type="button" className={btn} disabled={busy} onClick={remove}>
          {armed ? "Remove the saved diff?" : "Remove"}
        </button>
        {armed && (
          <button type="button" className={btn} onClick={() => setArmed(false)}>
            Keep it
          </button>
        )}
      </div>
      {made && (
        <div className="mt-2 text-success" role="status">
          Opened as the branch <span className="font-mono">{made}</span>. Your folder and its current branch are unchanged.
        </div>
      )}
      {err && (
        <div className="mt-2 rounded-2 border border-danger/40 bg-danger/10 px-2 py-1 text-danger" role="alert">
          {err}
        </div>
      )}
      {open && preview && lines && (
        <div className="mt-2 space-y-1">
          <div className="text-fg-3">{fileStatsLabel(preview.files)}</div>
          {preview.files.length > 0 && (
            <ul className="max-h-32 overflow-auto font-mono text-[11px] text-fg-2">
              {preview.files.map((f) => (
                <li key={f.path}>
                  {f.binary ? "binary" : `+${f.added} -${f.deleted}`} {f.path}
                </li>
              ))}
            </ul>
          )}
          <pre
            className="max-h-96 overflow-auto rounded-2 border border-line-2 bg-bg-1 p-2 font-mono text-[11px] leading-snug"
            aria-label="Diff preview (read only)"
          >
            {lines.lines.map((l, i) => (
              <div key={i} className={LINE_CLASS[l.kind]}>
                {l.text || " "}
              </div>
            ))}
          </pre>
          {(lines.more || preview.cut) && <div className="text-fg-3">The preview shows only the start of the diff.</div>}
        </div>
      )}
    </div>
  );
}

function LocalReturnRow({ v, onChanged }: { v: LocalReturn; onChanged: () => void }) {
  const status = localReturnStatus(v);
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function remove() {
    if (!armed) {
      setArmed(true);
      return;
    }
    setBusy(true);
    setMsg(null);
    try {
      await post(`${RETURNS}/remove-copy`, v.id);
      onChanged();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setArmed(false);
    }
  }
  async function copyFetch() {
    if (!v.fetch_command) return;
    const r = await writeClipboard(v.fetch_command);
    setCopied(r !== "failed");
  }

  return (
    <div className="rounded-2 border border-line-2 px-3 py-2 text-[12px]" data-local-run={v.id}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-fg-1">Run {fmtShortId(v.id, 10)}</span>
        <span className="text-fg-2">{sourceLabel(v.source)}</span>
        <span className="text-fg-3">{fmtRelative(v.created_at)}</span>
        <span className="text-fg-3">
          {fmtBytes(v.size_bytes)}
          {v.size_over ? "+" : ""}
        </span>
        <Pill variant={status.tone}>{status.label}</Pill>
        <HelpTooltip
          technical
          subject="this copy"
          content={
            <>
              {v.copy_dir ?? v.id}
              {v.commit ? ` · commit ${v.commit}` : ""}
              {v.state ? ` · ${v.state}` : ""}
            </>
          }
        />
      </div>
      <div className="mt-1 text-fg-2">From {v.origin}</div>
      {status.detail && <div className="mt-1 text-fg-2">{status.detail}</div>}
      {v.fetch_command && (
        <div className="mt-1 flex flex-wrap items-center gap-2 text-fg-2">
          <span>To bring them into your own checkout, run this there:</span>
          <code className="break-all font-mono text-[11px] text-fg-1">{v.fetch_command}</code>
          <button type="button" className={btn} onClick={copyFetch}>
            Copy
          </button>
          {copied && <SuccessCheck label="Copied" className="!text-[11px]" />}
        </div>
      )}
      {v.removable && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button type="button" className={btn} disabled={busy} onClick={remove}>
            {armed ? "Remove the copy now?" : "Remove the copy"}
          </button>
          {armed && (
            <>
              <button type="button" className={btn} onClick={() => setArmed(false)}>
                Keep it
              </button>
              <span className="text-fg-3">It is removed only if everything in it is already in its commits.</span>
            </>
          )}
          {v.safe_to_remove === false && v.keep_reason && (
            <span className="text-fg-3">Not counted as safe to remove: {v.keep_reason}.</span>
          )}
        </div>
      )}
      {msg && (
        <div className="mt-2 rounded-2 border border-warn/40 bg-warn/10 px-2 py-1 text-warn" role="alert">
          {msg}
        </div>
      )}
    </div>
  );
}

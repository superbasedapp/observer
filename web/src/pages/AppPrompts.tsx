import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { ColumnDef } from "@tanstack/react-table";
import { FileText, Plus } from "lucide-react";
import { Button, ChartShell, DataTable, EmptyState, ErrorState, InlineLoading, PageHeader, Pill, SlideOver, TableSkeleton } from "@/components/primitives";
import { VocabDefPill } from "@shared/primitives/VocabDefPill";
import { PROMPT_TYPE } from "@shared/lib/obsVocab";
import { dateTime } from "@shared/lib/displayFormat";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import type { AppPromptList, AppPromptListRow } from "@/lib/planeaApi";
import { APPS_HEADER_CLASS, AppsGate, ReadState } from "@/components/apps/AppsChrome";
import {
  PromptDraftForm,
  PromptHistoryList,
  PromptLabelBar,
  PromptVersionList,
  type PromptDetail,
  type PromptDraft,
  type PromptLabel,
} from "@shared/components/planea/prompts";
import { PromptDiffPicker, PromptDiffView, PromptRolloutPanel, type PromptDiff } from "@shared/components/planea/promptRollout";

// Your apps > Prompts (Plane A lane B5, node parity for W3-3; authoring added
// by lane C8 for review finding R-B15 and W5-3): the machine's prompt
// registry, the one an SDK with destination = local fetches from
// (GET /api/obs/sdk/prompts, contracts/prompts.md section 7). Authoring runs
// over the machine's management routes, the same writes as
// `observer obs prompts`: POST /api/obs/prompts/{name}/versions,
// PUT .../labels/{label}, POST .../rollback, PUT .../rollouts/{label}, and the
// read GET .../diff. The writes are owner-local (the confirm token). Approval
// is an org rule (a second member approves); a machine has one user, so it
// has none.

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    try {
      const v = JSON.parse(e.body) as { error?: string; message?: string };
      if (v.message) return v.message;
      if (v.error) return v.error;
    } catch {
      // fall through
    }
  }
  return e instanceof Error ? e.message : String(e);
}

async function send<T>(method: "PUT" | "POST", path: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method,
    headers: { "content-type": "application/json", ...(await localConfirmHeaders()) },
    body: JSON.stringify(body),
  });
}

const promptRoute = (name: string) => `/api/obs/prompts/${encodeURIComponent(name)}`;

export function AppPromptsPage() {
  const [sp, setSp] = useSearchParams();
  const open = sp.get("prompt");
  const q = useApi<AppPromptList>("/api/obs/sdk/prompts", { limit: 500 });
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const columns = useMemo<ColumnDef<AppPromptListRow, any>[]>(
    () => [
      { accessorKey: "name", header: "Prompt", cell: (c) => <span className="font-medium text-fg-1">{c.row.original.name}</span> },
      { accessorKey: "type", header: "Type", cell: (c) => <VocabDefPill of={PROMPT_TYPE} value={c.row.original.type} /> },
      { accessorKey: "latest_version", header: "Latest", cell: (c) => `v${c.row.original.latest_version}`, meta: { align: "right" } },
      {
        id: "labels",
        header: "Labels",
        cell: (c) => (
          <span className="inline-flex gap-1">
            {(["production", "staging"] as const).map((l) =>
              c.row.original.labels[l] != null ? (
                <Pill key={l} variant={l === "production" ? "success" : "info"}>
                  {l} v{c.row.original.labels[l]}
                </Pill>
              ) : null,
            )}
          </span>
        ),
      },
      { accessorKey: "updated_at", header: "Updated", cell: (c) => dateTime(c.row.original.updated_at), meta: { align: "right" } },
    ],
    [],
  );
  const rows = q.data?.prompts ?? [];
  const setOpen = (name: string | null) => {
    const next = new URLSearchParams(sp);
    if (name) next.set("prompt", name);
    else next.delete("prompt");
    setSp(next, { replace: true });
  };
  async function create(name: string, draft: PromptDraft) {
    setBusy(true);
    setErr(null);
    try {
      await send<PromptDetail>("POST", `${promptRoute(name)}/versions`, draft);
      setCreating(false);
      q.reload();
      setOpen(name);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-prompts")}
        title="Prompts"
        className={APPS_HEADER_CLASS}
        sub="Versioned prompts your apps fetch through the SDK, with their production and staging labels."
        right={
          <Button variant="primary" iconLeft={Plus} onClick={() => setCreating(true)}>
            New prompt
          </Button>
        }
      />
      <AppsGate>
        <ChartShell title="Prompts">
          <ReadState error={q.error} onRetry={q.reload} feature="Prompts" />
          {q.loading && !q.data ? (
            <TableSkeleton rows={6} />
          ) : !q.error && rows.length === 0 ? (
            <EmptyState
              variant="inline"
              icon={FileText}
              title="No prompts on this machine yet"
              body="Create one with New prompt; an app fetches it by name once a label points at it."
            />
          ) : (
            !q.error && <DataTable data={rows} columns={columns} rowKey={(r) => r.name} onRowClick={(r) => setOpen(r.name)} zebra minWidth={640} />
          )}
        </ChartShell>
      </AppsGate>
      <SlideOver open={creating} onClose={() => setCreating(false)} width={640} bodyClassName="p-5" title="New prompt" subtitle="Creates version 1. Apps see it once a label points at it.">
        {creating && <PromptDraftForm busy={busy} error={err} onSubmit={(n, d) => void create(n, d)} />}
      </SlideOver>
      <SlideOver open={open !== null} onClose={() => setOpen(null)} width={820} bodyClassName="p-5" title="Prompt" subtitle={open ?? undefined}>
        {open && <PromptManage key={open} name={open} onChanged={q.reload} />}
      </SlideOver>
    </div>
  );
}

function PromptManage({ name, onChanged }: { name: string; onChanged: () => void }) {
  const q = useApi<PromptDetail>(promptRoute(name));
  const [shown, setShown] = useState<PromptDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [newVersion, setNewVersion] = useState(false);
  const detail = shown ?? q.data;
  const latest = detail?.latest_version ?? 0;
  const [pair, setPair] = useState<{ from: number; to: number } | null>(null);
  const from = pair?.from ?? Math.max(1, latest - 1);
  const to = pair?.to ?? latest;
  const diff = useApi<PromptDiff>(latest > 1 ? `${promptRoute(name)}/diff` : null, { from, to }, [from, to, latest]);

  async function write(method: "PUT" | "POST", path: string, body: unknown) {
    setBusy(true);
    setErr(null);
    try {
      setShown(await send<PromptDetail>(method, path, body));
      setNewVersion(false);
      onChanged();
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  }
  if (q.error && !detail) return <ErrorState error={q.error} onRetry={q.reload} />;
  if (!detail) return <InlineLoading label="Loading the prompt..." />;
  const actions = {
    busy,
    onMoveLabel: (label: PromptLabel, version: number) => void write("PUT", `${promptRoute(name)}/labels/${label}`, { version }),
    onRollback: (label: PromptLabel) => void write("POST", `${promptRoute(name)}/rollback`, { label }),
  };
  return (
    <div className="space-y-4">
      <PromptLabelBar detail={detail} actions={actions} />
      {err && <p className="text-[11px] text-danger">{err}</p>}
      <div className="flex justify-end">
        <Button size="sm" variant="secondary" iconLeft={Plus} onClick={() => setNewVersion((v) => !v)}>
          {newVersion ? "Cancel" : "New version"}
        </Button>
      </div>
      {newVersion && (
        <PromptDraftForm
          lockedName={name}
          lockedType={detail.type}
          initial={detail.versions[0]}
          busy={busy}
          error={err}
          onSubmit={(n, d) => void write("POST", `${promptRoute(n)}/versions`, d)}
        />
      )}
      <section className="space-y-2">
        <h3 className="text-[13px] font-medium text-fg-1">Versions</h3>
        <PromptVersionList detail={detail} actions={actions} />
      </section>
      <section className="space-y-2">
        <h3 className="text-[13px] font-medium text-fg-1">Staged rollout</h3>
        <PromptRolloutPanel
          key={JSON.stringify(detail.rollouts ?? {}) + detail.latest_version}
          detail={detail}
          actions={{ busy, onSetRollout: (label, version, percent) => void write("PUT", `${promptRoute(name)}/rollouts/${label}`, { version, percent }) }}
        />
      </section>
      {latest > 1 && (
        <section className="space-y-2">
          <h3 className="text-[13px] font-medium text-fg-1">Compare versions</h3>
          <PromptDiffPicker latest={latest} from={from} to={to} onChange={(f, t) => setPair({ from: f, to: t })} />
          {diff.error ? <ErrorState error={diff.error} onRetry={diff.reload} /> : diff.data ? <PromptDiffView diff={diff.data} /> : null}
        </section>
      )}
      <section className="space-y-2">
        <h3 className="text-[13px] font-medium text-fg-1">Label history</h3>
        <PromptHistoryList history={detail.history} />
      </section>
    </div>
  );
}

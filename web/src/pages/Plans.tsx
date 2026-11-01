import { useEffect, useMemo, useState } from "react";
import { Plus, RefreshCw } from "lucide-react";
import {
  Button,
  Callout,
  EmptyState,
  ErrorState,
  InlineLoading,
  Input,
  PageHeader,
  Pill,
  SlideOver,
  Toggle,
} from "@/components/primitives";
import { AddAccountModal } from "@/components/plans/AddAccountModal";
import { PlanCardView } from "@/components/plans/PlanCardView";
import { ExperimentalSources, TrackMore } from "@/components/plans/PlansSections";
import { SourceFields } from "@/components/plans/SourceFields";
import { useApi } from "@/lib/useApi";
import { apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { navIcon } from "@/lib/nav";
import type { ToolsStatusResponse } from "@/lib/types";
import { fmtDateTime } from "../../../shared/lib/format.ts";
import {
  SOURCE_LABELS,
  errorText,
  providerLabel,
  statusVocab,
  type CatalogProvider,
  type PlanAccount,
  type PlanRunState,
  type PlansResponse,
} from "@/lib/plans";
import { experimentalRows, suggestions, vendorCount } from "@/lib/plansView";

// Plans & limits: how much of each coding plan and API balance is left.
// The server (internal/planlimitssvc) owns every rule; this page renders
// its page model and collects account edits. Secrets are typed here and
// sent once; no reply ever carries one back. The view rules (the headline,
// the picker, the suggestions) are pure, in lib/plansView.ts.

async function post<T>(path: string, body: unknown): Promise<T> {
  return fetchJSON<T>(path, undefined, {
    method: "POST",
    headers: await localConfirmHeaders(),
    body: JSON.stringify(body),
  });
}

function reason(e: unknown): string {
  return errorText(apiReason(e));
}

/** usedToolIds: tools this machine has captured, most used first. */
function usedToolIds(r: ToolsStatusResponse | null): string[] {
  return (r?.tools ?? [])
    .filter((t) => t.action_count > 0)
    .sort((a, b) => b.action_count - a.action_count)
    .map((t) => t.tool);
}

export function PlansPage() {
  const res = useApi<PlansResponse>("/api/plans");
  const toolsRes = useApi<ToolsStatusResponse, string[]>("/api/tools/status", undefined, [], { select: usedToolIds });
  const [adding, setAdding] = useState<{ provider?: string } | null>(null);
  const [editing, setEditing] = useState<PlanAccount | null>(null);
  const [history, setHistory] = useState<PlanAccount | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);

  // The page keeps itself current while open (the server polls faster then).
  const reload = res.reload;
  useEffect(() => {
    const t = window.setInterval(() => reload(), 60_000);
    return () => window.clearInterval(t);
  }, [reload]);

  const data = res.data;
  const catalog = useMemo(() => data?.catalog ?? [], [data]);
  const accountList = useMemo(() => data?.view.accounts ?? [], [data]);
  const accounts = useMemo(() => new Map(accountList.map((a) => [a.id, a])), [accountList]);
  const optIns = useMemo(() => new Set(data?.view.opt_ins ?? []), [data]);
  const cards = data?.view.cards ?? [];
  const tracked = useMemo(() => new Set((data?.view.cards ?? []).map((c) => c.provider)), [data]);
  const suggested = useMemo(() => suggestions(catalog, tracked, toolsRes.data ?? []), [catalog, tracked, toolsRes.data]);
  const expRows = useMemo(() => experimentalRows(catalog, optIns, accountList), [catalog, optIns, accountList]);

  async function act(fn: () => Promise<unknown>, ok?: string) {
    setNotice(null);
    try {
      await fn();
      if (ok) setNotice({ ok: true, text: ok });
    } catch (e) {
      setNotice({ ok: false, text: reason(e) });
    }
    reload();
  }

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Plans & limits"
        icon={navIcon("plans")}
        sub="How much of each coding plan and API balance you have left."
        right={
          <Button variant="primary" iconLeft={Plus} onClick={() => setAdding({})} disabled={!data}>
            Add account
          </Button>
        }
      />

      {notice && (
        <Callout tone={notice.ok ? "success" : "warn"} title={notice.ok ? notice.text : "That did not work"}>
          {notice.ok ? null : notice.text}
        </Callout>
      )}

      {res.error && !data ? (
        <ErrorState error={res.error} onRetry={reload} />
      ) : !data ? (
        <InlineLoading block label="Loading plans" />
      ) : cards.length === 0 ? (
        <EmptyState
          title="No plans yet"
          body="Observer already sees Claude and Codex limits when you use them. Add an account to track a plan or an API balance."
        >
          <Button variant="primary" iconLeft={Plus} onClick={() => setAdding({})}>
            Add account
          </Button>
        </EmptyState>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {cards.map((c) => (
            <PlanCardView
              key={c.id}
              card={c}
              account={c.account_id ? accounts.get(c.account_id) : undefined}
              onRefresh={(id) => act(() => post(`/api/plans/accounts/${encodeURIComponent(id)}/refresh`, {}), "Refreshed.")}
              onEdit={setEditing}
              onHistory={setHistory}
              onRemove={(id) => act(() => post(`/api/plans/accounts/${encodeURIComponent(id)}/remove`, {}), "Account removed.")}
            />
          ))}
        </div>
      )}

      {data && (
        <TrackMore
          items={suggested}
          total={vendorCount(catalog)}
          onPick={(provider) => setAdding({ provider })}
          onBrowse={() => setAdding({})}
        />
      )}

      {data && (
        <ExperimentalSources
          rows={expRows}
          onToggle={(provider, on) => act(() => post("/api/plans/optin", { provider, on }))}
        />
      )}

      {data && (
        <AddAccountModal
          open={adding != null}
          initialProvider={adding?.provider}
          catalog={catalog}
          optIns={optIns}
          onClose={() => setAdding(null)}
          onOptIn={(provider) => act(() => post("/api/plans/optin", { provider, on: true }))}
          onSaved={() => {
            setAdding(null);
            setNotice({ ok: true, text: "Account added." });
            reload();
          }}
          post={post}
          reason={reason}
        />
      )}

      {editing && (
        <EditAccount
          account={editing}
          catalog={catalog}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            setNotice({ ok: true, text: "Account saved." });
            reload();
          }}
        />
      )}

      {history && <HistoryPanel account={history} onClose={() => setHistory(null)} />}
    </div>
  );
}

// ---------- edit an account ----------

function EditAccount({
  account,
  catalog,
  onClose,
  onSaved,
}: {
  account: PlanAccount;
  catalog: CatalogProvider[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const src = catalog.flatMap((p) => p.sources).find((s) => s.id === account.source);
  const [label, setLabel] = useState(account.label);
  const [enabled, setEnabled] = useState(account.enabled);
  const [params, setParams] = useState<Record<string, string>>({ ...(account.params ?? {}) });
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function save() {
    setBusy(true);
    setMsg(null);
    try {
      const typed = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v.trim() !== ""));
      await post(`/api/plans/accounts/${encodeURIComponent(account.id)}`, {
        label,
        enabled,
        params,
        secrets: Object.keys(typed).length > 0 ? typed : undefined,
      });
      onSaved();
    } catch (e) {
      setMsg(reason(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <SlideOver
      open
      onClose={onClose}
      title={`Edit ${providerLabel(account.provider)}`}
      subtitle={SOURCE_LABELS[account.source] ?? ""}
      footer={
        <div className="flex justify-end">
          <Button variant="primary" onClick={save} disabled={busy} loading={busy}>
            Save
          </Button>
        </div>
      }
    >
      <div className="space-y-3">
        <Input label="Name" value={label} onChange={(e) => setLabel(e.target.value)} />
        <Toggle on={enabled} onChange={setEnabled} label="Check this account" />
        {src && (
          <SourceFields
            src={src}
            params={params}
            secrets={secrets}
            keepSecrets={account.secrets}
            setParam={(k, v) => setParams((p) => ({ ...p, [k]: v }))}
            setSecret={(k, v) => setSecrets((s) => ({ ...s, [k]: v }))}
          />
        )}
        {msg && <p className="text-[12px] text-fg-2" role="status">{msg}</p>}
      </div>
    </SlideOver>
  );
}

// ---------- history ----------

type HistoryResponse = {
  snapshots: { observed_at: string; status: string }[];
  runs: { started_at: string; outcome: string }[];
};

function HistoryPanel({ account, onClose }: { account: PlanAccount; onClose: () => void }) {
  const res = useApi<HistoryResponse>(`/api/plans/accounts/${encodeURIComponent(account.id)}/history`);
  const runs = res.data?.runs ?? [];
  return (
    <SlideOver
      open
      onClose={onClose}
      title={`${providerLabel(account.provider)} history`}
      subtitle={nextCheckText(account.state)}
      footer={
        <div className="flex justify-end">
          <Button variant="secondary" iconLeft={RefreshCw} onClick={res.reload}>
            Reload
          </Button>
        </div>
      }
    >
      {res.error ? (
        <ErrorState error={res.error} onRetry={res.reload} />
      ) : !res.data ? (
        <InlineLoading block label="Loading history" />
      ) : (
        <div className="space-y-3 text-[12px]">
          <p className="text-fg-3">{res.data.snapshots.length} readings in the last 7 days.</p>
          {runs.length === 0 ? (
            <p className="text-fg-3">No checks yet.</p>
          ) : (
            <ul className="divide-y divide-line-1">
              {runs.map((r, i) => {
                const v = statusVocab(r.outcome);
                return (
                  <li key={i} className="flex items-center justify-between gap-3 py-1.5">
                    <span className="text-fg-2">{fmtDateTime(r.started_at)}</span>
                    {v.label ? <Pill variant={v.tone}>{v.label}</Pill> : <span className="text-success">OK</span>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </SlideOver>
  );
}

function nextCheckText(s: PlanRunState | undefined): string {
  if (!s) return "";
  if (s.stopped) return "Checks are paused.";
  if (!s.next_due || s.next_due.startsWith("0001")) return "";
  return `Next check ${fmtDateTime(s.next_due)}`;
}

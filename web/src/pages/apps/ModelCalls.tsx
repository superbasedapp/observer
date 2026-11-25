import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Cable, Code, Plus, Trash2 } from "lucide-react";
import {
  Button,
  Callout,
  ChartShell,
  CopyOnClick,
  DataTable,
  EmptyState,
  EntityMultiPicker,
  ErrorState,
  HelpTooltip,
  HostMark,
  Input,
  InlineLoading,
  PageHeader,
  Pill,
  RowActions,
  SegmentedControl,
} from "@/components/primitives";
import { GatedLink } from "@/components/GatedLink";
import { pushToast } from "@/components/Toast";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { navIcon } from "@/lib/nav";
import { useApi } from "@/lib/useApi";
import { useModelOptions } from "@/lib/usePickerSources";
import { keepSelected } from "@/lib/pickerOptions";
import {
  LANE_PROVIDERS,
  SNIPPET_LANGS,
  clientBaseUrl,
  hostOf,
  laneCli,
  laneIdError,
  laneInput,
  laneSnippet,
  laneWriteError,
  lanesOf,
  modelsText,
  providerById,
  serviceError,
  type AppLane,
  type AppLanesResult,
  type SnippetLang,
} from "@/lib/modelCalls";

// Your apps > Model calls (hosted AI gateway arc, lane L9; the lane itself is
// lane L7's). A lane is an address on this machine's proxy that an app points
// its OpenAI or Anthropic client at: the call is priced exactly, held to the
// app budgets and checked by admission before it leaves the machine, with the
// app's own provider key forwarded unchanged. Off until the user adds a lane,
// loopback only (decision 8).
//
// Seam S5: GET /api/apps/lanes, POST /api/apps/lanes, DELETE
// /api/apps/lanes/{id}; the writes are owner-local with the confirm token
// (lib/api.ts localConfirmHeaders). The command-line twin is `observer apps
// lane add|list|remove` (CLI parity), named only in a technical tooltip.
//
// This page reads no AI Apps observability route, so it stays in a build
// without app observability (web/compgen: component capture.proxy).

export const LANES_PATH = "/api/apps/lanes";

async function laneWrite<T>(method: "POST" | "DELETE", path: string, body?: unknown): Promise<T> {
  try {
    return await fetchJSON<T>(path, undefined, {
      method,
      headers: await localConfirmHeaders(),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    if (e instanceof ApiError) throw new Error(laneWriteError(e.body) || e.message);
    throw e;
  }
}

export function ModelCallsPage() {
  const q = useApi<AppLanesResult>(LANES_PATH);
  const lanes = useMemo(() => lanesOf(q.data), [q.data]);
  const [selected, setSelected] = useState<string>("");
  const [busy, setBusy] = useState("");
  const shown = lanes.find((l) => l.id === selected) ?? lanes[0] ?? null;

  async function remove(id: string) {
    setBusy(id);
    try {
      await laneWrite("DELETE", `${LANES_PATH}/${encodeURIComponent(id)}`);
      pushToast(`Lane ${id} removed. Apps pointed at it now get no answer.`, "success");
      if (selected === id) setSelected("");
      q.reload();
    } catch (e) {
      pushToast(`Lane ${id} was not removed. ${e instanceof Error ? e.message : String(e)}`, "danger");
    } finally {
      setBusy("");
    }
  }

  const columns: ColumnDef<AppLane, unknown>[] = [
      {
        accessorKey: "id",
        header: "Lane",
        cell: (c) => (
          <span className="inline-flex items-center gap-2">
            <span className="font-mono text-fg-1">{c.row.original.id}</span>
            {c.row.original.enabled === false && <Pill variant="neutral">off</Pill>}
          </span>
        ),
      },
      {
        id: "provider",
        header: "Provider",
        accessorFn: (r) => hostOf(r.upstream),
        cell: (c) => (
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <HostMark host={c.row.original.upstream} size={12} />
            {hostOf(c.row.original.upstream)}
          </span>
        ),
      },
      {
        id: "client_base_url",
        header: "Client base URL",
        enableSorting: false,
        cell: (c) => {
          const url = clientBaseUrl(c.row.original);
          return (
            <CopyOnClick value={url} ariaLabel={`Copy the base URL of lane ${c.row.original.id}`} className="font-mono text-[11px] text-fg-2">
              {url}
            </CopyOnClick>
          );
        },
      },
      { id: "models", header: "Models", accessorFn: (r) => modelsText(r), cell: (c) => <span className="text-fg-2">{modelsText(c.row.original)}</span> },
      {
        id: "service",
        header: "App",
        accessorFn: (r) => r.service ?? "",
        cell: (c) => <span className="text-fg-2">{c.row.original.service || "-"}</span>,
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        meta: { align: "right" },
        cell: (c) => {
          const id = c.row.original.id;
          return (
            <RowActions
              menuLabel={`Actions for lane ${id}`}
              disabled={busy === id}
              actions={[
                { id: "code", label: "Show code", icon: Code, inline: true, onSelect: () => setSelected(id) },
                {
                  id: "remove",
                  label: "Remove lane",
                  icon: Trash2,
                  destructive: true,
                  confirm: { label: "Remove lane?", note: "Apps pointed at it get no answer until it is added again." },
                  onSelect: () => void remove(id),
                },
              ]}
            />
          );
        },
      },
  ];

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-model-calls")}
        title="Model calls"
        sub="Point your app's model client at this machine to price each call and apply budgets and admission first."
      />
      <Callout
        title="Off until you add a lane"
        action={
          <HelpTooltip subject="adding a lane from the command line" technical content="observer apps lane add <id> --upstream <url>" />
        }
      >
        A lane listens on this machine only. Your app keeps its own provider key; the lane forwards it unchanged.
      </Callout>
      {q.data?.proxy_running === false && (
        <Callout
          tone="warn"
          title="The proxy is not running"
          action={
            <GatedLink to="/settings?section=proxy" className="text-[12px] text-accent hover:underline">
              Open Settings &gt; Proxy
            </GatedLink>
          }
        >
          Lanes answer nothing until it runs.
        </Callout>
      )}

      <ChartShell title="Lanes" icon={Cable} sub="Each lane is an address on this machine that forwards to one provider.">
        {q.error && q.status === 404 ? (
          <EmptyState
            variant="inline"
            illustration="setup"
            title="This daemon has no app lanes yet"
            body="Update Observer on this machine to add lanes from here."
          />
        ) : q.error ? (
          <ErrorState title="Couldn't load the lanes" error={q.error} onRetry={q.reload} />
        ) : q.loading && !q.data ? (
          <InlineLoading label="Loading lanes" />
        ) : lanes.length === 0 ? (
          <EmptyState
            variant="inline"
            illustration="connect"
            title="No lanes yet"
            body="Add one below, then point your app's client at its address."
          />
        ) : (
          <DataTable data={lanes} columns={columns} rowKey={(r) => r.id} minWidth={720} />
        )}
      </ChartShell>

      {!(q.error && q.status === 404) && <AddLane existing={lanes.map((l) => l.id)} onAdded={(id) => { setSelected(id); q.reload(); }} />}

      {shown && <LaneCode lane={shown} />}
    </div>
  );
}

// AddLane is the add form: a known provider, the lane name (the provider's
// id by default, so the address is predictable), an optional model list and
// an optional app name the lane's calls are counted under.
function AddLane({ existing, onAdded }: { existing: string[]; onAdded: (id: string) => void }) {
  const [provider, setProvider] = useState(LANE_PROVIDERS[0].id);
  const [id, setId] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [service, setService] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const modelOptions = useModelOptions();

  const laneId = id.trim() || provider;
  const idErr = laneIdError(laneId, existing);
  const svcErr = serviceError(service);
  const body = laneInput({ id: laneId, provider, models, service });
  const why = idErr || svcErr || (body ? "" : "Pick a provider.");

  async function add() {
    if (!body || why) return;
    setBusy(true);
    setErr("");
    try {
      await laneWrite("POST", LANES_PATH, body);
      pushToast(`Lane ${body.id} added.`, "success");
      setId("");
      setModels([]);
      setService("");
      onAdded(body.id);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const p = providerById(provider);
  return (
    <ChartShell
      title="Add a lane"
      icon={Plus}
      sub="Calls through a lane are priced, held to your app budgets and checked by admission."
      right={<HelpTooltip subject="this form on the command line" technical content={laneCli(body)} />}
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="space-y-1">
          <span className="text-[12px] text-fg-3">Provider</span>
          <SegmentedControl
            options={LANE_PROVIDERS.map((x) => ({ value: x.id, label: x.label }))}
            value={provider}
            onChange={(v) => setProvider(v)}
            size="sm"
          />
          {p && <p className="text-[11.5px] text-fg-3">Forwards to {p.host}.</p>}
        </div>
        <Input
          label="Lane name"
          mono
          value={id}
          placeholder={provider}
          onChange={(e) => setId(e.target.value.trim().toLowerCase())}
          error={id.trim() ? idErr || undefined : undefined}
          help={idErr && !id.trim() ? idErr : "Part of the address your app uses."}
        />
        <div className="space-y-1">
          <span className="text-[12px] text-fg-3">Models (optional)</span>
          <EntityMultiPicker
            options={keepSelected(modelOptions.options, models, "Added here")}
            value={models}
            onChange={setModels}
            allowFreeId
            loading={modelOptions.loading}
            placeholder="Any model"
            ariaLabel="Models the lane forwards"
          />
          <p className="text-[11.5px] text-fg-3">Leave empty to forward any model.</p>
        </div>
        <Input
          label="App name (optional)"
          value={service}
          placeholder="support-bot"
          onChange={(e) => setService(e.target.value)}
          error={svcErr || undefined}
          help={svcErr ? undefined : "The app budgets and checks this lane's calls count toward."}
        />
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <Button variant="primary" iconLeft={Plus} loading={busy} disabled={busy || why !== ""} title={why || undefined} onClick={() => void add()}>
          Add lane
        </Button>
        {why && <span className="text-[12px] text-fg-3">{why}</span>}
      </div>
      {err && (
        <Callout tone="danger" title="The lane was not added" className="mt-3">
          {err}
        </Callout>
      )}
    </ChartShell>
  );
}

// LaneCode is a plain client configuration for one lane: the base URL set to
// the lane and the app's own provider key read from its environment.
function LaneCode({ lane }: { lane: AppLane }) {
  const [lang, setLang] = useState<SnippetLang>("python");
  const code = laneSnippet(lane, lang);
  return (
    <ChartShell
      title={`Use lane ${lane.id}`}
      icon={Code}
      sub="Set your client's base URL to the lane. Nothing else in your app changes."
      right={<SegmentedControl options={[...SNIPPET_LANGS]} value={lang} onChange={setLang} size="sm" />}
    >
      <div className="relative">
        <pre className="max-h-72 overflow-auto rounded-2 border border-line-2 bg-bg-3 p-3 font-mono text-[11.5px] leading-relaxed text-fg-1">
          {code}
        </pre>
        <span className="absolute right-2 top-2">
          <CopyOnClick value={code} ariaLabel="Copy the code" className="text-[11px] text-accent">
            copy
          </CopyOnClick>
        </span>
      </div>
    </ChartShell>
  );
}

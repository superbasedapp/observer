import { useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus, Send, Trash2 } from "lucide-react";
import {
  Button,
  Callout,
  Card,
  ConfirmButton,
  DataTable,
  EmptyState,
  Input,
  PageHeader,
  Pill,
  Select,
  TableSkeleton,
} from "@/components/primitives";
import { GatedLink } from "@/components/GatedLink";
import { dateTime, ms, pct1 } from "@shared/lib/displayFormat";
import { fmtCostFine } from "@shared/lib/format";
import { ApiError, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { navIcon } from "@/lib/nav";
import { PLACES } from "@/lib/settingsPlaces";
import type { AppAlertDimensions, AppAlertFiring, AppAlertRule, AppAlertsResult } from "@/lib/planeaApi";
import { AppsGate, ReadState } from "@/components/apps/AppsChrome";
import { AlertingSwitch } from "@/components/apps/AlertingSwitch";

// Your apps > Alerts (Plane A lane B5, node parity for W3-5; the first page
// of internal/obs/alert): the machine's alert rules over your apps' traces,
// their current value, the firings, and the Slack channel. Routes are lane
// B9's (contracts/alerts.md): GET /api/obs/alerts, PUT /api/obs/alerts/rules,
// PUT /api/obs/alerts/slack, POST /api/obs/alerts/slack/test and
// GET /api/obs/alerts/firings. The writes are owner-local (the confirm
// token); turning alerting itself on stays in Settings > AI Apps.
// Lane C9 (W5-5) adds the PagerDuty card: PUT /api/obs/alerts/pagerduty and
// POST /api/obs/alerts/pagerduty/test (a fire triggers an incident, the
// rule's clear resolves it).

type EditRule = Omit<AppAlertRule, "current_value" | "breaching" | "last_fired_at">;

const EMPTY_DIMS: AppAlertDimensions = { model: "", user: "", tag: "", service: "" };

// METRIC_LABEL / DIMENSION_LABEL: the words for the alert vocabularies the
// daemon lists (GET /api/obs/alerts metrics, dimensions). An unknown value
// keeps its own spelling with underscores as spaces.
const METRIC_LABEL: Readonly<Record<string, string>> = {
  error_rate: "Error rate",
  cost_usd: "Cost",
  latency_p95_ms: "p95 latency",
};
// What a threshold is measured in, per metric (the label beside the field).
const METRIC_UNIT: Readonly<Record<string, string>> = {
  error_rate: "0 to 1",
  cost_usd: "USD",
  latency_p95_ms: "ms",
};
const DIMENSION_LABEL: Readonly<Record<keyof AppAlertDimensions, string>> = {
  model: "Model",
  user: "End user",
  tag: "Tag",
  service: "Service",
};
const COMPARATOR_LABEL: Readonly<Record<string, string>> = { gt: "above", gte: "at or above" };

function words(table: Readonly<Record<string, string>>, v: string): string {
  return Object.prototype.hasOwnProperty.call(table, v) ? table[v] : v.replace(/_/g, " ");
}

function errText(e: unknown): string {
  if (e instanceof ApiError) {
    try {
      const v = JSON.parse(e.body) as { error?: string };
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
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// fmtValue renders a metric value in its own unit; cost goes through the
// shared sub-cent formatter (an app's per-window cost is routinely < $0.01).
function fmtValue(metric: string, v: number | null): string {
  if (v == null) return "unreadable";
  if (metric === "error_rate") return pct1(v);
  if (metric === "cost_usd") return fmtCostFine(v);
  return ms(v);
}

function dimsText(d: AppAlertDimensions): string {
  return (Object.entries(d) as [keyof AppAlertDimensions, string][])
    .filter(([, v]) => v)
    .map(([k, v]) => `${DIMENSION_LABEL[k] ?? k} ${v}`)
    .join(", ");
}

function editable(rules: AppAlertRule[]): EditRule[] {
  return rules.map((r) => ({
    name: r.name,
    metric: r.metric,
    comparator: r.comparator,
    threshold: r.threshold,
    window_minutes: r.window_minutes,
    cooldown_minutes: r.cooldown_minutes,
    dimensions: { ...EMPTY_DIMS, ...r.dimensions },
  }));
}

export function AppAlertsPage() {
  const q = useApi<AppAlertsResult>("/api/obs/alerts");
  const firings = useApi<{ firings: AppAlertFiring[] }>("/api/obs/alerts/firings", { limit: 50 });
  const [rules, setRules] = useState<EditRule[] | null>(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [slack, setSlack] = useState("");
  const [pdKey, setPdKey] = useState("");

  useEffect(() => {
    if (q.data && rules === null) setRules(editable(q.data.rules));
  }, [q.data, rules]);

  // Save is a primary action: it stays disabled until the rules changed
  // (Emphasis: a primary action that would do nothing is disabled with a reason).
  const saved = useMemo(() => (q.data ? JSON.stringify(editable(q.data.rules)) : ""), [q.data]);
  const dirty = rules !== null && JSON.stringify(rules) !== saved;

  const metrics = q.data?.metrics ?? ["error_rate", "cost_usd", "latency_p95_ms"];
  const metricOptions = metrics.map((m) => ({ value: m, label: words(METRIC_LABEL, m) }));
  const edit = (i: number, patch: Partial<EditRule>) => setRules((rs) => (rs ?? []).map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const editDim = (i: number, k: keyof AppAlertDimensions, v: string) =>
    setRules((rs) => (rs ?? []).map((r, j) => (j === i ? { ...r, dimensions: { ...r.dimensions, [k]: v } } : r)));

  async function run(action: () => Promise<string>) {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      setMsg(await action());
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const firingColumns = useMemo<ColumnDef<AppAlertFiring, unknown>[]>(
    () => [
      { accessorKey: "rule_name", header: "Rule", cell: (c) => <span className="font-medium text-fg-1">{c.row.original.rule_name}</span> },
      {
        id: "value",
        header: "Value",
        accessorFn: (r) => r.value,
        meta: { align: "right" },
        cell: (c) => {
          const f = c.row.original;
          return (
            <span className="whitespace-nowrap tabular-nums">
              {fmtValue(f.metric, f.value)} <span className="text-fg-3">{words(COMPARATOR_LABEL, f.comparator)} {fmtValue(f.metric, f.threshold)}</span>
            </span>
          );
        },
      },
      { id: "dims", header: "Narrowed to", enableSorting: false, cell: (c) => <span className="text-fg-3">{dimsText(c.row.original.dimensions) || "-"}</span> },
      {
        accessorKey: "delivered",
        header: "Delivered",
        cell: (c) => (c.row.original.delivered ? <Pill variant="success">sent</Pill> : <Pill variant="neutral">not sent</Pill>),
      },
      {
        id: "fired_at",
        header: "Fired",
        accessorFn: (r) => r.fired_at,
        meta: { align: "right" },
        cell: (c) => <span className="whitespace-nowrap">{dateTime(c.row.original.fired_at)}</span>,
      },
    ],
    [],
  );

  const firingRows = firings.data?.firings ?? [];

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        icon={navIcon("app-alerts")}
        title="Alerts"
        sub="Rules over your apps' error rate, cost and latency, sent to a webhook, Slack or PagerDuty."
      />
      <AppsGate>
        <ReadState error={q.error} onRetry={q.reload} feature="Alerts" />
        {q.data && (
          <>
            {q.data.enabled ? (
              <Callout
                title="Alerting is on"
                action={
                  !q.data.webhook_configured ? (
                    <GatedLink to={PLACES.observability_settings.href} managed={null} className="text-[12px] font-medium text-accent hover:underline">
                      Set a webhook in {PLACES.observability_settings.label}
                    </GatedLink>
                  ) : undefined
                }
              >
                Rules are checked every {q.data.interval_minutes} min.{" "}
                {q.data.webhook_configured ? "A webhook is set." : "No webhook is set."}
              </Callout>
            ) : (
              <AlertingSwitch />
            )}

            <Card
              title="Rules"
              actions={
                <>
                  <Button
                    size="sm"
                    iconLeft={Plus}
                    onClick={() =>
                      setRules((rs) => [
                        ...(rs ?? []),
                        { name: "", metric: metrics[0], comparator: "gt", threshold: 0, window_minutes: 60, cooldown_minutes: 60, dimensions: { ...EMPTY_DIMS } },
                      ])
                    }
                  >
                    Add rule
                  </Button>
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={busy || !dirty}
                    title={!dirty ? "Change a rule to save." : undefined}
                    onClick={() =>
                      void run(async () => {
                        await send("PUT", "/api/obs/alerts/rules", { rules });
                        setRules(null);
                        q.reload();
                        return "Rules saved. The next check uses them.";
                      })
                    }
                  >
                    Save rules
                  </Button>
                </>
              }
            >
              {(rules ?? []).length === 0 ? (
                <EmptyState
                  variant="inline"
                  title="No rules yet"
                  body="Add a rule to be told when an app's error rate, cost or latency crosses a threshold."
                />
              ) : (
                <div className="space-y-3">
                  {(rules ?? []).map((r, i) => {
                    const live = q.data?.rules.find((x) => x.name === r.name);
                    return (
                      <div key={i} className="space-y-2 rounded-2 border border-line-2 bg-bg-3/40 p-3" data-testid="alert-rule">
                        <div className="flex flex-wrap items-end gap-2">
                          <Input label="Name" value={r.name} onChange={(e) => edit(i, { name: e.target.value })} className="w-44" />
                          <Select label="Metric" value={r.metric} onChange={(e) => edit(i, { metric: e.target.value })} options={metricOptions} className="w-36" />
                          <Select
                            label="When"
                            value={r.comparator}
                            onChange={(e) => edit(i, { comparator: e.target.value })}
                            options={[
                              { value: "gt", label: "above" },
                              { value: "gte", label: "at or above" },
                            ]}
                            className="w-32"
                          />
                          <Input
                            label={`Threshold (${words(METRIC_UNIT, r.metric)})`}
                            type="number"
                            step="any"
                            min={0}
                            value={r.threshold}
                            onChange={(e) => edit(i, { threshold: Number(e.target.value) })}
                            className="w-28"
                          />
                          <Input label="Window (min)" type="number" min={1} value={r.window_minutes} onChange={(e) => edit(i, { window_minutes: Number(e.target.value) })} className="w-24" />
                          <Input label="Cooldown (min)" type="number" min={0} value={r.cooldown_minutes} onChange={(e) => edit(i, { cooldown_minutes: Number(e.target.value) })} className="w-24" />
                          <Button
                            size="sm"
                            variant="ghost"
                            iconLeft={Trash2}
                            aria-label={`Remove rule ${r.name || i + 1}`}
                            onClick={() => setRules((rs) => (rs ?? []).filter((_, j) => j !== i))}
                          >
                            Remove
                          </Button>
                        </div>
                        <div className="flex flex-wrap items-end gap-2">
                          {(["model", "user", "tag", "service"] as const).map((k) => (
                            <Input
                              key={k}
                              label={DIMENSION_LABEL[k]}
                              value={r.dimensions[k]}
                              placeholder="any"
                              onChange={(e) => editDim(i, k, e.target.value)}
                              className="w-36"
                            />
                          ))}
                        </div>
                        {live && (
                          <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-[11px] text-fg-3">
                            <span>Now {fmtValue(live.metric, live.current_value)}</span>
                            {live.breaching && <Pill variant="danger">breaching</Pill>}
                            <span>{live.last_fired_at ? `Last fired ${dateTime(live.last_fired_at)}` : "Never fired"}</span>
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </Card>

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <Card
                title="Slack"
                sub="Posts each firing to an incoming webhook."
                actions={<ChannelPill set={q.data.slack_configured} />}
              >
                <div className="flex flex-wrap items-end gap-2">
                  <Input
                    label="Incoming webhook URL"
                    type="password"
                    value={slack}
                    placeholder={q.data.slack_configured ? "Set (hidden)" : "https://hooks.slack.com/services/..."}
                    onChange={(e) => setSlack(e.target.value)}
                    className="w-full sm:w-72"
                  />
                  <ConfirmButton
                    size="sm"
                    variant={slack ? "primary" : "danger-outline"}
                    requireConfirm={!slack}
                    confirmLabel="Clear it?"
                    armedNote="Alerts stop going to this channel."
                    disabled={busy || (!slack && !q.data.slack_configured)}
                    title={!slack && !q.data.slack_configured ? "Paste a webhook URL to save." : undefined}
                    onConfirm={() =>
                      void run(async () => {
                        await send("PUT", "/api/obs/alerts/slack", { webhook_url: slack });
                        setSlack("");
                        q.reload();
                        return slack ? "Slack webhook saved." : "Slack webhook cleared.";
                      })
                    }
                  >
                    {slack ? "Save" : "Clear"}
                  </ConfirmButton>
                  <Button
                    size="sm"
                    iconLeft={Send}
                    disabled={busy || !q.data.slack_configured}
                    title={!q.data.slack_configured ? "Save a webhook first." : undefined}
                    onClick={() =>
                      void run(async () => {
                        await send("POST", "/api/obs/alerts/slack/test", undefined);
                        return "Test message sent to Slack.";
                      })
                    }
                  >
                    Send a test
                  </Button>
                </div>
              </Card>
              <Card
                title="PagerDuty"
                sub="A firing opens an incident; it resolves when the rule clears."
                actions={<ChannelPill set={!!q.data.pagerduty_configured} />}
              >
                <div className="flex flex-wrap items-end gap-2">
                  <Input
                    label="Events API v2 routing key"
                    type="password"
                    value={pdKey}
                    placeholder={q.data.pagerduty_configured ? "Set (hidden)" : "32-character integration key"}
                    onChange={(e) => setPdKey(e.target.value)}
                    className="w-full sm:w-72"
                  />
                  <ConfirmButton
                    size="sm"
                    variant={pdKey ? "primary" : "danger-outline"}
                    requireConfirm={!pdKey}
                    confirmLabel="Clear it?"
                    armedNote="Alerts stop going to this channel."
                    disabled={busy || (!pdKey && !q.data.pagerduty_configured)}
                    title={!pdKey && !q.data.pagerduty_configured ? "Paste a routing key to save." : undefined}
                    onConfirm={() =>
                      void run(async () => {
                        await send("PUT", "/api/obs/alerts/pagerduty", { routing_key: pdKey });
                        setPdKey("");
                        q.reload();
                        return pdKey ? "PagerDuty routing key saved." : "PagerDuty routing key cleared.";
                      })
                    }
                  >
                    {pdKey ? "Save" : "Clear"}
                  </ConfirmButton>
                  <Button
                    size="sm"
                    iconLeft={Send}
                    disabled={busy || !q.data.pagerduty_configured}
                    title={!q.data.pagerduty_configured ? "Save a routing key first." : undefined}
                    onClick={() =>
                      void run(async () => {
                        await send("POST", "/api/obs/alerts/pagerduty/test", undefined);
                        return "Test event sent to PagerDuty and resolved.";
                      })
                    }
                  >
                    Send a test
                  </Button>
                </div>
              </Card>
            </div>
            {msg && <Callout tone="success">{msg}</Callout>}
            {err && <Callout tone="danger" title="That did not work">{err}</Callout>}
          </>
        )}
        <Card title="Firings">
          <ReadState error={firings.error} onRetry={firings.reload} feature="Alert firings" />
          {firings.loading && !firings.data ? (
            <TableSkeleton rows={4} />
          ) : firings.error ? null : firingRows.length === 0 ? (
            <EmptyState variant="inline" illustration="all-clear" illustrationSize={96} title="No alert has fired" />
          ) : (
            <DataTable data={firingRows} columns={firingColumns} rowKey={(r) => `${r.rule_name}:${r.fired_at}`} zebra minWidth={760} />
          )}
        </Card>
      </AppsGate>
    </div>
  );
}

// ChannelPill: whether a delivery channel is set up. Not set is neutral, not
// a warning: a channel is optional.
function ChannelPill({ set }: { set: boolean }) {
  return set ? <Pill variant="success">set</Pill> : <Pill variant="neutral">not set</Pill>;
}

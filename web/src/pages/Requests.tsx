import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ShieldCheck, Clock, Send } from "lucide-react";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  PageHeader,
  Pill,
  Select,
  SinglePicker,
} from "@/components/primitives";
import { componentOptions, featureOptions, keepSelected, type PickOption } from "@/lib/pickerOptions";
import { GUARD_RULE_OPTIONS, useModelOptions, useToolOptions } from "@/lib/usePickerSources";
import { useComponentCatalog } from "@/lib/useComponents";
import { useApi } from "@/lib/useApi";
import { apiReason, fetchJSON, localConfirmHeaders } from "@/lib/api";
import { NAV_ITEMS, navIcon } from "@/lib/nav";
import { NODE_TAB_ROUTES } from "@/lib/pageTabRoutes";
import { useGovernance } from "@/lib/governance";
import { defaultPageChoice, hiddenPageChoices } from "@/lib/pageRequest";
import { configEditChoices } from "@/lib/configEditRequest";
import {
  budgetAmountFields,
  budgetDeltaHelp,
  budgetOptions,
  budgetDurationOptions,
  budgetPickNote,
  budgetSuggestion,
  defaultBudgetId,
  type RequestableBudget,
} from "@/lib/requestBudgets";
import { dollarsShown } from "@/lib/format";
import { requestEntryFrom, withoutEntryParams } from "@/lib/requestEntry";
import { grantsCacheLine, sentToLine } from "@/lib/grantsCache";
import { requestAsk, requestOutcome, splitRequests, RECENT_FINISHED_DAYS, type RequestGrantSummary } from "@/lib/requestRows";
import { exceptionRows } from "@/lib/exceptionsInForce";

// Requests (request-grants design §1.2, phase G6): ask the organization for
// a time-limited exception, preview exactly what will be sent, and follow the
// answer. Every action here is also `observer request ...` / `observer
// requests` on the command line.

// The request types that name a target (accessgrant targetTypes); any other
// type sends none, so a target picked before switching type is not sent.
const TARGET_TYPES = new Set(["tool_allow", "model_access", "feature_enable", "page_access", "config_edit", "component_enable"]);

type RequestType = {
  id: string;
  label: string;
  grantable: boolean;
  required?: string[];
  max_seconds?: number;
  max_rule: string;
  default_seconds: number;
  /** "answer": the organization answers with a note; nothing lands on this
   *  machine (T-437). Absent on an older daemon. */
  landing?: string;
};

type Payload = {
  rule_id?: string;
  lane?: string;
  command_class?: string;
  operand_hash?: string;
  project_root_hash?: string;
  effect?: string;
  breadth?: string;
  budget_id?: string;
  delta_tokens?: number;
  delta_usd?: number;
  target?: string;
};

type ReqContext = {
  rule_id?: string;
  category?: string;
  severity?: string;
  decision?: string;
  tool?: string;
  target_excerpt?: string;
  project_root?: string;
  git_branch?: string;
  hits_7d?: number;
  event_id?: number;
  tenancy?: string;
};

type CreateRequest = {
  kind?: string;
  target?: string;
  message: string;
  request_type?: string;
  payload?: Payload;
  context?: ReqContext;
  requested_duration_s?: number;
  requested_uses?: number;
  subject_kind?: string;
  machine_identity?: string;
};

type GrantSummary = RequestGrantSummary;

type OrgRequest = {
  id: number;
  kind: string;
  target?: string;
  message: string;
  status: string;
  created_at: string;
  resolved_at?: string;
  resolved_by?: string;
  resolution_note?: string;
  request_type?: string;
  subject_kind?: string;
  payload?: Payload;
  requested_duration_s?: number;
  grant?: GrantSummary;
};

type GrantWire = {
  id: number;
  type: string;
  effect?: string;
  subject_kind: string;
  rule_id?: string;
  lane?: string;
  command_class?: string;
  operand_hash?: string;
  project_root_hash?: string;
  target?: string;
  starts_at_ns: number;
  expires_at_ns?: number;
  max_uses?: number;
};

type GrantView = { grant: GrantWire; uses_used: number; honoured: boolean; reason?: string; covered_by?: number };

type Queued = { id: number; created_at: string; attempts: number; last_error?: string; request_json: string };

type RequestsPage = {
  available: boolean;
  enrolled: boolean;
  org_name?: string;
  ships_raw: boolean;
  requests: OrgRequest[];
  requests_error?: string;
  queued: Queued[];
  grants: { version: number; last_verified_ns: number; max_offline_s: number; grants: GrantView[]; unverified?: boolean };
  grants_cached: boolean;
  types: RequestType[];
  // The org budgets this machine is governed by (budget rail); absent on a
  // daemon that predates the picker.
  budgets?: RequestableBudget[];
  now_ns: number;
};

type Problem = { field: string; code: string; message: string };
type Preview = { request: CreateRequest; json: string; problems: Problem[] };

const REASON_TEXT: Record<string, string> = {
  not_started: "starts later",
  expired: "expired",
  exhausted: "all uses spent",
  stale: "not confirmed with the organization recently",
  no_receipt: "not yet confirmed",
};

function humanDuration(seconds: number): string {
  if (seconds <= 0) return "0m";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}

function expiryText(expiresNs: number | undefined, nowNs: number): string {
  if (!expiresNs) return "no expiry";
  const left = Math.round((expiresNs - nowNs) / 1e9);
  const at = new Date(expiresNs / 1e6).toLocaleString();
  return left > 0 ? `until ${at} (${humanDuration(left)} left)` : `expired ${at}`;
}

const DURATIONS = [
  { value: "3600", label: "1 hour" },
  { value: "28800", label: "8 hours" },
  { value: "86400", label: "24 hours" },
  { value: "259200", label: "3 days" },
  { value: "604800", label: "7 days" },
  { value: "2592000", label: "30 days" },
];

export function RequestsPage() {
  const page = useApi<RequestsPage>("/api/requests");
  const [params, setParams] = useSearchParams();
  const [dialog, setDialog] = useState<CreateRequest | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const data = page.data;
  const types = data?.types ?? [];
  const now = data?.now_ns ?? Date.now() * 1e6;

  // Entry points (§1.2, lib/requestEntry): /requests?event=<guard event id>
  // from the Security page, /requests?rule=<rule>&session=<id> from the
  // guard's org-locked deny line (G4), /requests?new=budget[&budget=<id>]
  // from the budget banner and the guard's budget deny line (T-522). Each
  // only opens the form; nothing is sent until Send.
  useEffect(() => {
    const entry = requestEntryFrom(params);
    if (!entry) return;
    const clear = () => setParams(withoutEntryParams(params), { replace: true });
    if (entry.kind === "prefill") {
      fetchJSON<{ request: CreateRequest }>("/api/requests/prefill", entry.query)
        .then((r) => setDialog({ ...r.request, message: "" }))
        .catch(() => setDialog(entry.fallback as CreateRequest))
        .finally(clear);
      return;
    }
    setDialog(entry.draft as CreateRequest);
    clear();
  }, [params, setParams]);

  const withdraw = async (id: number) => {
    try {
      await fetchJSON(`/api/requests/${id}/withdraw`, undefined, { method: "POST", headers: await localConfirmHeaders(), body: "{}" }).catch((e) => {
        // 204 has no body; fetchJSON's res.json() rejects on it.
        if (!(e instanceof SyntaxError)) throw e;
      });
      setNotice(`Request #${id} withdrawn.`);
    } catch (e) {
      setNotice(`Could not withdraw #${id}: ${apiReason(e)}`);
    }
    page.reload();
  };
  const cancelQueued = async (id: number) => {
    try {
      await fetchJSON(`/api/requests/queued/${id}/cancel`, undefined, { method: "POST", headers: await localConfirmHeaders(), body: "{}" }).catch((e) => {
        if (!(e instanceof SyntaxError)) throw e;
      });
      setNotice("Queued request cancelled; it was never sent.");
    } catch (e) {
      setNotice(`Could not cancel: ${apiReason(e)}`);
    }
    page.reload();
  };

  const [showHistory, setShowHistory] = useState(false);
  const dollars = dollarsShown();
  const split = useMemo(() => splitRequests(data?.requests ?? [], now), [data?.requests, now]);

  // Both rails: grant-rail grants and the budget increases the budget rail
  // folds into a cap (lib/exceptionsInForce).
  const exceptions = useMemo(
    () => exceptionRows(data?.grants.grants ?? [], data?.budgets ?? [], types, now, dollars),
    [data?.grants.grants, data?.budgets, types, now, dollars],
  );

  return (
    <div className="space-y-6 p-4 sm:p-6">
      <PageHeader
        title="Requests"
        icon={navIcon("requests")}
        sub="Ask your organization for a time-limited exception and follow the answer. A granted exception reaches this machine on its next sync and ends on its own."
        right={
          data?.enrolled ? (
            <Button variant="primary" onClick={() => setDialog({ request_type: "guard_exemption", message: "", payload: { breadth: "rule" } })}>
              New request
            </Button>
          ) : null
        }
      />
      {notice && (
        <div className="flex items-center justify-between gap-3 rounded-3 border border-line-2 bg-bg-2 px-3 py-2 text-[12px] text-fg-1" role="status">
          <span>{notice}</span>
          <button type="button" className="text-fg-3 hover:text-fg-1" onClick={() => setNotice(null)}>
            dismiss
          </button>
        </div>
      )}
      {page.error && <div className="text-[12px] text-danger">{apiReason(page.error)}</div>}
      {data && !data.enrolled && (
        <EmptyState
          title="Requests go to an organization"
          body="This machine is not enrolled with an organization, so there is nobody to ask. Enrol from Settings to send requests for exceptions."
          illustration="connect"
          to="/settings?section=enrolment"
          toLabel="Open enrolment"
        />
      )}
      {data?.enrolled && (
        <>
          <Card
            title="Exceptions in force on this machine"
            icon={ShieldCheck}
            sub={grantsCacheLine(
              {
                cached: data.grants_cached,
                unverified: data.grants.unverified,
                lastVerifiedNs: data.grants.last_verified_ns,
                maxOfflineS: data.grants.max_offline_s,
                orgName: data.org_name,
                nowNs: now,
              },
              humanDuration,
            )}
          >
            {exceptions.length === 0 ? (
              <p className="text-[12px] text-fg-3">No exceptions. Everything your organization configured applies as written.</p>
            ) : (
              <ul className="divide-y divide-line-1">
                {exceptions.map((g) => (
                  <li key={g.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-[12px]">
                    <span className="font-mono text-fg-3">G-{g.grantId}</span>
                    <span className="font-medium text-fg-0" title={g.title}>
                      {g.what}
                    </span>
                    {g.effect && <Pill variant={g.effect === "exempt" ? "accent" : "info"}>{g.effect}</Pill>}
                    {g.scope && <span className="text-fg-3">{g.scope}</span>}
                    <span className="text-fg-2">{expiryText(g.expiresAtNs, now)}</span>
                    {g.maxUses ? (
                      <span className="text-fg-3">
                        {g.usesUsed} of {g.maxUses} uses
                      </span>
                    ) : null}
                    <span className="flex-1" />
                    {g.coveredBy ? (
                      <Pill variant="neutral" title={`G-${g.coveredBy} already gives everything this grant gives. Your approver can revoke this one; nothing changes for you.`}>
                        same as G-{g.coveredBy}
                      </Pill>
                    ) : null}
                    {g.honoured ? (
                      <Pill variant="success">in force</Pill>
                    ) : (
                      <Pill variant="neutral" title={g.reason}>
                        {REASON_TEXT[g.reason ?? ""] ?? "not in force"}
                      </Pill>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {data.queued.length > 0 && (
            <Card title="Queued, not yet sent" icon={Clock} sub="The organization was unreachable. These go out on the next sync.">
              <ul className="divide-y divide-line-1">
                {data.queued.map((q) => (
                  <li key={q.id} className="flex flex-wrap items-center gap-3 py-2 text-[12px]">
                    <span className="text-fg-1">{safeMessage(q.request_json)}</span>
                    <span className="text-fg-3">since {new Date(q.created_at).toLocaleString()}</span>
                    {q.last_error && <span className="text-warn">{q.last_error}</span>}
                    <span className="flex-1" />
                    <Button size="sm" variant="ghost" onClick={() => cancelQueued(q.id)}>
                      Cancel
                    </Button>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card
            title="Your requests"
            icon={Send}
            sub={sentToLine(data.org_name, data.requests_error)}
          >
            {data.requests.length === 0 ? (
              <EmptyState
                variant="inline"
                title="No requests yet"
                body="When a guardrail blocks you, or you need more budget, a tool, a model or a feature, ask here. Use Request access on a Security verdict to start from the exact command."
                illustration="inbox"
              />
            ) : (
              <>
                <RequestRows
                  rows={split.current}
                  types={types}
                  budgets={data.budgets ?? []}
                  dollars={dollars}
                  nowNs={now}
                  onWithdraw={withdraw}
                  label="Your requests"
                />
                {split.current.length === 0 && (
                  <p className="text-[12px] text-fg-3">Nothing open or recent. Older requests are under History.</p>
                )}
                {split.history.length > 0 && (
                  <div className="mt-3 border-t border-line-1 pt-2">
                    <button
                      type="button"
                      className="text-[12px] font-medium text-fg-2 hover:text-fg-0"
                      aria-expanded={showHistory}
                      onClick={() => setShowHistory((v) => !v)}
                    >
                      {showHistory ? "Hide" : "Show"} history ({split.history.length} finished more than {RECENT_FINISHED_DAYS} days ago)
                    </button>
                    {showHistory && (
                      <div className="mt-2">
                        <RequestRows
                          rows={split.history}
                          types={types}
                          budgets={data.budgets ?? []}
                          dollars={dollars}
                          nowNs={now}
                          onWithdraw={withdraw}
                          label="Request history"
                        />
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </Card>
        </>
      )}
      {dialog && data && (
        <RequestDialog
          initial={dialog}
          types={types}
          budgets={data.budgets ?? []}
          nowNs={now}
          shipsRaw={data.ships_raw}
          onClose={() => setDialog(null)}
          onSent={(msg) => {
            setDialog(null);
            setNotice(msg);
            page.reload();
          }}
        />
      )}
    </div>
  );
}

// RequestRows renders a list of the developer's requests: one card per
// request on phones, a table from md up. The status and answer come from
// requestOutcome (a granted row reads its grant's live state, #27) and the
// ask from requestAsk (a budget by name, #20).
function RequestRows({
  rows,
  types,
  budgets,
  dollars,
  nowNs,
  onWithdraw,
  label,
}: {
  rows: OrgRequest[];
  types: RequestType[];
  budgets: RequestableBudget[];
  dollars: boolean;
  nowNs: number;
  onWithdraw: (id: number) => void;
  label: string;
}) {
  if (rows.length === 0) return null;
  const view = rows.map((r) => ({
    r,
    o: requestOutcome(r, nowNs),
    ask: requestAsk(r, budgets, dollars),
    typeLabel: types.find((t) => t.id === r.request_type)?.label ?? r.kind,
  }));
  return (
    <>
      {/* Phones: one card per request; the table needs ~560px. */}
      <ul className="divide-y divide-line-1 md:hidden" aria-label={label}>
        {view.map(({ r, o, ask, typeLabel }) => (
          <li key={r.id} className="space-y-1 py-2.5 text-[12px]">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 font-medium text-fg-0" title={ask.title}>
                <span className="font-mono text-fg-3">{r.id}</span> {typeLabel}
                {ask.detail}
              </div>
              <Pill variant={o.tone}>{o.status}</Pill>
            </div>
            <div className="text-fg-2">{r.message}</div>
            {o.answer && <div className="text-fg-1">{o.answer}</div>}
            <div className="flex items-center justify-between gap-2 text-fg-3">
              <span>{new Date(r.created_at).toLocaleString()}</span>
              {r.status === "open" && (
                <Button size="sm" variant="ghost" onClick={() => onWithdraw(r.id)}>
                  Withdraw
                </Button>
              )}
            </div>
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto md:block">
        <table className="w-full min-w-[560px] text-left text-[12px]" aria-label={label}>
          <thead className="text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
            <tr>
              <th className="py-1.5 pr-3 font-semibold">#</th>
              <th className="py-1.5 pr-3 font-semibold">Ask</th>
              <th className="py-1.5 pr-3 font-semibold">Status</th>
              <th className="py-1.5 pr-3 font-semibold">Answer</th>
              <th className="py-1.5 font-semibold" />
            </tr>
          </thead>
          <tbody>
            {view.map(({ r, o, ask, typeLabel }) => (
              <tr key={r.id} className="border-t border-line-1/60 align-top">
                <td className="py-2 pr-3 font-mono text-fg-3">{r.id}</td>
                <td className="py-2 pr-3">
                  <div className="font-medium text-fg-0" title={ask.title}>
                    {typeLabel}
                    {ask.detail}
                  </div>
                  <div className="mt-0.5 text-fg-2">{r.message}</div>
                  <div className="mt-0.5 text-fg-3">{new Date(r.created_at).toLocaleString()}</div>
                </td>
                <td className="py-2 pr-3">
                  <Pill variant={o.tone}>{o.status}</Pill>
                </td>
                <td className="py-2 pr-3 text-fg-2">{o.answer ? <span>{o.answer}</span> : <span className="text-fg-3">-</span>}</td>
                <td className="py-2 text-right">
                  {r.status === "open" && (
                    <Button size="sm" variant="ghost" onClick={() => onWithdraw(r.id)}>
                      Withdraw
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function safeMessage(raw: string): string {
  try {
    const v = JSON.parse(raw) as CreateRequest;
    return v.message || v.request_type || "request";
  } catch {
    return "request";
  }
}

function RequestDialog({
  initial,
  types,
  budgets,
  nowNs,
  shipsRaw,
  onClose,
  onSent,
}: {
  initial: CreateRequest;
  types: RequestType[];
  budgets: RequestableBudget[];
  nowNs: number;
  shipsRaw: boolean;
  onClose: () => void;
  onSent: (msg: string) => void;
}) {
  const [type, setType] = useState(initial.request_type ?? "guard_exemption");
  // T-523: a budget request starts on the budget that ran out (or the one
  // the entry point named), never on a typed id.
  const [payload, setPayload] = useState<Payload>(() => {
    const p: Payload = { ...(initial.payload ?? {}) };
    if ((initial.request_type ?? "") === "budget_increase") p.budget_id = defaultBudgetId(budgets, p.budget_id) || undefined;
    return p;
  });
  // T-435: a page-access request names a page or tab hidden on this machine,
  // picked from the same resolved visibility the nav filters on.
  const gov = useGovernance();
  const pageChoices = useMemo(() => hiddenPageChoices(gov.data?.visibility, NAV_ITEMS, NODE_TAB_ROUTES), [gov.data?.visibility]);
  const pickType = (next: string) => {
    setType(next);
    if (next === "budget_increase") {
      setPayload((p) => (p.budget_id !== undefined ? p : { ...p, budget_id: defaultBudgetId(budgets) || undefined }));
    }
    if (next === "page_access") {
      setPayload((p) => ({ ...p, target: defaultPageChoice(pageChoices, p.target) || undefined }));
    }
  };
  // T-436: an AI tool setting edit names the asked setting or one tool's
  // settings, from the tools the AI tool settings page lists.
  const [askedSetting] = useState(() => (initial.request_type === "config_edit" ? initial.payload?.target : undefined));
  const agentTools = useApi<{ tools?: { tool: string; status: string }[] }>(type === "config_edit" ? "/api/agent-config/tools" : null);
  const editChoices = useMemo(
    () =>
      configEditChoices(
        askedSetting,
        (agentTools.data?.tools ?? []).filter((t) => t.status !== "no_surface").map((t) => t.tool),
      ),
    [askedSetting, agentTools.data],
  );
  useEffect(() => {
    if (type !== "config_edit" || editChoices.length === 0) return;
    setPayload((p) => (p.target && editChoices.some((c) => c.id === p.target) ? p : { ...p, target: editChoices[0].id }));
  }, [type, editChoices]);
  useEffect(() => {
    if (type !== "page_access" || pageChoices.length === 0) return;
    setPayload((p) => {
      const t = defaultPageChoice(pageChoices, p.target);
      return t === p.target ? p : { ...p, target: t };
    });
  }, [type, pageChoices]);
  // D-571: a tool / model / feature / component target is picked from what
  // this node knows, never typed. Each list is read only while its type is
  // chosen.
  const tools = useToolOptions(type === "tool_allow");
  const models = useModelOptions(type === "model_access");
  const catalog = useComponentCatalog();
  const targetSource: { options: PickOption[]; loading: boolean } =
    type === "tool_allow"
      ? tools
      : type === "model_access"
        ? models
        : type === "component_enable"
          ? { options: componentOptions(catalog.data?.components ?? []), loading: catalog.loading }
          : { options: featureOptions(gov.data?.read_only_settings ?? []), loading: gov.loading };
  const [message, setMessage] = useState(initial.message ?? "");
  const [duration, setDuration] = useState(String(initial.requested_duration_s ?? 86400));
  const [uses, setUses] = useState("");
  const [optIn, setOptIn] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fromEvent = Boolean(initial.context?.event_id);
  // The cost display mode; the gate remounts the app when it changes.
  const dollars = dollarsShown();

  const typeMeta = types.find((t) => t.id === type);
  const picked = budgets.find((b) => b.budget_id === payload.budget_id);
  const fields = budgetAmountFields(picked, dollars);
  // T-522: a picked budget prefills the window (until its period ends, the
  // most a budget increase may last) and the amount spend is over the cap,
  // until the developer edits either; nothing is sent until Send.
  const [amountTouched, setAmountTouched] = useState(false);
  const [durationTouched, setDurationTouched] = useState(false);
  const periodLeftS = picked?.period_end_ns ? Math.floor((picked.period_end_ns - nowNs) / 1e9) : undefined;
  useEffect(() => {
    if (type !== "budget_increase") return;
    const s = budgetSuggestion(picked, dollars, nowNs);
    if (!durationTouched && s.duration_s) setDuration(String(s.duration_s));
    if (!amountTouched) setPayload((p) => ({ ...p, delta_tokens: s.delta_tokens, delta_usd: s.delta_usd }));
    // Re-suggest only when the pick changes, never on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, payload.budget_id]);
  const body = useMemo<{ request: CreateRequest; opt_in_excerpt: boolean }>(() => {
    const p: Payload = { ...payload };
    if (type !== "budget_increase") {
      delete p.budget_id;
      delete p.delta_tokens;
      delete p.delta_usd;
    }
    // Token-usage display (D-013 / D-179): no dollar figure in the preview or
    // the request; the dialog offers no dollar field in that mode.
    if (!dollars) delete p.delta_usd;
    // The amount follows the picked budget's unit (T-523): a figure typed
    // for a unit the budget has no cap in is not sent, so the preview shows
    // only what the approver can act on.
    if (!fields.tokens) delete p.delta_tokens;
    if (!fields.usd) delete p.delta_usd;
    if (type !== "guard_exemption") {
      delete p.rule_id;
      delete p.breadth;
      delete p.operand_hash;
      delete p.command_class;
    }
    if (!TARGET_TYPES.has(type)) delete p.target;
    if (p.breadth === "rule") {
      delete p.operand_hash;
      delete p.command_class;
    } else if (p.breadth === "class") {
      delete p.operand_hash;
    }
    return {
      request: {
        request_type: type,
        message,
        target: p.target,
        payload: p,
        context: type === "guard_exemption" ? initial.context : undefined,
        requested_duration_s: Number(duration) || undefined,
        requested_uses: Number(uses) > 0 ? Number(uses) : undefined,
      },
      opt_in_excerpt: optIn,
    };
  }, [type, payload, message, duration, uses, optIn, initial.context, dollars, fields.tokens, fields.usd]);

  // Preview is the exact bytes the org would receive (D-083); refreshed on
  // every edit so what the developer reads is what they send.
  useEffect(() => {
    if (!message.trim()) {
      setPreview(null);
      return;
    }
    const t = setTimeout(() => {
      fetchJSON<Preview>("/api/requests/preview", undefined, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
        .then(setPreview)
        .catch((e) => setError(apiReason(e)));
    }, 250);
    return () => clearTimeout(t);
  }, [body, message]);

  const send = async () => {
    setBusy(true);
    setError(null);
    try {
      const res = await fetchJSON<{ request?: OrgRequest & { duplicate?: boolean }; queued_id?: number }>("/api/requests", undefined, {
        method: "POST",
        headers: await localConfirmHeaders(),
        body: JSON.stringify(body),
      });
      if (res.queued_id) onSent("The organization is unreachable right now. Your request is queued and goes out on the next sync.");
      else if (res.request?.duplicate) onSent(`You already have this request open (#${res.request.id}); nothing new was sent.`);
      else onSent(`Request #${res.request?.id ?? ""} sent. You will see the answer here.`);
    } catch (e) {
      setError(apiReason(e));
    } finally {
      setBusy(false);
    }
  };

  const set = (k: keyof Payload, v: string | number | undefined) => setPayload((p) => ({ ...p, [k]: v }));
  const problems = preview?.problems ?? [];
  const excerpt = initial.context?.target_excerpt;

  return (
    <Modal
      open
      onClose={onClose}
      title="Ask for an exception"
      subtitle="Your organization decides. Nothing changes on this machine until an admin grants it."
      width={640}
      dismissible={!busy}
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={send} disabled={busy || !message.trim() || problems.length > 0}>
            {busy ? "Sending" : "Send request"}
          </Button>
        </div>
      }
    >
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Select
            label="What do you need?"
            value={type}
            onChange={(e) => pickType(e.target.value)}
            options={types.map((t) => ({ value: t.id, label: t.label }))}
          />
          <Select
            label="For how long?"
            value={duration}
            onChange={(e) => {
              setDurationTouched(true);
              setDuration(e.target.value);
            }}
            options={
              type === "budget_increase"
                ? budgetDurationOptions(DURATIONS, periodLeftS, humanDuration)
                : DURATIONS.filter((d) => !typeMeta?.max_seconds || Number(d.value) <= typeMeta.max_seconds)
            }
            help={type === "budget_increase" ? "At most until the end of the current budget period." : "Never permanent; the org sets the maximum."}
          />
        </div>
        {type === "guard_exemption" && (
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <span className="mb-1 block text-[11px] font-medium text-fg-2">Rule</span>
              <SinglePicker
                options={keepSelected(GUARD_RULE_OPTIONS, payload.rule_id ? [payload.rule_id] : [], "Custom rule")}
                value={payload.rule_id ?? ""}
                onChange={(v) => set("rule_id", v)}
                allowFree
                freeLabel="Custom rule id"
                placeholder="Pick the rule…"
                ariaLabel="Rule"
              />
            </div>
            <Select
              label="Scope"
              value={payload.breadth ?? "rule"}
              onChange={(e) => set("breadth", e.target.value)}
              options={[
                ...(payload.operand_hash || fromEvent ? [{ value: "exact", label: "This exact command" }] : []),
                ...(payload.command_class || fromEvent ? [{ value: "class", label: "This kind of command" }] : []),
                { value: "rule", label: "Anything this rule matches" },
              ]}
            />
            <Input label="Uses (optional)" type="number" min={0} value={uses} onChange={(e) => setUses(e.target.value)} help="Leave empty for until it expires." />
          </div>
        )}
        {type === "budget_increase" && budgets.length > 0 && (
          <Select
            label="Which budget?"
            value={payload.budget_id ?? ""}
            onChange={(e) => set("budget_id", e.target.value || undefined)}
            options={budgetOptions(budgets, dollars)}
            help={budgetPickNote(picked, budgets.length) ?? "The budgets your organization applies to you. The approver can change the pick."}
          />
        )}
        {type === "budget_increase" && budgets.length === 0 && (
          <p className="text-[11.5px] text-fg-3">{budgetPickNote(undefined, 0)}</p>
        )}
        {type === "budget_increase" && (fields.tokens || fields.usd) && (
          <div className={fields.tokens && fields.usd ? "grid gap-3 sm:grid-cols-2" : "grid gap-3"}>
            {fields.tokens && (
              <Input
                label="Additional tokens"
                type="number"
                min={0}
                value={payload.delta_tokens ?? ""}
                onChange={(e) => {
                  setAmountTouched(true);
                  set("delta_tokens", e.target.value ? Number(e.target.value) : undefined);
                }}
                help={budgetDeltaHelp(dollars, picked)}
              />
            )}
            {fields.usd && (
              <Input
                label="Additional dollars"
                type="number"
                min={0}
                step="0.01"
                value={payload.delta_usd ?? ""}
                onChange={(e) => {
                  setAmountTouched(true);
                  set("delta_usd", e.target.value ? Number(e.target.value) : undefined);
                }}
              />
            )}
          </div>
        )}
        {type === "budget_increase" && !fields.tokens && !fields.usd && (
          <p className="text-[11.5px] text-fg-3">{budgetDeltaHelp(dollars, picked)}</p>
        )}
        {(type === "tool_allow" || type === "model_access" || type === "feature_enable" || type === "component_enable") && (
          <div>
            <span className="mb-1 block text-[11px] font-medium text-fg-2">
              {type === "tool_allow" ? "Tool" : type === "model_access" ? "Model" : type === "component_enable" ? "Component" : "Feature"}
            </span>
            <SinglePicker
              options={keepSelected(targetSource.options, payload.target ? [payload.target] : [])}
              value={payload.target ?? ""}
              onChange={(v) => set("target", v)}
              allowFree={type === "model_access" || type === "feature_enable"}
              loading={targetSource.loading}
              placeholder="Pick one…"
              ariaLabel="Target"
            />
          </div>
        )}
        {type === "page_access" && pageChoices.length > 0 && (
          <Select
            label="Which page?"
            value={payload.target ?? ""}
            onChange={(e) => set("target", e.target.value)}
            options={pageChoices.map((c) => ({ value: c.id, label: c.label }))}
            help="If your organization agrees, it shows on this machine read-only until the grant ends."
          />
        )}
        {type === "page_access" && pageChoices.length === 0 && (
          <p className="text-[11.5px] text-fg-3">Your organization hides no page on this machine, so there is nothing to ask for here.</p>
        )}
        {type === "config_edit" && editChoices.length > 0 && (
          <Select
            label="Which setting?"
            value={payload.target ?? ""}
            onChange={(e) => set("target", e.target.value)}
            options={editChoices.map((c) => ({ value: c.id, label: c.label }))}
            help="If your organization agrees, you can edit it until the grant ends; then its policy applies again."
          />
        )}
        {typeMeta?.landing === "answer" && (
          <p className="text-[11.5px] text-fg-3">
            Describe what you need. Your organization answers with a note you will read here; nothing changes on this machine by itself.
          </p>
        )}
        <label className="block space-y-1">
          <span className="text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">Why do you need it?</span>
          <textarea
            className="min-h-[72px] w-full rounded-2 border border-line-2 bg-bg-1 px-2.5 py-1.5 text-[12px] text-fg-0 focus:border-accent focus:outline-none"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="The approver reads this. Secrets are removed before it is sent."
          />
        </label>
        {excerpt && !shipsRaw && (
          <label className="flex items-start gap-2 text-[12px] text-fg-2">
            <input type="checkbox" className="mt-0.5" checked={optIn} onChange={(e) => setOptIn(e.target.checked)} />
            <span>
              Include the command excerpt so the approver can see it:{" "}
              <code className="break-all font-mono text-fg-1">{excerpt}</code>
            </span>
          </label>
        )}
        {excerpt && shipsRaw && (
          <p className="text-[11.5px] text-fg-3">Your organization manages this machine, so the command excerpt is part of the request.</p>
        )}
        {problems.length > 0 && (
          <ul className="space-y-0.5 text-[11.5px] text-danger">
            {problems.map((p) => (
              <li key={p.field + p.code}>{p.message}</li>
            ))}
          </ul>
        )}
        {error && <div className="text-[11.5px] text-danger">{error}</div>}
        <details className="rounded-2 border border-line-2 bg-bg-1" open={Boolean(preview)}>
          <summary className="cursor-pointer px-2.5 py-1.5 text-[11.5px] font-medium text-fg-2">Exactly what will be sent</summary>
          <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all px-2.5 pb-2 font-mono text-[11px] text-fg-1">
            {preview?.json ?? "Write why you need it to see the preview."}
          </pre>
        </details>
      </div>
    </Modal>
  );
}

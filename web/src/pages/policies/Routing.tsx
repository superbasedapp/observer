import { useEffect, useMemo, useState } from "react";
import { Pill, SegmentedControl } from "@/components/primitives";
import { useApi } from "@/lib/useApi";
import { pushToast } from "@/components/Toast";
import { markRestartPending } from "@/lib/restartPending";
import {
  EGRESS_REASON_CODES,
  type EgressAction,
  type EgressActionKind,
  type EgressPolicy,
  type EgressPolicyGet,
  type EgressRule,
  type EgressTarget,
  type EgressWhen,
  type LintIssue,
  egressActionKind,
  emptyEgressWhen,
  postPolicy,
} from "./types";
import {
  Card,
  IssueList,
  Labeled,
  Muted,
  NumberInput,
  Select,
  TextInput,
  btnGhost,
  btnGhostDanger,
  btnPrimary,
  btnSecondary,
  inputClass,
} from "./ui";

// Routing tab — the Plane-A egress (routing) authoring surface: typed upstream
// targets + a first-match-wins WHEN→ROUTE rule table. Egress only takes real
// effect on the PROXY path (only the proxy can reroute an upstream), and the
// proxy holds a SEPARATE service instance — so "Apply (preview)" validates and
// updates this dashboard's egress preview, but the routing behavior changes
// only after "Save & restart". The buttons say so.

const VERDICTS = ["", "allow", "flag", "ask", "deny"];
const SEVERITIES = ["", "info", "warn", "high", "critical"];
const EFFORTS = ["minimal", "low", "medium", "high"];
const ACTION_KINDS: { value: EgressActionKind; label: string }[] = [
  { value: "route_to_upstream", label: "Route to upstream" },
  { value: "route_to_model", label: "Swap model" },
  { value: "set_effort", label: "Set effort" },
  { value: "deny", label: "Deny" },
  { value: "no_route", label: "No route (log only)" },
];

export function RoutingTab({ onApplied }: { onApplied?: () => void }) {
  const api = useApi<EgressPolicyGet>("/api/obs/egress/policy");
  const [draft, setDraft] = useState<EgressPolicy | null>(null);
  const [busy, setBusy] = useState<"" | "apply" | "save">("");
  const [issues, setIssues] = useState<LintIssue[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!api.data) return;
    const p = structuredClone(api.data.policy);
    p.targets = p.targets ?? [];
    p.rules = (p.rules ?? []).map((r) => ({ ...r, when: { ...emptyEgressWhen(), ...r.when } }));
    p.cohorts = p.cohorts ?? {};
    setDraft(p);
  }, [api.data]);

  const globalIssues = useMemo(() => issues.filter((i) => !i.rule_name), [issues]);

  if (api.loading && !draft) return <Card title="Egress policy"><Muted>Loading…</Muted></Card>;
  if (!draft) return <Card title="Egress policy"><Muted>No policy loaded.</Muted></Card>;

  const patch = (p: Partial<EgressPolicy>) => setDraft({ ...draft, ...p });
  const patchTarget = (i: number, t: Partial<EgressTarget>) =>
    setDraft({ ...draft, targets: draft.targets.map((x, n) => (n === i ? { ...x, ...t } : x)) });
  const patchRule = (i: number, r: Partial<EgressRule>) =>
    setDraft({ ...draft, rules: draft.rules.map((x, n) => (n === i ? { ...x, ...r } : x)) });
  const moveRule = (i: number, dir: -1 | 1) => {
    const j = i + dir;
    if (j < 0 || j >= draft.rules.length) return;
    const rules = draft.rules.slice();
    [rules[i], rules[j]] = [rules[j], rules[i]];
    setDraft({ ...draft, rules });
  };

  async function submit(persist: boolean) {
    setBusy(persist ? "save" : "apply");
    setErr("");
    setIssues([]);
    try {
      const { status, data } = await postPolicy("/api/obs/egress/policy", draft, persist);
      setIssues(data.issues ?? []);
      if (status === 422 || !data.applied) {
        setErr(data.error || "Policy rejected - fix the issues below.");
        pushToast("Egress policy not applied - see issues", "danger");
        return;
      }
      if (persist && !data.persisted) {
        pushToast(`Validated, but not saved: ${data.persist_error || "persist failed"}`, "warn");
      } else if (persist) {
        markRestartPending("egress policy");
        pushToast("Saved. Restart the daemon to apply routing on the proxy.", "success");
      } else {
        pushToast("Validated - dashboard preview updated (routing changes on Save & restart).", "success");
      }
      api.reload();
      onApplied?.();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      pushToast("Apply failed", "danger");
    } finally {
      setBusy("");
    }
  }

  const targetIds = draft.targets.map((t) => t.id).filter(Boolean);

  return (
    <div className="space-y-4">
      {/* Targets */}
      <Card
        title="Upstream targets"
        sub="Named upstreams a rule can route to. A declared shape (anthropic | openai) is required for any enforce-mode route - cross-shape routing is rejected at compile."
      >
        <div className="space-y-2">
          {draft.targets.length === 0 && <Muted>No targets. Add one before a route-to-upstream rule can reference it.</Muted>}
          {draft.targets.map((t, i) => (
            <div key={i} className="flex flex-wrap items-center gap-2">
              <TextInput value={t.id} onChange={(id) => patchTarget(i, { id })} placeholder="id (e.g. ollama-local)" className="min-w-[9rem]" />
              <TextInput value={t.url} onChange={(url) => patchTarget(i, { url })} placeholder="http://127.0.0.1:11434" className="min-w-[14rem] flex-1" />
              <Select
                value={t.shape}
                onChange={(shape) => patchTarget(i, { shape: shape as EgressTarget["shape"] })}
                options={[{ value: "openai", label: "openai" }, { value: "anthropic", label: "anthropic" }]}
              />
              <button type="button" onClick={() => patch({ targets: draft.targets.filter((_, n) => n !== i) })} className={btnGhostDanger}>Remove</button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={() => patch({ targets: [...draft.targets, { id: "", url: "", shape: "openai" }] })}
          className={btnGhost + " mt-3"}
        >
          + Add target
        </button>
      </Card>

      {/* Cohorts */}
      <CohortsCard value={draft.cohorts} onChange={(cohorts) => patch({ cohorts })} />

      {/* Rules */}
      <Card
        title="Routing rules"
        sub="First match wins - order matters (use ↑/↓). Each rule matches on the admission verdict, budget, cohort, or request shape, then takes exactly one action."
      >
        <div className="mb-3 flex flex-wrap items-center gap-x-6 gap-y-3">
          <Labeled label="Mode">
            <SegmentedControl<EgressPolicy["mode"]>
              options={[
                { value: "off", label: "Off" },
                { value: "advise", label: "Advise" },
                { value: "enforce", label: "Enforce" },
              ]}
              value={draft.mode}
              onChange={(mode) => patch({ mode })}
            />
          </Labeled>
          <Labeled label="Cost-switch cooldown (s)">
            <NumberInput value={draft.cooldown_seconds} onChange={(cooldown_seconds) => patch({ cooldown_seconds })} />
          </Labeled>
        </div>

        {draft.mode === "enforce" && (
          <div className="mb-3 rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
            Enforce actively reroutes or denies end-user traffic on the proxy path. A route-to-upstream needs a target with a matching shape.
          </div>
        )}

        <div className="space-y-3">
          {draft.rules.length === 0 && <Muted>No rules - nothing is rerouted. Add one, or apply a Template.</Muted>}
          {draft.rules.map((r, i) => (
            <RuleRow
              key={i}
              rule={r}
              index={i}
              count={draft.rules.length}
              targetIds={targetIds}
              issues={issues.filter((x) => x.rule_name === r.name && r.name !== "")}
              onChange={(p) => patchRule(i, p)}
              onRemove={() => patch({ rules: draft.rules.filter((_, n) => n !== i) })}
              onMove={(dir) => moveRule(i, dir)}
            />
          ))}
        </div>
        <button
          type="button"
          onClick={() =>
            patch({
              rules: [
                ...draft.rules,
                { name: `rule-${draft.rules.length + 1}`, when: emptyEgressWhen(), action: { route_to_upstream: targetIds[0] ?? "", route_to_model: "", set_effort: "", deny: false, no_route: false }, on_unavailable: "fail_open", reason: "", reason_code: "" },
              ],
            })
          }
          className={btnGhost + " mt-3"}
        >
          + Add rule
        </button>

        {globalIssues.length > 0 && <IssueList issues={globalIssues} />}
        {err && <div className="mt-3 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">{err}</div>}

        <div className="mt-4 flex items-center gap-2">
          <button type="button" disabled={busy !== ""} onClick={() => submit(false)} className={btnSecondary}>
            {busy === "apply" ? "Validating…" : "Apply (preview)"}
          </button>
          <button type="button" disabled={busy !== ""} onClick={() => submit(true)} className={btnPrimary}>
            {busy === "save" ? "Saving…" : "Save & restart"}
          </button>
          <span className="text-[11px] text-fg-3">Routing changes only take effect on the proxy after Save &amp; restart</span>
        </div>
      </Card>
    </div>
  );
}

// CohortsCard edits the end-user → cohort map that a rule's user_cohort matcher
// keys on. It holds the rows in local state (seeded once) so a user id — the map
// KEY — can be typed without the entry vanishing mid-edit; every change emits a
// cleaned map (empty user ids dropped, values trimmed) up to the draft.
function CohortsCard({ value, onChange }: { value: Record<string, string>; onChange: (v: Record<string, string>) => void }) {
  const [rows, setRows] = useState<[string, string][]>(() => Object.entries(value ?? {}));
  const emit = (next: [string, string][]) => {
    setRows(next);
    const map: Record<string, string> = {};
    for (const [u, c] of next) if (u.trim()) map[u.trim()] = c.trim();
    onChange(map);
  };
  return (
    <Card title="Cohorts" sub="Map an end-user id to a cohort label so a rule can match on it (user_cohort). Optional; local-only.">
      <div className="space-y-2">
        {rows.length === 0 && <Muted>No cohorts mapped.</Muted>}
        {rows.map(([u, c], i) => (
          <div key={i} className="flex flex-wrap items-center gap-2">
            <TextInput value={u} onChange={(v) => emit(rows.map((r, n) => (n === i ? [v, r[1]] : r)))} placeholder="user id" className="min-w-[10rem]" />
            <span className="text-fg-3">→</span>
            <TextInput value={c} onChange={(v) => emit(rows.map((r, n) => (n === i ? [r[0], v] : r)))} placeholder="cohort (e.g. eu)" className="min-w-[8rem]" />
            <button type="button" onClick={() => emit(rows.filter((_, n) => n !== i))} className={btnGhostDanger}>Remove</button>
          </div>
        ))}
      </div>
      <button type="button" onClick={() => emit([...rows, ["", ""]])} className={btnGhost + " mt-3"}>+ Add cohort</button>
    </Card>
  );
}

function RuleRow({
  rule,
  index,
  count,
  targetIds,
  issues,
  onChange,
  onRemove,
  onMove,
}: {
  rule: EgressRule;
  index: number;
  count: number;
  targetIds: string[];
  issues: LintIssue[];
  onChange: (p: Partial<EgressRule>) => void;
  onRemove: () => void;
  onMove: (dir: -1 | 1) => void;
}) {
  const kind = egressActionKind(rule.action);
  const setWhen = (w: Partial<EgressWhen>) => onChange({ when: { ...rule.when, ...w } });
  const setKind = (k: EgressActionKind) => {
    // One-hot the action so exactly one primary is set (lint requirement).
    const a: EgressAction = { route_to_upstream: "", route_to_model: "", set_effort: "", deny: false, no_route: false };
    if (k === "route_to_upstream") a.route_to_upstream = targetIds[0] ?? "";
    else if (k === "route_to_model") a.route_to_model = "";
    else if (k === "set_effort") a.set_effort = "medium";
    else if (k === "deny") a.deny = true;
    else a.no_route = true;
    onChange({ action: a });
  };
  const setAction = (a: Partial<EgressAction>) => onChange({ action: { ...rule.action, ...a } });

  return (
    <div className="rounded-2 border border-line-1 bg-bg-2/40 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10.5px] font-mono text-fg-3">#{index + 1}</span>
        <TextInput value={rule.name} onChange={(name) => onChange({ name })} placeholder="rule name" className="min-w-[10rem] flex-1" />
        <div className="flex items-center gap-1">
          <button type="button" disabled={index === 0} onClick={() => onMove(-1)} className={btnGhost} title="Move up (earlier match)">↑</button>
          <button type="button" disabled={index === count - 1} onClick={() => onMove(1)} className={btnGhost} title="Move down">↓</button>
          <button type="button" onClick={onRemove} className={btnGhostDanger}>Remove</button>
        </div>
      </div>

      {/* WHEN */}
      <div className="mt-2">
        <div className="mb-1 text-[10px] uppercase tracking-[0.06em] text-fg-3">When</div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Labeled label="Verdict ≥">
            <Select value={rule.when.verdict_at_least} onChange={(v) => setWhen({ verdict_at_least: v })} options={VERDICTS.map((v) => ({ value: v, label: v || "(any)" }))} />
          </Labeled>
          <Labeled label="Severity ≥">
            <Select value={rule.when.severity_at_least} onChange={(v) => setWhen({ severity_at_least: v })} options={SEVERITIES.map((s) => ({ value: s, label: s || "(any)" }))} />
          </Labeled>
          <Labeled label="Criterion">
            <TextInput value={rule.when.criterion} onChange={(v) => setWhen({ criterion: v })} placeholder="(any)" />
          </Labeled>
          <Labeled label="Provider">
            <Select value={rule.when.provider} onChange={(v) => setWhen({ provider: v })} options={[{ value: "", label: "(any)" }, { value: "anthropic", label: "anthropic" }, { value: "openai", label: "openai" }]} />
          </Labeled>
          <Labeled label="Budget band ≥">
            <input
              type="number"
              step={0.1}
              min={0}
              max={1}
              value={rule.when.budget_band_at_least ?? ""}
              placeholder="unset"
              onChange={(e) => setWhen({ budget_band_at_least: e.target.value === "" ? null : Number(e.target.value) })}
              className={inputClass + " w-24"}
            />
          </Labeled>
          <Labeled label="Cohort">
            <TextInput value={rule.when.user_cohort} onChange={(v) => setWhen({ user_cohort: v })} placeholder="(any)" />
          </Labeled>
        </div>
        <details className="mt-2">
          <summary className="cursor-pointer text-[10.5px] text-fg-3 hover:text-fg-2">More matchers</summary>
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
            <Labeled label="Content class"><TextInput value={rule.when.content_class} onChange={(v) => setWhen({ content_class: v })} placeholder="(any)" /></Labeled>
            <Labeled label="Model glob"><TextInput value={rule.when.model_glob} onChange={(v) => setWhen({ model_glob: v })} placeholder="(any)" /></Labeled>
            <Labeled label="User"><TextInput value={rule.when.user} onChange={(v) => setWhen({ user: v })} placeholder="(any)" /></Labeled>
            <Labeled label="Min prompt tokens"><NumberInput value={rule.when.min_prompt_tokens} onChange={(n) => setWhen({ min_prompt_tokens: n })} /></Labeled>
          </div>
        </details>
      </div>

      {/* THEN */}
      <div className="mt-3">
        <div className="mb-1 text-[10px] uppercase tracking-[0.06em] text-fg-3">Then</div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Select value={kind} onChange={(k) => setKind(k as EgressActionKind)} options={ACTION_KINDS} />
          {kind === "route_to_upstream" && (
            <Labeled label="Target">
              {targetIds.length > 0 ? (
                <Select value={rule.action.route_to_upstream} onChange={(v) => setAction({ route_to_upstream: v })} options={targetIds.map((id) => ({ value: id, label: id }))} />
              ) : (
                <span className="text-[11px] text-warn">add a target first</span>
              )}
            </Labeled>
          )}
          {kind === "route_to_model" && (
            <Labeled label="Model"><TextInput value={rule.action.route_to_model} onChange={(v) => setAction({ route_to_model: v })} placeholder="claude-haiku-4-5" /></Labeled>
          )}
          {kind === "set_effort" && (
            <Labeled label="Effort">
              <Select value={rule.action.set_effort} onChange={(v) => setAction({ set_effort: v })} options={EFFORTS.map((e) => ({ value: e, label: e }))} />
            </Labeled>
          )}
          <Labeled label="On unavailable">
            <Select value={rule.on_unavailable} onChange={(v) => onChange({ on_unavailable: v })} options={[{ value: "fail_open", label: "fail open" }, { value: "deny", label: "deny" }]} />
          </Labeled>
          <Labeled label="Reason code">
            <Select value={rule.reason_code} onChange={(v) => onChange({ reason_code: v })} options={EGRESS_REASON_CODES.map((c) => ({ value: c, label: c || "(derived)" }))} />
          </Labeled>
        </div>
      </div>

      <div className="mt-2 rounded-2 bg-bg-2/60 px-2.5 py-1.5 text-[11px] leading-relaxed text-fg-2">
        <Pill variant="neutral" className="mr-1.5">preview</Pill>
        {previewSentence(rule)}
      </div>

      <IssueList issues={issues} />
    </div>
  );
}

// previewSentence renders a rule as a plain-English WHEN → THEN sentence so the
// operator can read the intent without decoding the matcher grid.
function previewSentence(r: EgressRule): string {
  const w = r.when;
  const conds: string[] = [];
  if (w.verdict_at_least) conds.push(`the verdict is at least ${w.verdict_at_least}`);
  if (w.severity_at_least) conds.push(`severity ≥ ${w.severity_at_least}`);
  if (w.criterion) conds.push(`criterion "${w.criterion}" fired`);
  if (w.provider) conds.push(`the provider is ${w.provider}`);
  if (w.budget_band_at_least != null) conds.push(`the user's budget burn ≥ ${Math.round(w.budget_band_at_least * 100)}%`);
  if (w.user_cohort) conds.push(`the user is in cohort "${w.user_cohort}"`);
  if (w.content_class) conds.push(`content class is "${w.content_class}"`);
  if (w.model_glob) conds.push(`the model matches "${w.model_glob}"`);
  if (w.user) conds.push(`the user is "${w.user}"`);
  if (w.min_prompt_tokens > 0) conds.push(`the prompt is ≥ ${w.min_prompt_tokens} tokens`);
  const when = conds.length ? conds.join(" and ") : "every request";

  const a = r.action;
  let then = "leave routing unchanged (log only)";
  if (a.deny) then = "deny the request";
  else if (a.route_to_upstream) then = `route to upstream "${a.route_to_upstream}"`;
  else if (a.route_to_model) then = `swap to model "${a.route_to_model}"`;
  else if (a.set_effort) then = `set reasoning effort to ${a.set_effort}`;

  const tail =
    a.route_to_upstream && r.on_unavailable === "deny"
      ? "; if that upstream is unavailable, deny"
      : a.route_to_upstream
        ? "; if unavailable, fall through"
        : "";

  return `When ${when}, ${then}${tail}.`;
}

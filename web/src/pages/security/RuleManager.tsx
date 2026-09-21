import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Button,
  Card,
  ComboChip,
  type ComboOption,
  EntityMultiPicker,
  type EntityMultiPickerOption,
  Pill,
  SegmentedControl,
} from "@/components/primitives";
import { fetchJSON } from "@/lib/api";
import type { ApiState } from "@/lib/useApi";
import { markRestartPending } from "@/lib/restartPending";
import type {
  GuardPolicyLint,
  GuardPolicyProjectSaveResponse,
  GuardPolicyView,
  GuardRule,
  GuardRulesResponse,
  ProjectRow,
} from "@/lib/types";
import {
  type GuardOverrideRow,
  type GuardRuleRow,
  composeRuleToml,
  emptyGuardOverride,
  guardRuleInfo,
  parseRules,
} from "@shared/lib/guardCatalog";
import { DECISION_VARIANT, RuleCell, SEVERITY_VARIANT } from "../Security";
import { RuleEditor } from "./RuleEditor";

// RuleManager — the structured guard-rule editor (spec §1/§6 Track B). Two
// scopes:
//   - "global" composes the USER layer (~/.observer/guard-policy.toml, the
//     same file PolicyLayersCard's raw editor writes). The structured override
//     picker MAY weaken as well as escalate here (parity with the raw editor);
//     the org floor and the integrity-rule backstop (R-160/R-161) are still
//     enforced server-side at merge time. Disabling a rule globally goes
//     through the separate config seam (PUT /api/config/section/guard,
//     Rules.Disable) per §5, not the TOML.
//   - "project" composes the NEW trusted daemon-local per-project layer
//     (PUT /api/guard/policy/project, §3) — this layer may WEAKEN or DISABLE
//     (operator decision (d)); `disable` lives inside that layer's own TOML.
//
// Both scopes round-trip through parseRules/composeRuleToml. When the
// layer's current content doesn't parse (a hand-authored construct this
// form can't represent), the structured editor steps aside and points at
// PolicyLayersCard's raw-TOML "Advanced" editor below — the safety pattern
// the spec calls for.

type Scope = "global" | "project";

type GuardSectionConfig = {
  Rules?: { Disable?: string[] } & Record<string, unknown>;
} & Record<string, unknown>;

function shortenRoot(p: string): string {
  if (!p) return "-";
  const parts = p.split(/[\\/]/).filter(Boolean);
  if (parts.length <= 2) return p;
  return ".../" + parts.slice(-2).join("/");
}

export function RuleManager({
  rulesApi,
  policyApi,
  projects,
}: {
  rulesApi: ApiState<GuardRulesResponse>;
  policyApi: ApiState<GuardPolicyView>;
  projects: ProjectRow[];
}) {
  const [scope, setScope] = useState<Scope>("global");
  const [projectRoot, setProjectRoot] = useState("");

  // Effective catalog, deduped by id (a rule id can carry several catalog
  // rows — e.g. R-152's write/read variants) so the overview lists each id
  // once with every row's doc/severity available to RuleCell's tooltip.
  const ruleDefs = useMemo(() => {
    const m = new Map<string, GuardRule[]>();
    for (const r of rulesApi.data?.rules ?? []) {
      const list = m.get(r.id) ?? [];
      list.push(r);
      m.set(r.id, list);
    }
    return m;
  }, [rulesApi.data]);
  const effectiveIds = useMemo(() => [...ruleDefs.keys()].sort(), [ruleDefs]);

  // --- Global disable list: lives in config, not the policy TOML (§5). ---
  const [globalDisable, setGlobalDisable] = useState<string[]>([]);
  const [globalDisableLoaded, setGlobalDisableLoaded] = useState(false);
  const [globalDisableDirty, setGlobalDisableDirty] = useState(false);

  const loadGlobalDisable = async () => {
    try {
      const cfg = await fetchJSON<{ config: { Guard: GuardSectionConfig } }>("/api/config");
      setGlobalDisable(cfg.config.Guard.Rules?.Disable ?? []);
    } catch {
      // Best-effort — the disable chips just start empty; Save still works,
      // it would only overwrite with an empty list if the operator never
      // touches this control (guarded by globalDisableDirty below).
    } finally {
      setGlobalDisableLoaded(true);
    }
  };
  useEffect(() => {
    if (scope === "global" && !globalDisableLoaded) void loadGlobalDisable();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope]);

  // --- Structured rule/override/disable state for the active scope. ---
  const [rows, setRows] = useState<GuardRuleRow[]>([]);
  const [overrides, setOverrides] = useState<GuardOverrideRow[]>([]);
  const [projectDisable, setProjectDisable] = useState<string[]>([]);
  const [rawFallback, setRawFallback] = useState(false);
  const [sourceKey, setSourceKey] = useState("");
  // edited tracks "the operator changed something since the last load/save",
  // independent of the current row COUNT — deleting the last remaining
  // custom rule must still enable Save, which a naive `rows.length > 0`
  // dirty check would get wrong.
  const [edited, setEdited] = useState(false);

  const trustedRow = useMemo(() => {
    if (!projectRoot) return undefined;
    return (policyApi.data?.layers ?? []).find(
      (l) => l.layer === "trusted_project" && l.project_root === projectRoot,
    );
  }, [policyApi.data, projectRoot]);

  // Re-derive the structured state whenever the SCOPE or PROJECT changes, or
  // the underlying content actually changed (policyApi.data is reference-
  // stable across no-op polls — see useApi's stringify dedupe). Deliberately
  // NOT re-run on every render so an in-progress edit survives an unrelated
  // reload.
  useEffect(() => {
    const content = scope === "global" ? policyApi.data?.user.content ?? "" : trustedRow?.content ?? "";
    const key = `${scope}|${projectRoot}|${content}`;
    if (key === sourceKey) return;
    setSourceKey(key);
    const parsed = parseRules(content);
    setEdited(false);
    if (parsed === null) {
      setRawFallback(content.trim() !== "");
      setRows([]);
      setOverrides([]);
      setProjectDisable([]);
      return;
    }
    setRawFallback(false);
    setRows(parsed.rules);
    setOverrides(parsed.overrides);
    setProjectDisable(parsed.disable);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope, projectRoot, policyApi.data, trustedRow, sourceKey]);

  const [editor, setEditor] = useState<
    | { kind: "rule"; index: number | null; initial?: GuardRuleRow }
    | { kind: "override"; index: number | null; initial?: GuardOverrideRow }
    | null
  >(null);

  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [lint, setLint] = useState<GuardPolicyLint | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [error, setError] = useState("");

  const dirty = !rawFallback && (edited || (scope === "global" && globalDisableDirty));

  const projectOptions: ComboOption[] = projects.map((p) => ({
    value: p.root_path,
    label: <span className="font-mono text-[11px]">{shortenRoot(p.root_path)}</span>,
    searchable: p.root_path.toLowerCase(),
    title: p.root_path,
    rightMeta: p.action_count.toLocaleString(),
  }));

  function upsertOverride(row: GuardOverrideRow, index: number | null) {
    setOverrides((cur) => {
      const withoutThis = index !== null ? cur.filter((_, i) => i !== index) : cur;
      const withoutSameRule = withoutThis.filter((r) => r.rule !== row.rule);
      return [...withoutSameRule, row];
    });
    setEdited(true);
    setEditor(null);
  }
  function upsertRule(row: GuardRuleRow, index: number | null) {
    setRows((cur) => {
      const withoutThis = index !== null ? cur.filter((_, i) => i !== index) : cur;
      const withoutSameId = withoutThis.filter((r) => r.id !== row.id);
      return [...withoutSameId, row];
    });
    setEdited(true);
    setEditor(null);
  }
  function removeRule(index: number) {
    setRows((cur) => cur.filter((_, i) => i !== index));
    setEdited(true);
  }
  function removeOverride(index: number) {
    setOverrides((cur) => cur.filter((_, i) => i !== index));
    setEdited(true);
  }

  const runLint = async (content: string): Promise<GuardPolicyLint> =>
    fetchJSON<GuardPolicyLint>("/api/guard/policy/lint", undefined, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, layer: scope === "project" ? "trusted_project" : "user" }),
    });

  const save = async () => {
    setBusy(true);
    setError("");
    setProblems([]);
    setSaved(false);
    try {
      if (scope === "global") {
        const content = composeRuleToml(rows, overrides, [], { allowDisable: false });
        const l = await runLint(content);
        setLint(l);
        if (!l.ok) {
          setProblems(l.problems ?? []);
          return;
        }
        await fetchJSON("/api/guard/policy", undefined, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content }),
        });
        if (globalDisableDirty) {
          const cfg = await fetchJSON<{ config: { Guard: GuardSectionConfig } }>("/api/config");
          const guardSec = { ...cfg.config.Guard, Rules: { ...cfg.config.Guard.Rules, Disable: globalDisable } };
          await fetchJSON("/api/config/section/guard", undefined, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(guardSec),
          });
          setGlobalDisableDirty(false);
        }
        markRestartPending("guard-policy");
      } else {
        if (!projectRoot) {
          setError("Pick a project first.");
          return;
        }
        const content = composeRuleToml(rows, overrides, projectDisable, { allowDisable: true });
        const l = await runLint(content);
        setLint(l);
        if (!l.ok) {
          setProblems(l.problems ?? []);
          return;
        }
        await fetchJSON<GuardPolicyProjectSaveResponse>("/api/guard/policy/project", undefined, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ project_root: projectRoot, content }),
        });
        markRestartPending("guard-policy");
      }
      setSaved(true);
      setEdited(false);
      policyApi.reload();
      rulesApi.reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const disableOptions: EntityMultiPickerOption[] = effectiveIds.map((id) => {
    const info = guardRuleInfo(id);
    return { id, label: id, sublabel: info?.doc };
  });

  const activeDisable = scope === "global" ? globalDisable : projectDisable;
  const setActiveDisable = (next: string[]) => {
    if (scope === "global") {
      setGlobalDisable(next);
      setGlobalDisableDirty(true);
    } else {
      setProjectDisable(next);
      setEdited(true);
    }
  };

  return (
    <Card
      title="Rule manager"
      sub="Create, override, enable/disable and enforce guard rules without hand-editing TOML. Global changes bind at daemon restart; project changes write a trusted daemon-local layer the agent can't touch."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {saved && <Pill variant="warn">saved - restart the daemon to apply</Pill>}
          <SegmentedControl<Scope>
            size="sm"
            options={[
              { value: "global", label: "Global" },
              { value: "project", label: "Project" },
            ]}
            value={scope}
            onChange={setScope}
          />
          {scope === "project" && (
            <ComboChip
              label="Project"
              value={projectRoot}
              onChange={setProjectRoot}
              options={projectOptions}
              popoverWidth={420}
              placeholder="Pick a project…"
            />
          )}
        </div>
      }
    >
      {scope === "project" && !projectRoot && (
        <div className="py-3 text-[11.5px] text-fg-3">
          Pick a project above. Project rules write a trusted daemon-local file the agent cannot
          edit (R-160-protected) — unlike the in-repo project policy file, this layer MAY weaken or
          disable a rule for just this project.
        </div>
      )}

      {(scope === "global" || projectRoot) && (
        <div className="space-y-4">
          {rawFallback && (
            <div className="rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11.5px] text-warn">
              This layer's current file uses a construct the structured editor can't represent
              (or a hand-written comment/format it won't faithfully round-trip). Use the Advanced
              raw-TOML editor below instead — editing here and saving would discard it.
            </div>
          )}

          {!rawFallback && (
            <>
              <RuleSection
                title={`Custom rules (${rows.length})`}
                onAdd={() => setEditor({ kind: "rule", index: null })}
                addLabel="+ Add custom rule"
              >
                {rows.length === 0 ? (
                  <p className="py-2 text-[11.5px] text-fg-3">No custom [[rule]] definitions yet.</p>
                ) : (
                  rows.map((r, i) => (
                    <RuleRow
                      key={r.id}
                      r={r}
                      onEdit={() => setEditor({ kind: "rule", index: i, initial: r })}
                      onRemove={() => removeRule(i)}
                    />
                  ))
                )}
              </RuleSection>

              <RuleSection
                title={`Overrides (${overrides.length})`}
                onAdd={() => setEditor({ kind: "override", index: null })}
                addLabel="+ Add override"
              >
                {overrides.length === 0 ? (
                  <p className="py-2 text-[11.5px] text-fg-3">
                    No overrides — every built-in stays at its catalog decision.
                  </p>
                ) : (
                  overrides.map((r, i) => (
                    <OverrideRow
                      key={r.rule}
                      r={r}
                      onEdit={() => setEditor({ kind: "override", index: i, initial: r })}
                      onRemove={() => removeOverride(i)}
                    />
                  ))
                )}
              </RuleSection>

              <div>
                <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
                  Disabled rule IDs {scope === "project" ? "(this project)" : "(everywhere)"}
                </h4>
                <EntityMultiPicker
                  options={disableOptions}
                  value={activeDisable}
                  onChange={setActiveDisable}
                  allowFreeId
                  placeholder="Disable a rule id…"
                />
                <p className="mt-1 text-[11px] text-fg-3">
                  {scope === "global"
                    ? "Global disables are unconditional — prefer a scoped approval or an override first."
                    : "Project disables apply only to sessions rooted here, and can never remove an org-protected budget rule."}
                </p>
              </div>
            </>
          )}

          {(problems.length > 0 || (lint && !lint.ok)) && (
            <div className="space-y-0.5 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11.5px] text-danger">
              {(problems.length > 0 ? problems : lint?.problems ?? []).map((p, i) => (
                <div key={i}>{p}</div>
              ))}
            </div>
          )}
          {error && <div className="text-[11.5px] text-danger">{error}</div>}

          <div className="flex items-center gap-2">
            <Button variant="primary" disabled={busy || rawFallback || !dirty} onClick={save}>
              {busy ? "Saving…" : "Save"}
            </Button>
            {lint?.ok && <span className="text-[11px] text-success">Lints clean.</span>}
          </div>
        </div>
      )}

      <EffectiveRulesTable ruleDefs={ruleDefs} ids={effectiveIds} loading={rulesApi.loading} onOverride={(id) => setEditor({ kind: "override", index: null, initial: { rule: id, decision: "", enforce: true } })} onDisable={(id) => setActiveDisable([...new Set([...activeDisable, id])])} />

      {editor?.kind === "rule" && (
        <RuleEditor
          open
          kind="rule"
          initial={editor.initial}
          onClose={() => setEditor(null)}
          onSave={(row) => upsertRule(row, editor.index)}
        />
      )}
      {editor?.kind === "override" && (
        <RuleEditor
          open
          kind="override"
          initial={editor.initial ?? emptyGuardOverride()}
          allowWeaken={true}
          onClose={() => setEditor(null)}
          onSave={(row) => upsertOverride(row, editor.index)}
        />
      )}
    </Card>
  );
}

function RuleSection({
  title,
  addLabel,
  onAdd,
  children,
}: {
  title: string;
  addLabel: string;
  onAdd: () => void;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <h4 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">{title}</h4>
        <Button size="sm" variant="secondary" onClick={onAdd}>
          {addLabel}
        </Button>
      </div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

function RuleRow({ r, onEdit, onRemove }: { r: GuardRuleRow; onEdit: () => void; onRemove: () => void }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-2 border border-line-1 bg-bg-1 px-3 py-1.5 text-[11.5px]">
      <span className="font-mono text-fg-1">{r.id}</span>
      <span className="text-fg-3">{r.category}</span>
      <Pill variant={SEVERITY_VARIANT[r.severity] ?? "neutral"}>{r.severity}</Pill>
      <Pill variant={DECISION_VARIANT[r.decision] ?? "neutral"}>{r.decision}</Pill>
      {r.enforce && <Pill variant="warn">enforced</Pill>}
      <span className="text-fg-3">{r.scope} matcher</span>
      <span className="ml-auto flex items-center gap-1">
        <Button size="sm" variant="ghost" onClick={onEdit}>
          Edit
        </Button>
        <Button size="sm" variant="ghost" onClick={onRemove}>
          Remove
        </Button>
      </span>
    </div>
  );
}

function OverrideRow({ r, onEdit, onRemove }: { r: GuardOverrideRow; onEdit: () => void; onRemove: () => void }) {
  const info = guardRuleInfo(r.rule);
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-2 border border-line-1 bg-bg-1 px-3 py-1.5 text-[11.5px]">
      <span className="font-mono text-fg-1">{r.rule}</span>
      {info && <span className="text-fg-3">{info.category}</span>}
      {r.decision ? (
        <Pill variant={DECISION_VARIANT[r.decision] ?? "neutral"}>{r.decision}</Pill>
      ) : (
        <Pill variant="neutral">no change</Pill>
      )}
      {r.enforce && <Pill variant="warn">enforced</Pill>}
      <span className="ml-auto flex items-center gap-1">
        <Button size="sm" variant="ghost" onClick={onEdit}>
          Edit
        </Button>
        <Button size="sm" variant="ghost" onClick={onRemove}>
          Remove
        </Button>
      </span>
    </div>
  );
}

// EffectiveRulesTable — the read side: every rule currently in effect
// (builtins + user/project/trusted_project/org layers), with quick actions
// that pre-fill the editor rather than mutating anything directly.
function EffectiveRulesTable({
  ruleDefs,
  ids,
  loading,
  onOverride,
  onDisable,
}: {
  ruleDefs: Map<string, GuardRule[]>;
  ids: string[];
  loading: boolean;
  onOverride: (id: string) => void;
  onDisable: (id: string) => void;
}) {
  return (
    <div className="mt-4 border-t border-line-1 pt-3">
      <h4 className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Effective rules ({ids.length})
      </h4>
      {loading ? (
        <div className="py-4 text-center text-[12px] text-fg-3">Loading…</div>
      ) : (
        <div className="max-h-72 overflow-y-auto">
          <table className="w-full text-left text-[11.5px]">
            <thead>
              <tr className="border-b border-line-1 text-[10.5px] uppercase tracking-[0.06em] text-fg-3">
                <th className="py-1 pr-3 font-semibold">Rule</th>
                <th className="py-1 pr-3 font-semibold">Source</th>
                <th className="py-1 font-semibold"></th>
              </tr>
            </thead>
            <tbody>
              {ids.map((id) => {
                const defs = ruleDefs.get(id) ?? [];
                const source = defs[0]?.source ?? "builtin";
                return (
                  <tr key={id} className="border-b border-line-1/60">
                    <td className="py-1.5 pr-3">
                      <RuleCell id={id} category={defs[0]?.category} defs={defs} />
                    </td>
                    <td className="py-1.5 pr-3">
                      <Pill variant={source === "builtin" ? "neutral" : "accent"}>{source}</Pill>
                    </td>
                    <td className="py-1.5 text-right">
                      <span className="inline-flex items-center gap-1">
                        <Button size="sm" variant="ghost" onClick={() => onOverride(id)}>
                          Override
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => onDisable(id)}>
                          Disable
                        </Button>
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

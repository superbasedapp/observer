import { useState } from "react";
import {
  Button,
  EntityMultiPicker,
  type EntityMultiPickerOption,
  Input,
  SegmentedControl,
  Select,
  SettingRow,
  SlideOver,
  Toggle,
} from "@/components/primitives";
import {
  type Decision,
  type GuardOverrideRow,
  type GuardRuleRow,
  DECISIONS,
  GUARD_CATEGORIES,
  GUARD_EVENT_KINDS,
  GUARD_RULE_CATALOG,
  GUARD_SINKS,
  GUARD_TAINT_SOURCES,
  SEVERITIES,
  emptyGuardCommandMatch,
  emptyGuardEventMatch,
  emptyGuardRuleRow,
  guardDecisionOptionsFor,
  guardRuleInfo,
  guardRuleRowProblems,
  isGuardIntegrityRuleId,
} from "@shared/lib/guardCatalog";

// RuleEditor — the SlideOver form for authoring ONE `[[rule]]` (a brand-new
// custom rule) or tuning ONE `[[override]]` (escalate/loosen a built-in).
// docs/plans/guard-rule-management-ui-plan-2026-09-21.md §6 Track B. A
// controlled, save-on-submit form: the parent (RuleManager) owns the row
// list and only receives the finished row via onSaveRule/onSaveOverride —
// this component never talks to the network itself.
//
// `allowWeaken` widens the override decision picker past the built-in's
// escalate-only floor: true for the trusted-project layer (§2/§3) AND the
// user/global layer (both may weaken or disable, at parity with the raw TOML
// editor). guardDecisionOptionsFor still keeps integrity rules (R-160/R-161)
// escalate-only even when allowWeaken is true, and the org floor + integrity
// backstop are enforced server-side at merge time. The org bundle itself is
// authored escalate-only (it passes allowWeaken=false).

const EVENT_KIND_OPTIONS: EntityMultiPickerOption[] = GUARD_EVENT_KINDS.map((k) => ({ id: k, label: k }));

export type RuleEditorProps =
  | {
      open: boolean;
      onClose: () => void;
      kind: "rule";
      initial?: GuardRuleRow;
      onSave: (row: GuardRuleRow) => void;
    }
  | {
      open: boolean;
      onClose: () => void;
      kind: "override";
      initial?: GuardOverrideRow;
      allowWeaken: boolean;
      onSave: (row: GuardOverrideRow) => void;
    };

export function RuleEditor(props: RuleEditorProps) {
  if (props.kind === "override") return <OverrideEditor {...props} />;
  return <CustomRuleEditor {...props} />;
}

function OverrideEditor({
  open,
  onClose,
  initial,
  allowWeaken,
  onSave,
}: Extract<RuleEditorProps, { kind: "override" }>) {
  const [row, setRow] = useState<GuardOverrideRow>(initial ?? { rule: "", decision: "", enforce: true });
  const info = guardRuleInfo(row.rule);
  const decisionOpts = guardDecisionOptionsFor(row.rule, allowWeaken);

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title={initial ? `Edit override — ${initial.rule}` : "Override a built-in rule"}
      subtitle="Tunes an existing rule's decision/enforce. No matcher — overrides can't redefine what a rule matches, only how it decides."
      width={520}
    >
      <div className="space-y-4 p-5">
        <SettingRow label="Rule" layout="stack">
          <Input
            list="rule-editor-catalog"
            value={row.rule}
            onChange={(e) => {
              const rule = e.target.value;
              const opts = guardDecisionOptionsFor(rule, allowWeaken);
              setRow((r) => ({ ...r, rule, decision: r.decision && opts.includes(r.decision) ? r.decision : "" }));
            }}
            placeholder="rule id (e.g. R-110)"
            mono
            disabled={!!initial}
          />
          <datalist id="rule-editor-catalog">
            {GUARD_RULE_CATALOG.map((r) => (
              <option key={r.id} value={r.id}>
                {r.category} · {r.severity} - {r.doc}
              </option>
            ))}
          </datalist>
          {info && (
            <p className="mt-1 text-[11px] leading-snug text-fg-3">
              {info.doc} Built-in floor: observe={info.observe}, enforce={info.enforce}.
            </p>
          )}
        </SettingRow>

        <SettingRow
          label="Decision"
          layout="stack"
          help={
            allowWeaken && !isGuardIntegrityRuleId(row.rule)
              ? "This layer may loosen or disable — pick any decision, including below the built-in floor."
              : "Escalate-only: only decisions at or above the built-in's floor are offered."
          }
        >
          <SegmentedControl<Decision | "">
            options={[{ value: "", label: "no change" }, ...decisionOpts.map((d) => ({ value: d, label: d }))]}
            value={row.decision}
            onChange={(decision) => setRow((r) => ({ ...r, decision }))}
          />
        </SettingRow>

        <SettingRow label="Enforce" layout="stack" help="Block/hold even while the global mode stays observe.">
          <Toggle on={row.enforce} onChange={(enforce) => setRow((r) => ({ ...r, enforce }))} label={row.enforce ? "on" : "off"} />
        </SettingRow>
      </div>
      <div className="flex items-center gap-2 border-t border-line-1 px-5 py-3">
        <Button variant="primary" disabled={!row.rule.trim()} onClick={() => onSave(row)}>
          {initial ? "Save override" : "Add override"}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </SlideOver>
  );
}

function CustomRuleEditor({ open, onClose, initial, onSave }: Extract<RuleEditorProps, { kind: "rule" }>) {
  const [row, setRow] = useState<GuardRuleRow>(initial ?? emptyGuardRuleRow());
  const problems = guardRuleRowProblems(row);

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title={initial ? `Edit rule — ${initial.id}` : "New custom rule"}
      subtitle="A [[rule]] definition (matcher-v1). Command-scoped and event-scoped matchers can't mix in one rule."
      width={640}
    >
      <div className="space-y-4 p-5">
        <div className="grid grid-cols-2 gap-3">
          <SettingRow label="Id" layout="stack" help="Must not collide with a built-in id.">
            <Input
              value={row.id}
              onChange={(e) => setRow((r) => ({ ...r, id: e.target.value }))}
              placeholder="U-100"
              mono
              disabled={!!initial}
            />
          </SettingRow>
          <SettingRow label="Category" layout="stack">
            <Select
              value={row.category}
              onChange={(e) => setRow((r) => ({ ...r, category: e.target.value }))}
              options={[...GUARD_CATEGORIES]}
            />
          </SettingRow>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <SettingRow label="Decision" layout="stack">
            <SegmentedControl<Decision>
              size="sm"
              options={DECISIONS.map((d) => ({ value: d, label: d }))}
              value={row.decision}
              onChange={(decision) => setRow((r) => ({ ...r, decision }))}
            />
          </SettingRow>
          <SettingRow label="Severity" layout="stack">
            <Select
              value={row.severity}
              onChange={(e) => setRow((r) => ({ ...r, severity: e.target.value as GuardRuleRow["severity"] }))}
              options={[...SEVERITIES]}
            />
          </SettingRow>
        </div>

        <SettingRow label="Enforce" layout="stack" help="Block/hold even while the global mode stays observe.">
          <Toggle on={row.enforce} onChange={(enforce) => setRow((r) => ({ ...r, enforce }))} label={row.enforce ? "on" : "off"} />
        </SettingRow>

        <SettingRow
          label="Applies to"
          layout="stack"
          help="Leave empty to let the matchers imply it. Required for a pure-condition rule (taint_source / cost / repeat only)."
        >
          <EntityMultiPicker
            options={EVENT_KIND_OPTIONS}
            value={row.applies_to}
            onChange={(applies_to) => setRow((r) => ({ ...r, applies_to }))}
            placeholder="Pick event kinds…"
          />
        </SettingRow>

        <SettingRow label="Matcher scope" layout="stack" help="A rule may use only one scope — split into two rules to mix.">
          <SegmentedControl<GuardRuleRow["scope"]>
            options={[
              { value: "command", label: "Command" },
              { value: "event", label: "Event" },
            ]}
            value={row.scope}
            onChange={(scope) =>
              setRow((r) => ({
                ...r,
                scope,
                command: scope === "command" ? r.command : emptyGuardCommandMatch(),
                event: scope === "event" ? r.event : emptyGuardEventMatch(),
              }))
            }
          />
        </SettingRow>

        {row.scope === "command" ? (
          <div className="space-y-3 rounded-2 border border-line-1 bg-bg-1 p-3">
            <SettingRow label="command_regex" layout="stack" help="RE2 over the raw command text.">
              <Input
                value={row.command.command_regex}
                onChange={(e) => setRow((r) => ({ ...r, command: { ...r.command, command_regex: e.target.value } }))}
                mono
                placeholder='(?i)\bterraform\s+(apply|destroy)\b'
              />
            </SettingRow>
            <SettingRow label="command_base" layout="stack" help='Exact base-command match, e.g. "git".'>
              <Input
                value={row.command.command_base}
                onChange={(e) => setRow((r) => ({ ...r, command: { ...r.command, command_base: e.target.value } }))}
                mono
              />
            </SettingRow>
            <SettingRow label="arg_contains" layout="stack" help="Substring match over any argument.">
              <Input
                value={row.command.arg_contains}
                onChange={(e) => setRow((r) => ({ ...r, command: { ...r.command, arg_contains: e.target.value } }))}
                mono
              />
            </SettingRow>
          </div>
        ) : (
          <div className="space-y-3 rounded-2 border border-line-1 bg-bg-1 p-3">
            <SettingRow label="path_glob" layout="stack" help="Gitignore-style globs over the event path.">
              <EntityMultiPicker
                options={[]}
                allowFreeId
                value={row.event.path_glob}
                onChange={(path_glob) => setRow((r) => ({ ...r, event: { ...r.event, path_glob } }))}
                placeholder="Type a glob, press Enter…"
              />
            </SettingRow>
            <SettingRow label="path_not" layout="stack" help="Exemption globs, checked first.">
              <EntityMultiPicker
                options={[]}
                allowFreeId
                value={row.event.path_not}
                onChange={(path_not) => setRow((r) => ({ ...r, event: { ...r.event, path_not } }))}
                placeholder="Type a glob, press Enter…"
              />
            </SettingRow>
            <div className="grid grid-cols-2 gap-3">
              <Toggle
                on={row.event.path_outside_project}
                onChange={(v) => setRow((r) => ({ ...r, event: { ...r.event, path_outside_project: v } }))}
                label="path_outside_project"
              />
              <Toggle
                on={row.event.path_sensitive}
                onChange={(v) => setRow((r) => ({ ...r, event: { ...r.event, path_sensitive: v } }))}
                label="path_sensitive"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <SettingRow label="url_domain" layout="stack">
                <Input
                  value={row.event.url_domain}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, url_domain: e.target.value } }))}
                  mono
                />
              </SettingRow>
              <SettingRow label="sink" layout="stack">
                <Select
                  value={row.event.sink}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, sink: e.target.value } }))}
                  options={["", ...GUARD_SINKS]}
                />
              </SettingRow>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <SettingRow label="mcp_server" layout="stack">
                <Input
                  value={row.event.mcp_server}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, mcp_server: e.target.value } }))}
                  mono
                />
              </SettingRow>
              <SettingRow label="mcp_tool" layout="stack">
                <Input
                  value={row.event.mcp_tool}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, mcp_tool: e.target.value } }))}
                  mono
                />
              </SettingRow>
            </div>
            <SettingRow label="event_kind" layout="stack" help="The event's kind must be in this list.">
              <EntityMultiPicker
                options={EVENT_KIND_OPTIONS}
                value={row.event.event_kind}
                onChange={(event_kind) => setRow((r) => ({ ...r, event: { ...r.event, event_kind } }))}
                placeholder="Pick event kinds…"
              />
            </SettingRow>
            <SettingRow label="taint_source" layout="stack" help="Pure condition — session carries this taint mark.">
              <Select
                value={row.event.taint_source}
                onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, taint_source: e.target.value } }))}
                options={["", ...GUARD_TAINT_SOURCES]}
              />
            </SettingRow>
            <div className="grid grid-cols-2 gap-3">
              <SettingRow label="session_cost_usd_gt" layout="stack" help="Pure condition, float.">
                <Input
                  value={row.event.session_cost_usd_gt}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, session_cost_usd_gt: e.target.value } }))}
                  inputMode="decimal"
                  placeholder="20.0"
                />
              </SettingRow>
              <SettingRow label="repeat_count_gt" layout="stack" help="Pure condition, integer.">
                <Input
                  value={row.event.repeat_count_gt}
                  onChange={(e) => setRow((r) => ({ ...r, event: { ...r.event, repeat_count_gt: e.target.value } }))}
                  inputMode="numeric"
                  placeholder="5"
                />
              </SettingRow>
            </div>
          </div>
        )}

        {problems.length > 0 && (
          <div className="space-y-1 rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
            {problems.map((p, i) => (
              <div key={i}>{p}</div>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center gap-2 border-t border-line-1 px-5 py-3">
        <Button variant="primary" disabled={!row.id.trim()} onClick={() => onSave(row)}>
          {initial ? "Save rule" : "Add rule"}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </SlideOver>
  );
}

import { Plus } from "lucide-react";
import { useState } from "react";
import { Button, SegmentedControl, SettingRow, SinglePicker, SlideOver, Toggle } from "@/components/primitives";
import { type OverrideEditorMode, overrideEditorView } from "@/lib/guardEditorMode";
import { keepSelected } from "@/lib/pickerOptions";
import { GUARD_RULE_OPTIONS, useMCPServerOptions } from "@/lib/usePickerSources";
import {
  type Decision,
  type GuardOverrideRow,
  type GuardRuleRow,
  guardDecisionOptionsFor,
  guardRuleInfo,
  isGuardIntegrityRuleId,
} from "@shared/lib/guardCatalog";
import {
  CustomRuleEditor as SharedCustomRuleEditor,
  LOCAL_CUSTOM_RULE_VOCAB,
} from "@shared/components/guard/CustomRuleEditor";
import { withIntegrityEnforce } from "./integrityLock";

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
// editor). guardDecisionOptionsFor still keeps the integrity rules (isGuardIntegrityRuleId)
// escalate-only even when allowWeaken is true, and the org floor + integrity
// backstop are enforced server-side at merge time. The org bundle itself is
// authored escalate-only (it passes allowWeaken=false). The Enforce toggle is
// locked on for an integrity rule in every layer (withIntegrityEnforce, audit
// CF2-A1): `enforce = false` is a cap the engine refuses for these.

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
      // How the editor was opened (T-762): "add" lets the rule be picked;
      // "preset" and "edit" keep it locked to the row's rule. Never inferred
      // from `initial`, which "+ Add override" also passes (a blank row).
      mode: OverrideEditorMode;
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
  mode,
  initial,
  allowWeaken,
  onSave,
}: Extract<RuleEditorProps, { kind: "override" }>) {
  const [row, setRow] = useState<GuardOverrideRow>(() =>
    withIntegrityEnforce(initial ?? { rule: "", decision: "", enforce: true }),
  );
  const info = guardRuleInfo(row.rule);
  const integrity = isGuardIntegrityRuleId(row.rule);
  const decisionOpts = guardDecisionOptionsFor(row.rule, allowWeaken);
  const view = overrideEditorView(mode, initial?.rule ?? row.rule);

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title={view.title}
      subtitle="Tunes an existing rule's decision/enforce. No matcher - overrides can't redefine what a rule matches, only how it decides."
      width={520}
    >
      <div className="space-y-4 p-5">
        <SettingRow label="Rule" layout="stack">
          <SinglePicker
            options={keepSelected(GUARD_RULE_OPTIONS, row.rule ? [row.rule] : [], "Custom rule")}
            value={row.rule}
            onChange={(rule) => {
              const opts = guardDecisionOptionsFor(rule, allowWeaken);
              setRow((r) =>
                withIntegrityEnforce({ ...r, rule, decision: r.decision && opts.includes(r.decision) ? r.decision : "" }),
              );
            }}
            allowFree
            freeLabel="Custom rule id"
            placeholder="Pick a rule…"
            ariaLabel="Rule"
            disabled={view.ruleLocked}
          />
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
              ? "This layer may loosen or disable - pick any decision, including below the built-in floor."
              : "Escalate-only: only decisions at or above the built-in's floor are offered."
          }
        >
          <SegmentedControl<Decision | "">
            options={[{ value: "", label: "no change" }, ...decisionOpts.map((d) => ({ value: d, label: d }))]}
            value={row.decision}
            onChange={(decision) => setRow((r) => ({ ...r, decision }))}
          />
        </SettingRow>

        <SettingRow
          label="Enforce"
          layout="stack"
          help={
            integrity
              ? "Locked on: this is a guard integrity rule, and the guard refuses to turn its enforcement off in any layer."
              : "Block/hold even while the global mode stays observe."
          }
        >
          <Toggle
            on={row.enforce || integrity}
            onChange={(enforce) => setRow((r) => withIntegrityEnforce({ ...r, enforce }))}
            disabled={integrity}
            label={row.enforce || integrity ? "on" : "off"}
          />
        </SettingRow>
      </div>
      <div className="flex items-center gap-2 border-t border-line-1 px-5 py-3">
        <Button
          variant="primary"
          iconLeft={view.isNew ? Plus : undefined}
          disabled={!row.rule.trim()}
          onClick={() => onSave(withIntegrityEnforce(row))}
        >
          {view.saveLabel}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </SlideOver>
  );
}

// CustomRuleEditor is the shared form (shared/components/guard/
// CustomRuleEditor.tsx), promoted out of this file so the org guard form
// authors rules with the same one; the node injects only what is its own: the
// MCP servers it has seen, for the mcp_server suggestions.
function CustomRuleEditor(props: Extract<RuleEditorProps, { kind: "rule" }>) {
  return (
    <SharedCustomRuleEditor
      open={props.open}
      onClose={props.onClose}
      initial={props.initial}
      onSave={props.onSave}
      vocab={LOCAL_CUSTOM_RULE_VOCAB}
      useMcpServerOptions={useMCPServerOptions}
    />
  );
}

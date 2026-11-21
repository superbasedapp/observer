import { Plus } from "lucide-react";
import { useState, type Dispatch, type ReactNode, type SetStateAction } from "react";
import { Button } from "../../primitives/Button";
import { EntityMultiPicker, type EntityMultiPickerOption } from "../../primitives/EntityMultiPicker";
import { HelpTooltip } from "../../primitives/HelpTooltip";
import { Input } from "../../primitives/Input";
import { SegmentedControl } from "../../primitives/SegmentedControl";
import { Select } from "../../primitives/Select";
import { SettingRow } from "../../primitives/SettingRow";
import { SinglePicker } from "../../primitives/SinglePicker";
import { SlideOver } from "../../primitives/SlideOver";
import { Toggle } from "../../primitives/Toggle";
import {
  type Decision,
  type GuardFileAccess,
  type GuardRuleRow,
  DECISIONS,
  GUARD_CATEGORIES,
  GUARD_EVENT_KINDS,
  GUARD_FILE_ACCESS,
  GUARD_RULE_TEXT_MAX,
  GUARD_SINKS,
  GUARD_TAINT_SOURCES,
  SEVERITIES,
  emptyGuardCommandMatch,
  emptyGuardEventMatch,
  emptyGuardRuleRow,
  guardRuleRowProblems,
} from "../../lib/guardCatalog";
import {
  type GuardMatchKind,
  type GuardMatcherField,
  GUARD_MATCHER_FIELD_COPY,
  GUARD_MATCH_KIND_GUIDE,
  guardMatchKindGuide,
  inferMatchKind,
} from "../../lib/guardMatcherGuide";

// CustomRuleEditor — the SlideOver form for authoring ONE guard `[[rule]]`
// (a custom rule, matcher-v1; docs/guard-policy-authoring.md). PROMOTED from
// web/src/pages/security/RuleEditor.tsx (moved, not copied: that file now
// renders this component) so the node rule manager (Security > Rules) and the
// org guard form (Policies > Guard) author rules with one form.
//
// Pure: a controlled, save-on-submit form that never talks to the network.
// What differs between the two dashboards is injected, never branched on:
//   - `vocab` carries the wording that depends on the layer (the id example,
//     the id help) and its advisory id check (the org form's ORG- convention
//     and duplicate check); the rule grammar itself is the same in every
//     layer (internal/guard/policyfile.go compileRule).
//   - `useMcpServerOptions` is a hook the caller passes for the mcp_server
//     picker's suggestions (the node lists the servers it has seen; the org
//     passes none and the field stays free text). It must be the same
//     function on every render.
//   - `serverProblems` are the last lint's problems for this rule, shown
//     beside the client-side hints (the server lint is the gate).
//   - `startKind` opens a NEW rule on one kind of target (the org form's
//     empty state offers "A command", "A file path", ...).
//
// Guidance (2026-11-12): the matchers are led by a "What should this rule
// stop?" choice (command, file path, domain, MCP tool, other), which sets the
// matcher scope and puts that kind's fields first, under a short note on what
// to enter with a worked example. Every field carries a plain label, the
// match syntax and an example; the bundle key sits behind the field's
// technical-details tooltip. The wording is the table in
// shared/lib/guardMatcherGuide.ts, grounded in the rule compiler. The kind is
// a UI notion only: the row's data model (scope + matchers) is unchanged.

/** Picker suggestions for the mcp_server field. */
export type McpServerOptions = { options: EntityMultiPickerOption[]; loading: boolean };

/** The layer-dependent wording and advisory checks. */
export type CustomRuleEditorVocab = {
  /** Example id shown in the empty id field. */
  idPlaceholder: string;
  /** Help under the id field. */
  idHelp: string;
  /** Advisory id problems beyond the shared row checks (never a gate). */
  idProblems?: (id: string) => string[];
};

/** The node rule manager's wording (user and trusted-project layers). */
export const LOCAL_CUSTOM_RULE_VOCAB: CustomRuleEditorVocab = {
  idPlaceholder: "U-100",
  idHelp: "Must not collide with a built-in id.",
};

export type CustomRuleEditorProps = {
  open: boolean;
  onClose: () => void;
  /** The rule being edited; absent for a new rule. */
  initial?: GuardRuleRow;
  /** The starting row of a NEW rule (e.g. with a suggested id). */
  seed?: GuardRuleRow;
  /** The kind of target a NEW rule starts on; inferred from the row when absent. */
  startKind?: GuardMatchKind;
  onSave: (row: GuardRuleRow) => void;
  vocab?: CustomRuleEditorVocab;
  useMcpServerOptions?: (enabled: boolean) => McpServerOptions;
  serverProblems?: readonly string[];
};

const EVENT_KIND_OPTIONS: EntityMultiPickerOption[] = GUARD_EVENT_KINDS.map((k) => ({ id: k, label: k }));

const NO_MCP_SERVERS: McpServerOptions = { options: [], loading: false };
function useNoMcpServerOptions(): McpServerOptions {
  return NO_MCP_SERVERS;
}

// withSelected keeps the current value pickable when the suggestion list
// does not carry it (a value from an older bundle, or one typed by hand).
function withSelected(options: EntityMultiPickerOption[], value: string): EntityMultiPickerOption[] {
  if (!value || options.some((o) => o.id === value)) return options;
  return [...options, { id: value, label: value }];
}

// withScope moves a row to a matcher scope, clearing the other scope's
// matchers (a rule may use only one scope; compileRule rejects a mix). A row
// already in that scope is returned unchanged.
function withScope(r: GuardRuleRow, scope: GuardRuleRow["scope"]): GuardRuleRow {
  if (r.scope === scope) return r;
  return {
    ...r,
    scope,
    command: scope === "command" ? r.command : emptyGuardCommandMatch(),
    event: scope === "event" ? r.event : emptyGuardEventMatch(),
  };
}

// startingRow is the row the editor opens on: the rule being edited, else the
// seed of a new rule moved to the start kind's scope.
function startingRow(initial: GuardRuleRow | undefined, seed: GuardRuleRow | undefined, startKind: GuardMatchKind | undefined): GuardRuleRow {
  if (initial) return initial;
  const row = seed ?? emptyGuardRuleRow();
  return startKind ? withScope(row, guardMatchKindGuide(startKind).scope) : row;
}

export function CustomRuleEditor({
  open,
  onClose,
  initial,
  seed,
  startKind,
  onSave,
  vocab = LOCAL_CUSTOM_RULE_VOCAB,
  useMcpServerOptions = useNoMcpServerOptions,
  serverProblems = [],
}: CustomRuleEditorProps) {
  const [row, setRow] = useState<GuardRuleRow>(() => startingRow(initial, seed, startKind));
  const [kind, setKind] = useState<GuardMatchKind>(() => (initial ? undefined : startKind) ?? inferMatchKind(startingRow(initial, seed, startKind)));
  const problems = [...guardRuleRowProblems(row), ...(vocab.idProblems?.(row.id) ?? [])];
  const mcpServers = useMcpServerOptions(open && row.scope === "event");

  return (
    <SlideOver
      open={open}
      onClose={onClose}
      title={initial ? `Edit rule - ${initial.id}` : "New custom rule"}
      subtitle="Name the rule, pick what it decides, then say what it should stop."
      width={640}
    >
      <div className="space-y-4 p-5">
        <div className="grid grid-cols-2 gap-3">
          <SettingRow label="Id" layout="stack" help={vocab.idHelp}>
            <Input
              value={row.id}
              onChange={(e) => setRow((r) => ({ ...r, id: e.target.value }))}
              placeholder={vocab.idPlaceholder}
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

        <SettingRow label="Doc" layout="stack" help="Optional one line the agent reads when the rule fires. Empty keeps the guard's own wording.">
          <Input
            value={row.doc}
            onChange={(e) => setRow((r) => ({ ...r, doc: e.target.value }))}
            maxLength={GUARD_RULE_TEXT_MAX}
            placeholder="What this rule catches"
          />
        </SettingRow>
        <SettingRow label="Advice" layout="stack" help="Optional one sentence on what to do instead.">
          <Input
            value={row.advice}
            onChange={(e) => setRow((r) => ({ ...r, advice: e.target.value }))}
            maxLength={GUARD_RULE_TEXT_MAX}
            placeholder="What to do instead"
          />
        </SettingRow>

        <MatcherSection row={row} setRow={setRow} kind={kind} setKind={setKind} mcpServers={mcpServers} />

        {problems.length > 0 && (
          <div className="space-y-1 rounded-2 border border-warn/30 bg-warn-soft px-3 py-2 text-[11px] text-warn">
            {problems.map((p, i) => (
              <div key={i}>{p}</div>
            ))}
          </div>
        )}
        {serverProblems.length > 0 && (
          <div className="space-y-1 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11px] text-danger">
            <div className="font-medium">The last check found:</div>
            {serverProblems.map((p, i) => (
              <div key={i} className="font-mono">
                {p}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="flex items-center gap-2 border-t border-line-1 px-5 py-3">
        <Button
          variant="primary"
          iconLeft={initial ? undefined : Plus}
          disabled={!row.id.trim()}
          onClick={() => onSave(row)}
        >
          {initial ? "Save rule" : "Add rule"}
        </Button>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </SlideOver>
  );
}

// PRIMARY_FIELDS is which matcher fields lead the form for each kind of
// target; every other field of the scope follows under "More conditions".
// "applies_to" is the rule's own key, listed here so the "Other" kind (pure
// conditions, which imply no action kind) puts it first.
type FieldId = GuardMatcherField | "applies_to";
const PRIMARY_FIELDS: Record<GuardMatchKind, readonly FieldId[]> = {
  command: ["command_base", "command_regex", "arg_contains"],
  path: ["path_glob", "path_not", "path_outside_project", "path_sensitive", "access"],
  domain: ["url_domain"],
  mcp: ["mcp_server", "mcp_tool"],
  other: ["applies_to", "session_cost_usd_gt", "repeat_count_gt", "taint_source", "sink", "event_kind"],
};

const EVENT_FIELDS: readonly FieldId[] = [
  "path_glob",
  "path_not",
  "path_outside_project",
  "path_sensitive",
  "access",
  "url_domain",
  "mcp_server",
  "mcp_tool",
  "sink",
  "taint_source",
  "event_kind",
  "session_cost_usd_gt",
  "repeat_count_gt",
  "applies_to",
];
const COMMAND_FIELDS: readonly FieldId[] = ["command_base", "command_regex", "arg_contains", "applies_to"];

// FieldLabel is a matcher field's plain label, with its bundle key behind a
// technical-details tooltip (what "Edit as TOML" and the docs call it).
function FieldLabel({ field }: { field: GuardMatcherField }) {
  const c = GUARD_MATCHER_FIELD_COPY[field];
  return (
    <span className="inline-flex items-center gap-1">
      {c.label}
      <HelpTooltip technical content={c.key} subject={c.label} />
    </span>
  );
}

function MatcherSection({
  row,
  setRow,
  kind,
  setKind,
  mcpServers,
}: {
  row: GuardRuleRow;
  setRow: Dispatch<SetStateAction<GuardRuleRow>>;
  kind: GuardMatchKind;
  setKind: (k: GuardMatchKind) => void;
  mcpServers: McpServerOptions;
}) {
  const guide = guardMatchKindGuide(kind);
  const primary = PRIMARY_FIELDS[kind];
  const scopeFields = row.scope === "command" ? COMMAND_FIELDS : EVENT_FIELDS;
  const rest = scopeFields.filter((f) => !primary.includes(f));
  const ev = (patch: Partial<GuardRuleRow["event"]>) => setRow((r) => ({ ...r, event: { ...r.event, ...patch } }));
  const cmd = (patch: Partial<GuardRuleRow["command"]>) => setRow((r) => ({ ...r, command: { ...r.command, ...patch } }));
  const copy = GUARD_MATCHER_FIELD_COPY;

  const FIELDS: Record<FieldId, () => ReactNode> = {
    command_base: () => (
      <SettingRow label={<FieldLabel field="command_base" />} layout="stack" help={copy.command_base.help}>
        <Input value={row.command.command_base} onChange={(e) => cmd({ command_base: e.target.value })} mono placeholder={copy.command_base.placeholder} />
      </SettingRow>
    ),
    command_regex: () => (
      <SettingRow label={<FieldLabel field="command_regex" />} layout="stack" help={copy.command_regex.help}>
        <Input value={row.command.command_regex} onChange={(e) => cmd({ command_regex: e.target.value })} mono placeholder={copy.command_regex.placeholder} />
      </SettingRow>
    ),
    arg_contains: () => (
      <SettingRow label={<FieldLabel field="arg_contains" />} layout="stack" help={copy.arg_contains.help}>
        <Input value={row.command.arg_contains} onChange={(e) => cmd({ arg_contains: e.target.value })} mono placeholder={copy.arg_contains.placeholder} />
      </SettingRow>
    ),
    path_glob: () => (
      <SettingRow label={<FieldLabel field="path_glob" />} layout="stack" help={copy.path_glob.help}>
        <EntityMultiPicker
          options={[]}
          allowFreeId
          value={row.event.path_glob}
          onChange={(path_glob) => ev({ path_glob })}
          placeholder={copy.path_glob.placeholder}
        />
      </SettingRow>
    ),
    path_not: () => (
      <SettingRow label={<FieldLabel field="path_not" />} layout="stack" help={copy.path_not.help}>
        <EntityMultiPicker
          options={[]}
          allowFreeId
          value={row.event.path_not}
          onChange={(path_not) => ev({ path_not })}
          placeholder={copy.path_not.placeholder}
        />
      </SettingRow>
    ),
    path_outside_project: () => (
      <Toggle
        on={row.event.path_outside_project}
        onChange={(path_outside_project) => ev({ path_outside_project })}
        label={copy.path_outside_project.label}
      />
    ),
    path_sensitive: () => (
      <Toggle on={row.event.path_sensitive} onChange={(path_sensitive) => ev({ path_sensitive })} label={copy.path_sensitive.label} />
    ),
    access: () => (
      <SettingRow label={<FieldLabel field="access" />} layout="stack" help={copy.access.help}>
        <Select
          value={row.event.access}
          onChange={(e) => ev({ access: e.target.value as GuardFileAccess | "" })}
          options={[{ value: "", label: "either" }, ...GUARD_FILE_ACCESS]}
        />
      </SettingRow>
    ),
    url_domain: () => (
      <SettingRow label={<FieldLabel field="url_domain" />} layout="stack" help={copy.url_domain.help}>
        <Input value={row.event.url_domain} onChange={(e) => ev({ url_domain: e.target.value })} mono placeholder={copy.url_domain.placeholder} />
      </SettingRow>
    ),
    mcp_server: () => (
      <SettingRow label={<FieldLabel field="mcp_server" />} layout="stack" help={copy.mcp_server.help}>
        <SinglePicker
          options={withSelected(mcpServers.options, row.event.mcp_server)}
          value={row.event.mcp_server}
          onChange={(mcp_server) => ev({ mcp_server })}
          allowFree
          loading={mcpServers.loading}
          placeholder={`Type a server name, e.g. ${copy.mcp_server.placeholder}`}
          ariaLabel={copy.mcp_server.label}
        />
      </SettingRow>
    ),
    mcp_tool: () => (
      <SettingRow label={<FieldLabel field="mcp_tool" />} layout="stack" help={copy.mcp_tool.help}>
        <Input value={row.event.mcp_tool} onChange={(e) => ev({ mcp_tool: e.target.value })} mono placeholder={copy.mcp_tool.placeholder} />
      </SettingRow>
    ),
    sink: () => (
      <SettingRow label={<FieldLabel field="sink" />} layout="stack" help={copy.sink.help}>
        <Select value={row.event.sink} onChange={(e) => ev({ sink: e.target.value })} options={["", ...GUARD_SINKS]} />
      </SettingRow>
    ),
    taint_source: () => (
      <SettingRow label={<FieldLabel field="taint_source" />} layout="stack" help={copy.taint_source.help}>
        <Select value={row.event.taint_source} onChange={(e) => ev({ taint_source: e.target.value })} options={["", ...GUARD_TAINT_SOURCES]} />
      </SettingRow>
    ),
    event_kind: () => (
      <SettingRow label={<FieldLabel field="event_kind" />} layout="stack" help={copy.event_kind.help}>
        <EntityMultiPicker
          options={EVENT_KIND_OPTIONS}
          value={row.event.event_kind}
          onChange={(event_kind) => ev({ event_kind })}
          placeholder="Pick action kinds…"
        />
      </SettingRow>
    ),
    session_cost_usd_gt: () => (
      <SettingRow label={<FieldLabel field="session_cost_usd_gt" />} layout="stack" help={copy.session_cost_usd_gt.help}>
        <Input
          value={row.event.session_cost_usd_gt}
          onChange={(e) => ev({ session_cost_usd_gt: e.target.value })}
          inputMode="decimal"
          placeholder={copy.session_cost_usd_gt.placeholder}
        />
      </SettingRow>
    ),
    repeat_count_gt: () => (
      <SettingRow label={<FieldLabel field="repeat_count_gt" />} layout="stack" help={copy.repeat_count_gt.help}>
        <Input
          value={row.event.repeat_count_gt}
          onChange={(e) => ev({ repeat_count_gt: e.target.value })}
          inputMode="numeric"
          placeholder={copy.repeat_count_gt.placeholder}
        />
      </SettingRow>
    ),
    applies_to: () => (
      <SettingRow
        label="Applies to these actions"
        layout="stack"
        help={
          kind === "other"
            ? "Required here: these conditions do not name an action on their own."
            : "Leave empty: the fields above already say which actions the rule checks."
        }
      >
        <EntityMultiPicker
          options={EVENT_KIND_OPTIONS}
          value={row.applies_to}
          onChange={(applies_to) => setRow((r) => ({ ...r, applies_to }))}
          placeholder="Pick action kinds…"
        />
      </SettingRow>
    ),
  };

  return (
    <div className="space-y-3">
      <SettingRow
        label="What should this rule stop?"
        layout="stack"
        help="A command rule can't also match a file, a domain or an MCP tool: add a second rule for that."
      >
        <SegmentedControl<GuardMatchKind>
          size="sm"
          options={GUARD_MATCH_KIND_GUIDE.map((g) => ({ value: g.kind, label: g.label }))}
          value={kind}
          onChange={(k) => {
            setKind(k);
            setRow((r) => withScope(r, guardMatchKindGuide(k).scope));
          }}
        />
      </SettingRow>

      <div className="space-y-3 rounded-2 border border-line-1 bg-bg-1 p-3" data-match-kind={kind}>
        <div className="rounded-2 border border-accent/30 bg-accent-soft px-3 py-2 text-[11.5px] leading-snug text-fg-2">
          <p>{guide.help}</p>
          <ul className="mt-1.5 space-y-0.5">
            {guide.examples.map((x) => (
              <li key={x.field + x.value}>
                <span className="text-fg-3">Example, {x.field}: </span>
                <code className="rounded bg-bg-2 px-1 font-mono text-fg-1">{x.value}</code>
                <span className="text-fg-3"> ({x.note})</span>
              </li>
            ))}
          </ul>
        </div>
        {primary.filter((f) => scopeFields.includes(f)).map((f) => (
          <div key={f}>{FIELDS[f]()}</div>
        ))}
      </div>

      {rest.length > 0 && (
        <div className="space-y-3 rounded-2 border border-line-1 p-3">
          <div className="text-[11px] text-fg-3">More conditions, optional. Every field you fill in has to match.</div>
          {rest.map((f) => (
            <div key={f}>{FIELDS[f]()}</div>
          ))}
        </div>
      )}
    </div>
  );
}

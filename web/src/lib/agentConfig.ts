// agentConfig.ts - the AI tool settings page's wire types, API calls and
// pure helpers (backlog items 2 and 7, phases P4 and P5; plan of record
// docs/plans/adapter-config-and-common-vocabulary-plan-2026-10-03.md).
//
// The server (internal/intelligence/dashboard/agentconfig.go over
// internal/agentconfigsvc) owns every decision: what a file holds, which
// layer decides a value, what the sanity check finds and whether a save may
// land. This module only carries the shapes and formats them. The pure
// helpers at the bottom are pinned by agentConfig.test.ts (plain
// `node --test`, so no React and no "@/" imports above the API section).

// ---------- wire vocabulary ----------

export type Scope = "managed" | "system" | "user" | "project_shared" | "project_local";
export type Format =
  | "json"
  | "jsonc"
  | "toml"
  | "yaml"
  | "markdown"
  | "mdc"
  | "crushrc"
  | "vscode_settings"
  | "script";
export type FileState = "present" | "missing" | "never_read" | "unresolved" | "unreadable";
export type ValueLayer =
  | "vendor_default"
  | "l1_all_adapters"
  | "l2_adapter"
  | "l3_project"
  | "system"
  | "vendor_managed"
  // The org AI tool policy's layers (adapter config P6): a value the
  // organization wrote on a managed machine.
  | "o1_org"
  | "o2_team"
  | "o3_member";
export type Severity = "error" | "refuse" | "confirm" | "warning";
export type ValueType =
  | "string"
  | "enum"
  | "int"
  | "float"
  | "bool"
  | "string_list"
  | "string_map"
  | "object"
  | "rule_list"
  | "mcp_map";
export type DangerClass = "" | "confirm" | "refuse_while_integrated";
export type CoverageStatus = "generated" | "authored" | "pending" | "no_surface";

export type Access = {
  read_only: boolean;
  reason?: string;
  /** Setting id to the org policy that enforces it ("set by your organization"). */
  locked?: Record<string, string>;
  secrets_posture: "warn" | "refuse" | "allow";
  /** A managed machine whose organization granted editing of some settings only. */
  grants_only?: boolean;
  grants?: string[];
  /** The org policy whose instruction blocks this machine holds: the text
   *  between the observer:org markers is locked (D-107, T-426). */
  org_block_locked?: string;
};

/** OrgState is what a managed machine did with one org directive on one file. */
export type OrgState =
  | "applied"
  | "reasserted"
  | "drifted"
  | "backed_off"
  | "refused_by_hygiene"
  | "not_installed"
  | "no_file"
  | "developer_value"
  | "unknown_setting";

export const ORG_STATE_LABEL: Record<OrgState, string> = {
  applied: "Applied",
  reasserted: "Put back",
  drifted: "Changed here",
  backed_off: "Changed here, no longer put back",
  refused_by_hygiene: "Refused by the sanity check",
  not_installed: "Tool not installed",
  no_file: "No file to write",
  developer_value: "Your value kept",
  unknown_setting: "Unknown to this version",
};

export const ORG_STATE_TONE: Record<OrgState, "success" | "info" | "neutral" | "warn" | "danger"> = {
  applied: "success",
  reasserted: "info",
  drifted: "warn",
  backed_off: "danger",
  refused_by_hygiene: "danger",
  not_installed: "neutral",
  no_file: "neutral",
  developer_value: "info",
  unknown_setting: "neutral",
};

export type OrgStateRow = {
  setting: string;
  tool: string;
  file_id: string;
  /** project_shared: the file commits with the repository (T-431). */
  scope?: string;
  project_root?: string;
  mode: "enforced" | "default";
  layer: string;
  policy: string;
  state: OrgState;
  reason?: string;
  observed_value?: string;
  observed_secret?: boolean;
  personal?: boolean;
  drift: boolean;
  drift_count: number;
  last_applied_at?: string;
  last_drift_at?: string;
  observed_at?: string;
};

/** OrgManagementStatus is the Organization tab's state (agentconfig_org.go's orgManagementTable). */
export type OrgManagementStatus = "not_enrolled" | "unmanaged" | "managed_inactive" | "managed";

/** OrgPolicyView is GET /api/agent-config/org. */
export type OrgPolicyView = {
  managed: boolean;
  /** Absent from an older daemon: orgStatusOf derives it from `managed`. */
  status?: OrgManagementStatus;
  enrolled?: boolean;
  org_name?: string;
  tenancy?: string;
  /** The governance verdict (govern.State) when managed but not in force. */
  grant_state?: string;
  has_policy: boolean;
  version?: number;
  received_at?: string;
  on_drift?: string;
  developer_access?: string;
  secrets_posture?: string;
  grants: string[];
  policies: string[];
  directives: { setting: string; mode: string; layer: string; policy: string; project?: string; placement?: string }[];
  /** Org instruction blocks (D-107, T-426). Absent from an older daemon. */
  instructions?: { project?: string; placement?: string; text: string; policy: string; layer: string }[];
  rows: OrgStateRow[];
  drifted: number;
};

export type ToolCoverage = {
  tool: string;
  status: CoverageStatus;
  rows: number;
  verified: number;
  writable: number;
  secret: number;
  dangerous: number;
  deprecated: number;
  verified_against?: string;
  note?: string;
};

export type CommonSpec = {
  key: string;
  tier: "core" | "secondary" | "observer_owned";
  type: ValueType;
  enum?: string[];
  danger?: string[];
  unit?: string;
  order?: string;
  desc: string;
};

export type SchemaPin = {
  tool: string;
  shape: string;
  file: string;
  url: string;
  sha256: string;
  fetched_on: string;
};

export type CoverageResponse = {
  coverage: ToolCoverage[];
  common_keys: CommonSpec[];
  schemas: SchemaPin[];
};

export type ToolSummary = {
  tool: string;
  status: CoverageStatus;
  rows: number;
  verified: number;
  writable: number;
  dangerous: number;
  verified_against?: string;
  note?: string;
  installed: boolean;
  files_present: number;
  files: number;
  common: number;
};

export type ToolsResponse = {
  tools: ToolSummary[];
  access: Access;
  confirm_token: string;
};

export type SpanState = {
  path: string;
  owner: string;
  match: string;
  entry?: string;
  verb: string;
  live: boolean;
  enforced: boolean;
  note?: string;
};

export type FileView = {
  id: string;
  shape: string;
  kind: string;
  scope: Scope;
  format: Format;
  path?: string;
  path_status: string;
  state: FileState;
  reason?: string;
  precedence: number;
  write_needs: "user" | "admin_root" | "never";
  gitignored?: boolean;
  note?: string;
  editable: boolean;
  not_editable?: string;
  parse_error?: string;
  etag: string;
  tracked?: boolean;
  spans?: SpanState[];
  uncatalogued?: string[];
  secrets?: string[];
  size: number;
};

export type SettingValue = {
  file_id: string;
  scope: Scope;
  layer: ValueLayer;
  value?: unknown;
  secret_present?: boolean;
  masked?: boolean;
};

export type Effective = {
  set: boolean;
  value?: unknown;
  secret_present?: boolean;
  masked?: boolean;
  layer?: ValueLayer;
  file_id?: string;
  shadowed?: string[];
};

export type SettingView = {
  id: string;
  path: string;
  shape: string;
  type: ValueType;
  enum?: string[];
  min?: number;
  max?: number;
  default?: string;
  desc?: string;
  source?: string;
  verified: string;
  owner: string;
  writable: boolean;
  danger?: DangerClass;
  secret?: boolean;
  deprecated?: boolean;
  scopes?: Scope[];
  note?: string;
  common?: string[];
  values?: SettingValue[];
  effective: Effective;
  locked?: string;
  read_only_reason?: string;
};

export type ToolView = {
  tool: string;
  project?: string;
  coverage: ToolCoverage;
  files: FileView[];
  settings: SettingView[];
  access: Access;
};

export type RawView = {
  file_id: string;
  path: string;
  format: Format;
  state: string;
  text: string;
  etag: string;
  masked?: string[];
  editable: boolean;
  not_editable?: string;
  raw_save_blocked?: boolean;
  spans?: SpanState[];
};

export type Edit = { path: string[]; op: "set" | "delete"; value?: unknown };

export type Finding = {
  step: number;
  code: string;
  severity: Severity;
  path?: string;
  setting_id?: string;
  message: string;
  line?: number;
  column?: number;
};

export type Change = {
  path: string;
  setting_id?: string;
  op: "add" | "set" | "delete";
  before?: unknown;
  after?: unknown;
  secret?: boolean;
  danger?: DangerClass;
  uncatalogued?: boolean;
  shadowed_by?: string;
  common?: string[];
};

export type Disclosure = { op: string; path: string[]; reason: string };

export type Preview = {
  ok: boolean;
  needs_confirm: boolean;
  no_change: boolean;
  created: boolean;
  findings: Finding[] | null;
  changes: Change[] | null;
  diff: string;
  diff_stats: { added: number; removed: number };
  disclosures?: Disclosure[];
  before_etag: string;
  after_etag: string;
  preview_etag: string;
  add_exclude?: boolean;
  file_id: string;
  path: string;
  layer: string;
};

export type SaveTarget = {
  tool: string;
  file_id: string;
  project?: string;
  path?: string;
};

export type SaveRequest = SaveTarget & {
  edits?: Edit[];
  raw?: string;
  preview_etag?: string;
  confirm?: boolean;
};

export type SaveOutcome = {
  saved: boolean;
  no_change?: boolean;
  file_id: string;
  path: string;
  backup_path?: string;
  created?: boolean;
  etag: string;
  changes: Change[] | null;
  findings: Finding[] | null;
  excluded?: string;
};

export type CommonToolValue = {
  tool: string;
  settings: string[];
  transform: string;
  lossy?: boolean;
  note?: string;
  set: boolean;
  value?: unknown;
  masked?: boolean;
  error?: string;
  layer?: ValueLayer;
  writable: boolean;
};

export type CommonKeyView = {
  spec: CommonSpec;
  exposed: number;
  lossy: number;
  set_in: number;
  tools: CommonToolValue[];
  not_exposed?: string[];
};

export type CommonResponse = { keys: CommonKeyView[]; access: Access };

export type CommonTarget = {
  tool: string;
  status: "write" | "not_installed" | "refused" | "not_writable" | "no_user_file" | "no_project_file";
  reason?: string;
  file_id?: string;
  edits?: Edit[];
  lossy?: boolean;
  path?: string;
  preview?: Preview;
};

export type CommonPreview = {
  key: string;
  ok: boolean;
  needs_confirm: boolean;
  danger?: boolean;
  writes: number;
  targets: CommonTarget[];
  preview_etag: string;
};

export type CommonPlacement = "local_only" | "shared";

export type CommonRequest = {
  key: string;
  value?: unknown;
  clear?: boolean;
  /** A project root: the value goes into each tool's project file there
   *  (the project rank, T-429); absent = each tool's user file. */
  project?: string;
  placement?: CommonPlacement;
  preview_etag?: string;
  confirm?: boolean;
};

/** commonScope is where a common write lands: the request fields to send
 *  and the words the form uses for it (T-429, D-106: all adapters, then per
 *  adapter, then project). */
export function commonScope(
  project: string,
  placement: CommonPlacement,
): { fields: Pick<CommonRequest, "project" | "placement">; where: string; tracked: boolean } {
  if (!project) {
    return { fields: {}, where: "each installed tool's own user settings file", tracked: false };
  }
  if (placement === "shared") {
    return {
      fields: { project, placement },
      where: "each installed tool's shared project file in this project (it can be committed with the repo)",
      tracked: true,
    };
  }
  return {
    fields: { project, placement },
    where: "each installed tool's personal project file in this project (kept out of git)",
    tracked: false,
  };
}

export type InstructionFile = {
  file_id: string;
  tool: string;
  kind: string;
  scope: Scope;
  glob: string;
  path: string;
  exists: boolean;
  name?: string;
  description?: string;
  size?: number;
  new_name?: boolean;
  parse_error?: string;
  tracked?: boolean;
};

export type HistoryRow = {
  id: number;
  at: string;
  tool: string;
  file_id: string;
  path: string;
  layer: string;
  common_key?: string;
  origin: string;
  mode: string;
  changed_keys: string[] | null;
  backup_path?: string;
  created?: boolean;
  warnings: number;
};

/** The error body a refused or stale save returns (it carries the preview). */
export type AgentConfigErrorBody = {
  error: string;
  message: string;
  preview?: Preview | CommonPreview;
};

// ---------- pure helpers ----------

/** LAYER_LABEL names each value layer the way the page shows it. */
export const LAYER_LABEL: Record<ValueLayer, string> = {
  vendor_default: "Tool default",
  l1_all_adapters: "All AI tools (Observer)",
  l2_adapter: "This tool",
  l3_project: "This project",
  system: "System file",
  vendor_managed: "Vendor managed",
  o1_org: "Your organization",
  o2_team: "Your organization (team)",
  o3_member: "Your organization (for you)",
};

/** layerLabel words a layer; a layer this build does not know passes through. */
export function layerLabel(layer: string): string {
  return (LAYER_LABEL as Record<string, string>)[layer] ?? layer.replace(/_/g, " ");
}

/** SCOPE_LABEL names each file scope. */
export const SCOPE_LABEL: Record<Scope, string> = {
  managed: "Managed",
  system: "System",
  user: "User",
  project_shared: "Project (shared)",
  project_local: "Project (local)",
};

/** STATE_LABEL names each file state. */
export const STATE_LABEL: Record<FileState, string> = {
  present: "Present",
  missing: "Not created",
  never_read: "Never read",
  unresolved: "No path",
  unreadable: "Unreadable",
};

/** SEVERITY_ORDER sorts findings: blocking first. */
const SEVERITY_ORDER: Record<Severity, number> = { error: 0, refuse: 1, confirm: 2, warning: 3 };

/** sortFindings orders findings by severity, then step, keeping input order. */
export function sortFindings(fs: readonly Finding[] | null | undefined): Finding[] {
  return [...(fs ?? [])]
    .map((f, i) => ({ f, i }))
    .sort((a, b) => SEVERITY_ORDER[a.f.severity] - SEVERITY_ORDER[b.f.severity] || a.f.step - b.f.step || a.i - b.i)
    .map((x) => x.f);
}

/** blocking reports findings that stop a save outright (not even a confirm lands it). */
export function blocking(fs: readonly Finding[] | null | undefined): Finding[] {
  return (fs ?? []).filter((f) => f.severity === "error" || f.severity === "refuse");
}

/** severityTone maps a finding severity onto a Pill variant. */
export function severityTone(s: Severity): "danger" | "warn" | "neutral" {
  if (s === "error" || s === "refuse") return "danger";
  if (s === "confirm") return "warn";
  return "neutral";
}

/** SEVERITY_LABEL is the word shown beside each finding. */
export const SEVERITY_LABEL: Record<Severity, string> = {
  error: "Error",
  refuse: "Refused",
  confirm: "Needs confirm",
  warning: "Warning",
};

/**
 * editorLanguage picks the CodeEditor grammar for a vendor file format. The
 * crushrc and VS Code settings shapes are JSON with comments; a script file
 * is shown as plain text.
 */
export function editorLanguage(f: Format): "json" | "jsonc" | "toml" | "yaml" | "markdown" | "text" {
  switch (f) {
    case "json":
      return "json";
    case "jsonc":
    case "crushrc":
    case "vscode_settings":
      return "jsonc";
    case "toml":
      return "toml";
    case "yaml":
      return "yaml";
    case "markdown":
    case "mdc":
      return "markdown";
  }
  return "text";
}

/**
 * formatValue renders a setting value for a table cell. A masked or secret
 * value never reaches here as text (the server sends secret_present only).
 */
export function formatValue(v: unknown): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}

/** effectiveText is the one-line effective value of a setting. */
export function effectiveText(e: Effective): string {
  if (!e.set) return "Not set";
  if (e.secret_present) return "Set (hidden)";
  return formatValue(e.value);
}

/** The parsed form input for one setting: a value, or why it is not one. */
export type ParsedInput = { ok: true; value: unknown } | { ok: false; error: string };

/**
 * parseInput turns the text a developer typed into a typed value for a
 * setting of type t. It only shapes the input; the server's sanity check is
 * the authority on whether the value is allowed (enum, bounds, danger).
 */
export function parseInput(t: ValueType, text: string): ParsedInput {
  const s = text.trim();
  switch (t) {
    case "bool":
      if (s === "true") return { ok: true, value: true };
      if (s === "false") return { ok: true, value: false };
      return { ok: false, error: "Choose true or false." };
    case "int": {
      if (!/^-?\d+$/.test(s)) return { ok: false, error: "Enter a whole number." };
      return { ok: true, value: Number(s) };
    }
    case "float": {
      if (s === "" || Number.isNaN(Number(s))) return { ok: false, error: "Enter a number." };
      return { ok: true, value: Number(s) };
    }
    case "string":
    case "enum":
      return { ok: true, value: text };
    case "string_list":
    case "rule_list": {
      if (s.startsWith("[")) return parseJSON(s);
      const items = text
        .split("\n")
        .map((x) => x.trim())
        .filter((x) => x !== "");
      return { ok: true, value: items };
    }
    default:
      return parseJSON(s);
  }
}

function parseJSON(s: string): ParsedInput {
  try {
    return { ok: true, value: JSON.parse(s) };
  } catch {
    return { ok: false, error: "Enter valid JSON." };
  }
}

/** inputText is the editable text form of a current value (parseInput's inverse). */
export function inputText(t: ValueType, v: unknown): string {
  if (v === undefined || v === null) return "";
  if ((t === "string_list" || t === "rule_list") && Array.isArray(v) && v.every((x) => typeof x === "string")) {
    return v.join("\n");
  }
  if (t === "string" || t === "enum" || t === "bool" || t === "int" || t === "float") return formatValue(v);
  return JSON.stringify(v, null, 2);
}

/** keyPath splits a dotted catalogue path into the edit path. */
export function keyPath(dotted: string): string[] {
  return dotted.split(".").filter((p) => p !== "");
}

/**
 * writableFiles lists the files of a tool a setting can be written to: same
 * shape, a scope the setting allows, resolved and editable. Ordered by
 * precedence (lowest first) so the default target is the user file.
 */
export function writableFiles(view: ToolView, s: SettingView): FileView[] {
  return view.files
    .filter(
      (f) =>
        f.shape === s.shape &&
        f.editable &&
        (s.scopes === undefined || s.scopes.length === 0 || s.scopes.includes(f.scope)),
    )
    .sort((a, b) => a.precedence - b.precedence);
}

/** settingFilter is the Tools tab's search + facet filter. */
export type SettingFilter = {
  q: string;
  onlySet: boolean;
  onlyCommon: boolean;
  onlyDanger: boolean;
};

export function filterSettings(rows: readonly SettingView[], f: SettingFilter): SettingView[] {
  const q = f.q.trim().toLowerCase();
  return rows.filter((r) => {
    if (f.onlySet && !r.effective.set) return false;
    if (f.onlyCommon && !(r.common && r.common.length > 0)) return false;
    if (f.onlyDanger && !r.danger) return false;
    if (q === "") return true;
    return r.path.toLowerCase().includes(q) || (r.desc ?? "").toLowerCase().includes(q);
  });
}

/** diagnosticsFor maps findings with a position onto CodeEditor diagnostics. */
export function diagnosticsFor(
  fs: readonly Finding[] | null | undefined,
): { line?: number; column?: number; message: string; severity: "error" | "warning" | "info" }[] {
  return (fs ?? [])
    .filter((f) => (f.line ?? 0) > 0)
    .map((f) => ({
      line: f.line,
      column: f.column,
      message: f.message,
      severity: f.severity === "warning" ? "warning" : f.severity === "confirm" ? "info" : "error",
    }));
}

/**
 * countNoun renders "1 file" / "3 files": a count with the noun in the right
 * number. `many` defaults to the noun plus "s"; pass it for an irregular
 * plural.
 */
export function countNoun(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** errorBody parses a structured agent-config error, or null. */
export function errorBody(raw: string): AgentConfigErrorBody | null {
  try {
    const b = JSON.parse(raw) as AgentConfigErrorBody;
    return b && typeof b.error === "string" ? b : null;
  } catch {
    return null;
  }
}

// ---------- Organization tab ----------

/** orgStatusOf reads the tab's state, falling back for an older daemon that sends only `managed`. */
export function orgStatusOf(v: Pick<OrgPolicyView, "managed" | "status">): OrgManagementStatus {
  return v.status ?? (v.managed ? "managed" : "not_enrolled");
}

/** Why a managed machine's grant is not in force, by govern.State. */
export const GRANT_STATE_REASON: Record<string, string> = {
  no_grant: "it has not received its management grant yet",
  grant_expired: "its management grant has expired",
  identity_changed: "its management grant was issued for a different enrolment",
  key_pin_mismatch: "your organization's signing key no longer matches the one this machine pinned",
  grant_signature_invalid: "its stored management grant no longer verifies",
};

/** OrgNotice is the empty state the Organization tab shows instead of a policy. */
export type OrgNotice = { title: string; body: string; to?: string; toLabel?: string };

const ENROLMENT_LINK = "/settings?section=enrolment";

/**
 * orgNotice says which of the tab's states this machine is in, or null when
 * the organization's policy is in force and the policy itself is shown. An
 * enrolled machine is never told to enrol: an individual (teams) enrolment
 * names its org and says how management would be turned on.
 */
export function orgNotice(v: Pick<OrgPolicyView, "managed" | "status" | "org_name" | "grant_state" | "has_policy">): OrgNotice | null {
  const org = v.org_name?.trim() || "your organization";
  switch (orgStatusOf(v)) {
    case "not_enrolled":
      return {
        title: "Not enrolled with an organization",
        body: "This machine is not enrolled with an organization, so no organization sets its AI tool settings. Everything on this page is yours to edit. To join your organization, enrol this machine in Settings > Enrolment with the server address and the enrolment code or link your admin gave you.",
        to: ENROLMENT_LINK,
        toLabel: "Open Settings > Enrolment",
      };
    case "unmanaged":
      return {
        title: `Enrolled with ${org}, not managed`,
        body: `This machine is enrolled with ${org} with an individual (teams) enrolment. It shares what you chose to share, but ${org} does not manage its AI tool settings, so everything on this page is yours to edit. An organization manages AI tool settings only on managed machines: that turns on when your admin switches the organization to enterprise (this machine picks it up the next time it reaches the org server), or when you enrol again with a managed enrolment code from your admin.`,
        to: ENROLMENT_LINK,
        toLabel: "Open Settings > Enrolment",
      };
    case "managed_inactive": {
      const reason = GRANT_STATE_REASON[v.grant_state ?? ""] ?? "its management grant is not in force";
      return {
        title: `Managed by ${org}, not in force`,
        body: `This machine is managed by ${org}, but ${reason}. Until it is in force, ${org}'s AI tool settings do not apply here and everything on this page is yours to edit.`,
        to: ENROLMENT_LINK,
        toLabel: "Review the grant in Settings > Enrolment",
      };
    }
    case "managed":
      if (v.has_policy) return null;
      return {
        title: "No AI tool policy yet",
        body: `${org === "your organization" ? "Your organization" : org} manages this machine but has not sent an AI tool policy. Until it does, AI tool settings are read-only here.`,
      };
  }
}

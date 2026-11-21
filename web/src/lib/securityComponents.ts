// securityComponents: the Code security page's Scanners tab, as pure data
// (redesign plan docs/plans/code-security-page-redesign-plan-2026-11-06.md
// sections 3.7 and 4.6). It picks the scanner components out of the
// component catalog (GET /api/components) and the node's resolved state
// (GET /api/components/state), maps each to a row (name, one line, state
// pills, whether a switch is offered), and turns a components preview
// (POST /api/components/preview) into the lines the confirm dialog shows.
//
// The set is DERIVED, not listed: every catalog row whose id starts with
// `security.scan.`, plus the `security.` rows those rows require (so
// security.deps and security.code appear because the catalog says the
// drivers need them), plus EXTRA_IDS below. DISPLAY is the one small
// table of order and plain-language lines; a row it does not name still
// shows, after the named ones, with the first sentence of its catalog
// text. Pure: no React, no fetch, no app path aliases, so
// securityComponents.test.ts runs under `node --test`.

import type { CatalogComponent, CatalogReport, ComponentsStateResponse, ArtifactStatus } from "./componentState.ts";
import { ARTIFACT_STATE_LABEL } from "./componentState.ts";

/** SCANNER_PREFIX marks the scanner components in the catalog. */
export const SCANNER_PREFIX = "security.scan.";

/** The module root, which is never a row (it is the whole page). */
const SECURITY_ROOT = "security";

/** EXTRA_IDS are scanner-like components that neither start with the prefix
 *  nor are required by a scanner row. */
export const EXTRA_IDS: readonly string[] = ["security.reach.go"];

/** DISPLAY gives each known component its place and its one line. */
const DISPLAY: Readonly<Record<string, { order: number; line: string }>> = {
  "security.deps": { order: 1, line: "Checks the packages an AI agent installs against the malicious-packages list and the vulnerability database." },
  "security.scan.scalibr": { order: 2, line: "Reads lockfiles, manifests, workflows and build artifacts and matches the packages against local vulnerability databases." },
  "security.scan.osv": { order: 3, line: "Runs osv-scanner against the local vulnerability database." },
  "security.scan.os": { order: 4, line: "Checks the OS packages inside a container image." },
  "security.scan.image.trivy": { order: 5, line: "Checks container image OS packages with Trivy, as the alternative image driver." },
  "security.scan.trivy": { order: 6, line: "Checks Dockerfiles, Kubernetes, Terraform and Helm files for misconfiguration." },
  "security.scan.kics": { order: 7, line: "Checks infrastructure-as-code files for misconfiguration with KICS." },
  "security.scan.actionlint": { order: 8, line: "Lints GitHub Actions workflows." },
  "security.scan.opengrep": { order: 9, line: "Runs Observer's code rules over Python, JavaScript, TypeScript and Go." },
  "security.code": { order: 10, line: "Native rules on agent changes and commits: risky workflows and weakened tests." },
  "security.scan.custom": { order: 11, line: "Runs scanners you configure, such as gosec, Bandit or Semgrep, and reads their results." },
  "security.scan.sarif-import": { order: 12, line: "Imports the results file of a scanner you ran yourself." },
  "security.reach.go": { order: 13, line: "Marks Go findings as called or not called, from the binary or the source." },
};

/** Which way a row's state is moving: the daemon applies a change at its next start. */
export type PendingChange = "activate" | "deactivate" | null;

/** Pill tones the page maps onto the shared Pill. */
export type RowPillTone = "success" | "neutral" | "warn" | "danger" | "accent";

export type RowPill = { text: string; tone: RowPillTone };

/** The driver facts GET /api/security/scanners adds (platform and beta). */
export type DriverFacts = { component: string; platform?: string; beta?: boolean; labels?: string[] };

/** One row of the switches. */
export type ScannerRow = {
  id: string;
  name: string;
  line: string;
  /** In this binary and not blocked: the only rows that get a switch. */
  switchable: boolean;
  /** Why there is no switch, or null. */
  whyNot: string | null;
  /** True when the scanner is selected and active on this machine. */
  on: boolean;
  pending: PendingChange;
  pills: RowPill[];
};

/** firstSentence trims a catalog paragraph to its first sentence. */
export function firstSentence(text: string): string {
  const t = (text ?? "").trim();
  const m = /^(.+?[.!?])(\s|$)/.exec(t);
  return (m ? m[1] : t).trim();
}

/** scannerIds derives the ordered id list from the catalog. */
export function scannerIds(components: readonly CatalogComponent[]): string[] {
  const byId = new Map(components.map((c) => [c.id, c]));
  const out = new Set<string>();
  for (const c of components) {
    if (!c.id.startsWith(SCANNER_PREFIX)) continue;
    out.add(c.id);
    for (const r of c.requires ?? []) {
      if (r !== SECURITY_ROOT && r.startsWith("security.") && byId.has(r)) out.add(r);
    }
  }
  for (const id of EXTRA_IDS) if (byId.has(id)) out.add(id);
  return [...out].sort((a, b) => {
    const oa = DISPLAY[a]?.order ?? 100;
    const ob = DISPLAY[b]?.order ?? 100;
    return oa - ob || a.localeCompare(b);
  });
}

/** lineFor is a row's one-line description. */
export function lineFor(c: Pick<CatalogComponent, "id" | "about">): string {
  return DISPLAY[c.id]?.line ?? firstSentence(c.about);
}

function pendingFor(state: ComponentsStateResponse | null | undefined, id: string): PendingChange {
  return state?.pending?.find((p) => p.id === id)?.change ?? null;
}

/**
 * isOn reads the switch position. `security_selected` is the daemon's one
 * opt-in rule (an opt-in child is listed only when a [components] block
 * names it), so it wins when the daemon sends it; an older daemon falls
 * back to the resolved state.
 */
export function isOn(state: ComponentsStateResponse | null | undefined, id: string): boolean {
  const row = state?.view?.components?.find((r) => r.id === id);
  if (!row || row.state !== "active") return false;
  const selected = state?.security_selected;
  return selected ? selected.includes(id) : true;
}

/**
 * buildScannerRows maps catalog and state to the rows, in display order.
 * Ordered rules for the switch: not in this build (no switch, the build's
 * name for it), blocked on this machine (no switch, the reason), else a
 * switch. Nothing is dropped: a row the state does not list is shown as
 * not available rather than hidden.
 */
export function buildScannerRows(
  catalog: Pick<CatalogReport, "components" | "artifact_states"> | null | undefined,
  state: ComponentsStateResponse | null | undefined,
  drivers: readonly DriverFacts[] = [],
): ScannerRow[] {
  if (!catalog) return [];
  const byId = new Map(catalog.components.map((c) => [c.id, c]));
  const artifacts = new Map<string, ArtifactStatus>((catalog.artifact_states ?? []).map((a) => [a.id, a]));
  const driverBy = new Map(drivers.map((d) => [d.component, d]));
  return scannerIds(catalog.components).map((id) => {
    const c = byId.get(id) as CatalogComponent;
    const rs = state?.view?.components?.find((r) => r.id === id);
    const compiled = c.compiled && rs?.state !== "absent";
    const pending = pendingFor(state, id);
    const on = isOn(state, id);
    const pills: RowPill[] = [];
    let switchable = true;
    let whyNot: string | null = null;
    if (!compiled) {
      switchable = false;
      whyNot = "This build does not include it. Install a build that does, or ask your organization.";
      pills.push({ text: "Not in this build", tone: "neutral" });
    } else {
      pills.push({ text: "In this build", tone: "success" });
      if (rs?.state === "blocked") {
        switchable = false;
        whyNot = rs.reason ? rs.reason : "Blocked on this machine.";
        pills.push({ text: "Blocked", tone: "danger" });
      } else if (!state) {
        switchable = false;
        whyNot = "The component state has not loaded yet.";
      }
    }
    const d = driverBy.get(id);
    if (compiled && d?.beta) pills.push({ text: d.platform ? `Beta on ${d.platform}` : "Beta here", tone: "warn" });
    if (compiled && pending === "activate") pills.push({ text: "On after restart", tone: "accent" });
    if (compiled && pending === "deactivate") pills.push({ text: "Off after restart", tone: "warn" });
    const art = artifacts.get(id);
    if (compiled && art) {
      pills.push({ text: ARTIFACT_STATE_LABEL[art.state] ?? art.state, tone: art.state === "installed" || art.state === "connected" ? "success" : "neutral" });
    }
    for (const l of d?.labels ?? []) pills.push({ text: `Last run: ${l}`, tone: "warn" });
    return { id, name: c.title, line: lineFor(c), switchable, whyNot, on, pending, pills };
  });
}

/** The change shape the components preview and apply take. */
export type ComponentChange = { add?: string[]; remove?: string[] };

/** changeFor is the change one switch sends: add the id to turn it on, remove it to turn it off. */
export function changeFor(id: string, turnOn: boolean): ComponentChange {
  return turnOn ? { add: [id] } : { remove: [id] };
}

/** The preview body (componentsvc.Preview), the fields the dialog reads. */
export type ComponentPreview = {
  activated: string[];
  deactivated: string[];
  cascade: string[];
  teardown: { component?: string; kind?: string; tool?: string; what: string; command?: string }[];
  refused: string[];
  issues: string[];
  restart_required: boolean;
  fingerprint: string;
  no_change: boolean;
  managed_by?: string;
  managed_refused?: string[];
  /** The [components] selection before and after (componentsvc.Selection). */
  current?: ComponentSelection;
  proposed?: ComponentSelection;
};

/** A [components] selection as the preview sends it (Go field names). */
export type ComponentSelection = { Distro?: string; Add?: string[] | null; Remove?: string[] | null };

/**
 * selectionFlips reports whether the change moves `id` into or out of the
 * explicit [components] list. An opt-in scanner (Opengrep, actionlint) can
 * already be active in the build's base set and still be off: the switch
 * follows the list (`security_selected`), so listing it is the change even
 * when the resolver activates nothing.
 */
export function selectionFlips(preview: ComponentPreview, id: string): boolean {
  const listed = (s: ComponentSelection | undefined) => !!s && (s.Add ?? []).includes(id) && !(s.Remove ?? []).includes(id);
  return !!preview.current && !!preview.proposed && listed(preview.current) !== listed(preview.proposed);
}

export type ConfirmSection = { heading: string; items: string[]; tone?: "warn" | "danger" };

export type ConfirmModel = {
  title: string;
  sections: ConfirmSection[];
  /** Plain notes under the lists. */
  notes: string[];
  /** True when the change can be applied. */
  canApply: boolean;
  /** Why it cannot, or null. */
  blockedReason: string | null;
  applyLabel: string;
};

/**
 * confirmModel turns a preview into the confirm dialog. `nameOf` maps a
 * component id to its title (ids a caller cannot name show as the id).
 * Ordered rules: an org-managed refusal blocks the apply; a preview where
 * every part was refused blocks it; "no change" blocks it. Everything the
 * preview lists is shown, nothing else is claimed.
 */
export function confirmModel(
  preview: ComponentPreview,
  target: { id: string; name: string; turnOn: boolean },
  nameOf: (id: string) => string = (id) => id,
): ConfirmModel {
  const names = (xs: readonly string[] | undefined) => (xs ?? []).map((x) => nameOf(x));
  const sections: ConfirmSection[] = [];
  const add = (heading: string, items: string[], tone?: "warn" | "danger") => {
    if (items.length > 0) sections.push({ heading, items, tone });
  };
  const activated = preview.activated ?? [];
  const alsoOn = activated.filter((x) => x !== target.id);
  const deactivated = preview.deactivated ?? [];
  const alsoOff = [...deactivated.filter((x) => x !== target.id), ...(preview.cascade ?? [])];
  const targetMoves = activated.includes(target.id) || deactivated.includes(target.id) || selectionFlips(preview, target.id);
  add(target.turnOn ? "Turns on" : "Turns off", targetMoves ? [nameOf(target.id)] : []);
  add("Also turned on, because it needs them", names(alsoOn));
  add("Also turned off, because they need it", names([...new Set(alsoOff)]));
  add(
    "Undone on your machine",
    (preview.teardown ?? []).map((t) => (t.command ? `${t.what} (${t.command})` : t.what)),
  );
  const managedRefused = preview.managed_refused ?? [];
  add("Your organization refuses", managedRefused, "danger");
  add("Cannot be done", preview.refused ?? [], "warn");
  add("Selection problems", preview.issues ?? [], "warn");

  const notes: string[] = [];
  if (target.turnOn) {
    notes.push("Installing a scanner program or downloading a database is a separate step with its own confirmation. Turning it on installs nothing.");
  }
  if (preview.restart_required) {
    notes.push("The change takes full effect after Observer restarts. Commands pick it up at once.");
  }

  const onlyRefused =
    !preview.no_change && (preview.refused?.length ?? 0) > 0 && activated.length === 0 && deactivated.length === 0;
  let blockedReason: string | null = null;
  if (managedRefused.length > 0) {
    blockedReason = "Your organization manages this setting.";
  }
  if (!blockedReason && onlyRefused) blockedReason = "Nothing in this change can be applied here. The list above says why.";
  if (!blockedReason && preview.no_change) blockedReason = "Nothing changes.";
  return {
    title: target.turnOn ? `Turn on ${target.name}?` : `Turn off ${target.name}?`,
    sections,
    notes,
    canApply: blockedReason == null && !!preview.fingerprint,
    blockedReason,
    applyLabel: target.turnOn ? "Turn on" : "Turn off",
  };
}

/** The kinds of failure an apply or preview can answer. */
export type ApplyFailureKind = "stale" | "managed" | "refused" | "other";

export type ApplyFailure = { kind: ApplyFailureKind; message: string; preview?: ComponentPreview };

/**
 * classifyFailure reads the error body of /api/components/preview and
 * /apply (`{error, message, preview?}`): stale_preview asks for a fresh
 * preview, managed_by_org carries the org's refused parts, anything else
 * is shown as the server's own message.
 */
export function classifyFailure(body: string | null | undefined, fallback: string): ApplyFailure {
  type FailureBody = { error?: string; message?: string; preview?: ComponentPreview };
  const v = ((): FailureBody | null => {
    try {
      return body ? (JSON.parse(body) as FailureBody) : null;
    } catch {
      return null;
    }
  })();
  const message = v?.message || fallback;
  switch (v?.error) {
    case "stale_preview":
      return { kind: "stale", message: "The selection changed since the preview. Here is the new one.", preview: v.preview };
    case "managed_by_org":
      return { kind: "managed", message: "Your organization manages this setting.", preview: v.preview };
    case "apply_refused":
    case "teardown_refused":
      return { kind: "refused", message };
    default:
      return { kind: "other", message };
  }
}

/** appliedNote is the line shown after a successful apply. */
export function appliedNote(turnOn: boolean, name: string, restartNote: string | undefined, restartRequired: boolean): string {
  const base = `${name} is ${turnOn ? "on" : "off"}.`;
  if (!restartRequired) return base;
  return `${base} ${restartNote?.trim() || "Restart Observer for the background work to follow."}`;
}

/** A project a picker can offer; `active` is the Projects status flag. */
export type PickableProject = { project_root_hash: string; label: string; active?: boolean };

/** One picker option (the shared SinglePicker's option shape, structurally). */
export type ProjectPickerOption = { id: string; label: string; group?: string };

export const ACTIVE_PROJECTS_GROUP = "Active projects";
export const IDLE_PROJECTS_GROUP = "Idle projects";

/**
 * projectPickerOptions lists active projects first, then idle ones, each
 * group in the order given (callers pass the page's own sort). When no
 * project carries the active flag at all the list keeps its order with no
 * group headings, rather than calling every project idle.
 */
export function projectPickerOptions(projects: readonly PickableProject[]): ProjectPickerOption[] {
  const known = projects.some((p) => p.active !== undefined);
  if (!known) return projects.map((p) => ({ id: p.project_root_hash, label: p.label }));
  const opt = (p: PickableProject, group: string): ProjectPickerOption => ({ id: p.project_root_hash, label: p.label, group });
  return [
    ...projects.filter((p) => p.active === true).map((p) => opt(p, ACTIVE_PROJECTS_GROUP)),
    ...projects.filter((p) => p.active !== true).map((p) => opt(p, IDLE_PROJECTS_GROUP)),
  ];
}

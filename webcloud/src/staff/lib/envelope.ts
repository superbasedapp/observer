// The availability envelope's staff inputs (plan 06 18.3.5; the signed body
// is internal/platformcontract/availability.go). Staff write one input per
// (section, key) through PUT /staff/api/availability/{section}/{key}; the
// server stores the value as an opaque JSON object (staffauth
// ValidateAvailabilityInput) and keeps the reason and author on the row. The
// envelope composer (M6.3) turns each row into one body row, adding the
// row's reason and author. These models build and check the value the
// composer will read, with the body's own rules (platformcontract Validate),
// so a staff member cannot store an input that the signer would refuse.
//
// Key conventions (this console's; the composer reads the same):
//   components     key = the catalog component id
//   release_flags  key = the release flag id
//   org_controls   key = the org's UUID, or PLATFORM_KEY for the
//                  platform-wide row. The value carries "org" (the org id,
//                  or "*") so the composer never infers it from the key: the
//                  stored key may not be "*" (the key CHECK).
// Pure: no fetch, no React.

export type Section = "components" | "org_controls" | "release_flags";

export const SECTIONS: readonly Section[] = ["org_controls", "components", "release_flags"];

/** PLATFORM_KEY is the org_controls key of the platform-wide row. */
export const PLATFORM_KEY = "platform";
/** ALL_ORGS is platformcontract.AllOrgs. */
export const ALL_ORGS = "*";

/** KEY_RE is the availability_inputs.key CHECK. */
export const KEY_RE = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---- reach (components, release_flags) ------------------------------------

export type Reach = "off" | "named" | "cohort" | "stage-default";
export const REACHES: readonly Reach[] = ["stage-default", "off", "named", "cohort"];

export interface ReachValue {
  reach: Reach;
  orgs?: string[];
  cohort?: string;
}

/** reachRules mirrors platformcontract's reach table: what each reach must
 *  and must not carry. */
const reachRules: { reach: Reach; needOrgs: boolean; needCohort: boolean }[] = [
  { reach: "off", needOrgs: false, needCohort: false },
  { reach: "named", needOrgs: true, needCohort: false },
  { reach: "cohort", needOrgs: false, needCohort: true },
  { reach: "stage-default", needOrgs: false, needCohort: false },
];

export interface ReachDraft {
  reach: Reach;
  /** orgsText is the named orgs, one per line or comma separated. */
  orgsText: string;
  cohort: string;
}

export function splitList(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

/** buildReach turns a draft into the stored value and the errors the body's
 *  rules would raise (empty when it is valid). */
export function buildReach(d: ReachDraft): { value: ReachValue; errors: string[] } {
  const rule = reachRules.find((r) => r.reach === d.reach);
  if (!rule) return { value: { reach: d.reach }, errors: [`unknown reach "${d.reach}"`] };
  const orgs = splitList(d.orgsText);
  const cohort = d.cohort.trim();
  const errors: string[] = [];
  const value: ReachValue = { reach: d.reach };
  if (rule.needOrgs) {
    if (orgs.length === 0) errors.push("Named reach needs at least one org id.");
    errors.push(...orgListErrors(orgs));
    value.orgs = orgs;
  }
  if (rule.needCohort) {
    if (cohort === "") errors.push("Cohort reach needs a cohort name.");
    value.cohort = cohort;
  }
  return { value, errors };
}

function orgListErrors(orgs: string[]): string[] {
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const o of orgs) {
    if (!UUID_RE.test(o)) errors.push(`"${o}" is not an org id (a UUID).`);
    if (seen.has(o)) errors.push(`"${o}" is listed twice.`);
    seen.add(o);
  }
  return errors;
}

/** reachDraftFrom reads a stored value back into a draft (unknown shapes fall
 *  back to the stage default). */
export function reachDraftFrom(value: unknown): ReachDraft {
  const v = (value ?? {}) as Partial<ReachValue>;
  const reach = REACHES.includes(v.reach as Reach) ? (v.reach as Reach) : "stage-default";
  return { reach, orgsText: (v.orgs ?? []).join("\n"), cohort: v.cohort ?? "" };
}

/** describeReach is one line for a list row. */
export function describeReach(value: unknown): string {
  const v = (value ?? {}) as Partial<ReachValue>;
  switch (v.reach) {
    case "off":
      return "Off everywhere";
    case "named":
      return `Only ${v.orgs?.length ?? 0} named org${v.orgs?.length === 1 ? "" : "s"}`;
    case "cohort":
      return `Cohort ${v.cohort ?? "?"}`;
    case "stage-default":
      return "Stage default";
    default:
      return "Unrecognized value";
  }
}

// ---- org_controls ----------------------------------------------------------

export type IngestMode = "pause" | "throttle";
export type InferenceState = "on" | "paused" | "off";
export const INFERENCE_STATES: readonly InferenceState[] = ["on", "paused", "off"];

export interface InferenceControl {
  route?: string;
  admission: InferenceState;
  dispatch: InferenceState;
}

export interface OrgControlValue {
  org: string;
  ingest?: { mode: IngestMode; rate_per_minute?: number };
  inference?: InferenceControl[];
}

export interface InferenceDraft {
  route: string;
  admission: InferenceState;
  dispatch: InferenceState;
}

export interface OrgControlDraft {
  /** key is the org id, or PLATFORM_KEY. */
  key: string;
  ingest: "none" | IngestMode;
  rateText: string;
  inference: InferenceDraft[];
}

/** orgForKey is the body's org for a stored key. */
export function orgForKey(key: string): string {
  return key === PLATFORM_KEY ? ALL_ORGS : key;
}

/** buildOrgControl turns a draft into the stored value and the errors the
 *  body's org_controls rules would raise: the key is an org id or the
 *  platform row; the row carries a control; ingest is never platform-wide;
 *  throttle has a positive whole rate and pause none; at most one inference
 *  row per route. */
export function buildOrgControl(d: OrgControlDraft): { value: OrgControlValue; errors: string[] } {
  const errors: string[] = [];
  const key = d.key.trim();
  const platform = key === PLATFORM_KEY;
  if (!platform && !UUID_RE.test(key)) errors.push("The org must be an org id (a UUID), or the platform-wide row.");
  const value: OrgControlValue = { org: orgForKey(key) };
  if (d.ingest !== "none") {
    if (platform) errors.push("Ingest can only be paused or throttled per org, never platform-wide.");
    if (d.ingest === "throttle") {
      const rate = Number(d.rateText.trim());
      if (!Number.isInteger(rate) || rate <= 0) errors.push("A throttle needs a whole rate per minute above zero.");
      value.ingest = { mode: "throttle", rate_per_minute: rate };
    } else {
      value.ingest = { mode: "pause" };
    }
  }
  const routes = new Set<string>();
  const inference: InferenceControl[] = [];
  for (const row of d.inference) {
    const route = row.route.trim();
    if (routes.has(route)) errors.push(route === "" ? "Two rows cover every route." : `Route "${route}" has two rows.`);
    routes.add(route);
    if (route !== "" && !KEY_RE.test(route)) errors.push(`Route "${route}" has characters a route id never has.`);
    if (!INFERENCE_STATES.includes(row.admission) || !INFERENCE_STATES.includes(row.dispatch)) {
      errors.push("Admission and dispatch are each on, paused or off.");
    }
    const c: InferenceControl = { admission: row.admission, dispatch: row.dispatch };
    if (route !== "") c.route = route;
    inference.push(c);
  }
  if (inference.length > 0) value.inference = inference;
  if (!value.ingest && inference.length === 0) errors.push("The row carries no control: add an ingest or an inference control, or remove the row.");
  return { value, errors };
}

/** orgControlDraftFrom reads a stored row back into a draft. */
export function orgControlDraftFrom(key: string, value: unknown): OrgControlDraft {
  const v = (value ?? {}) as Partial<OrgControlValue>;
  const ingest = v.ingest?.mode === "pause" || v.ingest?.mode === "throttle" ? v.ingest.mode : "none";
  return {
    key,
    ingest,
    rateText: v.ingest?.rate_per_minute ? String(v.ingest.rate_per_minute) : "",
    inference: (v.inference ?? []).map((r) => ({
      route: r.route ?? "",
      admission: INFERENCE_STATES.includes(r.admission) ? r.admission : "on",
      dispatch: INFERENCE_STATES.includes(r.dispatch) ? r.dispatch : "on",
    })),
  };
}

/** emptyOrgControlDraft is a new row's draft. */
export function emptyOrgControlDraft(key: string): OrgControlDraft {
  return { key, ingest: "none", rateText: "", inference: [] };
}

/** describeOrgControl is the row's controls in plain lines. */
export function describeOrgControl(value: unknown): string[] {
  const v = (value ?? {}) as Partial<OrgControlValue>;
  const out: string[] = [];
  if (v.ingest?.mode === "pause") out.push("Ingest paused");
  if (v.ingest?.mode === "throttle") out.push(`Ingest throttled to ${v.ingest.rate_per_minute ?? "?"} pushes a minute`);
  for (const r of v.inference ?? []) {
    out.push(`Inference ${r.route ? `route ${r.route}` : "(every route)"}: admission ${r.admission}, dispatch ${r.dispatch}`);
  }
  return out.length > 0 ? out : ["No control"];
}

export type ControlTone = "danger" | "warn" | "info" | "neutral";

/** orgControlTone is how severe a row is: anything off is danger, paused is
 *  warn, a throttle alone is info. */
export function orgControlTone(value: unknown): ControlTone {
  const v = (value ?? {}) as Partial<OrgControlValue>;
  const states = (v.inference ?? []).flatMap((r) => [r.admission, r.dispatch]);
  if (states.includes("off")) return "danger";
  if (v.ingest?.mode === "pause" || states.includes("paused")) return "warn";
  if (v.ingest?.mode === "throttle") return "info";
  return "neutral";
}

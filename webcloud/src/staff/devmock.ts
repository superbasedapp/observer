// DEV-ONLY staff API mock: imported by main.tsx behind import.meta.env.DEV, so
// it is dropped from the production build. It patches window.fetch for
// /staff/* so the screens render under a bare `vite --config
// vite.staff.config.ts`. Mode from localStorage "sbci_staff_devmock":
// "admin" (default), "support" (read-only role), "signedout".
//
// The availability inputs, the issued envelope, the issue request and each
// host's delivery are state here, so a change made on a screen shows up in
// the issue preview, and issuing moves it: pending for about 5 s, then
// issued, then delivered to app-0 and (after one failed connect) app-1. The
// starting point comes from localStorage "sbci_staff_devmock_issue":
// "" (default: one change not issued, app-1 retrying), "pending" (a request
// waiting for the worker, done after about 8 s), "fresh" (no envelope issued
// yet), "problems" (an input the composer refuses, and a host that refused
// v12), "off" (the issue and per-org component routes are not mounted).
// Outside "signedout" the passkey check is faked (any assertion passes), so
// a change can be applied end to end.
//
// The team allow-list is state too (add and remove move it); localStorage
// "sbci_staff_devmock_allowlist": "" (default: two entries and one removed),
// "empty" (no entry), "off" (its route is not mounted).

import { validateAllowlistEntry } from "./lib/allowlist";

const ORGS = [
  {
    org_id: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    kind: "team",
    slug: "superbased-internal",
    display_name: "superbased internal",
    status: "active",
    tenancy: "managed",
    host_id: "app-0",
    platform_rail_enabled: true,
    lifecycle_gen: 2,
    created_at: "2026-11-10T09:12:00Z",
    updated_at: "2026-11-15T10:00:00Z",
    members: 4,
    grant: { action: "grant", plan_name: "business", plan_version: 3 },
    usage: { day: "2026-11-15", seats: 3, members: 4 },
    entitlements: { version: 7, issued_at: "2026-11-15T11:00:00Z" },
  },
  {
    org_id: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
    kind: "team",
    slug: "acme",
    display_name: "Acme Robotics",
    status: "provisioning",
    tenancy: "managed",
    platform_rail_enabled: true,
    lifecycle_gen: 0,
    created_at: "2026-11-16T08:00:00Z",
    updated_at: "2026-11-16T08:00:00Z",
    members: 1,
    subscription: { status: "trialing", plan_name: "team", plan_version: 2 },
  },
  {
    org_id: "cccccccc-dddd-4eee-8fff-000000000000",
    kind: "personal",
    slug: "ada-l",
    display_name: "Ada L",
    status: "pending_deletion",
    tenancy: "individual",
    host_id: "app-0",
    platform_rail_enabled: true,
    lifecycle_gen: 5,
    created_at: "2026-11-01T08:00:00Z",
    updated_at: "2026-11-16T07:00:00Z",
    members: 1,
  },
];

interface MockRow {
  section: string;
  key: string;
  value: unknown;
  reason: string;
  author: string;
  updated_at: string;
}

const INPUTS: MockRow[] = [
  {
    section: "org_controls",
    key: "platform",
    value: { org: "*", inference: [{ route: "gpt-oss-120b", admission: "paused", dispatch: "on" }] },
    reason: "OVH route degraded, holding new jobs",
    author: "staff:11111111-2222-4333-8444-555555555555",
    updated_at: "2026-11-16T09:30:00Z",
  },
  {
    section: "org_controls",
    key: ORGS[0].org_id,
    value: { org: ORGS[0].org_id, ingest: { mode: "throttle", rate_per_minute: 600 } },
    reason: "load test on app-0",
    author: "staff:11111111-2222-4333-8444-555555555555",
    updated_at: "2026-11-15T09:00:00Z",
  },
  {
    section: "components",
    key: "codeintel",
    value: { reach: "named", orgs: [ORGS[0].org_id] },
    reason: "internal alpha only",
    author: "operator",
    updated_at: "2026-11-14T12:00:00Z",
  },
];

const LOG = [
  {
    action_id: "a1",
    at: "2026-11-16T09:30:00Z",
    actor: "staff:11111111-2222-4333-8444-555555555555",
    verb: "availability.set",
    target: "org_controls/platform",
    detail: { value: INPUTS[0].value, previous: null },
    reason: INPUTS[0].reason,
    result: "ok",
  },
  {
    action_id: "a2",
    at: "2026-11-16T08:10:00Z",
    actor: "staff:11111111-2222-4333-8444-555555555555",
    verb: "support.signin",
    org_id: ORGS[0].org_id,
    target: "superbased-internal",
    reason: "ticket 118: dashboard empty",
    result: "ok",
  },
  {
    action_id: "a3",
    at: "2026-11-16T08:05:00Z",
    actor: "staff:33333333-4444-4555-8666-777777777777",
    verb: "action.refused",
    target: "support.signin",
    reason: "reauth_required",
    result: "refused",
  },
];

function json(body: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function bodyOf(init?: RequestInit): Record<string, unknown> {
  try {
    return JSON.parse(typeof init?.body === "string" ? init.body : "{}") as Record<string, unknown>;
  } catch {
    return {};
  }
}

// ---- the availability envelope: compose, issue, deliver (stateful) ----------

type Json = Record<string, unknown>;
type Body = { components: Json[]; org_controls: Json[]; release_flags: Json[] };

interface MockReq {
  request_id: string;
  requested_by: string;
  reason: string;
  requested_at: string;
  base_version: number;
  state: string;
  result_version: number;
  error_class: string;
  done_at: string | null;
  /** digest is the inputs digest the request named (not on the wire). */
  digest: string;
}

interface MockDelivery {
  host_id: string;
  version: number;
  state: string;
  attempts: number;
  error_class: string;
  updated_at: string;
}

const SELF = "staff:11111111-2222-4333-8444-555555555555";
const KEY_ID = "Zk3mQ1xU9pRv2sT8yW4aB6cD0eF7gH5iJ1kL3mN9oP2";
const COMPONENT_TITLES: Record<string, string> = { "org.security": "Code security (org)" };
const REACHES = ["off", "named", "cohort", "stage-default"];
const ROW_KEY: Record<string, string> = { components: "component", release_flags: "flag", org_controls: "org" };

let issued: { version: number; issued_at: string; body: Body & { issued_at: string } } | null = null;
let pending: MockReq | null = null;
let lastRequest: MockReq | null = null;
const deliveries = new Map<string, MockDelivery>();

const iso = (msAgo = 0) => new Date(Date.now() - msAgo).toISOString();
const sortKey = (r: MockRow) => `${r.section}/${r.key}`;

/** compose turns the inputs into body rows the way the composer does (one
 *  row per input, with its reason and author) and lists the inputs it
 *  cannot compose. */
function compose(rows: MockRow[]): { body: Body; problems: string[] } {
  const body: Body = { components: [], org_controls: [], release_flags: [] };
  const problems: string[] = [];
  for (const r of [...rows].sort((a, b) => sortKey(a).localeCompare(sortKey(b)))) {
    const v = (r.value ?? {}) as Json;
    const meta = { reason: r.reason, author: r.author };
    if (r.section === "org_controls") body.org_controls.push({ ...v, ...meta });
    else if (!REACHES.includes(String(v.reach))) problems.push(`${r.section}/${r.key}: reach: unknown value`);
    else if (r.section === "components") body.components.push({ component: r.key, ...v, ...meta });
    else body.release_flags.push({ flag: r.key, ...v, ...meta });
  }
  return { body, problems };
}

/** diff lists the section/key rows that differ between two bodies. */
function diff(prev: Body | null, next: Body): Json[] {
  const out: Json[] = [];
  for (const section of ["org_controls", "components", "release_flags"] as const) {
    const index = (rows: Json[] | undefined) => new Map((rows ?? []).map((r) => [String(r[ROW_KEY[section]]), r]));
    const a = index(prev?.[section]);
    const b = index(next[section]);
    for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
      const before = a.get(key) ?? null;
      const after = b.get(key) ?? null;
      if (JSON.stringify(before) === JSON.stringify(after)) continue;
      out.push({ section, key, kind: before === null ? "added" : after === null ? "removed" : "changed", before, after });
    }
  }
  return out;
}

/** digest stands in for the server's inputs digest: 64 hex characters that
 *  change whenever an input or the issued version does. */
function digest(text: string): string {
  let out = "";
  for (let seed = 0; seed < 8; seed++) {
    let h = 0x811c9dc5 ^ seed;
    for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193);
    out += (h >>> 0).toString(16).padStart(8, "0");
  }
  return out;
}

function wire(r: MockReq | null) {
  if (!r) return null;
  const { digest: _omit, ...rest } = r; // eslint-disable-line @typescript-eslint/no-unused-vars
  return rest;
}

function preview() {
  const { body, problems } = compose(INPUTS);
  const base = issued?.version ?? 0;
  const canonical = [...INPUTS].sort((a, b) => sortKey(a).localeCompare(sortKey(b))).map((r) => [r.section, r.key, r.value, r.reason, r.author]);
  return {
    base_version: base,
    inputs_digest: digest(JSON.stringify({ base, canonical })),
    body: problems.length > 0 ? null : { issued_at: iso(), ...body },
    problems,
    changes: diff(issued?.body ?? null, body),
    pending: wire(pending),
    last_request: wire(lastRequest),
    deliveries: [...deliveries.values()],
  };
}

function setInput(section: string, key: string, value: unknown, reason: string): void {
  const i = INPUTS.findIndex((r) => r.section === section && r.key === key);
  if (value === null) {
    if (i >= 0) INPUTS.splice(i, 1);
    return;
  }
  const row = { section, key, value, reason, author: SELF, updated_at: iso() };
  if (i >= 0) INPUTS[i] = row;
  else INPUTS.push(row);
}

/** finishIssue is the worker: it signs and stores the envelope the request
 *  reviewed (or marks it stale when the inputs moved), then delivers it. */
function finishIssue(req: MockReq): void {
  if (pending?.request_id !== req.request_id) return;
  const pv = preview();
  pending = null;
  if (pv.inputs_digest !== req.digest) {
    lastRequest = { ...req, state: "stale", done_at: iso() };
    return;
  }
  const version = (issued?.version ?? 0) + 1;
  const at = iso();
  issued = { version, issued_at: at, body: { issued_at: at, ...compose(INPUTS).body } };
  lastRequest = { ...req, state: "issued", result_version: version, done_at: at };
  deliveries.set("app-1", { host_id: "app-1", version, state: "retry", attempts: 1, error_class: "transport:dial", updated_at: at });
  setTimeout(() => deliveries.set("app-0", { host_id: "app-0", version, state: "delivered", attempts: 1, error_class: "", updated_at: iso() }), 1500);
  setTimeout(() => deliveries.set("app-1", { host_id: "app-1", version, state: "delivered", attempts: 2, error_class: "", updated_at: iso() }), 6000);
}

function seedIssue(scenario: string): void {
  if (scenario === "problems") {
    INPUTS.push({
      section: "components",
      key: "org.security",
      value: { reach: "bogus" },
      reason: "stored before values were checked",
      author: "operator",
      updated_at: "2026-11-12T10:00:00Z",
    });
  }
  if (scenario !== "fresh") {
    // v12 predates the platform-wide row (changed 09:30, issued 09:00).
    const { body } = compose(INPUTS.filter((r) => !(r.section === "org_controls" && r.key === "platform")));
    issued = { version: 12, issued_at: "2026-11-16T09:00:00Z", body: { issued_at: "2026-11-16T09:00:00Z", ...body } };
    lastRequest = {
      request_id: "r-12",
      requested_by: SELF,
      reason: "kill switch drill",
      requested_at: "2026-11-16T08:59:50Z",
      base_version: 11,
      state: "issued",
      result_version: 12,
      error_class: "",
      done_at: "2026-11-16T09:00:00Z",
      digest: "",
    };
    deliveries.set("app-0", { host_id: "app-0", version: 12, state: "delivered", attempts: 1, error_class: "", updated_at: "2026-11-16T09:00:04Z" });
    deliveries.set(
      "app-1",
      scenario === "problems"
        ? { host_id: "app-1", version: 12, state: "refused", attempts: 1, error_class: "refused:invalid", updated_at: "2026-11-16T09:00:05Z" }
        : { host_id: "app-1", version: 12, state: "retry", attempts: 3, error_class: "transport:dial", updated_at: iso(40_000) },
    );
  }
  if (scenario === "pending") {
    const pv = preview();
    const req: MockReq = {
      request_id: "r-13",
      requested_by: "staff:33333333-4444-4555-8666-777777777777",
      reason: "hold the OVH route on every host",
      requested_at: iso(3000),
      base_version: pv.base_version,
      state: "pending",
      result_version: 0,
      error_class: "",
      done_at: null,
      digest: pv.inputs_digest,
    };
    pending = req;
    setTimeout(() => finishIssue(req), 8000);
  }
}

function offered(value: unknown, orgId: string): boolean {
  const v = (value ?? {}) as { reach?: string; orgs?: string[] };
  return v.reach === "named" && (v.orgs ?? []).includes(orgId);
}

/** toggleFor is what the one button writes to move orgId to on. */
function toggleFor(input: unknown, orgId: string, on: boolean): { on: boolean; value: unknown; error: string } {
  const v = (input ?? null) as { reach?: string; orgs?: string[] } | null;
  if (v && !REACHES.includes(String(v.reach))) return { on, value: null, error: "The stored value is not valid: fix or remove it on Availability." };
  if (v?.reach === "cohort") return { on, value: null, error: "This component reaches a cohort: edit it on Availability." };
  const orgs = v?.reach === "named" ? (v.orgs ?? []).filter((o) => o !== orgId) : [];
  if (on) return { on, value: { reach: "named", orgs: [...orgs, orgId] }, error: "" };
  return { on, value: orgs.length > 0 ? { reach: "named", orgs } : null, error: "" };
}

// ---- the team create allow-list (stateful) -----------------------------------

interface MockAllow {
  entry_id: string;
  kind: string;
  value: string;
  added_by: string;
  added_reason: string;
  added_at: string;
  removed_at?: string;
  removed_by?: string;
  removed_reason?: string;
}

const ALLOWLIST: MockAllow[] = [
  { entry_id: "e-1", kind: "email_domain", value: "superbased.app", added_by: "operator", added_reason: "the internal team", added_at: "2026-11-12T10:00:00Z" },
  {
    entry_id: "e-2",
    kind: "account",
    value: "dddddddd-eeee-4fff-8000-111111111111",
    added_by: SELF,
    added_reason: "ticket 131: design partner asked for a team workspace",
    added_at: "2026-11-15T14:20:00Z",
  },
  {
    entry_id: "e-3",
    kind: "email_domain",
    value: "acme.dev",
    added_by: "operator",
    added_reason: "trial",
    added_at: "2026-11-10T09:00:00Z",
    removed_at: "2026-11-14T09:00:00Z",
    removed_by: "staff:33333333-4444-4555-8666-777777777777",
    removed_reason: "trial ended",
  },
];

/** listAllowlist orders like the store: active first, newest first within each. */
function listAllowlist(includeRemoved: boolean): MockAllow[] {
  const active = ALLOWLIST.filter((e) => !e.removed_at).sort((a, b) => b.added_at.localeCompare(a.added_at));
  const removed = ALLOWLIST.filter((e) => e.removed_at).sort((a, b) => (b.removed_at ?? "").localeCompare(a.removed_at ?? ""));
  return includeRemoved ? [...active, ...removed] : active;
}

function componentRow(orgId: string, component: string) {
  const input = INPUTS.find((r) => r.section === "components" && r.key === component)?.value ?? null;
  const issuedRow = issued?.body.components.find((c) => c.component === component) ?? null;
  const next = offered(input, orgId);
  return { component, title: COMPONENT_TITLES[component], issued: offered(issuedRow, orgId), next, input, toggle: toggleFor(input, orgId, !next) };
}

export function installStaffDevMock(): void {
  const mode = (() => {
    try {
      return localStorage.getItem("sbci_staff_devmock") ?? "admin";
    } catch {
      return "admin";
    }
  })();
  const role = mode === "support" ? "support" : "admin";
  const scenario = (() => {
    try {
      return localStorage.getItem("sbci_staff_devmock_issue") ?? "";
    } catch {
      return "";
    }
  })();
  const issueRoutes = scenario !== "off";
  seedIssue(scenario);
  const allowScenario = (() => {
    try {
      return localStorage.getItem("sbci_staff_devmock_allowlist") ?? "";
    } catch {
      return "";
    }
  })();
  const allowRoute = allowScenario !== "off";
  if (allowScenario === "empty") ALLOWLIST.splice(0, ALLOWLIST.length);
  if (mode !== "signedout" && navigator.credentials) {
    // A fake passkey: any assertion passes (the mock's finish mints a CSRF
    // token), so changes can be applied under the dev server.
    const buf = (...b: number[]) => new Uint8Array(b).buffer;
    const fake = {
      id: "AQ",
      rawId: buf(1),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: { clientDataJSON: buf(2), authenticatorData: buf(3), signature: buf(4), userHandle: buf(5) },
      getClientExtensionResults: () => ({}),
    };
    try {
      Object.defineProperty(navigator.credentials, "get", { value: async () => fake, configurable: true });
    } catch {
      // keep the browser's own
    }
  }
  const real = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, window.location.origin);
    const p = url.pathname;
    if (!p.startsWith("/staff/api/") && !p.startsWith("/staff/auth/")) return real(input, init);
    const method = (init?.method ?? "GET").toUpperCase();
    if (mode === "signedout" && p.startsWith("/staff/api/")) return json({ error: "not signed in", code: "unauthorized" }, 401);
    if (p === "/staff/api/me")
      return json({
        staff_id: "11111111-2222-4333-8444-555555555555",
        display_name: "Santosh",
        role,
        asserted_at: new Date(Date.now() - 4 * 60_000).toISOString(),
        fresh_until: new Date(Date.now() + 11 * 60_000).toISOString(),
        expires_at: new Date(Date.now() + 8 * 3600_000).toISOString(),
      });
    if (p === "/staff/api/features")
      return json({
        features: {
          orgs: true,
          availability_document: true,
          availability_issue: issueRoutes,
          org_components: issueRoutes,
          support_signin: true,
          team_allowlist: allowRoute,
          deletion_queue: false,
          plan_grant_write: false,
        },
        capabilities: [
          { action: "availability.read", permitted: true, fresh: false },
          { action: "availability.write", permitted: role !== "support", fresh: true },
          { action: "availability.issue", permitted: role !== "support", fresh: true },
          { action: "orgs.read", permitted: true, fresh: false },
          { action: "team_allowlist.read", permitted: true, fresh: false },
          { action: "team_allowlist.write", permitted: role !== "support", fresh: true },
        ],
        fresh_window_seconds: 900,
        max_reason_characters: 1000,
      });
    if (mode !== "signedout" && p === "/staff/auth/webauthn/assert/begin")
      return json({ publicKey: { challenge: "AQID", rpId: window.location.hostname, timeout: 60000, userVerification: "required", allowCredentials: [] } });
    if (mode !== "signedout" && p === "/staff/auth/webauthn/assert/finish") return json({ csrf_token: "dev-csrf" });
    if (p === "/staff/api/orgs") return json({ orgs: ORGS });
    const comp = issueRoutes ? p.match(/^\/staff\/api\/orgs\/([^/]+)\/components(?:\/([^/]+))?$/) : null;
    if (comp) {
      const org = ORGS.find((o) => o.org_id === comp[1]);
      if (!org) return json({ error: "no such org", code: "not_found" }, 404);
      if (!comp[2] && method === "GET") {
        return json({ org_id: org.org_id, base_version: issued?.version ?? 0, components: Object.keys(COMPONENT_TITLES).map((c) => componentRow(org.org_id, c)) });
      }
      const c = decodeURIComponent(comp[2] ?? "");
      if (method !== "PUT" || !COMPONENT_TITLES[c]) return json({ error: "no such component", code: "not_found" }, 404);
      const b = bodyOf(init);
      const reason = String(b.reason ?? "").trim();
      if (reason === "") return json({ error: "a reason is required", code: "reason_required" }, 400);
      const previous = INPUTS.find((r) => r.section === "components" && r.key === c)?.value ?? null;
      if (offered(previous, org.org_id) === (b.on === true)) return json({ error: "the org is already in that state", code: "no_change" }, 409);
      const t = toggleFor(previous, org.org_id, b.on === true);
      if (t.error) return json({ error: t.error, code: "invalid_input" }, 400);
      setInput("components", c, t.value, reason);
      return json({ section: "components", key: c, value: t.value, previous });
    }
    if (p.startsWith("/staff/api/orgs/")) {
      const org = ORGS.find((o) => o.org_id === p.split("/").pop());
      if (!org) return json({ error: "no such org", code: "not_found" }, 404);
      return json({
        org,
        grants: org.grant
          ? [{ seq: 2, action: "grant", plan_name: "business", plan_version: 3, actor: "operator", reason: "internal org (W15-D13)", at: "2026-11-12T10:00:00Z" }]
          : [],
        usage: Array.from({ length: 7 }, (_, i) => ({ day: `2026-11-${15 - i}`, seats: 3, members: 4, sessions: 40 - i * 3, machine_identities: 2 })),
        entitlements: org.entitlements
          ? {
              version: 7,
              key_id: "Zk3mQ1xU9pRv2sT8yW4aB6cD0eF7gH5iJ1kL3mN9oP2",
              issued_at: "2026-11-15T11:00:00Z",
              issued_by: "system",
              body_bytes: 220,
              body: {
                schema: "sbo-entitlements-v1",
                kind: "team",
                plan: { name: "business", version: 3, label: "Business" },
                caps: { seats: 50, retention_days: 365 },
                capabilities: ["sso", "audit_export"],
              },
            }
          : undefined,
        intents: [{ verb: "create_tenant", state: org.status === "provisioning" ? "pending" : "acked", attempts: 1, next_attempt_at: "2026-11-16T08:15:00Z", created_at: org.created_at }],
        deletion: org.status === "pending_deletion" ? { state: "deactivating_members", created_at: "2026-11-16T07:00:00Z", updated_at: "2026-11-16T07:05:00Z" } : undefined,
      });
    }
    if (p === "/staff/api/availability" && method === "GET") return json({ inputs: INPUTS });
    if (p === "/staff/api/availability/document")
      return json({
        document: issued
          ? { version: issued.version, key_id: KEY_ID, issued_at: issued.issued_at, issued_by: "system", body_bytes: JSON.stringify(issued.body).length, body: issued.body }
          : null,
      });
    if (issueRoutes && p === "/staff/api/availability/preview" && method === "GET") return json(preview());
    if (issueRoutes && p === "/staff/api/availability/issue" && method === "POST") {
      const b = bodyOf(init);
      const reason = String(b.reason ?? "").trim();
      if (reason === "") return json({ error: "a reason is required", code: "reason_required" }, 400);
      const pv = preview();
      if (pv.problems.length > 0) return json({ error: "some inputs cannot be composed", code: "invalid_inputs" }, 400);
      if (pending) return json({ error: "another issue request is pending", code: "issue_pending" }, 409);
      if (b.inputs_digest !== pv.inputs_digest || b.base_version !== pv.base_version)
        return json({ error: "the inputs changed since the preview", code: "inputs_changed" }, 409);
      if (pv.changes.length === 0) return json({ error: "nothing to issue", code: "nothing_to_issue" }, 409);
      const req: MockReq = {
        request_id: crypto.randomUUID(),
        requested_by: SELF,
        reason,
        requested_at: iso(),
        base_version: pv.base_version,
        state: "pending",
        result_version: 0,
        error_class: "",
        done_at: null,
        digest: pv.inputs_digest,
      };
      pending = req;
      setTimeout(() => finishIssue(req), 5000);
      return json({ request_id: req.request_id, state: "pending" }, 202);
    }
    const cancel = p.match(/^\/staff\/api\/availability\/issue\/([^/]+)\/cancel$/);
    if (issueRoutes && cancel && method === "POST") {
      const reason = String(bodyOf(init).reason ?? "").trim();
      if (reason === "") return json({ error: "a reason is required", code: "reason_required" }, 400);
      const id = decodeURIComponent(cancel[1]);
      if (pending?.request_id !== id) return json({ error: "that issue request is no longer pending", code: "not_pending" }, 409);
      lastRequest = { ...pending, state: "failed", error_class: "cancelled", done_at: iso() };
      pending = null;
      return json({ request_id: id, state: "failed", error_class: "cancelled" });
    }
    const avail = p.match(/^\/staff\/api\/availability\/(components|org_controls|release_flags)\/([^/]+)$/);
    if (avail && (method === "PUT" || method === "DELETE")) {
      const b = bodyOf(init);
      const key = decodeURIComponent(avail[2]);
      const previous = INPUTS.find((r) => r.section === avail[1] && r.key === key)?.value ?? null;
      const value = method === "DELETE" ? null : (b.value ?? null);
      setInput(avail[1], key, value, String(b.reason ?? ""));
      return method === "DELETE" ? json(null, 204) : json({ section: avail[1], key, value, previous });
    }
    if (p.startsWith("/staff/api/availability/")) return method === "DELETE" ? json(null, 204) : json({ ok: true });
    if (allowRoute && p === "/staff/api/team-allowlist" && method === "GET") {
      const v = url.searchParams.get("include_removed");
      return json({ entries: listAllowlist(v === "1" || v === "true") });
    }
    if (allowRoute && p === "/staff/api/team-allowlist" && method === "POST") {
      const b = bodyOf(init);
      const reason = String(b.reason ?? "").trim();
      if (reason === "") return json({ error: "a reason is required for every staff change", code: "reason_required" }, 400);
      const checked = validateAllowlistEntry(String(b.kind ?? ""), String(b.value ?? ""));
      if (checked.error) return json({ error: checked.error, code: "invalid_input" }, 400);
      if (ALLOWLIST.some((e) => !e.removed_at && e.kind === b.kind && e.value === checked.value))
        return json({ error: "that entry is already on the allow-list", code: "exists" }, 409);
      const entry: MockAllow = { entry_id: crypto.randomUUID(), kind: String(b.kind), value: checked.value, added_by: SELF, added_reason: reason, added_at: iso() };
      ALLOWLIST.push(entry);
      return json(entry, 201);
    }
    const allowDel = allowRoute ? p.match(/^\/staff\/api\/team-allowlist\/([^/]+)$/) : null;
    if (allowDel && method === "DELETE") {
      const reason = String(bodyOf(init).reason ?? "").trim();
      if (reason === "") return json({ error: "a reason is required for every staff change", code: "reason_required" }, 400);
      const entry = ALLOWLIST.find((e) => e.entry_id === decodeURIComponent(allowDel[1]) && !e.removed_at);
      if (!entry) return json({ error: "no active entry with that id", code: "not_found" }, 404);
      Object.assign(entry, { removed_at: iso(), removed_by: SELF, removed_reason: reason });
      return json(entry);
    }
    if (p === "/staff/api/log") {
      const verb = url.searchParams.get("verb");
      const org = url.searchParams.get("org");
      return json({ actions: LOG.filter((a) => (!verb || a.verb === verb) && (!org || a.org_id === org)) });
    }
    if (p === "/staff/auth/logout") return json(null, 204);
    return json({ error: "not in the dev mock", code: "not_found" }, 404);
  };
}

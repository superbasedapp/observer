// DEV-ONLY staff API mock: imported by main.tsx behind import.meta.env.DEV, so
// it is dropped from the production build. It patches window.fetch for
// /staff/* so the screens render under a bare `vite --config
// vite.staff.config.ts`. Mode from localStorage "sbci_staff_devmock":
// "admin" (default), "support" (read-only role), "signedout".

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

const INPUTS = [
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

export function installStaffDevMock(): void {
  const mode = (() => {
    try {
      return localStorage.getItem("sbci_staff_devmock") ?? "admin";
    } catch {
      return "admin";
    }
  })();
  const role = mode === "support" ? "support" : "admin";
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
        features: { orgs: true, availability_document: true, support_signin: true, team_allowlist: false, deletion_queue: false, plan_grant_write: false },
        capabilities: [
          { action: "availability.write", permitted: role !== "support", fresh: true },
          { action: "orgs.read", permitted: true, fresh: false },
        ],
        fresh_window_seconds: 900,
        max_reason_characters: 1000,
      });
    if (p === "/staff/api/orgs") return json({ orgs: ORGS });
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
      return json({ document: { version: 12, key_id: "Zk3mQ1xU9pRv2sT8yW4aB6cD0eF7gH5iJ1kL3mN9oP2", issued_at: "2026-11-16T09:00:00Z", issued_by: "system", body_bytes: 300, body: { issued_at: "2026-11-16T09:00:00Z", org_controls: [], components: [], release_flags: [] } } });
    if (p.startsWith("/staff/api/availability/")) return method === "DELETE" ? json(null, 204) : json({ ok: true });
    if (p === "/staff/api/log") {
      const verb = url.searchParams.get("verb");
      const org = url.searchParams.get("org");
      return json({ actions: LOG.filter((a) => (!verb || a.verb === verb) && (!org || a.org_id === org)) });
    }
    if (p === "/staff/auth/logout") return json(null, 204);
    return json({ error: "not in the dev mock", code: "not_found" }, 404);
  };
}

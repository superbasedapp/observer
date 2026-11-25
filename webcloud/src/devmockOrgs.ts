// DEV-ONLY mock of the console's org routes (plan 07 M6.5), imported only by
// devmock.ts (itself behind import.meta.env.DEV). One in-memory registry per
// page load covers every state the new pages render:
//
//   acme       an active team with a live Team subscription, seats reported,
//              the install link and its machines page link
//   beta-labs  a team waitlisted on capacity (refused:capacity_waitlist)
//   gamma      a team whose setup failed (parked)
//   delta      an active team, a member's view (no billing)
//
// The account owns three teams, so in "populated" mode it is at the team cap
// (W15-D12, default 3) and "Create a team" says so; a create past it answers
// 409 team_org_limit like the server. Creating a team adds a "queued" org
// that moves to "creating" and then "ready" on later reads, so the polling
// and the stage pills can be seen. In "empty" mode the account starts with
// no org.
//
// Deletion (plan 07 M6.9): delta (the member's view) has a deletion cooling
// off, so its page shows the status without a Cancel button; an owner team
// (acme) can be deleted by typing its slug, after which it cools off and an
// owner can cancel. `?deletion=purging|blocked|done|canceled` shows delta's
// deletion in that state instead (blocked shows a worded reason).
// `?deletion_reauth=broker_token|unavailable` changes the preview's
// re-authentication (default step_up, the mock signs in with WorkOS; a
// request is accepted with or without a step-up id, as after a recent
// passkey use), and `?deletion_refusal=personal_org|billing_cancel_unavailable`
// shows that refusal on an owner team. The account deletion precheck is derived
// from the registry: every team the account owns blocks it (acme pays for a
// live subscription), so deleting or leaving a team clears its row;
// `?precheck=clear` shows a precheck with no blocker, and `?precheck=stale`
// the same clear precheck with the deletion refused 409
// account_deletion_blocked (a blocker that appeared after the read).
//
// The personal org (D-IND-8): in "populated" mode the account has an active
// personal org, in "empty" mode it has none (so "Create my personal
// organization" shows). A flag overrides either, read from ?personal=<state>
// on the first load or localStorage "sbci_devmock_personal":
//
//   none | active | queued | waitlisted | failed | suspended
//
// POST /portal/api/orgs/personal answers 200 with the existing org, or adds
// a queued one (201) that moves through the stages like a created team.

import type {
  AccountDeletionBlocker,
  AccountDeletionPrecheck,
  OrgBillingView,
  OrgDeletionPreview,
  OrgDeletionReauth,
  OrgDeletionStatus,
  OrgDeletionView,
  OrgDetail,
  PortalOrg,
  ProvisioningStage,
} from "./api";

const TEAM_CAP = 3;

type Mode = "populated" | "empty" | "signedout" | "consent";

const DOMAIN = "superbased.app";
const RESERVED = new Set(["admin", "api", "app", "billing", "cloud", "www", "demo", "support", "status"]);

interface MockOrg {
  org: PortalOrg;
  billing: OrgBillingView | null;
  seats?: { in_use: number; members: number; day: string };
  reads: number;
  deletion?: OrgDeletionStatus | null;
}

const COOLING_OFF_DAYS = 30;

const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
const DAY = 24 * 3600_000;

const TEAM_PRICE = {
  price_id: "pri_dev_mock_team_monthly",
  plan_name: "team",
  plan_version: 1,
  interval: "month",
  display: "$12/seat/mo",
};

function checkout(available: boolean) {
  return {
    available,
    environment: "sandbox",
    client_token: available ? "test_dev_mock_token" : "",
    prices: available ? [TEAM_PRICE] : [],
    trial_days: 0,
  };
}

function org(slug: string, name: string, status: PortalOrg["status"], over: Partial<PortalOrg> = {}): PortalOrg {
  return {
    org_id: "org_dev_" + slug,
    slug,
    display_name: name,
    kind: "team",
    status,
    tenancy: "managed",
    console_role: "owner",
    is_billing_owner: true,
    created_at: iso(-20 * DAY),
    host: slug + "." + DOMAIN,
    ...over,
  };
}

function provisioning(stage: ProvisioningStage, extra: Partial<NonNullable<PortalOrg["provisioning"]>> = {}) {
  return { stage, attempts: 0, queued_at: iso(-3600_000), ...extra };
}

let registry: MockOrg[] | null = null;

type PersonalFlag = "none" | "active" | "queued" | "waitlisted" | "failed" | "suspended";
const PERSONAL_FLAGS: PersonalFlag[] = ["none", "active", "queued", "waitlisted", "failed", "suspended"];

function personalFlag(m: Mode): PersonalFlag {
  const ok = (v: string | null): v is PersonalFlag => !!v && (PERSONAL_FLAGS as string[]).includes(v);
  try {
    const q = new URLSearchParams(window.location.search).get("personal");
    if (ok(q)) return q;
  } catch {
    /* fall through */
  }
  try {
    const v = localStorage.getItem("sbci_devmock_personal");
    if (ok(v)) return v;
  } catch {
    /* fall through */
  }
  return m === "empty" ? "none" : "active";
}

const PERSONAL_PRICE = {
  price_id: "pri_dev_mock_personal_monthly",
  plan_name: "personal_pro",
  plan_version: 2,
  interval: "month",
  display: "$9/mo",
};

// personal builds the account's personal org in a given state.
function personal(state: Exclude<PersonalFlag, "none">): MockOrg {
  const over: Partial<PortalOrg> = {
    kind: "personal",
    tenancy: "individual",
    display_name: "Dev Developer",
  };
  const status: PortalOrg["status"] =
    state === "active" ? "active" : state === "suspended" ? "suspended" : "provisioning";
  if (state === "queued") over.provisioning = provisioning("queued", { state: "pending", queued_at: iso(0) });
  if (state === "waitlisted") {
    over.provisioning = provisioning("waitlisted", {
      state: "pending",
      attempts: 1,
      last_error_class: "refused:capacity_waitlist",
      next_attempt_at: iso(10 * 60_000),
    });
  }
  if (state === "failed") over.provisioning = provisioning("failed", { state: "failed", attempts: 6, last_error_class: "refused:conflict" });
  return {
    org: org("u-3f9a2c1d", "Dev Developer", status, over),
    billing: {
      has_subscription: false,
      plan: { name: "free", version: 1, label: "Free", source: "floor" },
      checkout: { ...checkout(true), prices: [PERSONAL_PRICE] },
      can_checkout: true,
      is_billing_owner: true,
    },
    reads: 0,
  };
}

function seed(m: Mode): MockOrg[] {
  const p = personalFlag(m);
  const mine = p === "none" ? [] : [personal(p)];
  if (m === "empty") return mine;
  return [
    ...mine,
    {
      org: org("acme", "Acme Engineering", "active"),
      billing: {
        has_subscription: true,
        subscription: {
          subscription_id: "sub_dev_acme",
          customer_id: "ctm_dev_acme",
          plan_name: "team",
          plan_version: 1,
          status: "active",
          current_period_end: iso(18 * DAY),
          management_urls: {
            update_payment_method: "https://sandbox-customer-portal.paddle.com/update",
            cancel: "https://sandbox-customer-portal.paddle.com/cancel",
          },
        },
        plan: { name: "team", version: 1, label: "Team", source: "subscription", seats_min: 3 },
        checkout: checkout(true),
        can_checkout: false,
        is_billing_owner: true,
      },
      seats: { in_use: 7, members: 9, day: iso(-DAY).slice(0, 10) },
      reads: 0,
    },
    {
      org: org("beta-labs", "Beta Labs", "provisioning", {
        provisioning: provisioning("waitlisted", {
          state: "pending",
          attempts: 2,
          last_error_class: "refused:capacity_waitlist",
          next_attempt_at: iso(12 * 60_000),
        }),
      }),
      billing: {
        has_subscription: false,
        plan: { name: "team_lapsed", version: 1, label: "Team (no active subscription)", source: "floor" },
        checkout: checkout(true),
        can_checkout: true,
        is_billing_owner: true,
      },
      reads: 0,
    },
    {
      org: org("gamma", "Gamma Research", "provisioning", {
        provisioning: provisioning("failed", { state: "failed", attempts: 6, last_error_class: "refused:conflict" }),
      }),
      billing: null,
      reads: 0,
    },
    {
      org: org("delta", "Delta Platform", "pending_deletion", { console_role: "member", is_billing_owner: false }),
      billing: null,
      seats: { in_use: 24, members: 30, day: iso(-DAY).slice(0, 10) },
      reads: 0,
      deletion: {
        request_id: "odr_dev_delta_01",
        state: "cooling_off",
        step: "cooling_off",
        origin: "owner",
        requested_at: iso(-3 * DAY),
        purge_after: iso(27 * DAY),
        can_cancel: true,
      },
    },
  ];
}

function orgs(m: Mode): MockOrg[] {
  if (registry === null) registry = seed(m);
  return registry;
}

function caps(o: PortalOrg) {
  const admin = o.console_role === "owner" || o.console_role === "admin";
  return {
    rename: admin && (o.status === "active" || o.status === "suspended"),
    view_billing: admin || o.is_billing_owner,
    checkout: o.is_billing_owner,
  };
}

// advance moves a freshly created org along its stages on each read.
function advance(mo: MockOrg) {
  mo.reads++;
  const p = mo.org.provisioning;
  if (!p || mo.org.status !== "provisioning") return;
  if (p.stage === "queued" && mo.reads >= 2) mo.org.provisioning = { ...p, stage: "creating", state: "sent", attempts: 1 };
  else if (p.stage === "creating" && mo.reads >= 4) {
    mo.org = { ...mo.org, status: "active", provisioning: undefined };
    if (mo.billing && mo.org.kind === "team") {
      mo.billing.plan = { name: "team", version: 1, label: "Team", source: "launch", not_after: iso(14 * DAY), seats_min: 3 };
    }
  }
}

function detail(mo: MockOrg): OrgDetail {
  const o = mo.org;
  const d: OrgDetail = { org: o, can: caps(o) };
  if (o.status === "active" && o.host) {
    d.launch_url = "https://" + o.host + "/me/install";
  }
  if (d.can.view_billing && mo.billing?.plan) d.plan = mo.billing.plan;
  if (mo.seats) d.seats = mo.seats;
  return d;
}

// listRow is an org as the list answers it: an active org carries its
// open and machines page links (portal_orgs.go orgJSON, built there by
// tenantlink.go; this dev mock stands in for that server).
function listRow(o: PortalOrg): PortalOrg {
  return o.status === "active" && o.host
    ? { ...o, open_url: "https://" + o.host + "/", machines_page_url: "https://" + o.host + "/me/profile" }
    : o;
}

// teamOrgs is the account's team count against the cap: the teams it owns
// (the server also counts teams it created).
function teamOrgs(list: MockOrg[]) {
  const used = list.filter((x) => x.org.kind === "team" && x.org.console_role === "owner").length;
  return { used, limit: TEAM_CAP, remaining: Math.max(0, TEAM_CAP - used) };
}

function body<T>(init: RequestInit | undefined): T {
  try {
    return JSON.parse(String(init?.body ?? "{}")) as T;
  } catch {
    return {} as T;
  }
}

function err(json: (b: unknown, s?: number) => Response, status: number, code: string, msg: string): Response {
  return json({ error: msg, code }, status);
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

function flag(name: string): string | null {
  try {
    return new URLSearchParams(window.location.search).get(name);
  } catch {
    return null;
  }
}

const OPEN_DELETION = new Set(["cooling_off", "purging", "blocked"]);

// deletionOf is the org's deletion, with ?deletion=<state> applied to delta.
function deletionOf(mo: MockOrg): OrgDeletionStatus | null {
  const d = mo.deletion ?? null;
  const want = flag("deletion");
  if (!d || mo.org.slug !== "delta" || !want) return d;
  switch (want) {
    case "purging":
      return { ...d, state: "purging", step: "delete_tables", can_cancel: false, purge_after: iso(-DAY) };
    case "blocked":
      return {
        ...d,
        state: "blocked",
        step: "drain_log",
        can_cancel: false,
        purge_after: iso(-DAY),
        blocked_reason: "host_purge_overdue",
      };
    case "done":
      return { ...d, state: "done", step: "recorded", can_cancel: false, purge_after: iso(-2 * DAY), done_at: iso(-DAY) };
    case "canceled":
      return { ...d, state: "canceled", can_cancel: false, canceled_at: iso(-DAY) };
    default:
      return d;
  }
}

// forcedRefusal is ?deletion_refusal=, when it names a refusal the mock shows.
function forcedRefusal(): OrgDeletionPreview["refusal"] {
  const want = flag("deletion_refusal");
  return want === "personal_org" || want === "billing_cancel_unavailable" ? want : "";
}

// mockReauth is ?deletion_reauth=, step_up by default.
function mockReauth(): OrgDeletionReauth {
  const want = flag("deletion_reauth");
  return want === "broker_token" || want === "unavailable" ? want : "step_up";
}

function deletionPreview(mo: MockOrg): OrgDeletionPreview {
  const owner = mo.org.console_role === "owner";
  const open = OPEN_DELETION.has(deletionOf(mo)?.state ?? "");
  const refusal: OrgDeletionPreview["refusal"] = !owner
    ? "not_owner"
    : mo.org.kind === "personal"
      ? "personal_org"
      : open
        ? "deletion_open"
        : forcedRefusal();
  return {
    can_request: refusal === "",
    refusal,
    cooling_off_days: COOLING_OFF_DAYS,
    purge_after: iso(COOLING_OFF_DAYS * DAY),
    live_subscription: mo.billing?.subscription?.status === "active",
    members: mo.seats?.members ?? 1,
    kept: ["usage_counts", "deletion_record"],
    reauth: mockReauth(),
  };
}

function deletionView(mo: MockOrg): OrgDeletionView {
  return { deletion: deletionOf(mo), preview: deletionPreview(mo) };
}

function routeOrgDeletion(
  mo: MockOrg,
  method: string,
  init: RequestInit | undefined,
  json: (b: unknown, s?: number) => Response,
): Response | null {
  if (method === "GET") return json(deletionView(mo));
  if (method === "POST") {
    const p = deletionPreview(mo);
    if (p.refusal === "not_owner") return err(json, 403, "not_owner", "only an owner of the org can delete it");
    if (p.refusal === "deletion_open") return err(json, 409, "deletion_open", "the org already has a deletion in progress");
    if (p.refusal === "personal_org") return err(json, 409, "personal_org", "a personal org is deleted with its account");
    if (p.refusal === "org_not_deletable") return err(json, 409, "org_not_deletable", "this org cannot be deleted");
    const b = body<{ confirm_slug?: string; broker_token?: string; step_up_authorization_id?: string }>(init);
    if ((b.confirm_slug ?? "").trim() !== mo.org.slug) {
      return err(json, 400, "confirm_mismatch", "confirm_slug does not match the org's slug");
    }
    if (p.refusal === "billing_cancel_unavailable") {
      return err(json, 409, "billing_cancel_unavailable", "the subscription cannot be canceled automatically");
    }
    // Any step-up id is accepted, and none (a recent passkey use); a dev
    // sign-in needs a broker token, any one.
    if (p.reauth === "unavailable") {
      return err(json, 501, "provider_not_configured", "re-authentication is not available on this deployment");
    }
    if (p.reauth === "broker_token" && !(b.broker_token ?? "").trim()) {
      return err(json, 401, "reauth_required", "re-enter your credential to confirm deleting the team");
    }
    mo.deletion = {
      request_id: "odr_dev_" + mo.org.slug + "_" + Math.random().toString(36).slice(2, 8),
      state: "cooling_off",
      step: "cooling_off",
      origin: "owner",
      requested_at: iso(0),
      purge_after: p.purge_after,
      can_cancel: true,
    };
    mo.org = { ...mo.org, status: "pending_deletion" };
    return json(mo.deletion, 202);
  }
  if (method === "DELETE") {
    if (mo.org.console_role !== "owner") return err(json, 403, "not_owner", "only an owner of the org can cancel its deletion");
    const d = deletionOf(mo);
    if (!d || !d.can_cancel) {
      return err(json, 409, "not_cancellable", "the deletion can no longer be canceled");
    }
    mo.deletion = { ...d, state: "canceled", can_cancel: false, canceled_at: iso(0) };
    mo.org = { ...mo.org, status: "active" };
    return json(mo.deletion);
  }
  return null;
}

const PERSONAL = { org_id: "org_dev_personal", slug: "u-dev-local", display_name: "Personal" };

// accountBlockers derives the precheck's blockers from the registry: each
// live team the account owns blocks it, by the first matching rule.
function accountBlockers(m: Mode): AccountDeletionBlocker[] {
  const out: AccountDeletionBlocker[] = [];
  for (const mo of orgs(m)) {
    const o = mo.org;
    if (o.kind !== "team" || o.console_role !== "owner") continue;
    if (OPEN_DELETION.has(deletionOf(mo)?.state ?? "") || o.status === "purged") continue;
    const ref = { org_id: o.org_id, slug: o.slug, display_name: o.display_name };
    if (mo.billing?.subscription?.status === "active" && o.is_billing_owner) out.push({ code: "pays_for_live_org", ...ref });
    else if ((mo.seats?.members ?? 1) > 1) out.push({ code: "sole_owner_with_members", ...ref });
    else out.push({ code: "sole_owner_alone", ...ref });
  }
  return out;
}

function precheck(m: Mode): AccountDeletionPrecheck {
  const f = flag("precheck");
  const blockers = f === "clear" || f === "stale" ? [] : accountBlockers(m);
  return {
    can_delete: blockers.length === 0,
    blockers,
    personal_org: PERSONAL,
    memberships_removed: orgs(m)
      .filter((x) => x.org.kind === "team" && x.org.console_role !== "owner")
      .map((x) => ({ org_id: x.org.org_id, slug: x.org.slug, display_name: x.org.display_name })),
  };
}

/** routeAccountDeletion answers the account deletion precheck, and refuses
 * the account deletion itself while a team blocks it (or always, under
 * ?precheck=stale); null lets the default deletion answer through. */
export function routeAccountDeletion(
  path: string,
  method: string,
  m: Mode,
  json: (b: unknown, s?: number) => Response,
): Response | null {
  if (path === "/portal/api/account/deletion-precheck" && method === "GET") return json(precheck(m));
  if (path === "/portal/api/deletion-requests" && method === "POST") {
    const blockers = flag("precheck") === "stale" ? accountBlockers(m) : precheck(m).blockers;
    if (blockers.length > 0) {
      return json(
        {
          error:
            "Your account cannot be deleted yet: a team you own or pay for needs a change first. Each team below says what to do.",
          code: "account_deletion_blocked",
          blockers,
        },
        409,
      );
    }
  }
  return null;
}

/** routeOrgs answers the console's org routes, or returns null. */
export function routeOrgs(
  path: string,
  method: string,
  init: RequestInit | undefined,
  search: string,
  m: Mode,
  json: (b: unknown, s?: number) => Response,
): Response | null {
  if (!path.startsWith("/portal/api/orgs")) return null;
  const list = orgs(m);
  if (path === "/portal/api/orgs" && method === "GET") {
    list.forEach(advance);
    return json({ orgs: list.map((x) => listRow(x.org)), tenant_domain: DOMAIN, team_orgs: teamOrgs(list) });
  }
  if (path === "/portal/api/orgs/slug-availability") {
    const slug = (new URLSearchParams(search).get("slug") ?? "").trim().toLowerCase();
    if (!/^[a-z0-9]([a-z0-9-]{1,38})[a-z0-9]$/.test(slug) || slug.includes("--") || slug.startsWith("u-")) {
      return json({ slug, available: false, reason: "invalid" });
    }
    if (RESERVED.has(slug)) return json({ slug, available: false, reason: "reserved" });
    if (list.some((x) => x.org.slug === slug)) {
      return json({ slug, available: false, reason: "taken", host: slug + "." + DOMAIN });
    }
    return json({ slug, available: true, host: slug + "." + DOMAIN });
  }
  if (path === "/portal/api/orgs" && method === "POST") {
    const b = body<{ display_name?: string; slug?: string }>(init);
    const slug = (b.slug ?? "").trim().toLowerCase();
    if (RESERVED.has(slug)) return err(json, 400, "slug_reserved", "that name is reserved");
    if (list.some((x) => x.org.slug === slug)) return err(json, 409, "slug_taken", "that address is taken");
    if (teamOrgs(list).remaining <= 0) {
      return err(json, 409, "team_org_limit", `you already have ${TEAM_CAP} team orgs, the most one account can create. We can raise this on request: contact support with how many you need.`);
    }
    const mo: MockOrg = {
      org: org(slug, (b.display_name ?? "").trim(), "provisioning", {
        created_at: iso(0),
        provisioning: provisioning("queued", { state: "pending", queued_at: iso(0) }),
      }),
      billing: {
        has_subscription: false,
        plan: { name: "team_lapsed", version: 1, label: "Team (no active subscription)", source: "floor" },
        checkout: checkout(true),
        can_checkout: true,
        is_billing_owner: true,
      },
      reads: 0,
    };
    list.push(mo);
    return json(detail(mo), 201);
  }
  if (path === "/portal/api/orgs/personal" && method === "POST") {
    const existing = list.find((x) => x.org.kind === "personal");
    if (existing) return json(detail(existing), 200);
    const mo = personal("queued");
    list.unshift(mo);
    return json(detail(mo), 201);
  }
  const rest = path.slice("/portal/api/orgs/".length).split("/");
  const mo = list.find((x) => x.org.org_id === decodeURIComponent(rest[0] ?? ""));
  if (!mo) return err(json, 404, "not_found", "org not found");
  if (rest.length === 1 && method === "GET") {
    advance(mo);
    return json(detail(mo));
  }
  if (rest.length === 1 && method === "PATCH") {
    if (mo.org.status === "provisioning") {
      return err(json, 409, "org_provisioning", "the team is still being created; rename it once it is ready");
    }
    if (!caps(mo.org).rename) return err(json, 403, "forbidden", "only an org owner or admin may rename the org");
    const b = body<{ display_name?: string }>(init);
    mo.org = { ...mo.org, display_name: (b.display_name ?? "").trim() || mo.org.display_name };
    return json(detail(mo));
  }
  if (rest[1] === "deletion" && rest.length === 2) {
    return routeOrgDeletion(mo, method, init, json);
  }
  if (rest[1] === "billing" && rest.length === 2) {
    if (!caps(mo.org).view_billing || !mo.billing) {
      return err(json, 403, "forbidden", "only an org owner, admin or billing owner can see billing");
    }
    return json(mo.billing);
  }
  if (rest[1] === "billing" && rest[2] === "checkout" && method === "POST") {
    if (!mo.org.is_billing_owner) return err(json, 403, "billing_owner_required", "only the billing owner");
    if (mo.billing?.subscription && mo.billing.subscription.status === "active") {
      return err(json, 409, "already_subscribed", "this team already holds a live subscription");
    }
    return json({
      price_id: TEAM_PRICE.price_id,
      expires_at: iso(30 * 60_000),
      custom_data: {
        account_id: "acct_dev_local",
        org_id: mo.org.org_id,
        checkout_nonce: "nonce_dev_mock_" + Math.random().toString(36).slice(2),
      },
    });
  }
  return null;
}

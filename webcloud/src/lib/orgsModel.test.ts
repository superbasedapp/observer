import assert from "node:assert/strict";
import test from "node:test";

import {
  BILLING_TEXT,
  CREATE_ERROR_TEXT,
  MANAGED_TEAM_NOTICE,
  PLAN_SOURCE_TEXT,
  PROVISIONING_STAGE,
  billingState,
  createFormView,
  machineLinks,
  orgStatusView,
  slugShapeProblem,
  stageView,
  suggestSlug,
  teamCapView,
  type AvailabilityState,
} from "./orgsModel.ts";
import type { OrgBillingView, PortalOrg } from "../api.ts";

// The console's team org rules (plan 07 M6.5): the slug shape mirror, the
// create form, the managed notice and the team cap, the provisioning and
// waitlist vocabulary, the billing states and the per-team machines links.

test("slug shape: one case per rule, and a good slug", () => {
  const cases: [string, ReturnType<typeof slugShapeProblem>][] = [
    ["", "empty"],
    ["ab", "length"],
    ["a".repeat(41), "length"],
    ["Acme", "charset"],
    ["acme_eng", "charset"],
    ["-acme", "hyphen-edges"],
    ["acme-", "hyphen-edges"],
    ["ac--me", "hyphen-edges"],
    ["u-abcdefgh", "personal-prefix"],
    ["acme-eng", null],
    ["a1b", null],
  ];
  for (const [slug, want] of cases) assert.equal(slugShapeProblem(slug), want, slug);
});

test("a suggested slug is always well shaped", () => {
  const cases: [string, string][] = [
    ["Acme Engineering", "acme-engineering"],
    ["  Café Ünïcode!! ", "cafe-unicode"],
    ["U-Boat Team", "boat-team"],
    ["---", ""],
    ["x".repeat(60) + " y", "x".repeat(40)],
  ];
  for (const [name, want] of cases) {
    const got = suggestSlug(name);
    assert.equal(got, want, name);
    if (got.length >= 3) assert.equal(slugShapeProblem(got), null, got);
  }
});

const answered = (slug: string, available: boolean, reason?: "invalid" | "reserved" | "taken"): AvailabilityState => ({
  kind: "answered",
  answer: { slug, available, reason, host: available || reason === "taken" ? slug + ".superbased.app" : undefined },
});

test("create form: submit only for a named team on an available slug", () => {
  const ok = createFormView({ name: "Acme", slug: "acme", availability: answered("acme", true), submitting: false });
  assert.equal(ok.canSubmit, true);
  assert.equal(ok.host, "acme.superbased.app");
  assert.equal(ok.slugTone, "success");

  const cases: { name: string; input: Parameters<typeof createFormView>[0]; message: RegExp | null }[] = [
    { name: "no name", input: { name: " ", slug: "acme", availability: answered("acme", true), submitting: false }, message: /Available/ },
    { name: "bad shape answers before any request", input: { name: "A", slug: "ac--me", availability: { kind: "idle" }, submitting: false }, message: /hyphen/ },
    { name: "checking", input: { name: "A", slug: "acme", availability: { kind: "checking", slug: "acme" }, submitting: false }, message: /Checking/ },
    { name: "a stale answer for another slug", input: { name: "A", slug: "acme2", availability: answered("acme", true), submitting: false }, message: /Checking/ },
    { name: "taken", input: { name: "A", slug: "acme", availability: answered("acme", false, "taken"), submitting: false }, message: /taken/ },
    { name: "reserved", input: { name: "A", slug: "admin", availability: answered("admin", false, "reserved"), submitting: false }, message: /reserved/ },
    { name: "check failed", input: { name: "A", slug: "acme", availability: { kind: "error", slug: "acme", message: "offline" }, submitting: false }, message: /offline/ },
    { name: "submitting", input: { name: "A", slug: "acme", availability: answered("acme", true), submitting: true }, message: /Available/ },
    { name: "name too long", input: { name: "n".repeat(101), slug: "acme", availability: answered("acme", true), submitting: false }, message: /Available/ },
  ];
  for (const tc of cases) {
    const v = createFormView(tc.input);
    assert.equal(v.canSubmit, false, tc.name);
    if (tc.message) assert.match(v.slugMessage ?? "", tc.message, tc.name);
  }
  // The host is never composed in the browser: no answer, no host.
  assert.equal(createFormView({ name: "A", slug: "acme", availability: { kind: "checking", slug: "acme" }, submitting: false }).host, null);
  assert.match(createFormView({ name: "n".repeat(101), slug: "acme", availability: answered("acme", true), submitting: false }).nameError ?? "", /at most 100/);
});

const team = (over: Partial<PortalOrg> = {}): PortalOrg => ({
  org_id: "o1",
  slug: "acme",
  display_name: "Acme",
  kind: "team",
  status: "active",
  tenancy: "managed",
  console_role: "owner",
  is_billing_owner: true,
  created_at: "2026-11-15T00:00:00Z",
  ...over,
});

test("a provisioning org is labelled by its stage; a waitlisted team says so and keeps polling", () => {
  const waitlisted = team({ status: "provisioning", provisioning: { stage: "waitlisted", attempts: 2 } });
  assert.deepEqual(orgStatusView(waitlisted), { label: "Waitlisted", tone: "warn" });
  assert.equal(stageView("waitlisted").pending, true);
  assert.match(stageView("waitlisted").sentence, /waitlist/);
  assert.equal(stageView("failed").pending, false);
  assert.equal(stageView("ready").pending, false);
  assert.equal(stageView("no-such-stage").label, "Unknown");
  assert.deepEqual(orgStatusView(team()), { label: "Active", tone: "success" });
  // Every server stage has a row.
  for (const s of ["ready", "closing", "unknown", "failed", "finishing", "waitlisted", "queued", "retrying", "creating"]) {
    assert.ok(PROVISIONING_STAGE[s as keyof typeof PROVISIONING_STAGE], s);
  }
});

const billing = (over: Partial<OrgBillingView> = {}): OrgBillingView => ({
  has_subscription: false,
  checkout: { available: true, environment: "sandbox", client_token: "test_x", prices: [{ price_id: "p", plan_name: "team", plan_version: 1, interval: "month", display: "" }], trial_days: 0 },
  can_checkout: true,
  is_billing_owner: true,
  ...over,
});
const sub = (status: string) => ({ subscription_id: "s", customer_id: "c", plan_name: "team", plan_version: 1, status }) as OrgBillingView["subscription"];

test("billing state: one case per rule", () => {
  const cases: [string, OrgBillingView, string][] = [
    ["trialing", billing({ has_subscription: true, subscription: sub("trialing"), can_checkout: false }), "trialing"],
    ["past due", billing({ has_subscription: true, subscription: sub("past_due"), can_checkout: false }), "past_due"],
    ["active", billing({ has_subscription: true, subscription: sub("active"), can_checkout: false }), "subscribed"],
    ["admin, not billing owner", billing({ is_billing_owner: false, can_checkout: false }), "owner_only"],
    ["no prices configured", billing({ checkout: { available: false, environment: "sandbox", client_token: "", prices: [], trial_days: 0 } }), "checkout_unconfigured"],
    ["canceled, can resubscribe", billing({ has_subscription: true, subscription: sub("canceled") }), "ended"],
    ["fresh", billing(), "can_subscribe"],
    ["org closing", billing({ can_checkout: false }), "not_billable"],
  ];
  for (const [name, v, want] of cases) {
    assert.equal(billingState(v), want, name);
    assert.ok(BILLING_TEXT[billingState(v)], name);
  }
});

test("machines: one server-built link per active team, nothing read from a tenant", () => {
  const links = machineLinks([
    team({ org_id: "a", display_name: "A", host: "a.superbased.app", machines_page_url: "https://a.superbased.app/me/profile" }),
    team({ org_id: "b", display_name: "B", status: "provisioning", machines_page_url: "https://b.superbased.app/me/profile" }),
    team({ org_id: "c", display_name: "C" }),
    team({ org_id: "d", display_name: "D", slug: "d", status: "suspended", machines_page_url: "https://d.superbased.app/me/profile" }),
  ]);
  assert.deepEqual(links, [{ orgId: "a", orgName: "A", host: "a.superbased.app", url: "https://a.superbased.app/me/profile" }]);
});

test("team cap: under, at and barred, and unknown lets the server decide", () => {
  const under = teamCapView({ used: 1, limit: 3, remaining: 2 });
  assert.equal(under.canCreate, true);
  assert.match(under.note ?? "", /2 more teams \(up to 3 per account; we can raise this on request\)/);

  const one = teamCapView({ used: 2, limit: 3, remaining: 1 });
  assert.match(one.note ?? "", /1 more team \(/);

  const at = teamCapView({ used: 3, limit: 3, remaining: 0 });
  assert.equal(at.canCreate, false);
  assert.match(at.note ?? "", /You have 3 teams, the most one account can create \(3\)\. We can raise this on request/);

  const invited = teamCapView({ used: 0, limit: 3, remaining: 3, invite_only: true, create_allowed: true });
  assert.equal(invited.canCreate, true);

  const uninvited = teamCapView({ used: 0, limit: 3, remaining: 3, invite_only: true, create_allowed: false, account_ref: "acct-1" });
  assert.equal(uninvited.canCreate, false);
  assert.match(uninvited.note ?? "", /by invitation while superbased is in early access\. Your personal dashboard works as usual\./);
  assert.match(uninvited.note ?? "", /quote your account reference: acct-1\.$/);
  assert.match(CREATE_ERROR_TEXT.team_create_invite_only ?? "", /by invitation/);

  const barred = teamCapView({ used: 0, limit: 0, remaining: 0 });
  assert.equal(barred.canCreate, false);
  assert.match(barred.note ?? "", /cannot create teams/);

  assert.deepEqual(teamCapView(undefined), { canCreate: true, note: null });
  assert.match(CREATE_ERROR_TEXT.team_org_limit, /raise this on request/);
});

test("the team notice says full detail is sent and admins can read it", () => {
  assert.equal(MANAGED_TEAM_NOTICE.title, "Full detail");
  assert.match(MANAGED_TEAM_NOTICE.body, /prompts, responses and file paths/);
  assert.match(MANAGED_TEAM_NOTICE.body, /admins can read it/);
});

test("an operator grant names its plan source", () => {
  assert.equal(PLAN_SOURCE_TEXT.org_grant, "Granted by superbased");
});

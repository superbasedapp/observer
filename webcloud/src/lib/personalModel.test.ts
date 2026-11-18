import assert from "node:assert/strict";
import test from "node:test";

import {
  EARLIER_RESULTS_LINK,
  LEGACY_RULES,
  PERSONAL_BILLING_TEXT,
  PERSONAL_ORG_FACTS,
  PERSONAL_STAGE_SENTENCE,
  billingTextFor,
  legacyView,
  orgNoun,
  personalCardState,
  personalCardView,
  personalCreateError,
  personalOrg,
  personalPlaneOf,
  stageViewFor,
  subscribeLabel,
  teamOrgsOf,
  type PersonalCardState,
} from "./personalModel.ts";
import { BILLING_TEXT, PROVISIONING_STAGE } from "./orgsModel.ts";
import type { PortalOrg, ProvisioningStage } from "../api.ts";

// The console's personal org rules (D-IND-8): which org is personal, the
// personal card's state table, the personal wording of stages and billing,
// and the old personal pages' rule per personal_plane value.

function org(over: Partial<PortalOrg> = {}): PortalOrg {
  return {
    org_id: "org_p",
    slug: "u-3f9a2c1d",
    display_name: "Dev Developer",
    kind: "personal",
    status: "active",
    tenancy: "individual",
    console_role: "owner",
    is_billing_owner: true,
    created_at: "2026-11-01T00:00:00Z",
    host: "u-3f9a2c1d.superbased.app",
    ...over,
  };
}

test("personalOrg picks the personal org; teamOrgsOf keeps the rest in order", () => {
  const p = org();
  const a = org({ org_id: "a", kind: "team", slug: "acme" });
  const b = org({ org_id: "b", kind: "team", slug: "beta" });
  assert.equal(personalOrg([a, p, b]), p);
  assert.equal(personalOrg([a, b]), undefined);
  assert.equal(personalOrg(undefined), undefined);
  assert.deepEqual(teamOrgsOf([a, p, b]).map((o) => o.org_id), ["a", "b"]);
  assert.deepEqual(teamOrgsOf(undefined), []);
});

test("personal card state table: one case per row", () => {
  const cases: [string, Parameters<typeof personalCardState>[0], PersonalCardState][] = [
    ["no org, idle", { creating: false }, "none"],
    ["no org, request in flight", { creating: true }, "creating"],
    ["failed stage", { org: org({ status: "provisioning", provisioning: { stage: "failed", attempts: 6 } }), creating: false }, "failed"],
    ["queued stage", { org: org({ status: "provisioning", provisioning: { stage: "queued", attempts: 0 } }), creating: false }, "provisioning"],
    ["waitlisted stage", { org: org({ status: "provisioning", provisioning: { stage: "waitlisted", attempts: 2 } }), creating: false }, "provisioning"],
    ["provisioning, no progress row", { org: org({ status: "provisioning" }), creating: false }, "provisioning"],
    ["active", { org: org(), creating: false }, "active"],
    ["active wins over a stale creating flag", { org: org(), creating: true }, "active"],
    ["suspended", { org: org({ status: "suspended" }), creating: false }, "suspended"],
    ["deletion scheduled", { org: org({ status: "pending_deletion" }), creating: false }, "closing"],
    ["purging", { org: org({ status: "purging" }), creating: false }, "closing"],
  ];
  for (const [name, input, want] of cases) assert.equal(personalCardState(input), want, name);
});

test("personal card view: nothing offers a create (it is made at sign-in), only 'active' shows the links", () => {
  const none = personalCardView({ creating: false });
  assert.equal(none.canCreate, false);
  assert.equal(none.pending, true);
  assert.equal(none.sentence, "Setting up your personal dashboard...");
  assert.equal(none.showLinks, false);

  const creating = personalCardView({ creating: true });
  assert.equal(creating.canCreate, false);
  assert.equal(creating.pending, true);

  const active = personalCardView({ org: org(), creating: false });
  assert.equal(active.canCreate, false);
  assert.equal(active.showLinks, true);
  assert.deepEqual(active.pill, { label: "Active", tone: "success" });

  const waitlisted = personalCardView({
    org: org({ status: "provisioning", provisioning: { stage: "waitlisted", attempts: 1 } }),
    creating: false,
  });
  assert.equal(waitlisted.pill?.label, "Waitlisted");
  assert.equal(waitlisted.pending, true);
  assert.match(waitlisted.sentence, /personal dashboard is on the waitlist/);
  assert.equal(waitlisted.showLinks, false);

  const failed = personalCardView({
    org: org({ status: "provisioning", provisioning: { stage: "failed", attempts: 6 } }),
    creating: false,
  });
  assert.equal(failed.pill?.tone, "danger");
  assert.equal(failed.pending, false);

  const suspended = personalCardView({ org: org({ status: "suspended" }), creating: false });
  assert.equal(suspended.pill?.tone, "warn");
  assert.equal(suspended.showLinks, false);

  const closing = personalCardView({ org: org({ status: "pending_deletion" }), creating: false });
  assert.equal(closing.pill?.label, "Deletion scheduled");
  assert.equal(closing.canCreate, false);
});

test("every stage keeps the shared label, tone and pending flag, with a personal sentence", () => {
  for (const stage of Object.keys(PROVISIONING_STAGE) as ProvisioningStage[]) {
    const p = stageViewFor(stage, "personal");
    const t = stageViewFor(stage, "team");
    assert.equal(p.label, PROVISIONING_STAGE[stage].label, stage);
    assert.equal(p.tone, PROVISIONING_STAGE[stage].tone, stage);
    assert.equal(p.pending, PROVISIONING_STAGE[stage].pending, stage);
    assert.equal(p.sentence, PERSONAL_STAGE_SENTENCE[stage], stage);
    assert.doesNotMatch(p.sentence, /team/i, stage);
    assert.equal(t.sentence, PROVISIONING_STAGE[stage].sentence, stage);
  }
  // An unknown stage reads as unknown for both kinds.
  assert.equal(stageViewFor("bogus", "personal").sentence, PERSONAL_STAGE_SENTENCE.unknown);
  assert.equal(stageViewFor(undefined, "personal").label, "Unknown");
});

test("what a personal dashboard is says one member, Summary only and free", () => {
  assert.match(PERSONAL_ORG_FACTS.members, /one member: you/);
  assert.match(PERSONAL_ORG_FACTS.privacy, /^Summary only/);
  assert.match(PERSONAL_ORG_FACTS.privacy, /Never prompts, responses or file contents/);
  assert.match(PERSONAL_ORG_FACTS.price, /free/);
});

test("create errors: known codes are worded, others carry the server's message", () => {
  assert.match(personalCreateError("forbidden", "x"), /cannot create a personal dashboard/);
  assert.match(personalCreateError("", "server is busy"), /server is busy/);
  assert.match(personalCreateError("weird", ""), /request failed/);
});

test("billing and nouns per kind: a personal org never reads as a team", () => {
  for (const state of Object.keys(PERSONAL_BILLING_TEXT) as (keyof typeof PERSONAL_BILLING_TEXT)[]) {
    assert.doesNotMatch(billingTextFor(state, "personal"), /team/i, state);
    assert.equal(billingTextFor(state, "team"), BILLING_TEXT[state], state);
  }
  assert.equal(subscribeLabel("can_subscribe", "personal"), "Subscribe");
  assert.equal(subscribeLabel("can_subscribe", "team"), "Subscribe to Team");
  assert.equal(subscribeLabel("ended", "personal"), "Subscribe again");
  assert.equal(orgNoun("personal"), "personal dashboard");
  assert.equal(orgNoun("team"), "team");
});

test("personal_plane: only an exact 'retired' retires; the legacy rule follows", () => {
  const cases: [unknown, "serving" | "retired"][] = [
    [undefined, "serving"],
    [null, "serving"],
    ["serving", "serving"],
    ["retired", "retired"],
    ["RETIRED", "serving"],
    ["", "serving"],
  ];
  for (const [raw, want] of cases) assert.equal(personalPlaneOf(raw), want, String(raw));
  assert.deepEqual(legacyView(undefined), { showEarlierLink: true, showNavSection: true, routes: "page" });
  assert.deepEqual(legacyView("retired"), { showEarlierLink: false, showNavSection: false, routes: "moved" });
  assert.deepEqual(LEGACY_RULES.serving, legacyView("serving"));
  assert.equal(EARLIER_RESULTS_LINK.to, "/sessions");
  assert.match(EARLIER_RESULTS_LINK.label, /^Earlier AI summaries \(until they move to your personal dashboard\)$/);
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  ORG_INTEL_CARD_MODES,
  ORG_INTEL_PHASES,
  orgIntelCardMode,
  orgIntelOrgName,
  orgIntelEnrichButton,
  orgIntelSubmissionState,
  sessionEffectiveTitle,
  type OrgIntelSessionView,
  orgIntelBanner,
  orgIntelBannerDismissKey,
  ORG_INTEL_LEVEL_LABELS,
  orgIntelLevelLabel,
  orgIntelPhase,
  orgIntelSessionsBanner,
  ORG_SESSIONS_BANNER_STATES,
  type OrgIntelStatus,
  orgIntelBackgroundLine,
  orgPlaneEnrichAction,
  SESSION_ENRICH_PLANE_COPY,
  sessionEnrichPlane,
} from "./orgIntel.ts";

const req = {
  enabled: true,
  provider_label: "Azure OpenAI",
  model: "gpt-x",
  evidence_level: "titles",
  purposes: ["structural_activity_insights"],
  developer_actions: true,
  per_developer_daily_cap: 20,
  require_individual_consent: true,
  requirement_version: 2,
  deadline_days: 0,
  doc_version: 5,
};

function st(over: Partial<OrgIntelStatus>): OrgIntelStatus {
  return {
    class: "individual",
    org_name: "Acme",
    requirement: req,
    org_enabled: true,
    required: true,
    pending: false,
    covered: false,
    config_opt_in: false,
    effective_opt_in: false,
    notice_only: false,
    deadline_passed: false,
    history: [],
    receipts: [],
    cached_results: 0,
    ...over,
  };
}

// One case per row of the phase table, in table order.
test("orgIntelPhase walks the table top-down", () => {
  const cases: Array<[OrgIntelStatus, string]> = [
    [st({ class: "unenrolled" }), "unenrolled"],
    [st({ requirement: undefined }), "no_terms"],
    [st({ class: "managed", notice_only: true }), "managed_notice"],
    [st({ pending: true, pending_reason: "terms_changed" }), "terms_changed"],
    [st({ pending: true, pending_reason: "not_accepted" }), "pending_required"],
    [st({ org_enabled: false }), "org_off"],
    [st({ effective_opt_in: true }), "accepted"],
    [st({ required: false }), "not_opted_in"],
  ];
  assert.equal(cases.length, ORG_INTEL_PHASES.length);
  cases.forEach(([s, want], i) => {
    assert.equal(orgIntelPhase(s), want);
    assert.equal(ORG_INTEL_PHASES[i], want);
  });
});

test("the banner shows only for a pending individual node", () => {
  assert.equal(orgIntelBanner(null), null);
  assert.equal(orgIntelBanner(st({})), null);
  assert.equal(orgIntelBanner(st({ class: "managed", pending: true })), null);
  const b = orgIntelBanner(st({ pending: true, pending_reason: "not_accepted" }));
  assert.ok(b && b.text.startsWith("Acme now requires AI summaries. Accept, or leave the team."));
  const late = orgIntelBanner(st({ pending: true, deadline_passed: true }));
  assert.ok(late && /deadline has passed/.test(late.text));
  const changed = orgIntelBanner(st({ pending: true, pending_reason: "terms_changed" }));
  assert.ok(changed && changed.title === "Updated terms");
  for (const x of [b, late, changed]) assert.ok(!/—/.test(x!.text), "no em dash in copy");
});

test("a dismissal is scoped to the terms version", () => {
  const a = orgIntelBannerDismissKey(st({ pending: true }));
  const b = orgIntelBannerDismissKey(st({ pending: true, requirement: { ...req, requirement_version: 3 } }));
  assert.notEqual(a, b);
});

test("level labels fall back to the narrowest", () => {
  assert.equal(orgIntelLevelLabel("excerpts"), "Metadata and bounded excerpts");
  assert.equal(orgIntelLevelLabel("everything"), "Metadata only");
  assert.equal(orgIntelLevelLabel(undefined), "Metadata only");
});

function sv(over: Partial<OrgIntelSessionView>): OrgIntelSessionView {
  return {
    session_id: "s1",
    authority: "org",
    class: "individual",
    actions: { preview: true, enrich: true, needs_preview: true },
    submissions: 0,
    enriched: false,
    ...over,
  };
}

test("session card mode table: one case per row, in order", () => {
  const cases: Array<[OrgIntelSessionView, string]> = [
    [sv({ authority: "personal" }), "hidden"],
    [sv({ authority: "personal", enriched: true }), "result_only"],
    [sv({ actions: { preview: false, enrich: false, needs_preview: false, reason: "org_off" } }), "unavailable"],
    [sv({}), "actions"],
  ];
  assert.deepEqual(cases.map(([, m]) => m), [...ORG_INTEL_CARD_MODES]);
  for (const [v, mode] of cases) assert.equal(orgIntelCardMode(v), mode);
  // An org session with a past submission keeps the actions view even when
  // the actions are closed now (the ledger line still renders).
  const latest = { id: 1, state: "refused" } as OrgIntelSessionView["latest"];
  assert.equal(orgIntelCardMode(sv({ actions: { preview: false, enrich: false, needs_preview: false }, latest })), "actions");
});

test("enrich button: preview first for individual, direct for managed, re-enrich once submitted", () => {
  assert.deepEqual(orgIntelEnrichButton(sv({ actions: { preview: true, enrich: false, needs_preview: false } }), ""), {
    show: false, label: "", enabled: false,
  });
  const gated = orgIntelEnrichButton(sv({}), "");
  assert.equal(gated.enabled, false);
  assert.match(gated.hint ?? "", /Preview the evidence first/);
  assert.deepEqual(orgIntelEnrichButton(sv({}), "sha256:x"), { show: true, label: "Confirm and enrich", enabled: true });
  assert.deepEqual(orgIntelEnrichButton(sv({ actions: { preview: true, enrich: true, needs_preview: false } }), ""), {
    show: true, label: "Enrich", enabled: true,
  });
  assert.equal(orgIntelEnrichButton(sv({ enriched: true, actions: { preview: true, enrich: true, needs_preview: false } }), "").label, "Re-enrich");
});

test("session effective title: user, then personal AI, then org AI", () => {
  assert.deepEqual(sessionEffectiveTitle({ title: "Mine", cloud_title: "C", org_title: "O" }), { text: "Mine", source: "user" });
  assert.deepEqual(sessionEffectiveTitle({ cloud_title: "C", org_title: "O" }), { text: "C", source: "cloud" });
  assert.deepEqual(sessionEffectiveTitle({ org_title: "O" }), { text: "O", source: "org" });
  assert.deepEqual(sessionEffectiveTitle({}), { text: "", source: "none" });
});

test("submission state labels cover every outbox state and fall back to the raw value", () => {
  for (const s of ["pending", "failed_retryable", "submitted", "duplicate", "already_enriched", "refused"]) {
    assert.notEqual(orgIntelSubmissionState(s).label, s);
  }
  assert.equal(orgIntelSubmissionState("new_state").label, "new_state");
});

test("enrich plane: an org-stamped session goes to the org plane, everything else to personal (ruling Q3)", () => {
  assert.equal(sessionEnrichPlane({ enrich_plane: "org" }), "org");
  assert.equal(sessionEnrichPlane({}), "personal");
  assert.equal(sessionEnrichPlane({ enrich_plane: "other" }), "personal");
  assert.equal(orgPlaneEnrichAction({}), "Team AI summaries");
  assert.equal(orgPlaneEnrichAction({ org_title: "T" }), "View team AI summaries");
  for (const plane of ["org", "personal"] as const) {
    const c = SESSION_ENRICH_PLANE_COPY[plane];
    for (const text of [c.tooltip, c.drawerTitle, c.drawerNote]) {
      assert.ok(text.length > 0);
      assert.ok(!text.includes("—"), `em dash in ${text}`);
    }
  }
  assert.match(SESSION_ENRICH_PLANE_COPY.org.drawerNote, /team/);
  assert.match(SESSION_ENRICH_PLANE_COPY.personal.drawerNote, /personal/);
});

test("background line: on demand only, the org's bounds, the node defaults", () => {
  assert.equal(orgIntelBackgroundLine({ background: false }), "Off: sessions are enriched on demand only");
  assert.equal(orgIntelBackgroundLine({ background: true, quiet_minutes: 45, min_actions: 9, max_age_days: 2 }),
    "On: sessions idle 45 min with at least 9 actions, up to 2 days old");
  assert.equal(orgIntelBackgroundLine({}), "On: sessions idle 30 min with at least 3 actions, up to 7 days old");
});

test("ruling Q5: the titles level is 'Metadata and first prompt', never suffixed with the purpose name", () => {
  assert.equal(orgIntelLevelLabel("titles"), "Metadata and first prompt");
  for (const label of Object.values(ORG_INTEL_LEVEL_LABELS)) assert.ok(!label.includes("Title only"), label);
});

// Ruling Q6: on an enrolled machine whose listed sessions are on the org plane,
// the Sessions banner describes org enrichment (its state and the org's terms),
// never personal sign-in. One case per state row, in table order.
test("ruling Q6: the Sessions banner follows the plane of the listed sessions", () => {
  assert.equal(orgIntelSessionsBanner(null, ["org"]), null);
  assert.equal(orgIntelSessionsBanner(st({ class: "unenrolled" }), ["org"]), null);
  assert.equal(orgIntelSessionsBanner(st({ effective_opt_in: true }), ["personal", "personal"]), null);
  assert.equal(orgIntelSessionsBanner(st({ effective_opt_in: true }), []), null);

  const cases: Array<[OrgIntelStatus, string]> = [
    [st({ requirement: undefined }), "Not set up"],
    [st({ org_enabled: false }), "Off"],
    [st({ class: "managed", notice_only: true, managed_rail: { on: false, reason: "no_policy", message: "Acme has not published a machine policy for it." } }), "Not running"],
    [st({ class: "managed", notice_only: true, managed_rail: { on: true, reason: "on", message: "" } }), "Running"],
    [st({ pending: true, pending_reason: "terms_changed", effective_opt_in: true }), "Terms changed"],
    [st({ pending: true, pending_reason: "not_accepted" }), "Your answer needed"],
    [st({ effective_opt_in: true }), "Accepted"],
    [st({}), "Not accepted"],
  ];
  assert.equal(cases.length, ORG_SESSIONS_BANNER_STATES.length);
  cases.forEach(([s, want], i) => {
    const b = orgIntelSessionsBanner(s, ["org", "org"]);
    assert.ok(b, want);
    assert.equal(b.state, want);
    assert.equal(ORG_SESSIONS_BANNER_STATES[i], want);
    assert.equal(b.mode, "org");
    assert.equal(b.title, `Team AI summaries · ${want}`);
    assert.equal(b.link, "/settings?section=intel");
    assert.ok(!/sign in/i.test(b.text), `org banner mentions personal sign-in: ${b.text}`);
    assert.ok(!/—/.test(b.text + b.terms), "no em dash in copy");
  });

  const accepted = orgIntelSessionsBanner(st({ effective_opt_in: true }), ["org"])!;
  assert.match(accepted.text, /Acme/);
  assert.equal(accepted.terms, "Azure OpenAI / gpt-x · Metadata and first prompt · Background: On: sessions idle 30 min with at least 3 actions, up to 7 days old");
  const rail = orgIntelSessionsBanner(st({ class: "managed", notice_only: true, managed_rail: { on: false, reason: "no_policy", message: "Acme has not published a machine policy for it." } }), ["org"])!;
  assert.equal(rail.text, "Acme has not published a machine policy for it.");
  assert.equal(orgIntelSessionsBanner(st({ requirement: undefined }), ["org"])!.terms, "");

  const mixed = orgIntelSessionsBanner(st({ effective_opt_in: true }), ["org", "personal"])!;
  assert.equal(mixed.mode, "mixed");
  assert.match(mixed.text, /Sessions marked personal use your own AI summaries/);
});

// Review M4-14: the org name goes through orgDisplayLabel, so an id-shaped
// value (a grant recorded before the display-name fix) never renders.
test("orgIntelOrgName never renders an org id", () => {
  assert.equal(orgIntelOrgName({ org_name: "07d3f6e5dcd736effa3c58dc818adb8a" }), "Your organization");
  assert.equal(orgIntelOrgName({ org_name: "  " }), "Your organization");
  assert.equal(orgIntelOrgName({ org_name: "Acme" }), "Acme");
});

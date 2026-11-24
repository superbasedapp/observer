// Unit tests of the issue preview's display rules (lib/issue.ts): one case
// per rule-table row.

import assert from "node:assert/strict";
import test from "node:test";

import {
  ISSUE_POLL_MS,
  cancelGate,
  changeNamesOrg,
  changeView,
  classifyDelivery,
  componentView,
  deliveryView,
  errorClassText,
  issueBlocking,
  componentErrorText,
  issueErrorText,
  issueGate,
  issuePollMs,
  normalizeOrgComponents,
  normalizePreview,
  orgDelta,
  pendingSummary,
  requestView,
  type AvailabilityPreview,
  type HostDelivery,
  type IssueRequest,
  type OrgComponentRow,
} from "./issue.ts";

const ORG = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const OTHER = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
const NAMES = new Map([[ORG, "Acme"]]);

function preview(extra: Partial<AvailabilityPreview> = {}): AvailabilityPreview {
  return normalizePreview({
    base_version: 12,
    inputs_digest: "d".repeat(64),
    body: { components: [] },
    changes: [{ section: "components", key: "org.security", kind: "added", before: null, after: { component: "org.security", reach: "named", orgs: [ORG] } }],
    ...extra,
  });
}

const REQ: IssueRequest = {
  request_id: "r1",
  requested_by: "staff:me",
  reason: "turn it on",
  requested_at: "2026-11-23T10:00:00Z",
  base_version: 12,
  state: "pending",
};

// ---- the preview ----------------------------------------------------------------

test("a preview's null lists read as empty", () => {
  const p = normalizePreview({ base_version: 3, inputs_digest: "x", body: null, problems: null as unknown as string[], changes: null as unknown as [] });
  assert.deepEqual(p.problems, []);
  assert.deepEqual(p.changes, []);
  assert.deepEqual(p.deliveries, []);
  assert.equal(p.pending, null);
  assert.equal(p.last_request, null);
  assert.equal(normalizePreview(null).base_version, 0);
});

test("error classes read as words with the class after", () => {
  assert.equal(errorClassText("transport:dial"), "could not connect to the host (transport:dial)");
  assert.equal(errorClassText("transport:reset"), "could not reach the host (transport:reset)");
  assert.equal(errorClassText("refused:invalid"), "the host found the envelope invalid (refused:invalid)");
  assert.equal(errorClassText("refused:stale"), "the host refused the envelope (refused:stale)");
  assert.equal(errorClassText("signer:unavailable"), "signing failed (signer:unavailable)");
  assert.equal(errorClassText("weird"), "failed (weird)");
  assert.equal(errorClassText("version_moved"), "another envelope was issued after the review (version_moved)");
  assert.equal(errorClassText("verify"), "the signed envelope did not verify (verify)");
  assert.equal(errorClassText("store"), "the envelope could not be stored (store)");
  assert.equal(errorClassText("unverified:signature"), "the host's answer could not be verified (unverified:signature)");
  assert.equal(errorClassText("not_sent:no_host"), "not sent to the host (not_sent:no_host)");
  assert.equal(errorClassText("bad_response"), "the host answered with something unexpected (bad_response)");
  assert.equal(errorClassText("bad_intent"), "the delivery request was malformed (bad_intent)");
  assert.equal(errorClassText(""), "");
  assert.equal(errorClassText(undefined), "");
});

// ---- the changes ----------------------------------------------------------------

test("an added component names its orgs", () => {
  const v = changeView({ section: "components", key: "org.security", kind: "added", before: null, after: { reach: "named", orgs: [ORG], reason: "pilot" } }, NAMES);
  assert.equal(v.sectionLabel, "Components");
  assert.deepEqual(v.item, { label: "org.security", mono: true });
  assert.equal(v.kindLabel, "added");
  assert.deepEqual(v.before, []);
  assert.deepEqual(v.after, ["Only 1 named org", "Orgs: Acme"]);
  assert.equal(v.reason, "pilot");
  assert.equal(v.note, "");
});

test("a changed reach row says which orgs it adds and drops", () => {
  const before = { reach: "named", orgs: [ORG], reason: "a" };
  const after = { reach: "named", orgs: [OTHER], reason: "a" };
  assert.deepEqual(orgDelta(before, after), { added: [OTHER], removed: [ORG] });
  const v = changeView({ section: "release_flags", key: "new-nav", kind: "changed", before, after }, NAMES);
  assert.deepEqual(v.before, ["Only 1 named org"]);
  assert.deepEqual(v.after, ["Only 1 named org", "Adds bbbbbbbb", "Drops Acme"]);
  assert.equal(v.reason, "", "an unchanged reason is not repeated");
  assert.equal(v.note, "");
});

test("a reason-only change says so", () => {
  const v = changeView({ section: "components", key: "x", kind: "changed", before: { reach: "off", reason: "a" }, after: { reach: "off", reason: "b" } });
  assert.equal(v.note, "Only the reason changed.");
  assert.equal(v.reason, "b");
  const w = changeView({ section: "components", key: "x", kind: "changed", before: { reach: "off", author: "a" }, after: { reach: "off", author: "b" } });
  assert.equal(w.note, "Only the author or a detail changed.");
});

test("org control changes name the org, the platform row in words", () => {
  const platform = changeView({ section: "org_controls", key: "*", kind: "removed", before: { org: "*", inference: [{ admission: "paused", dispatch: "on" }] }, after: null });
  assert.equal(platform.item.label, "Every org (platform-wide)");
  assert.equal(platform.kindLabel, "removed");
  assert.deepEqual(platform.before, ["Inference (every route): admission paused, dispatch on"]);
  assert.deepEqual(platform.after, []);
  assert.equal(changeView({ section: "org_controls", key: "platform", kind: "added", before: null, after: {} }).item.label, "Every org (platform-wide)");
  assert.deepEqual(changeView({ section: "org_controls", key: ORG, kind: "added", before: null, after: { org: ORG, ingest: { mode: "pause" } } }, NAMES).item, {
    label: "Acme",
    sub: ORG,
    mono: false,
  });
  assert.equal(changeView({ section: "mystery", key: "k", kind: "odd", before: null, after: {} }).kindLabel, "odd");
});

test("a change names an org by its control or a reach list", () => {
  assert.equal(changeNamesOrg({ section: "org_controls", key: ORG, kind: "added", before: null, after: {} }, ORG), true);
  assert.equal(changeNamesOrg({ section: "org_controls", key: "*", kind: "added", before: null, after: { org: "*" } }, ORG), false);
  assert.equal(changeNamesOrg({ section: "components", key: "c", kind: "removed", before: { reach: "named", orgs: [ORG] }, after: null }, ORG), true);
  assert.equal(changeNamesOrg({ section: "components", key: "c", kind: "added", before: null, after: { reach: "off" } }, ORG), false);
});

test("the headline counts what is not issued yet", () => {
  assert.deepEqual(pendingSummary(preview()), { text: "1 change is not issued yet", tone: "warn" });
  assert.equal(pendingSummary(preview(), ORG).text, "1 change is not issued yet, 1 naming this org");
  assert.equal(pendingSummary(preview(), OTHER).text, "1 change is not issued yet");
  const two = preview({
    changes: [
      { section: "org_controls", key: ORG, kind: "added", before: null, after: {} },
      { section: "components", key: "c", kind: "added", before: null, after: { reach: "named", orgs: [ORG] } },
    ],
  });
  assert.equal(pendingSummary(two, ORG).text, "2 changes are not issued yet, all naming this org");
  assert.deepEqual(pendingSummary(preview({ changes: [] })), { text: "Everything is issued", tone: "success" });
  assert.equal(pendingSummary(preview({ changes: [], base_version: 0 })).text, "No envelope issued yet, and no input to issue");
  assert.equal(pendingSummary(preview({ changes: [], problems: ["components/x: reach"] })).tone, "danger");
});

// ---- "Review and issue" -----------------------------------------------------------

test("the issue button: hidden for support, else on or off with the first reason", () => {
  assert.deepEqual(issueGate(preview(), false), { show: false, enabled: false, reason: null });
  assert.deepEqual(issueGate(null, true), { show: true, enabled: false, reason: "Loading the changes." });
  assert.deepEqual(issueGate(preview(), true), { show: true, enabled: true, reason: null });
  const cases: [Partial<AvailabilityPreview>, RegExp][] = [
    [{ problems: ["components/x: reach: unknown value"], pending: REQ }, /inputs with problems/],
    [{ pending: REQ }, /already waiting/],
    [{ changes: [] }, /Nothing to issue/],
  ];
  for (const [extra, want] of cases) {
    const g = issueGate(preview(extra), true);
    assert.equal(g.enabled, false, JSON.stringify(extra));
    assert.match(g.reason ?? "", want);
  }
  assert.equal(issueBlocking(preview({ problems: ["p"], pending: REQ, changes: [] })).length, 3);
  assert.deepEqual(issueBlocking(preview()), []);
});

test("issue refusals read as words, unknown codes keep the server's message", () => {
  assert.match(issueErrorText("inputs_changed", "x"), /changed since this review/);
  assert.match(issueErrorText("issue_pending", "x"), /already waiting/);
  assert.match(issueErrorText("not_pending", "x"), /no longer waiting/);
  assert.equal(issueErrorText("forbidden_role", "role refused"), "role refused");
  assert.match(componentErrorText("no_change", "x"), /already in that state/);
  assert.equal(componentErrorText("invalid_input", "reach is cohort"), "reach is cohort");
});

// ---- requests and deliveries -----------------------------------------------------------

test("a request's outcome in words", () => {
  assert.equal(requestView(REQ).label, "waiting");
  assert.equal(requestView({ ...REQ, state: "issued", result_version: 13 }).text, "Issued v13.");
  assert.equal(requestView({ ...REQ, state: "stale" }).tone, "warn");
  assert.match(requestView({ ...REQ, state: "stale" }).text, /Review again/);
  assert.equal(requestView({ ...REQ, state: "failed", error_class: "sign:timeout" }).text, "Failed: signing failed (sign:timeout).");
  assert.equal(requestView({ ...REQ, state: "failed" }).text, "Failed: no reason recorded.");
  assert.equal(requestView({ ...REQ, state: "odd" }).tone, "neutral");
  const cancelled = requestView({ ...REQ, state: "failed", error_class: "cancelled" });
  assert.equal(cancelled.label, "cancelled");
  assert.equal(cancelled.tone, "neutral");
  assert.match(cancelled.text, /Cancelled by staff/);
  assert.equal(errorClassText("cancelled"), "cancelled by staff (cancelled)");
});

test("withdrawing a request: ops and admin, only while it is pending", () => {
  assert.equal(cancelGate(REQ, true), true);
  assert.equal(cancelGate(REQ, false), false);
  assert.equal(cancelGate(null, true), false);
  assert.equal(cancelGate({ ...REQ, state: "issued", result_version: 3 }, true), false);
});

test("each delivery row classifies by its table row", () => {
  const d = (extra: Partial<HostDelivery>): HostDelivery => ({ host_id: "app-0", version: 12, state: "delivered", attempts: 1, updated_at: "2026-11-23T10:00:00Z", ...extra });
  const cases: [Partial<HostDelivery>, string][] = [
    [{ state: "refused", version: 13 }, "refused"],
    [{ state: "retry", version: 13 }, "retrying"],
    [{ state: "delivered", version: 13 }, "current"],
    [{ state: "delivered", version: 12 }, "behind"],
    [{ state: "lost" }, "unknown"],
  ];
  for (const [extra, cls] of cases) assert.equal(classifyDelivery(d(extra), 13), cls, JSON.stringify(extra));
  assert.deepEqual(deliveryView(d({ version: 13 }), 13), { cls: "current", label: "current", tone: "success", version: "holds v13", detail: "" });
  assert.equal(deliveryView(d({}), 13).detail, "The newest is v13.");
  const retry = deliveryView(d({ state: "retry", version: 13, attempts: 3, error_class: "transport:dial" }), 13);
  assert.equal(retry.version, "sending v13");
  assert.equal(retry.detail, "could not connect to the host (transport:dial), attempt 3");
  assert.equal(deliveryView(d({ state: "retry", version: 13 }), 13).detail, "sending again");
  const refused = deliveryView(d({ state: "refused", version: 13, error_class: "refused:invalid" }), 13);
  assert.equal(refused.tone, "danger");
  assert.match(refused.detail, /found the envelope invalid/);
});

test("the preview is polled while a request is pending, and while hosts settle", () => {
  const current: HostDelivery = { host_id: "app-0", version: 12, state: "delivered", attempts: 1, updated_at: "x" };
  assert.equal(issuePollMs(null, true), 0);
  assert.equal(issuePollMs(preview({ pending: REQ }), false), ISSUE_POLL_MS);
  assert.equal(issuePollMs(preview(), false), 0);
  assert.equal(issuePollMs(preview({ deliveries: [current] }), true), 0, "every host current: stop");
  assert.equal(issuePollMs(preview({ deliveries: [{ ...current, state: "retry" }] }), true), ISSUE_POLL_MS);
  assert.equal(issuePollMs(preview({ deliveries: [] }), true), ISSUE_POLL_MS, "no host reached yet");
});

// ---- per-org components ------------------------------------------------------------------

function row(extra: Partial<OrgComponentRow> = {}): OrgComponentRow {
  return {
    component: "org.security",
    title: "Code security (org)",
    issued: false,
    next: false,
    input: null,
    toggle: { on: true, value: { reach: "named", orgs: [ORG] }, error: "" },
    ...extra,
  };
}

test("a component is off for an org by default, and says how to turn it on", () => {
  const v = componentView(row(), 12);
  assert.equal(v.headline, "Off for this org");
  assert.equal(v.issuedLabel, "Issued envelope (v12)");
  assert.equal(v.issuedText, "not offered");
  assert.equal(v.nextText, "not offered");
  assert.equal(v.differs, false);
  assert.equal(v.buttonLabel, "Turn on for this org");
  assert.equal(v.disabledReason, null);
  assert.equal(v.afterText, "The component's input becomes: Only 1 named org.");
});

test("a switched component is not issued until the envelope is", () => {
  const on = componentView(row({ next: true, toggle: { on: false, value: null, error: "" } }), 12);
  assert.equal(on.headline, "Off for this org");
  assert.equal(on.nextText, "offered");
  assert.equal(on.differs, true);
  assert.equal(on.buttonLabel, "Turn off for this org");
  assert.match(on.afterText, /row is removed/);
  const issued = componentView(row({ issued: true, next: true, toggle: { on: false, value: null, error: "" } }), 13);
  assert.equal(issued.headline, "On for this org");
  assert.equal(issued.headlineTone, "success");
  assert.equal(issued.differs, false);
  const none = componentView(row({ next: true }), 0);
  assert.equal(none.issuedLabel, "Issued envelope");
  assert.equal(none.issuedText, "none issued yet");
  assert.equal(none.differs, true);
  assert.equal(componentView(row({ toggle: { on: true, value: null, error: "reach is cohort: edit it on Availability" } }), 12).disabledReason, "reach is cohort: edit it on Availability");
});

test("component rows fill what a server leaves out", () => {
  const c = normalizeOrgComponents({ org_id: ORG, base_version: 2, components: [{ ...row(), input: undefined, toggle: undefined as unknown as OrgComponentRow["toggle"] }] });
  assert.equal(c.components[0].input, null);
  assert.deepEqual(c.components[0].toggle, { on: false, value: null, error: "" });
  assert.deepEqual(normalizeOrgComponents({ org_id: ORG, base_version: 0, components: null as unknown as [] }).components, []);
});

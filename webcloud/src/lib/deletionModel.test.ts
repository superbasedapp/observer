import assert from "node:assert/strict";
import test from "node:test";

import {
  ACCOUNT_BLOCKER,
  BLOCKED_REASON_TEXT,
  ORG_DELETION_ERROR_TEXT,
  ORG_DELETION_REFUSAL_TEXT,
  ORG_DELETION_STATE,
  REAUTH_UNAVAILABLE_TEXT,
  accountBlockerView,
  accountDeletionAllowed,
  blockedReasonText,
  deletionOpen,
  keptText,
  orgDeletionControl,
  orgDeletionFormReady,
  orgDeletionProof,
  orgDeletionReauthMode,
  orgDeletionRefusalNext,
  orgDeletionStateView,
  orgDeletionStepUpURL,
  parseStepUpStash,
  reauthNote,
  refusalText,
  showCancel,
  slugConfirmed,
  stateDate,
  stepUpConfirmSlug,
} from "./deletionModel.ts";
import type { AccountDeletionPrecheck, OrgDeletionPreview, OrgDeletionStatus } from "../api.ts";

// The console's deletion rules (plan 07 M6.9 / M7a.1): who sees the delete
// control, the typed slug, the deletion states and refusals in words, and
// the account deletion precheck's blockers.

function status(over: Partial<OrgDeletionStatus> = {}): OrgDeletionStatus {
  return {
    request_id: "odr_1",
    state: "cooling_off",
    step: "cooling_off",
    origin: "owner",
    requested_at: "2026-11-10T00:00:00Z",
    purge_after: "2026-12-10T00:00:00Z",
    can_cancel: true,
    ...over,
  };
}

function preview(over: Partial<OrgDeletionPreview> = {}): OrgDeletionPreview {
  return {
    can_request: true,
    refusal: "",
    cooling_off_days: 30,
    purge_after: "2026-12-16T00:00:00Z",
    live_subscription: false,
    members: 3,
    kept: ["usage_counts", "deletion_record"],
    ...over,
  };
}

const owner = { console_role: "owner" as const };
const admin = { console_role: "admin" as const };
const member = { console_role: "member" as const };

test("slugConfirmed: exact slug only, surrounding spaces ignored", () => {
  const cases: [string, string, boolean][] = [
    ["", "acme", false],
    ["acm", "acme", false],
    ["Acme", "acme", false],
    ["acme ", "acme", true],
    ["  acme", "acme", true],
    ["acme", "acme", true],
    ["acme-eng", "acme", false],
    ["", "", false],
  ];
  for (const [typed, slug, want] of cases) assert.equal(slugConfirmed(typed, slug), want, `${typed}/${slug}`);
});

test("orgDeletionControl: one row per rule, top to bottom", () => {
  const cases: [string, Parameters<typeof orgDeletionControl>, string][] = [
    ["member: no control", [member, null, preview()], "none"],
    ["admin: no control", [admin, null, preview({ can_request: false, refusal: "not_owner" })], "none"],
    ["owner, open request: status only", [owner, status(), preview({ can_request: false, refusal: "deletion_open" })], "none"],
    ["owner, purging: status only", [owner, status({ state: "purging", can_cancel: false }), preview()], "none"],
    ["owner, blocked: status only", [owner, status({ state: "blocked", can_cancel: false }), preview()], "none"],
    ["owner, refused", [owner, null, preview({ can_request: false, refusal: "org_not_deletable" })], "refused"],
    ["owner, canceled earlier: form again", [owner, status({ state: "canceled", can_cancel: false }), preview()], "form"],
    ["owner, nothing open: form", [owner, null, preview()], "form"],
  ];
  for (const [name, args, want] of cases) assert.equal(orgDeletionControl(...args).kind, want, name);
  const r = orgDeletionControl(owner, null, preview({ can_request: false, refusal: "org_not_deletable" }));
  assert.equal(r.kind === "refused" && r.sentence, ORG_DELETION_REFUSAL_TEXT.org_not_deletable);
});

test("showCancel: an owner, while the server says it can be canceled", () => {
  assert.equal(showCancel(owner, status()), true);
  assert.equal(showCancel(member, status()), false);
  assert.equal(showCancel(admin, status()), false);
  assert.equal(showCancel(owner, status({ state: "purging", can_cancel: false })), false);
  assert.equal(showCancel(owner, null), false);
});

test("deletionOpen: cooling off, purging and blocked hold the org", () => {
  assert.equal(deletionOpen(null), false);
  assert.equal(deletionOpen(status()), true);
  assert.equal(deletionOpen(status({ state: "purging" })), true);
  assert.equal(deletionOpen(status({ state: "blocked" })), true);
  assert.equal(deletionOpen(status({ state: "canceled" })), false);
  assert.equal(deletionOpen(status({ state: "done" })), false);
});

test("every deletion state has a label and a sentence; an unknown one is honest", () => {
  for (const [state, v] of Object.entries(ORG_DELETION_STATE)) {
    assert.ok(v.label, state);
    assert.ok(v.sentence("1 Dec").length > 0, state);
  }
  assert.match(ORG_DELETION_STATE.cooling_off.sentence("10 Dec 2026"), /Cooling off until 10 Dec 2026/);
  assert.match(ORG_DELETION_STATE.done.sentence("x"), /backups expire within 30 days/);
  for (const v of Object.values(ORG_DELETION_STATE)) assert.doesNotMatch(v.sentence("x"), /crypto|erase/i);
  assert.equal(orgDeletionStateView("frozen").label, "frozen");
  assert.match(orgDeletionStateView("frozen").sentence(""), /could not read/);
});

test("stateDate names the date each state's sentence uses", () => {
  assert.equal(stateDate(status()), "2026-12-10T00:00:00Z");
  assert.equal(stateDate(status({ state: "canceled", canceled_at: "c" })), "c");
  assert.equal(stateDate(status({ state: "done", done_at: "d" })), "d");
  assert.equal(stateDate(status({ state: "purging" })), undefined);
});

test("refusals and route errors are worded; an unknown code is honest", () => {
  assert.match(refusalText("not_owner"), /Only an owner/);
  assert.match(refusalText("deletion_open"), /already has a deletion/);
  assert.match(refusalText("mystery"), /cannot be deleted right now/);
  for (const code of ["not_owner", "deletion_open", "org_not_deletable", "confirm_mismatch", "not_cancellable"]) {
    assert.ok(ORG_DELETION_ERROR_TEXT[code], code);
  }
});

test("the new refusals are worded, and org_not_deletable no longer names personal orgs", () => {
  assert.equal(
    refusalText("personal_org"),
    "A personal dashboard is deleted with your account. Delete your account from Privacy instead.",
  );
  assert.equal(
    refusalText("billing_cancel_unavailable"),
    "This team has an active subscription that can't be canceled automatically right now. Cancel it from the team's billing page first, then delete the team.",
  );
  assert.equal(refusalText("org_not_deletable"), "This team cannot be deleted in its current state.");
  assert.doesNotMatch(ORG_DELETION_REFUSAL_TEXT.org_not_deletable, /personal/i);
  const r = orgDeletionControl(owner, null, preview({ can_request: false, refusal: "personal_org" }));
  assert.equal(r.kind === "refused" && r.sentence, ORG_DELETION_REFUSAL_TEXT.personal_org);
});

test("the request's re-authentication refusals are worded; step_up_required is not shown", () => {
  for (const code of ["reauth_required", "reauth_mismatch", "step_up_invalid", "provider_not_configured"]) {
    assert.ok(ORG_DELETION_ERROR_TEXT[code], code);
  }
  assert.equal(ORG_DELETION_ERROR_TEXT.step_up_required, undefined);
  assert.equal(ORG_DELETION_ERROR_TEXT.provider_not_configured, REAUTH_UNAVAILABLE_TEXT);
});

test("orgDeletionReauthMode: one row per rule, the server's answer first", () => {
  const cases: [string, Parameters<typeof orgDeletionReauthMode>, string][] = [
    ["unavailable wins over a WorkOS session", [{ reauth: "unavailable" }, "workos"], "unavailable"],
    ["broker_token wins over a WorkOS session", [{ reauth: "broker_token" }, "workos"], "broker_token"],
    ["step_up wins over a dev session", [{ reauth: "step_up" }, "dev"], "step_up"],
    ["older server, WorkOS session: step_up", [{}, "workos"], "step_up"],
    ["older server, dev session: broker_token", [{}, "dev"], "broker_token"],
    ["older server, sign-in unknown: broker_token", [{}, null], "broker_token"],
  ];
  for (const [name, args, want] of cases) assert.equal(orgDeletionReauthMode(...args), want, name);
});

test("orgDeletionFormReady: the slug, the subject when asked, and never when unavailable", () => {
  const cases: [Parameters<typeof orgDeletionFormReady>, boolean][] = [
    [["step_up", "acme", "acme", ""], true],
    [["step_up", "acm", "acme", ""], false],
    [["broker_token", "acme", "acme", ""], false],
    [["broker_token", "acme", "acme", "  "], false],
    [["broker_token", "acme", "acme", "dev-user"], true],
    [["broker_token", "acm", "acme", "dev-user"], false],
    [["unavailable", "acme", "acme", "dev-user"], false],
  ];
  for (const [args, want] of cases) assert.equal(orgDeletionFormReady(...args), want, args.join("/"));
});

test("orgDeletionProof: the subject, the step-up id when there is one, or nothing", () => {
  assert.deepEqual(orgDeletionProof("broker_token", " dev-user ", "su_1"), { brokerSubject: "dev-user" });
  assert.deepEqual(orgDeletionProof("step_up", "", "su_1"), { stepUpAuthorizationId: "su_1" });
  assert.deepEqual(orgDeletionProof("step_up", "", null), {});
  assert.deepEqual(orgDeletionProof("unavailable", "x", "su_1"), {});
});

test("orgDeletionRefusalNext: one row per refusal the page acts on", () => {
  const cases: [string, string][] = [
    ["step_up_required", "start_step_up"],
    ["step_up_invalid", "drop_step_up"],
    ["reauth_required", "show"],
    ["confirm_mismatch", "show"],
    ["", "show"],
  ];
  for (const [code, want] of cases) assert.equal(orgDeletionRefusalNext(code), want, code);
});

test("reauthNote: a line per re-authentication", () => {
  assert.equal(reauthNote("unavailable", false), REAUTH_UNAVAILABLE_TEXT);
  assert.equal(reauthNote("broker_token", false), "");
  assert.match(reauthNote("step_up", false), /sign in again/);
  assert.match(reauthNote("step_up", true), /Re-authentication confirmed/);
  assert.equal(reauthNote("broker_token", true), "");
});

test("the step-up URL returns to the org's page", () => {
  assert.equal(
    orgDeletionStepUpURL("org_1"),
    "/portal/auth/workos/start?purpose=step_up&action=deletion&return_to=/portal/orgs/org_1",
  );
  assert.match(orgDeletionStepUpURL("org a"), /return_to=\/portal\/orgs\/org%20a$/);
});

test("a stash finishes the request only for this org and its slug", () => {
  const org = { org_id: "o1", slug: "acme" };
  const cases: [string, Parameters<typeof stepUpConfirmSlug>[0], string | null][] = [
    ["no stash", null, null],
    ["this org", { orgId: "o1", slug: "acme" }, "acme"],
    ["another org", { orgId: "o2", slug: "acme" }, null],
    ["slug changed", { orgId: "o1", slug: "acme-old" }, null],
    ["spaces kept out", { orgId: "o1", slug: " acme " }, "acme"],
  ];
  for (const [name, stash, want] of cases) assert.equal(stepUpConfirmSlug(stash, org), want, name);
});

test("parseStepUpStash reads only the expected shape", () => {
  assert.deepEqual(parseStepUpStash('{"orgId":"o1","slug":"acme"}'), { orgId: "o1", slug: "acme" });
  assert.equal(parseStepUpStash(null), null);
  assert.equal(parseStepUpStash(""), null);
  assert.equal(parseStepUpStash("not json"), null);
  assert.equal(parseStepUpStash('{"orgId":1,"slug":"acme"}'), null);
  assert.equal(parseStepUpStash('"deletion"'), null);
});

test("every blocked reason is worded; an unknown one falls back to the token", () => {
  for (const reason of [
    "billing_seam_unwired",
    "billing_cancel_refused",
    "host_refused",
    "host_purge_overdue",
    "followup_unverified",
  ]) {
    assert.ok(BLOCKED_REASON_TEXT[reason], reason);
    assert.equal(blockedReasonText(reason), BLOCKED_REASON_TEXT[reason]);
    assert.doesNotMatch(blockedReasonText(reason), /_/, reason);
  }
  assert.equal(blockedReasonText("mystery_reason"), "mystery_reason");
});

test("keptText words the kept items and falls back to the token", () => {
  assert.match(keptText("usage_counts"), /10 years/);
  assert.match(keptText("deletion_record"), /record/);
  assert.equal(keptText("audit_log"), "audit_log");
});

test("every blocker code has the way out; an unknown one still links the team", () => {
  assert.match(ACCOUNT_BLOCKER.pays_for_live_org.wayOut, /Transfer the billing.*or delete the team/);
  assert.match(ACCOUNT_BLOCKER.billing_owner.wayOut, /Transfer the billing.*or delete the team/);
  assert.match(ACCOUNT_BLOCKER.sole_owner_with_members.wayOut, /another member an owner/);
  assert.match(ACCOUNT_BLOCKER.sole_owner_alone.wayOut, /Delete the team first/);
  for (const v of Object.values(ACCOUNT_BLOCKER)) assert.equal(v.linkToTeam, true);
  assert.equal(accountBlockerView("new_rule").linkToTeam, true);
});

test("accountDeletionAllowed: off only while the precheck names a blocker", () => {
  const clear: AccountDeletionPrecheck = { can_delete: true, blockers: [], personal_org: null, memberships_removed: [] };
  assert.equal(accountDeletionAllowed(clear), true);
  assert.equal(accountDeletionAllowed(null), true);
  assert.equal(accountDeletionAllowed(undefined), true);
  assert.equal(
    accountDeletionAllowed({
      ...clear,
      can_delete: false,
      blockers: [{ code: "sole_owner_alone", org_id: "o1", slug: "acme", display_name: "Acme" }],
    }),
    false,
  );
  // can_delete false with no blocker named is still a refusal.
  assert.equal(accountDeletionAllowed({ ...clear, can_delete: false }), false);
});

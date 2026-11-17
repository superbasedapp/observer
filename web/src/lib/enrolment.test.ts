import assert from "node:assert/strict";
import test from "node:test";

import {
  apiErrorCode,
  apiErrorMessage,
  canSubmit,
  checkCode,
  checkLink,
  checkServerUrl,
  DECISION_TONE,
  enrolBody,
  formErrors,
  IDP_STATUS_COPY,
  leavePlanGroups,
  METHOD_OPTIONS,
  pendingGrantOf,
  pollDelayMs,
  pushCadenceLine,
  resyncLine,
  shareModeLabel,
  UNSENT_ROWS,
  tenancyLabel,
  type EnrolOutcome,
  type EnrolmentOverview,
  type PendingGrant,
} from "./enrolment.ts";

test("checkServerUrl table", () => {
  const rows: [string, boolean][] = [
    ["https://org.example.com", true],
    ["http://127.0.0.1:18640/", true],
    ["https://proxy.example/observer", true],
    ["", false],
    ["org.example.com", false],
    ["ftp://org.example.com", false],
    ["https://u:p@org.example.com", false],
    ["https://org.example.com/enrol/x?token=y", false],
    ["https://org example.com", false],
  ];
  for (const [raw, ok] of rows) assert.equal(checkServerUrl(raw) === null, ok, raw);
});

test("checkCode table", () => {
  const rows: [string, boolean][] = [
    ["tok_id.secret", true],
    ["  abc.def  ", true],
    ["", false],
    ["nodot", false],
    [".secret", false],
    ["id.", false],
    ["id .secret", false],
    ["https://h/enrol/a.b", false],
    ["a." + "b".repeat(600), false],
  ];
  for (const [raw, ok] of rows) assert.equal(checkCode(raw) === null, ok, raw);
});

test("checkLink accepts only /enrol/<code> and names a sign-in invite", () => {
  assert.equal(checkLink("https://org.example/enrol/a.b"), null);
  assert.match(checkLink("https://org.example/set-password?token=a.b") ?? "", /sign-in invite/);
  assert.match(checkLink("https://org.example/login") ?? "", /sign-in invite/);
  assert.notEqual(checkLink("https://org.example/enrol/"), null);
  assert.notEqual(checkLink("not a link"), null);
  assert.notEqual(checkLink(""), null);
});

test("formErrors only checks the fields the method uses", () => {
  const base = { orgUrl: "", token: "", link: "" };
  assert.deepEqual(Object.keys(formErrors({ ...base, method: "code" })).sort(), ["orgUrl", "token"]);
  assert.deepEqual(Object.keys(formErrors({ ...base, method: "link" })), ["link"]);
  assert.deepEqual(Object.keys(formErrors({ ...base, method: "idp" })), ["orgUrl"]);
  assert.equal(canSubmit({ method: "code", orgUrl: "https://o.example", token: "a.b", link: "" }), true);
  assert.equal(canSubmit({ method: "idp", orgUrl: "https://o.example", token: "", link: "" }), true);
});

test("enrolBody never sends a field the method does not use", () => {
  const f = { orgUrl: " https://o.example ", token: " a.b ", link: " https://o.example/enrol/a.b " };
  assert.deepEqual(enrolBody({ ...f, method: "code" }), { method: "code", org_url: "https://o.example", token: "a.b" });
  assert.deepEqual(enrolBody({ ...f, method: "link" }), { method: "link", link: "https://o.example/enrol/a.b" });
});

test("enrolBody adds drop_unsent only for the explicit Switch anyway (R3-78)", () => {
  const f = { orgUrl: "https://o.example", token: "a.b", link: "https://o.example/enrol/a.b" };
  assert.equal("drop_unsent" in enrolBody({ ...f, method: "code" }), false);
  assert.deepEqual(enrolBody({ ...f, method: "code" }, true), {
    method: "code",
    org_url: "https://o.example",
    token: "a.b",
    drop_unsent: true,
  });
  assert.deepEqual(enrolBody({ ...f, method: "link" }, true), {
    method: "link",
    link: "https://o.example/enrol/a.b",
    drop_unsent: true,
  });
});

test("apiErrorCode reads the classified code, or nothing", () => {
  assert.equal(apiErrorCode({ body: '{"error":"unsent_rows","message":"Not switched: 6 rows"}' }), UNSENT_ROWS);
  assert.equal(apiErrorCode({ body: '{"message":"no code"}' }), "");
  assert.equal(apiErrorCode({ body: "plain failure" }), "");
  assert.equal(apiErrorCode(new Error("boom")), "");
  assert.equal(apiErrorCode(null), "");
});

test("apiErrorMessage prefers the server sentence", () => {
  assert.equal(apiErrorMessage({ body: '{"error":"token_rejected","message":"the organization refused"}' }), "the organization refused");
  assert.equal(apiErrorMessage({ body: '{"error":"gone"}' }), "gone");
  assert.equal(apiErrorMessage({ body: "plain failure" }), "plain failure");
  assert.equal(apiErrorMessage(new Error("boom")), "boom");
});

test("pollDelayMs honours the server interval with a floor", () => {
  assert.equal(pollDelayMs(5), 5000);
  assert.equal(pollDelayMs(0), 5000);
  assert.equal(pollDelayMs(1), 2000);
  assert.equal(pollDelayMs(undefined), 5000);
});

test("pendingGrantOf prefers the fresh offer and skips decided ones", () => {
  const p = (id: string): PendingGrant => ({
    offer_id: id,
    expires_at: "",
    disclosure: { intro: "", org_id: "o", server_url: "s", managed: false, may: [], may_not: [] },
  });
  const outcome = { pending_grant: p("fresh") } as unknown as EnrolOutcome;
  const overview = { pending_grant: p("held") } as unknown as EnrolmentOverview;
  assert.equal(pendingGrantOf(outcome, overview, new Set())?.offer_id, "fresh");
  assert.equal(pendingGrantOf(outcome, overview, new Set(["fresh"]))?.offer_id, "held");
  assert.equal(pendingGrantOf(null, overview, new Set(["held"])), null);
});

test("label tables cover their vocabularies", () => {
  assert.deepEqual(METHOD_OPTIONS.map((m) => m.value), ["code", "link", "idp"]);
  for (const s of ["accepted", "declined", "refused", "consented"] as const) assert.ok(DECISION_TONE[s]);
  for (const s of ["pending", "approved", "denied", "expired", "error"] as const) assert.ok(IDP_STATUS_COPY[s]);
  assert.equal(tenancyLabel("managed"), "Organization-managed");
  assert.equal(tenancyLabel("individual"), "Individual");
  assert.equal(shareModeLabel("metadata_only").tone, "success");
  assert.equal(shareModeLabel("nope").text, "Unknown");
});

test("no em dash in any user-facing copy", () => {
  const copy = [
    ...METHOD_OPTIONS.map((m) => m.help),
    ...Object.values(IDP_STATUS_COPY),
    checkServerUrl("x") ?? "",
    checkCode("x") ?? "",
    checkLink("x") ?? "",
  ];
  for (const s of copy) assert.ok(!s.includes("—"), s);
});

test("leavePlanGroups splits removals from kept routes", () => {
  const plan = [
    { tool: "claude-code", action: "remove" as const, message: "Removes ANTHROPIC_BASE_URL from /h/.claude/settings.json (written when this machine enrolled)." },
    { tool: "codex", action: "keep" as const, message: "Your Codex proxy setting will be kept because you set it yourself." },
  ];
  const g = leavePlanGroups(plan);
  assert.deepEqual(g.remove.map((r) => r.tool), ["claude-code"]);
  assert.deepEqual(g.keep.map((r) => r.tool), ["codex"]);
  assert.deepEqual(leavePlanGroups(null), { remove: [], keep: [] });
});

test("pushCadenceLine is push-status's cadence (T-642)", () => {
  const fmt = (iso: string) => iso;
  const base = { pushing_enabled: true, push_loop_running: true, push_interval_seconds: 120, last_push: null };
  assert.match(pushCadenceLine({ ...base, pushing_enabled: false }, fmt), /enabled = false/);
  assert.match(pushCadenceLine({ ...base, push_loop_running: false }, fmt), /not running in this daemon/);
  assert.match(pushCadenceLine(base, fmt), /at least every 120 s.*first push runs within 120 s/);
  const last = { pushed_at: "2026-10-07T10:00:00Z", status: "ok", row_count: 1, bytes: 1 };
  assert.match(pushCadenceLine({ ...base, last_push: last }, fmt), /Next push by 2026-10-07T10:02:00\.000Z\./);
  assert.equal(pushCadenceLine({ ...base, push_interval_seconds: 0 }, fmt), "The push loop is running.");
  for (const ov of [base, { ...base, last_push: last }, { ...base, pushing_enabled: false }]) {
    assert.ok(!/[\u2013\u2014]/.test(pushCadenceLine(ov, fmt)));
  }
});

test("resyncLine covers dry run, nothing to do and a confirmed run (T-642)", () => {
  const base = { window_days: 30, limit: 20000, queued: 7, ended_at_checked: 0, manifests: 2, manifests_checked: 3, manifests_too_big: 0, confirmed: false };
  assert.match(resyncLine(base), /^Re-send would queue 7 changed rows and 2 sessions .* last 30 days \(at most 20000 rows\)\.$/);
  assert.match(resyncLine({ ...base, queued: 0, manifests: 0 }), /^Nothing to re-send/);
  assert.match(resyncLine({ ...base, queued: 1, manifests: 1, confirmed: true }), /^Queued 1 changed row and 1 session to reconcile/);
  for (const r of [base, { ...base, confirmed: true }]) assert.ok(!/[\u2013\u2014]/.test(resyncLine(r)));
});

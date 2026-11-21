import assert from "node:assert/strict";
import test from "node:test";

import {
  PROJECT_CAVEAT,
  coveringGrant,
  dedupeApprovals,
  grantSession,
  notDowngradedText,
  ruleCanBlock,
  whyNotDowngraded,
  type ApprovalRow,
  type Target,
  type VerdictRow,
} from "./guardApprovals.ts";

const T0 = "2026-11-03T08:00:00Z";
const LATER = "2026-11-03T10:00:00Z";

const APPROVALS: ApprovalRow[] = [
  { id: 6, ts: T0, rule_id: "S-793", scope: "session", session_id: "sA" },
  { id: 8, ts: T0, rule_id: "S-793", scope: "project", project_root_hash: "ph" },
  { id: 9, ts: T0, rule_id: "S-794", scope: "global" },
  { id: 12, ts: LATER, rule_id: "R-101", scope: "session", session_id: "sB" },
];

// One row per coverage case: verdict rows (scope undefined) and grant-form
// requests (scope set) alike.
const COVER_CASES: { name: string; t: Target; want: number | null }[] = [
  { name: "session grant covers its session", t: { rule: "S-793", session: "sA" }, want: 6 },
  { name: "project grant covers a session of its project", t: { rule: "S-793", session: "sZ", projectHash: "ph" }, want: 8 },
  { name: "global grant covers anything", t: { rule: "S-794", session: "sZ" }, want: 9 },
  { name: "another rule is not covered", t: { rule: "S-792", session: "sA" }, want: null },
  { name: "another session, no project: not covered", t: { rule: "S-793", session: "sZ" }, want: null },
  { name: "a project request is not covered by a session grant", t: { rule: "S-793", session: "sA", scope: "project" }, want: null },
  { name: "a project request is covered by its project grant", t: { rule: "S-793", projectHash: "ph", scope: "project" }, want: 8 },
  { name: "a global request is covered only by a global grant", t: { rule: "S-793", session: "sA", projectHash: "ph", scope: "global" }, want: null },
  { name: "a global request over a global grant", t: { rule: "S-794", scope: "global" }, want: 9 },
  { name: "no rule picked yet", t: { rule: "" }, want: null },
];

for (const c of COVER_CASES) {
  test(`coveringGrant: ${c.name}`, () => {
    assert.equal(coveringGrant(APPROVALS, c.t)?.id ?? null, c.want);
  });
}

test("dedupeApprovals keeps the lowest id with the latest expiry and use", () => {
  const rows: ApprovalRow[] = [
    { id: 10, ts: T0, rule_id: "S-794", scope: "global", expires_at: "2026-11-04T00:00:00Z", last_used_at: LATER },
    { id: 9, ts: T0, rule_id: "S-794", scope: "global", expires_at: "2026-11-05T00:00:00Z" },
    { id: 11, ts: T0, rule_id: "S-793", scope: "session", session_id: "sA", expires_at: "2026-11-04T00:00:00Z" },
    { id: 13, ts: T0, rule_id: "S-793", scope: "session", session_id: "sA" },
    { id: 14, ts: T0, rule_id: "S-793", scope: "session", session_id: "sB" },
  ];
  const out = dedupeApprovals(rows);
  assert.deepEqual(
    out.map((r) => [r.id, r.expires_at ?? "never", r.last_used_at ?? ""]),
    [
      [9, "2026-11-05T00:00:00Z", LATER],
      [11, "never", ""],
      [14, "never", ""],
    ],
  );
});

test("grantSession names the parent of a subagent session", () => {
  assert.deepEqual(grantSession("4b18574f:agent:ae50bdfd"), { session: "4b18574f", subagent: true });
  assert.deepEqual(grantSession("c6e56962"), { session: "c6e56962", subagent: false });
  assert.deepEqual(grantSession(":agent:x"), { session: ":agent:x", subagent: false });
});

test("ruleCanBlock: flag-only rules cannot take an approval", () => {
  assert.equal(ruleCanBlock([{ observe: "flag", enforce: "flag" }]), false); // A-610
  assert.equal(ruleCanBlock([{ observe: "ask", enforce: "ask" }]), true); // the commit gate
  assert.equal(ruleCanBlock([{ observe: "flag", enforce: "deny" }]), true);
  assert.equal(ruleCanBlock(undefined), true);
});

const ask = (over: Partial<VerdictRow>): VerdictRow => ({
  ts: "2026-11-03T09:00:00Z",
  rule_id: "S-793",
  decision: "ask",
  enforced: true,
  reason: "commit gate",
  ...over,
});

const WHY_CASES: { name: string; ev: VerdictRow; want: string | null }[] = [
  { name: "a flag row is not explained", ev: ask({ decision: "flag", enforced: false }), want: null },
  { name: "a downgraded row is not explained", ev: ask({ decision: "flag", degraded_from: "approved" }), want: null },
  { name: "lookup failure", ev: ask({ reason: "x [approval lookup failed: database is locked; ...]", session_id: "sA" }), want: "lookup_error" },
  { name: "org locked", ev: ask({ reason: "x [org_locked: ...]" }), want: "org_locked" },
  { name: "a covering grant that predates the ask", ev: ask({ session_id: "sZ", project_root_hash: "ph" }), want: "grant_not_applied" },
  { name: "a covering grant made afterwards", ev: ask({ rule_id: "R-101", decision: "deny", session_id: "sB" }), want: "grant_came_later" },
  { name: "a grant for another scope", ev: ask({ session_id: "sZ", project_root_hash: "other" }), want: "scope_mismatch" },
  { name: "no grant for the rule", ev: ask({ rule_id: "S-791", session_id: "sA" }), want: "no_grant" },
];

for (const c of WHY_CASES) {
  test(`whyNotDowngraded: ${c.name}`, () => {
    const w = whyNotDowngraded(c.ev, APPROVALS);
    assert.equal(w?.kind ?? null, c.want);
    if (w) assert.ok(notDowngradedText(w).length > 0);
  });
}

test("a project grant in the answer carries the hook-root caveat", () => {
  const w = whyNotDowngraded(ask({ session_id: "sZ", project_root_hash: "other" }), APPROVALS);
  assert.equal(w?.kind, "scope_mismatch");
  assert.ok(w && notDowngradedText(w).endsWith(PROJECT_CAVEAT));
  const plain = whyNotDowngraded(ask({ rule_id: "S-794", decision: "deny", session_id: "sA", ts: "2026-11-03T07:00:00Z" }), APPROVALS);
  assert.equal(plain?.kind, "grant_came_later");
  assert.ok(plain && !notDowngradedText(plain).includes(PROJECT_CAVEAT));
});

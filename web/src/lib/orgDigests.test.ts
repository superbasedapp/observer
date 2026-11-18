// Pins the developer org-digest card's pure helpers (src/lib/orgDigests.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { groupOrgDigests, orgDigestNotice, weekLabel, type OrgDigestsResponse } from "./orgDigests.ts";

const base: OrgDigestsResponse = { state: "ok", org_name: "Acme", projects: 1, digests: [] };

test("orgDigestNotice: one row per state, first match wins", () => {
  const cases: Array<[Partial<OrgDigestsResponse>, string | null]> = [
    [{ state: "not_enrolled" }, "not connected"],
    [{ state: "not_supported" }, "does not offer"],
    [{ state: "auth_failed" }, "refused"],
    [{ state: "channel_off" }, "switched off"],
    [{ state: "unreachable" }, "Could not read"],
    [{ state: "weird" }, "not available"],
    [{ withheld: "posture" }, "individual"],
    [{ projects: 0 }, "90 days"],
    [{}, "No finished weekly digest"],
    [{ digests: [{ project_id: "p", week_start: "2026-09-21", session_count: 1, headline: "h" }] }, null],
  ];
  for (const [patch, want] of cases) {
    const n = orgDigestNotice({ ...base, ...patch });
    if (want === null) assert.equal(n, null);
    else assert.ok(n && n.text.includes(want), `${JSON.stringify(patch)} -> ${n?.text}`);
  }
  assert.ok(orgDigestNotice({ ...base, state: "not_supported", org_name: "" })!.text.startsWith("Your organization"));
});

test("groupOrgDigests keeps server order and folds older weeks", () => {
  const g = groupOrgDigests([
    { project_id: "bbbbbbbbbbbbbbbb", week_start: "2026-09-28", session_count: 1, headline: "b2" },
    { project_id: "aaaaaaaaaaaaaaaa", project_label: "api", week_start: "2026-09-28", session_count: 1, headline: "a2" },
    { project_id: "bbbbbbbbbbbbbbbb", week_start: "2026-09-21", session_count: 1, headline: "b1" },
  ]);
  assert.deepEqual(g.map((p) => p.projectId), ["bbbbbbbbbbbbbbbb", "aaaaaaaaaaaaaaaa"]);
  assert.equal(g[0].label, "Project bbbbbbbb");
  assert.equal(g[1].label, "api");
  assert.deepEqual(g[0].previous.map((d) => d.headline), ["b1"]);
});

test("weekLabel", () => {
  assert.equal(weekLabel({ project_id: "p", week_start: "2026-09-21", period_end: "2026-09-27", session_count: 1, headline: "" }), "Week of 2026-09-21 to 2026-09-27");
  assert.equal(weekLabel({ project_id: "p", week_start: "2026-09-21", session_count: 1, headline: "" }), "Week of 2026-09-21");
});

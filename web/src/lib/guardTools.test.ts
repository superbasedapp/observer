import assert from "node:assert/strict";
import test from "node:test";

import { guardTestHeadline, guardTestEnforceLine, guardJobLabel, type GuardTestResponse } from "./guardTools.ts";

const report = (over: Partial<GuardTestResponse["report"]> = {}): GuardTestResponse["report"] => ({
  advice: "",
  decision: "allow",
  enforce_decision: "allow",
  kind: "shell_exec",
  project_root: "/work/app",
  reason: "",
  rule_id: "",
  severity: "info",
  source: "",
  target: "ls",
  ...over,
});

test("guardTestHeadline names the decision and the rule in plain words", () => {
  const rows: { name: string; r: GuardTestResponse["report"]; want: string }[] = [
    { name: "no rule", r: report(), want: "Allowed: no rule matched." },
    {
      name: "a flag",
      r: report({ decision: "flag", rule_id: "R-110", severity: "high" }),
      want: "Flagged by R-110 (high severity).",
    },
    { name: "a deny", r: report({ decision: "deny", rule_id: "R-101", severity: "critical" }), want: "Blocked by R-101 (critical severity)." },
    { name: "an ask", r: report({ decision: "ask", rule_id: "R-120", severity: "warn" }), want: "Needs approval by R-120 (warn severity)." },
    { name: "an unknown decision", r: report({ decision: "mystery", rule_id: "R-9", severity: "info" }), want: "mystery by R-9 (info severity)." },
  ];
  for (const r of rows) assert.equal(guardTestHeadline(r.r), r.want, r.name);
});

test("guardTestEnforceLine says whether enforce would decide differently", () => {
  assert.equal(
    guardTestEnforceLine({ mode: "observe", mode_changes_verdict: true, report: report({ decision: "flag", enforce_decision: "deny" }) }),
    "Current mode is observe. In enforce mode this would be blocked.",
  );
  assert.equal(
    guardTestEnforceLine({ mode: "enforce", mode_changes_verdict: false, report: report({ decision: "deny", enforce_decision: "deny" }) }),
    "Current mode is enforce. Enforce mode decides the same.",
  );
});

test("guardJobLabel has a plain name for every job kind and no em dash", () => {
  for (const kind of [
    "rescan",
    "compile-diff",
    "compile",
    "mcp-scan",
    "mcp-report",
    // B-G8: the audit chain repairs, each a dry run and an apply.
    "repair-anchors",
    "repair-anchors-apply",
    "dedup-events",
    "dedup-events-apply",
    "relink-gaps",
    "relink-gaps-apply",
  ]) {
    const label = guardJobLabel(kind);
    assert.ok(label && label !== kind, kind);
    assert.ok(!/—/.test(label), kind);
  }
  assert.equal(guardJobLabel("guard:rescan"), guardJobLabel("rescan"));
  assert.equal(guardJobLabel("unknown"), "unknown");
});

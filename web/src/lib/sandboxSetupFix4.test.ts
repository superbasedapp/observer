// Fix round 4 (D-R4-2, D-R4-3, D-R4-5): the setup panel's re-probe table,
// the chooser label from a checked plan, and the record line of a step that
// is not done. One test per rule.

import assert from "node:assert/strict";
import test from "node:test";

import { REPROBE_RULES, recordView, setupSettleReprobe, summaryFromPlan, summaryOptionLabel } from "./sandboxSetup.ts";
import type { SandboxSetupPlan, SandboxSetupRecord, SandboxSetupSummary } from "./sandboxSetupTypes.ts";

test("reprobe: one case per rule", () => {
  const cases: [boolean | null, boolean, boolean, boolean, string][] = [
    [true, true, false, false, "still_running"],
    [true, false, false, true, "step_settled"],
    [null, false, true, true, "first_after_resume"],
    [null, false, false, false, "otherwise"],
  ];
  assert.equal(cases.length, REPROBE_RULES.length);
  for (const [prev, inFlight, resumed, want, rule] of cases) {
    assert.equal(setupSettleReprobe(prev, inFlight, resumed), want, rule);
  }
});

const rows: SandboxSetupSummary[] = [
  { backend: "apple-container", label: "Apple container", ready: false, unconfirmed: true },
  { backend: "seatbelt", label: "Seatbelt", ready: true },
];

const checked: SandboxSetupPlan = {
  backend: "apple-container",
  label: "Apple container",
  next: 1,
  ready: false,
  checked: true,
  fingerprint: "fp",
  steps: [
    { prereq: "apple-container-cli", kind: "program", label: "The container CLI", state: "done", class: "auto", channel: "pinned_download", can_run: false, can_undo: false },
    { prereq: "apple-container-image", kind: "content", label: "The sandbox image", state: "missing", class: "auto", channel: "terminal_cmd", can_run: true, can_undo: false },
  ],
};

test("summaryFromPlan: the checked row's label follows its plan; other rows are kept", () => {
  const out = summaryFromPlan(rows, checked);
  assert.equal(summaryOptionLabel(out[0]), "Apple container (next: The sandbox image)");
  assert.equal(out[1], rows[1]);
  assert.equal(summaryFromPlan(rows, null), rows);
});

const rec: SandboxSetupRecord = {
  id: 16,
  tool: "apple-container-image",
  channel: "terminal_cmd",
  command: "container image pull",
  status: "installed",
  installed_at: "2026-11-07T05:00:00Z",
  can_uninstall: false,
  can_forget: true,
} as SandboxSetupRecord;

test("record: a done step reads Installed, a step not done reads as history", () => {
  assert.match(recordView(rec, true).line, /^Installed from this dashboard on /);
  const v = recordView(rec, false);
  assert.match(v.line, /^Last run from this dashboard on /);
  assert.doesNotMatch(v.line, /Installed/);
});

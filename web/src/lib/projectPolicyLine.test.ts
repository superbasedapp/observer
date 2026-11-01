import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

import { projectPolicyView } from "./projectPolicyLine.ts";

const dashes = new RegExp("[\\u2013\\u2014]");

test("the line, one row per answer", () => {
  const cases: Array<[string, Parameters<typeof projectPolicyView>[0], string | null]> = [
    ["no reply", null, null],
    ["no project delivery", { shown: false }, null],
    ["an unknown state shows nothing", { shown: true, state: "later" }, null],
    ["matched one project", { shown: true, state: "matched", projects: 1 }, "Project policy: applied (1 project)"],
    ["matched two projects", { shown: true, state: "matched", projects: 2 }, "Project policy: applied (2 projects)"],
    ["not matched", { shown: true, state: "not_matched" }, "Project policy: not matched"],
    ["unknown", { shown: true, state: "unknown" }, "Project policy: unknown"],
  ];
  for (const [name, reply, want] of cases) {
    const v = projectPolicyView(reply);
    assert.equal(v?.text ?? null, want, name);
    if (v) assert.doesNotMatch(v.text + v.detail, dashes);
  }
});

test("the dialog fetches and renders the line", () => {
  const src = readFileSync(new URL("../components/NewTerminalDialog.tsx", import.meta.url), "utf8");
  assert.match(src, /"\/api\/terminal\/project-policy", \{ dir: effectiveRoot \}/);
  assert.match(src, /data-testid="project-policy-line"/);
  assert.match(src, /projectPolicyView\(/);
});

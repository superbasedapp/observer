import { test } from "node:test";
import assert from "node:assert/strict";

import {
  UPDATE_TERMINAL_PATH,
  UPDATE_TERMINAL_RESTART_NOTE,
  updateTerminalView,
  type UpdateTerminalPlan,
} from "./updateTerminal.ts";

const npm: UpdateTerminalPlan = {
  available: true,
  method: "npm",
  command: "npm i -g @superbased/observer@latest",
};
const brew: UpdateTerminalPlan = {
  available: false,
  method: "brew",
  reason: "This copy was not installed with npm or pipx, so there is no one command to run here. Update it with: brew upgrade superbased-observer.",
};

test("updateTerminalView: one row per outcome", () => {
  const rows: Array<{ name: string; plan: UpdateTerminalPlan | null; available: boolean; want: ReturnType<typeof updateTerminalView> }> = [
    { name: "no newer version: nothing", plan: npm, available: false, want: { kind: "none" } },
    { name: "plan not loaded yet: nothing", plan: null, available: true, want: { kind: "none" } },
    { name: "npm install: the button", plan: npm, available: true, want: { kind: "button", command: npm.command! } },
    { name: "no command: the reason", plan: brew, available: true, want: { kind: "note", text: brew.reason! } },
    {
      name: "available without a command is not a button",
      plan: { available: true, command: "  " },
      available: true,
      want: { kind: "none" },
    },
    { name: "empty refusal: nothing", plan: { available: false }, available: true, want: { kind: "none" } },
  ];
  for (const r of rows) {
    assert.deepEqual(updateTerminalView(r.plan, r.available), r.want, r.name);
  }
});

test("the route and the restart note name the controls", () => {
  assert.equal(UPDATE_TERMINAL_PATH, "/api/health/update-terminal");
  assert.match(UPDATE_TERMINAL_RESTART_NOTE, /Restart daemon/);
  assert.doesNotMatch(UPDATE_TERMINAL_RESTART_NOTE, /observer (serve|start)/);
});

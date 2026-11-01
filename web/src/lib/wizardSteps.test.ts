// Pins the Connected tools wizard step plan (wizardSteps.ts, T-421 item 2):
// the steps come from the server's wiring, never from a tool-name list.
import { test } from "node:test";
import assert from "node:assert/strict";
import { hasWizard, wizardStepsFor } from "./wizardSteps.ts";

const off = { register: false, remove: false };

test("the opt-in telemetry export step comes last, from the server's wiring", () => {
  const steps = wizardStepsFor({ hooks: { register: true, remove: true }, mcp: off, route: off, telemetry: { register: true, remove: true } });
  assert.deepEqual(steps.map((s) => s.id), ["hooks", "telemetry"]);
  assert.equal(steps[1].endpoint, "/api/setup/telemetry");
  assert.equal(hasWizard({ hooks: off, mcp: off, route: off, telemetry: { register: true, remove: true } }), true);
});

test("a hooks-and-MCP tool with no persisted route gets two steps", () => {
  const steps = wizardStepsFor({ hooks: { register: true, remove: true }, mcp: { register: true, remove: true }, route: off });
  assert.deepEqual(
    steps.map((s) => [s.id, s.endpoint]),
    [
      ["hooks", "/api/setup/hooks"],
      ["mcp", "/api/setup/mcp"],
    ],
  );
});

test("the route step uses the server's endpoint", () => {
  const steps = wizardStepsFor({
    hooks: { register: true, remove: true },
    mcp: off,
    route: { register: true, remove: true },
    route_endpoint: "/api/setup/codex",
  });
  assert.deepEqual(steps.map((s) => s.id), ["hooks", "route"]);
  assert.equal(steps[1].endpoint, "/api/setup/codex");
});

test("a write the server does not offer keeps its reason, and a removal-only step stays", () => {
  const steps = wizardStepsFor({
    hooks: { register: false, remove: true, note: "prompt lane off" },
    mcp: off,
    route: off,
  });
  assert.deepEqual(steps, [{ id: "hooks", endpoint: "/api/setup/hooks", register: false, remove: true, note: "prompt lane off" }]);
  assert.equal(hasWizard({ hooks: off, mcp: off, route: off }), false);
  assert.equal(hasWizard(undefined), false);
});

test("the route step carries the server's trade-off sentence for the consent (FU-24)", () => {
  const steps = wizardStepsFor({
    hooks: off,
    mcp: off,
    route: { register: true, remove: true, tradeoff: "turns Remote Control off" },
    route_endpoint: "/api/setup/claude",
  });
  assert.equal(steps[0].tradeoff, "turns Remote Control off");
});

import assert from "node:assert/strict";
import test from "node:test";

import {
  replayPlan,
  shouldArm,
  stillInsideAfterLeave,
  type ArmEvent,
  type ArmInput,
} from "../../../shared/lib/tooltipArming.ts";

// The lazy Tooltip (shared/primitives/Tooltip.tsx) mounts its @floating-ui
// machinery on the first pointer entry / focus and then replays that intent.
// These pin the decisions so the lazy tooltip behaves like the eager one.

const base: ArmInput = { armed: false, controlled: false, controlledOpen: false, inert: false };

test("shouldArm: one row per (state, event)", () => {
  const rows: Array<[string, Partial<ArmInput>, ArmEvent, boolean]> = [
    ["uncontrolled hover arms", {}, "pointerenter", true],
    ["uncontrolled focus arms", {}, "focusin", true],
    ["uncontrolled: no controlled-open", {}, "controlled-open", false],
    ["already armed never re-arms", { armed: true }, "pointerenter", false],
    ["already armed ignores controlled open", { armed: true, controlled: true, controlledOpen: true }, "controlled-open", false],
    ["inert (disabled / no content) never arms on hover", { inert: true }, "pointerenter", false],
    ["inert never arms on controlled open", { inert: true, controlled: true, controlledOpen: true }, "controlled-open", false],
    ["controlled closed: hover does not arm (listeners disabled)", { controlled: true }, "pointerenter", false],
    ["controlled closed: focus does not arm", { controlled: true }, "focusin", false],
    ["controlled closed: controlled-open does not arm", { controlled: true }, "controlled-open", false],
    ["controlled open arms", { controlled: true, controlledOpen: true }, "controlled-open", true],
  ];
  for (const [name, patch, event, want] of rows) {
    assert.equal(shouldArm({ ...base, ...patch }, event), want, name);
  }
});

test("replayPlan: replays only intents that still hold", () => {
  const rows: Array<[string, Parameters<typeof replayPlan>[0], { hover: boolean; focus: boolean }]> = [
    [
      "hover armed, pointer still inside: replay hover",
      { pointerInside: true, focusInside: false, armedBy: "pointerenter", controlled: false, inert: false },
      { hover: true, focus: false },
    ],
    [
      "hover armed, pointer left before mount: nothing opens",
      { pointerInside: false, focusInside: false, armedBy: "pointerenter", controlled: false, inert: false },
      { hover: false, focus: false },
    ],
    [
      "focus armed, focus still inside: replay focus",
      { pointerInside: false, focusInside: true, armedBy: "focusin", controlled: false, inert: false },
      { hover: false, focus: true },
    ],
    [
      "focus armed, focus already moved away: nothing opens",
      { pointerInside: false, focusInside: false, armedBy: "focusin", controlled: false, inert: false },
      { hover: false, focus: false },
    ],
    [
      "both still hold: both replayed (an eager tooltip saw both)",
      { pointerInside: true, focusInside: true, armedBy: "pointerenter", controlled: false, inert: false },
      { hover: true, focus: true },
    ],
    [
      "controlled: interactions disabled, nothing replayed",
      { pointerInside: true, focusInside: true, armedBy: "controlled-open", controlled: true, inert: false },
      { hover: false, focus: false },
    ],
    [
      "inert: nothing replayed",
      { pointerInside: true, focusInside: true, armedBy: "pointerenter", controlled: false, inert: true },
      { hover: false, focus: false },
    ],
    [
      "never armed by an event: nothing replayed",
      { pointerInside: true, focusInside: true, armedBy: null, controlled: false, inert: false },
      { hover: false, focus: false },
    ],
  ];
  for (const [name, input, want] of rows) {
    assert.deepEqual(replayPlan(input), want, name);
  }
});

test("stillInsideAfterLeave: a tap stays inside, a mouse or pen leave clears", () => {
  assert.equal(stillInsideAfterLeave("touch"), true);
  assert.equal(stillInsideAfterLeave("mouse"), false);
  assert.equal(stillInsideAfterLeave("pen"), false);
  assert.equal(stillInsideAfterLeave(undefined), false);
});

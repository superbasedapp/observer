import { test } from "node:test";
import assert from "node:assert/strict";
import { LAUNCH_SWITCHES_OFF, launchSwitchesOff } from "./launchSwitches.ts";

// One case per shape (D-12).
test("launchSwitchesOff: both off reads off", () => {
  assert.equal(launchSwitchesOff(false, false), true);
});

test("launchSwitchesOff: either on reads on", () => {
  assert.equal(launchSwitchesOff(true, false), false);
  assert.equal(launchSwitchesOff(false, true), false);
});

test("launchSwitchesOff: an unknown switch is never read as off", () => {
  assert.equal(launchSwitchesOff(undefined, false), false);
  assert.equal(launchSwitchesOff(null, false), false);
  assert.equal(launchSwitchesOff(false, undefined), false);
});

test("the sentence names both switches and the Settings path", () => {
  assert.match(LAUNCH_SWITCHES_OFF, /Fresh launch and plain shell terminals are both off/);
  assert.match(LAUNCH_SWITCHES_OFF, /Terminals > Settings > Fresh-agent launch policy/);
});

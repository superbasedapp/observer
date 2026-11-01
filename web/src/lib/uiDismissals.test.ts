import assert from "node:assert/strict";
import test from "node:test";

import {
  dismissConfirmToken,
  dismissRequestInit,
  isDismissed,
  markDismissedLocally,
  noteServerDismissals,
  resetDismissals,
  subscribeDismissals,
} from "./uiDismissals.ts";

// WINNODE2 16b: a notice the daemon reports dismissed stays dismissed in
// this tab, whatever the browser's own storage holds.
test("server dismissals are remembered and announced once", () => {
  resetDismissals();
  let calls = 0;
  subscribeDismissals(() => calls++);
  assert.equal(isDismissed("tour"), false);
  noteServerDismissals(["tour"], "tok-1");
  noteServerDismissals(["tour"]);
  assert.equal(isDismissed("tour"), true);
  assert.equal(isDismissed("components_setup"), false);
  assert.equal(calls, 1);
  assert.equal(dismissConfirmToken(), "tok-1");
  markDismissedLocally("components_setup");
  assert.equal(isDismissed("components_setup"), true);
  assert.equal(calls, 2);
});

test("the dismissal POST names the notice and echoes the confirm token", () => {
  const init = dismissRequestInit("components_setup", "tok-2");
  assert.equal(init.method, "POST");
  assert.deepEqual(JSON.parse(String(init.body)), { dismiss: "components_setup" });
  assert.equal((init.headers as Record<string, string>)["X-Observer-Confirm"], "tok-2");
});

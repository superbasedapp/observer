// Tests of the dock's status folds (launchStatus.ts): one test per rule of
// foldSessionExit, the setup terminal exit the dialog's resume waits on.

import assert from "node:assert/strict";
import test from "node:test";

import { foldSessionExit, installResume, isLiveStatus } from "./launchStatus.ts";

test("foldSessionExit: an exited setup session reads exited", () => {
  const prev = { t1: "open" as const };
  assert.deepEqual(foldSessionExit(prev, "t1", [{ token: "t1", exited: true }]), { t1: "exited" });
});

test("foldSessionExit: a session the daemon no longer lists reads exited", () => {
  assert.deepEqual(foldSessionExit({ t1: "open" as const }, "t1", [{ token: "other" }]), { t1: "exited" });
});

test("foldSessionExit: a running session keeps its status (same object)", () => {
  const prev = { t1: "open" as const };
  assert.equal(foldSessionExit(prev, "t1", [{ token: "t1", exited: false }]), prev);
});

test("foldSessionExit: an unreadable list changes nothing", () => {
  const prev = { t1: "open" as const };
  assert.equal(foldSessionExit(prev, "t1", null), prev);
});

test("foldSessionExit: exited and error are kept", () => {
  const prev = { t1: "error" as const };
  assert.equal(foldSessionExit(prev, "t1", [{ token: "t1", exited: true }]), prev);
});

// D-6: a setup terminal whose command exited stops reading live, and the
// dialog reopens with the same draft (the same setup row, read afresh).
test("installResume: after the setup command exits the tile is not live and the same draft returns", () => {
  const draft = { tool: "shell", setupBackend: "landlock" };
  const pending = { token: "t1", draft };
  let statuses: Record<string, "open" | "exited"> = { t1: "open" };
  assert.equal(installResume(pending, statuses), null);
  statuses = foldSessionExit(statuses, "t1", [{ token: "t1", exited: true }]) as typeof statuses;
  assert.equal(isLiveStatus(statuses.t1), false);
  assert.equal(installResume(pending, statuses), draft);
});

test("installResume: an error ends the wait too", () => {
  const pending = { token: "t1", draft: "d" };
  assert.equal(installResume(pending, { t1: "error" }), "d");
});

test("installResume: nothing waiting, or a token with no status yet, is null", () => {
  assert.equal(installResume(null, { t1: "exited" }), null);
  assert.equal(installResume({ token: "t2", draft: "d" }, { t1: "exited" }), null);
});

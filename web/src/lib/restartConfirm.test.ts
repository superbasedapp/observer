// Pins the daemon-restart question's copy (restartConfirm.ts) for each probe
// outcome: what a restart does, the live proxy count, and, only when a
// session is routing through the daemon, how to avoid a dropped request and
// why the safe restart command runs from a terminal the daemon did not start.
import { test } from "node:test";
import assert from "node:assert/strict";
import { probeUnsavedLive, restartConfirmBody } from "./restartConfirm.ts";

test("a routed session gets the count, the between-turns advice and the shipped safe restart", () => {
  const body = restartConfirmBody("This applies your pending config changes.", { available: true, proxy_recent_requests: 3 });
  assert.equal(body[0], "This applies your pending config changes.");
  assert.match(body[1], /shuts down gracefully and starts again in place/);
  assert.match(body[2], /3 requests in the last minute/);
  assert.match(body[2], /drops its in-flight proxy requests/);
  assert.match(body[3], /restart between turns/);
  assert.match(body[3], /does not take the proxy route off first/);
  assert.match(body[3], /`observer service restart` does \(route off, restart, route on\)/);
  // The command is never named without why it runs outside the daemon.
  assert.match(body[3], /a terminal the daemon did not start, because it restarts the daemon from outside it/);
  // The source checkout's script is never offered: users do not have it.
  assert.ok(!body.join(" ").includes("restart-daemon.sh"));
});

test("one request is singular", () => {
  const body = restartConfirmBody("lead", { available: true, proxy_recent_requests: 1 });
  assert.match(body[2], /\(1 request in the last minute\)/);
});

test("no traffic says no session should notice and names no command", () => {
  const body = restartConfirmBody("lead", { available: true, proxy_recent_requests: 0 });
  assert.equal(body.length, 3);
  assert.match(body[2], /no coding session should notice/);
  assert.ok(!body.join(" ").includes("observer service restart"));
});

test("an unavailable probe falls back to the generic warning", () => {
  const body = restartConfirmBody("lead", null);
  assert.equal(body.length, 3);
  assert.match(body[2], /may drop one in-flight request/);
});

test("an unsaved live change is named right after the lead", () => {
  const body = restartConfirmBody("lead", { available: true, proxy_recent_requests: 0 }, ["The admission policy was not saved."]);
  assert.equal(body[0], "lead");
  assert.equal(body[1], "The admission policy was not saved.");
  assert.match(body[2], /shuts down gracefully/);
  assert.equal(body.length, 4);
});

test("probeUnsavedLive reports only routes that say live_unsaved, and ignores failures", async () => {
  const lines = await probeUnsavedLive(async (path) => {
    assert.equal(path, "/api/obs/admission/status");
    return { live_unsaved: true };
  });
  assert.equal(lines.length, 1);
  assert.match(lines[0], /admission policy .* was not saved, so this restart drops it/);
  assert.deepEqual(await probeUnsavedLive(async () => ({ live_unsaved: false })), []);
  assert.deepEqual(await probeUnsavedLive(async () => ({})), []);
  assert.deepEqual(
    await probeUnsavedLive(async () => {
      throw new Error("api 404");
    }),
    [],
  );
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { LIVE_RESTART_POLL_MS, liveRestartPollMs } from "./liveRestartPoll.ts";

// The restart banner polls the restart report only while something is live
// or pending (SBX-UPD audit finding 5); with nothing live it does not poll.
test("no report or nothing live: no polling", () => {
  assert.equal(liveRestartPollMs(undefined), 0);
  assert.equal(liveRestartPollMs(null), 0);
  assert.equal(liveRestartPollMs({ available: true }), 0);
  assert.equal(liveRestartPollMs({ available: true, live_sandboxed_runs: [] }), 0);
});

test("a live run, a pending restart or update, or a held update: polls", () => {
  const run = { run_id: "r1", tool: "claude-code", backend: "bwrap", age_seconds: 5, native_resume: true };
  for (const s of [
    { available: true, live_sandboxed_runs: [run] },
    { available: true, restart_pending: true },
    { available: true, update_pending: true },
    { available: true, update_deferred_live_sandbox: true },
  ]) {
    assert.equal(liveRestartPollMs(s), LIVE_RESTART_POLL_MS);
  }
});

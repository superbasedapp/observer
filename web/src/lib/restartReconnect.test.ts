// Pins the restart reconnect wait (restartReconnect.ts, UI review U-22): it
// retries through refused connections, an old process and a hung request
// until the new process's started_at appears.
import { test } from "node:test";
import assert from "node:assert/strict";
import { RECONNECT_BACKOFF_MS, backoffFor, isNewProcess, waitForNewProcess } from "./restartReconnect.ts";

const before = "2026-11-21T10:00:00Z";
const after = "2026-11-21T10:00:02Z";
const isNew = (s: string | undefined) => isNewProcess(s, before, 0);

test("isNewProcess rule rows", () => {
  const rows: Array<[string, string | undefined, string | null, number, boolean]> = [
    ["no answer", undefined, before, 0, false],
    ["old process", before, before, 0, false],
    ["new process, known before", after, before, 0, true],
    ["new process with an earlier clock", "2026-11-21T09:00:00Z", before, Date.parse(before), true],
    ["before unknown, later start", after, null, Date.parse(before), true],
    ["before unknown, earlier start", "2026-11-21T09:59:00Z", null, Date.parse(before), false],
    ["before unknown, unparseable", "soon", null, 0, false],
  ];
  for (const [name, startedAt, prior, at, want] of rows) {
    assert.equal(isNewProcess(startedAt, prior, at), want, name);
  }
});

test("backoffFor walks the ladder and stays on its last step", () => {
  assert.deepEqual(RECONNECT_BACKOFF_MS.map((_, i) => backoffFor(i)), [...RECONNECT_BACKOFF_MS]);
  assert.equal(backoffFor(50), RECONNECT_BACKOFF_MS[RECONNECT_BACKOFF_MS.length - 1]);
});

test("keeps retrying through refused connections and the old process until the new one answers", async () => {
  const answers = ["old", "refused", "refused", "null", "refused", "old", "new"] as const;
  const sleeps: number[] = [];
  let calls = 0;
  const ok = await waitForNewProcess(isNew, {
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    probe: async () => {
      const a = answers[calls++];
      if (a === "refused") throw new TypeError("Failed to fetch");
      if (a === "null") return null;
      return { started_at: a === "old" ? before : after };
    },
  });
  assert.equal(ok, true);
  assert.equal(calls, answers.length);
  assert.deepEqual(sleeps, answers.map((_, i) => backoffFor(i)));
});

test("abandons an attempt that hangs and tries again", async () => {
  let calls = 0;
  const ok = await waitForNewProcess(isNew, {
    sleep: async () => {},
    attemptTimeoutMs: 5,
    probe: (signal) => {
      calls++;
      if (calls === 1) {
        // Never settles on its own: only the per-attempt timeout ends it.
        return new Promise((_resolve, reject) =>
          signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError"))),
        );
      }
      return Promise.resolve({ started_at: after });
    },
  });
  assert.equal(ok, true);
  assert.equal(calls, 2);
});

test("stops when the caller aborts", async () => {
  const ac = new AbortController();
  let calls = 0;
  const ok = await waitForNewProcess(isNew, {
    signal: ac.signal,
    sleep: async () => {},
    probe: async () => {
      calls++;
      if (calls === 3) ac.abort();
      throw new TypeError("Failed to fetch");
    },
  });
  assert.equal(ok, false);
  assert.equal(calls, 3);
});

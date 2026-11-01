// Render tests of the live sandboxed runs question (lane SBX-UPD, sandbox
// plan v2 section 5.5), rendered with react-dom/server under node's test
// runner (scripts/test-components.mjs). The view takes the runs as a prop.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { LiveSandboxRunsDialogView, ageLabel, liveRunsCopy } from "@/components/LiveSandboxRunsDialog";
import { liveRunsFromError } from "@/lib/useDaemonRestart";
import { ApiError } from "@/lib/api";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const runs = [
  { run_id: "r1", tool: "claude-code", backend: "bwrap", age_seconds: 300, native_resume: true },
  { run_id: "r2", tool: "aider", backend: "oci-runc", age_seconds: 7500, native_resume: false },
];

const noop = () => {};

test("restart mode names both answers and every run", () => {
  const html = renderToStaticMarkup(
    <LiveSandboxRunsDialogView runs={runs} mode="restart" onEnd={noop} onWhenFinished={noop} onClose={noop} />,
  );
  assert.match(html, /End the 2 runs and restart/);
  assert.match(html, /Restart when they finish/);
  assert.match(html, /claude-code/);
  assert.match(html, /oci-runc/);
  assert.match(html, /5 min/);
  assert.match(html, /2 h 5 min/);
  assert.match(html, /continues with the tool&#x27;s own resume/);
  assert.match(html, /no native resume/);
  assert.match(html, /Nothing ends until you choose/);
});

test("update mode asks about the update", () => {
  const html = renderToStaticMarkup(
    <LiveSandboxRunsDialogView runs={runs.slice(0, 1)} mode="update" onEnd={noop} onWhenFinished={noop} onClose={noop} />,
  );
  assert.match(html, /End the run and apply the update/);
  assert.match(html, /Apply when it finishes/);
  assert.match(html, /An update is waiting/);
});

test("copy and ages", () => {
  assert.equal(liveRunsCopy("restart", 1).end, "End the run and restart");
  assert.equal(liveRunsCopy("restart", 3).later, "Restart when they finish");
  assert.equal(ageLabel(30), "under a minute");
  assert.equal(ageLabel(3600), "1 h");
});

test("a 409 live_sandboxed_runs refusal yields its runs; other errors do not", () => {
  const body = JSON.stringify({ error: "live_sandboxed_runs", runs });
  assert.equal(liveRunsFromError(new ApiError(409, "/api/admin/restart", body))?.length, 2);
  assert.equal(liveRunsFromError(new ApiError(409, "/api/admin/restart", JSON.stringify({ error: "other" }))), null);
  assert.equal(liveRunsFromError(new ApiError(500, "/api/admin/restart", body)), null);
  assert.equal(liveRunsFromError(new Error("x")), null);
});

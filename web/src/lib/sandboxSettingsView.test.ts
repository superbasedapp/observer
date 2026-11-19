import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SANDBOX_CARD_SHAPE_RULES,
  SANDBOX_EDITOR_RULES,
  SANDBOX_PROBE_RULES,
  sandboxCardShape,
  sandboxEditorState,
  sandboxProbeLine,
  sandboxReadPhase,
  type SandboxCardShape,
  type SandboxCardShapeInput,
  type SandboxEditorState,
  type SandboxProbeFacts,
  type SandboxRead,
} from "./sandboxSettingsView.ts";

// The Sandbox isolation card's view model (lane L2): one case per rule of
// each table, plus the operator's report as its own row (a fresh install of
// the developer edition, every read skipped).

const ok: SandboxRead = { phase: "ok", complete: true };
const pending: SandboxRead = { phase: "pending" };
const skipped: SandboxRead = { phase: "skipped" };

test("sandboxReadPhase: skipped, then data, then error, then slow or pending", () => {
  const rows: [string, Parameters<typeof sandboxReadPhase>[0], string][] = [
    ["a skipped read is never pending", { skipped: true, hasData: false, error: false, slow: true }, "skipped"],
    ["data wins over a stale error", { skipped: false, hasData: true, error: true, slow: false }, "ok"],
    ["an error with no data", { skipped: false, hasData: false, error: true, slow: false }, "error"],
    ["in flight past the patience window", { skipped: false, hasData: false, error: false, slow: true }, "slow"],
    ["in flight", { skipped: false, hasData: false, error: false, slow: false }, "pending"],
  ];
  for (const [name, input, want] of rows) assert.equal(sandboxReadPhase(input), want, name);
});

test("sandboxCardShape: one case per rule, in table order", () => {
  const base: SandboxCardShapeInput = { module: "active", concealed: false, settings: ok, probe: ok };
  const rows: [string, Partial<SandboxCardShapeInput>, SandboxCardShape][] = [
    ["the visibility posture hides the section", { concealed: true }, "hidden"],
    ["the module is not in this build", { module: "absent" }, "hidden"],
    ["the route guard says not in this build", { module: "unknown", settings: { phase: "error", notInstalled: { component: "terminals.sandbox", state: "absent" } } }, "hidden"],
    ["the module is blocked here", { module: "blocked" }, "module_blocked"],
    ["the module is installed but not turned on", { module: "available" }, "module_off"],
    ["the route guard answered before the state read", { module: "unknown", probe: { phase: "error", notInstalled: { component: "terminals.sandbox", state: "available" } } }, "module_off"],
    // The operator's report: the state read says the routes are inactive,
    // so useApi skips both reads. This used to spin forever.
    ["fresh developer install: every read skipped", { module: "unknown", settings: skipped, probe: skipped }, "module_off"],
    ["the module runs here", {}, "shown"],
  ];
  assert.equal(rows.length - 3, SANDBOX_CARD_SHAPE_RULES.length, "one row per rule, plus two route-guard rows and the report row");
  for (const [name, over, want] of rows) assert.equal(sandboxCardShape({ ...base, ...over }), want, name);
});

test("sandboxEditorState: one case per rule, in table order", () => {
  const rows: [string, SandboxRead, boolean, SandboxEditorState][] = [
    ["the settings arrived", ok, false, "editor"],
    ["the route is local-only on a remote view", { phase: "error", message: "api 403" }, true, "local_only"],
    ["the read failed", { phase: "error", message: "api 500" }, false, "load_error"],
    ["the reply had no sandbox block", { phase: "ok", complete: false }, false, "incomplete"],
    ["the read is taking too long", { phase: "slow" }, false, "slow"],
    ["the read is in flight", pending, false, "loading"],
  ];
  assert.equal(rows.length, SANDBOX_EDITOR_RULES.length, "one row per rule");
  for (const [name, read, local, want] of rows) assert.equal(sandboxEditorState(read, local), want, name);
});

test("sandboxProbeLine: one case per rule, in table order", () => {
  type Row = [string, SandboxRead, SandboxProbeFacts | null, { tone: string; text: RegExp; retry: boolean; technical?: RegExp }];
  const rows: Row[] = [
    ["a backend is available", ok, { available: true, verdict: "available", backend: "bwrap", backend_version: "0.9.0", home_mode: "tmpfs", egress: "internet" }, { tone: "ok", text: /^bwrap 0\.9\.0 available; home is tmpfs; network is internet\.$/, retry: false }],
    ["sandbox support is off", ok, { available: false, verdict: "disabled_by_config", reason: "[terminal.sandbox].enabled is false on this daemon" }, { tone: "neutral", text: /^Sandbox support is off\. Turn on Enable sandbox support below and save/, retry: false, technical: /disabled_by_config.*\[terminal\.sandbox\]\.enabled/ }],
    ["on but could not start", ok, { available: false, verdict: "runtime_init_failed", reason: "workspaces_dir is not absolute" }, { tone: "warn", text: /could not start it/, retry: true, technical: /workspaces_dir is not absolute/ }],
    ["the check took too long", ok, { available: false, verdict: "probe_timed_out", reason: "did not answer within 20s" }, { tone: "warn", text: /took too long.*You can still change the settings below/, retry: true, technical: /probe_timed_out/ }],
    ["the check stopped with an error", ok, { available: false, verdict: "probe_failed", reason: "panic" }, { tone: "warn", text: /stopped with an error/, retry: true, technical: /probe_failed/ }],
    ["no backend can run: the server's reason", ok, { available: false, verdict: "backend_missing", reason: "Bubblewrap is not installed" }, { tone: "neutral", text: /^Bubblewrap is not installed$/, retry: false, technical: /backend_missing/ }],
    ["the check failed", { phase: "error", message: "api 500 /api/terminal/sandbox" }, null, { tone: "warn", text: /^Could not check this machine's sandbox support\. You can still change/, retry: true, technical: /api 500/ }],
    ["the check is taking too long", { phase: "slow" }, null, { tone: "warn", text: /has not answered yet/, retry: true }],
    ["the check is in flight", pending, null, { tone: "neutral", text: /^Checking this machine's sandbox support\.$/, retry: false }],
  ];
  assert.equal(rows.length, SANDBOX_PROBE_RULES.length, "one row per rule");
  for (const [name, read, facts, want] of rows) {
    const got = sandboxProbeLine(read, facts);
    assert.equal(got.tone, want.tone, `${name}: tone`);
    assert.match(got.text, want.text, `${name}: text`);
    assert.equal(got.retry, want.retry, `${name}: retry`);
    if (want.technical) assert.match(got.technical ?? "", want.technical, `${name}: technical`);
  }
});

test("sandboxProbeLine: plain words never carry the internal names (copy rules)", () => {
  // The internal key, verdict and route names live only in technical.
  const reads: [SandboxRead, SandboxProbeFacts | null][] = [
    [ok, { available: false, verdict: "disabled_by_config", reason: "[terminal.sandbox].enabled is false on this daemon" }],
    [ok, { available: false, verdict: "runtime_init_failed", reason: "[terminal.sandbox].workspaces_dir must be absolute" }],
    [ok, { available: false, verdict: "probe_timed_out", reason: "x" }],
    [ok, { available: false, verdict: "probe_failed", reason: "x" }],
    [{ phase: "error", message: "api 500 /api/terminal/sandbox" }, null],
  ];
  for (const [r, p] of reads) {
    const { text } = sandboxProbeLine(r, p);
    assert.doesNotMatch(text, /\[terminal\.sandbox\]|_by_|_init_|probe_|\/api\//, text);
  }
});

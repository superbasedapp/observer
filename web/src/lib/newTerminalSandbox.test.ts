import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SHELL_TOOL,
  betaRowChoosable,
  isolationPickerProps,
  sandboxLaunchFields,
  sandboxDisabledReason,
  sandboxStartBlock,
  sshSystemDisabledReason,
} from "./newTerminalSandbox.ts";
import { ISOLATION_AUTO, ISOLATION_NONE, launchBackend } from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxBackendAvail } from "./types.ts";

// The New Terminal dialog's sandbox and remote-system decisions (lane
// sbx-p2b, plans decision log P-017 (j) and P-026): one case per branch.

const ready: SandboxAvailability = {
  available: true,
  default_on: false,
  tools: {
    "claude-code": { available: true },
    aider: { available: false, reason: "aider keeps its state in the repository; no grounded profile" },
    codex: { available: false },
  },
};

test("sandboxDisabledReason: every branch, in priority order", () => {
  const cases: Array<[string, string, SandboxAvailability | null, RegExp | null]> = [
    ["no tool beats everything", "", null, /^Choose a tool first\.$/],
    ["a probe that never answered", "claude-code", null, /^Sandbox status unknown/],
    ["not in this build, by verdict", "claude-code", { available: false, default_on: false, verdict: "not_in_build", reason: "" }, /not in this build.*Settings -> Components/],
    ["not in this build, by the stub's reason", "claude-code", { available: false, default_on: false, reason: "the sandbox is not in this build" }, /^Sandbox isolation is not in this build - the sandbox is not in this build\./],
    ["switched off: names the switch, not a config key", "claude-code", { available: false, default_on: false, verdict: "disabled_by_config" }, /turned off\. Enable it in Terminals -> Settings -> Sandbox isolation/],
    ["runtime failed: quotes the server, never says enable", "claude-code", { available: false, default_on: false, verdict: "runtime_init_failed", reason: "workspaces_dir is not writable" }, /enabled but the daemon could not start it - workspaces_dir is not writable/],
    ["an environment gap, quoted verbatim", "claude-code", { available: false, default_on: false, verdict: "backend_missing", reason: "bwrap is not installed" }, /^Sandbox unavailable - bwrap is not installed$/],
    ["an environment gap with no reason", "claude-code", { available: false, default_on: false, verdict: "userns_denied" }, /^Sandbox unavailable - sandboxing is unavailable on this daemon$/],
    ["the plain shell", SHELL_TOOL, ready, /plain shell has no AI-tool state dirs/],
    ["a tool with its own reason", "aider", ready, /^aider keeps its state in the repository/],
    ["a tool with no reason", "codex", ready, /^No grounded sandbox profile for this tool/],
    ["a tool missing from the map", "gemini", ready, /^No grounded sandbox profile for this tool/],
    ["a sandbox-launchable tool", "claude-code", ready, null],
  ];
  for (const [name, tool, probe, want] of cases) {
    const got = sandboxDisabledReason(tool, probe);
    if (want === null) assert.equal(got, null, name);
    else assert.match(got ?? "", want, name);
  }
});

test("sshSystemDisabledReason: the kill switch beats an empty list", () => {
  assert.match(sshSystemDisabledReason(false, 0) ?? "", /are off\. Turn them on/);
  assert.match(sshSystemDisabledReason(false, 3) ?? "", /are off\. Turn them on/);
  assert.match(sshSystemDisabledReason(true, 0) ?? "", /^No remote systems yet\./);
  assert.equal(sshSystemDisabledReason(true, 1), null);
});

test("sandboxStartBlock: only a sandboxed launch with an enabled control is judged", () => {
  const sources = [
    { id: "live", available: true },
    { id: "clone-remote", available: true },
    { id: "worktree", available: false, reason: "worktree source is off" },
  ];
  const base = { sandboxOn: true, controlDisabled: false, source: "live", remote: "", sources };
  const cases: Array<[string, Partial<typeof base>, { remote: boolean; source: boolean; message: RegExp | null }]> = [
    ["a live workspace starts", {}, { remote: false, source: false, message: null }],
    ["clone-remote with no URL", { source: "clone-remote" }, { remote: true, source: false, message: /Enter a remote URL/ }],
    ["clone-remote with only spaces", { source: "clone-remote", remote: "   " }, { remote: true, source: false, message: /Enter a remote URL/ }],
    ["clone-remote with a URL", { source: "clone-remote", remote: "https://example.com/r.git" }, { remote: false, source: false, message: null }],
    ["an unavailable source", { source: "worktree" }, { remote: false, source: true, message: /isn't available - pick another one/ }],
    ["a source the probe does not list", { source: "something-new" }, { remote: false, source: false, message: null }],
    ["sandbox off: nothing blocks", { sandboxOn: false, source: "clone-remote" }, { remote: false, source: false, message: null }],
    ["control disabled: nothing blocks", { controlDisabled: true, source: "worktree" }, { remote: false, source: false, message: null }],
    ["no probe sources", { sources: undefined, source: "worktree" }, { remote: false, source: false, message: null }],
  ];
  for (const [name, mut, want] of cases) {
    const got = sandboxStartBlock({ ...base, ...mut });
    assert.equal(got.remoteURLMissing, want.remote, `${name}: remote`);
    assert.equal(got.sourceUnavailable, want.source, `${name}: source`);
    assert.equal(got.blocks, want.remote || want.source, `${name}: blocks`);
    if (want.message === null) assert.equal(got.message, null, `${name}: message`);
    else assert.match(got.message ?? "", want.message, `${name}: message`);
  }
});

// Audit SBX-P3B F1: a host whose only available rows are beta (verdict
// beta_not_chosen, every macOS and Windows host today) keeps the picker
// enabled, lists the beta rows labelled beta, keeps Automatic disabled with
// its reason, and a chosen beta row is what the launch names.
const seatbelt: SandboxBackendAvail = {
  id: "seatbelt",
  label: "Seatbelt",
  class: "process",
  location: "local",
  maturity: "preview",
  available: true,
  beta: true,
  capture_by_tier: {},
  component: "terminals.sandbox.seatbelt",
};
const betaOnly: SandboxAvailability = {
  available: false,
  verdict: "beta_not_chosen",
  reason: "a beta backend is used only when it is chosen for the launch",
  default_on: true,
  tools: ready.tools,
  backends: [
    { ...seatbelt, id: "bwrap", label: "Bubblewrap", maturity: "beta", beta: false, available: false, reason: "unsupported platform" },
    seatbelt,
    { ...seatbelt, id: "oci-runc", label: "Docker or Podman", class: "container", maturity: "planned", available: false },
  ],
};

test("a beta-only host: the picker is enabled, Automatic is disabled with its reason, a chosen beta row runs", () => {
  assert.equal(betaRowChoosable(betaOnly), true);
  assert.equal(sandboxDisabledReason("claude-code", betaOnly), null);
  // The tool's own row still applies.
  assert.match(sandboxDisabledReason("aider", betaOnly) ?? "", /^aider keeps its state/);

  // Before a row is chosen (the default Automatic, even with default_on):
  // the picker is enabled but shows None, so no launch naming no backend is
  // posted.
  const before = isolationPickerProps("claude-code", betaOnly, true, ISOLATION_AUTO);
  assert.equal(before.disabled, false);
  assert.equal(before.reason, null);
  assert.equal(before.value, ISOLATION_NONE);
  const auto = before.options.find((o) => o.id === ISOLATION_AUTO)!;
  assert.equal(auto.disabled, true);
  assert.equal(auto.reason, betaOnly.reason);
  const row = before.options.find((o) => o.id === "seatbelt")!;
  assert.equal(row.beta, true);
  assert.equal(row.disabled, false);
  assert.equal(before.options.some((o) => o.id === "oci-runc"), false);

  // The user picks the beta row: it is shown, and the launch names it.
  const chosen = isolationPickerProps("claude-code", betaOnly, true, "seatbelt");
  assert.equal(chosen.value, "seatbelt");
  assert.equal(chosen.disabled, false);
  assert.match(chosen.chip ?? "", /beta$/);
  assert.equal(launchBackend(chosen.value), "seatbelt");
});

test("beta_not_chosen with no available beta row still disables the picker", () => {
  const none: SandboxAvailability = { ...betaOnly, backends: [{ ...seatbelt, available: false }] };
  assert.equal(betaRowChoosable(none), false);
  assert.match(sandboxDisabledReason("claude-code", none) ?? "", /^Sandbox unavailable - a beta backend is used only when/);
  assert.equal(betaRowChoosable({ ...betaOnly, verdict: "backend_missing" }), false);
  assert.equal(betaRowChoosable({ ...betaOnly, available: true }), false);
  assert.equal(betaRowChoosable(null), false);
  assert.equal(isolationPickerProps("claude-code", none, true, "seatbelt").disabled, true);
});

// B4 (Windows 11 Pro live run): the launch body's sandbox fields. A chosen
// row, a beta one included, is the backend; Automatic sends none; off sends
// nothing at all; the branch rides only where it applies.
test("sandboxLaunchFields: a chosen row is the backend, Automatic and off send none", () => {
  const base = { workspaceSource: "", workspaceRemote: " ", workspaceBranch: "feat", branchApplies: false };
  assert.deepEqual(sandboxLaunchFields({ ...base, sandboxOn: false, isolationChoice: "mxc-process" }), {});
  assert.deepEqual(sandboxLaunchFields({ ...base, sandboxOn: true, isolationChoice: "mxc-process" }), {
    sandbox: true,
    sign_in_ask: true,
    backend: "mxc-process",
    workspace_source: "live",
  });
  assert.deepEqual(sandboxLaunchFields({ ...base, sandboxOn: true, isolationChoice: ISOLATION_AUTO }), { sandbox: true, sign_in_ask: true, workspace_source: "live" });
  assert.deepEqual(
    sandboxLaunchFields({ sandboxOn: true, isolationChoice: "bwrap", workspaceSource: "clone-remote", workspaceRemote: " git@x:y.git ", workspaceBranch: " feat ", branchApplies: true }),
    { sandbox: true, sign_in_ask: true, backend: "bwrap", workspace_source: "clone-remote", workspace_remote: "git@x:y.git", workspace_branch: "feat" },
  );
});

// Lane BOXSIGNIN: a sandboxed launch says it can ask about the sign-in, and
// the inline step's answer rides the retried Start; off sends nothing.
test("sandboxLaunchFields: the sign-in step's answer rides Start", () => {
  const base = { sandboxOn: true, isolationChoice: ISOLATION_AUTO, workspaceSource: "", workspaceRemote: "", workspaceBranch: "", branchApplies: false };
  assert.equal(sandboxLaunchFields(base).sign_in_seed, undefined);
  assert.equal(sandboxLaunchFields({ ...base, signInSeed: true }).sign_in_seed, true);
  assert.equal(sandboxLaunchFields({ ...base, signInSeed: false }).sign_in_seed, false);
  assert.deepEqual(sandboxLaunchFields({ ...base, sandboxOn: false, signInSeed: true }), {});
});

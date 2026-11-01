// Component tests of the New Terminal dialog's sandbox surface (lane
// sbx-p2b, plans decision log P-017 (j) and P-026), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).
// The pure decisions are pinned in src/lib/newTerminalSandbox.test.ts; these
// prove the dialog and the Isolation picker render them.

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import type { ReactElement } from "react";
import { renderToPipeableStream, renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { SandboxIsolationPicker } from "@/components/SandboxIsolationPicker";
import { NewTerminalDialog, branchField, worktreeBranchProblem, type NewTerminalDraft } from "@/components/NewTerminalDialog";
import { ISOLATION_AUTO, ISOLATION_NONE, isolationOptions } from "@/lib/sandboxIsolation";
import { isolationPickerProps, sandboxLaunchFields } from "@/lib/newTerminalSandbox";
import type { SandboxAvailability } from "@/lib/types";

// React warns that a layout effect does nothing on the server; the dialog's
// chips use one, and the warning says nothing about these tests.
const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

// renderAll renders el with every Suspense boundary resolved (the Isolation
// picker is a lazy compgen row).
function renderAll(el: ReactElement): Promise<string> {
  return new Promise((resolve, reject) => {
    let html = "";
    const sink = new PassThrough();
    sink.on("data", (c) => (html += c.toString()));
    sink.on("end", () => resolve(html));
    const s = renderToPipeableStream(el, {
      onAllReady() {
        s.pipe(sink);
      },
      onShellError: reject,
      onError: reject,
    });
  });
}

const probe: SandboxAvailability = {
  available: true,
  default_on: false,
  backends: [
    {
      id: "bwrap",
      label: "Bubblewrap",
      class: "process",
      location: "local",
      maturity: "beta",
      available: true,
      beta: false,
      capture_by_tier: {},
      component: "terminals.sandbox",
    },
    {
      id: "oci-runc",
      label: "Docker or Podman",
      class: "container",
      location: "local",
      maturity: "beta",
      available: false,
      reason: "no container runtime found",
      beta: true,
      capture_by_tier: {},
      component: "terminals.sandbox",
    },
  ],
};

test("the Isolation picker lists None and every offered backend, an unavailable one disabled with its reason", () => {
  const html = renderToStaticMarkup(
    <SandboxIsolationPicker options={isolationOptions(probe)} value="bwrap" disabled={false} reason={null} chip="process sandbox, egress none" onChange={() => {}} />,
  );
  assert.match(html, /<option value="none"[^>]*>None<\/option>/);
  assert.match(html, /<option value="bwrap"[^>]*>Bubblewrap - process sandbox<\/option>/);
  assert.doesNotMatch(html, /<option value="bwrap"[^>]*disabled/);
  assert.match(html, /<option value="oci-runc" disabled="" title="no container runtime found">Docker or Podman - container \(beta\) \(unavailable\)<\/option>/);
  assert.match(html, /process sandbox, egress none/);
  assert.doesNotMatch(html, /<select[^>]*disabled/);
});

test("a disabled Isolation picker shows its reason instead of the chip", () => {
  const html = renderToStaticMarkup(
    <SandboxIsolationPicker options={isolationOptions(null)} value={ISOLATION_NONE} disabled reason="Sandbox status unknown - the probe failed." chip="never shown" onChange={() => {}} />,
  );
  assert.match(html, /<select[^>]*disabled/);
  assert.match(html, /title="Sandbox status unknown - the probe failed\."/);
  assert.doesNotMatch(html, /never shown/);
});

function dialog(draft?: NewTerminalDraft, sandboxProbe?: SandboxAvailability, windowsPathsToWSL?: boolean): ReactElement {
  return (
    <MemoryRouter>
      <NewTerminalDialog
        onClose={() => {}}
        onLaunched={() => {}}
        initialDraft={draft}
        initialSandboxProbe={sandboxProbe}
        initialWindowsPathsToWSL={windowsPathsToWSL}
      />
    </MemoryRouter>
  );
}

const sandboxDraft: NewTerminalDraft = {
  tool: "claude-code",
  rootSel: "",
  customRoot: "",
  modelSel: "",
  sandboxOn: true,
  workspaceSource: "clone-remote",
  workspaceRemote: "",
  workspaceBranch: "",
};

test("the dialog's first paint: the Isolation picker is disabled until the sandbox probe answers", async () => {
  // Effects (the probe fetch) never run on the server, so this is the
  // dialog before the probe resolved: whatever the draft says, the picker
  // is disabled with the honest reason, and the workspace panel (which only
  // a usable sandboxed launch shows) is absent.
  const html = await renderAll(dialog(sandboxDraft));
  assert.match(html, /id="new-terminal-isolation"/);
  assert.match(html, /<select[^>]*id="new-terminal-isolation"[^>]*disabled|<select[^>]*disabled[^>]*id="new-terminal-isolation"/);
  assert.match(html, /Sandbox status unknown - this daemon may not support sandboxed terminals/);
  assert.doesNotMatch(html, /new-terminal-sandbox-source/);
  assert.doesNotMatch(html, /Enter a remote URL/);
});

test("the dialog with no tool chosen names that first", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, tool: "" }));
  assert.match(html, /title="Choose a tool first\."/);
});

// Audit SBX-P3B F1: the picker as the dialog renders it (isolationPickerProps
// is the dialog's own computation) on a host whose only available rows are
// beta. The probe fetch is an effect, which never runs on the server, so the
// dialog's own state is fed through the same function here.
const betaOnlyProbe: SandboxAvailability = {
  available: false,
  verdict: "beta_not_chosen",
  reason: "a beta backend is used only when it is chosen for the launch",
  default_on: true,
  tools: { "claude-code": { available: true } },
  backends: [
    { ...probe.backends![0], available: false, reason: "unsupported platform" },
    { ...probe.backends![1], id: "seatbelt", label: "Seatbelt", class: "process", maturity: "preview", available: true, reason: undefined, beta: true },
  ],
};

test("on a beta-only host the picker is enabled, Automatic disabled with its reason, the beta row choosable", () => {
  const before = isolationPickerProps("claude-code", betaOnlyProbe, true, ISOLATION_AUTO);
  const html = renderToStaticMarkup(<SandboxIsolationPicker {...before} onChange={() => {}} />);
  assert.doesNotMatch(html, /<select[^>]*disabled/);
  assert.match(html, /<option value="auto" disabled="" title="a beta backend is used only when it is chosen for the launch">Automatic \(unavailable\)<\/option>/);
  assert.match(html, /<option value="seatbelt">Seatbelt - process sandbox \(beta\)<\/option>/);
  assert.match(html, /None: the agent runs on the host/);

  const chosen = isolationPickerProps("claude-code", betaOnlyProbe, true, "seatbelt");
  const html2 = renderToStaticMarkup(<SandboxIsolationPicker {...chosen} onChange={() => {}} />);
  assert.match(html2, /<option value="seatbelt"[^>]*selected=""[^>]*>Seatbelt - process sandbox \(beta\)<\/option>/);
  assert.match(html2, /process sandbox, network internet, beta/);
});

// P-087 (owed by the SBX-P3B merge): the whole dialog on a beta-only host,
// with its probe answered: the picker enabled, Automatic disabled with its
// reason, so a launch never posts a disabled Automatic.
test("the dialog on a beta-only host renders the enabled picker with Automatic disabled", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, betaOnlyProbe));
  assert.doesNotMatch(html, /<select[^>]*id="new-terminal-isolation"[^>]*disabled|<select[^>]*disabled[^>]*id="new-terminal-isolation"/);
  // Streamed rendering splits adjacent text with a comment marker.
  assert.match(html, /<option value="auto" disabled="" title="a beta backend is used only when it is chosen for the launch">Automatic(<!-- -->)? \(unavailable\)<\/option>/);
  assert.match(html, /<option value="seatbelt">Seatbelt - process sandbox(<!-- -->)? \(beta\)<\/option>/);
});

// Windows 11 Pro live run, B4: a native Windows host whose only available
// row is the beta mxc-process (the daemon's real verdict and reason). The
// dialog offers mxc-process, and choosing it sends it as the launch's
// backend, exactly as `observer claude --observer-sandbox mxc-process`;
// Automatic stays disabled and sends no backend (P-062).
const windowsBetaProbe: SandboxAvailability = {
  available: false,
  verdict: "beta_not_chosen",
  reason:
    "terminal_sandbox: mxc-process is available but not chosen (beta_not_chosen): a beta backend is used only when it is chosen for the launch (observer <tool> --observer-sandbox mxc-process); automatic selection never picks one (ruling P-062)",
  backend: "mxc-process",
  default_on: false,
  tools: { "claude-code": { available: true } },
  sources: [{ id: "live", available: true }],
  backends: [
    { ...probe.backends![0], id: "hcs", label: "Hyper-V container", class: "vm", maturity: "preview", available: false, verdict: "image_missing", reason: "no utility VM image is configured", beta: true },
    { ...probe.backends![0], id: "mxc-appcontainer", label: "MXC AppContainer", maturity: "preview", available: false, verdict: "psec_unavailable", reason: "base-container tier only", beta: true },
    { ...probe.backends![0], id: "mxc-process", label: "MXC process", maturity: "preview", available: true, beta: true },
    { ...probe.backends![0], id: "wslc", label: "WSL container", class: "container", maturity: "preview", available: false, verdict: "backend_missing", reason: "WSL is not installed", beta: true },
  ],
};

test("on Windows the dialog offers the beta mxc-process row and a chosen one is the launch's backend", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, windowsBetaProbe));
  assert.doesNotMatch(html, /<select[^>]*id="new-terminal-isolation"[^>]*disabled|<select[^>]*disabled[^>]*id="new-terminal-isolation"/);
  assert.match(html, /<option value="mxc-process">MXC process - process sandbox(<!-- -->)? \(beta\)<\/option>/);
  assert.match(html, /<option value="auto" disabled=""/);
  assert.doesNotMatch(html, /Sandbox unavailable - /);

  const chosen = isolationPickerProps("claude-code", windowsBetaProbe, true, "mxc-process");
  assert.equal(chosen.disabled, false);
  assert.equal(chosen.value, "mxc-process");
  const fields = { workspaceSource: "live", workspaceRemote: "", workspaceBranch: "", branchApplies: false };
  // sign_in_ask (lane BOXSIGNIN): the dialog can answer the sign-in step.
  assert.deepEqual(sandboxLaunchFields({ sandboxOn: true, isolationChoice: "mxc-process", ...fields }), {
    sandbox: true,
    sign_in_ask: true,
    backend: "mxc-process",
    workspace_source: "live",
  });
  assert.deepEqual(sandboxLaunchFields({ sandboxOn: true, isolationChoice: ISOLATION_AUTO, ...fields }), { sandbox: true, sign_in_ask: true, workspace_source: "live" });
  assert.deepEqual(sandboxLaunchFields({ sandboxOn: false, isolationChoice: "mxc-process", ...fields }), {});
});

// B4: the custom-root hint about Windows paths shows only for a daemon in
// WSL (the only daemon that translates them).
test("the Windows path hint shows only when the daemon runs in WSL", async () => {
  const custom: NewTerminalDraft = { ...sandboxDraft, sandboxOn: false, rootSel: "\u0000custom", customRoot: "C:\\Users\\u\\proj" };
  const native = await renderAll(dialog(custom, undefined, false));
  assert.doesNotMatch(native, /translated to their WSL/);
  const wsl = await renderAll(dialog(custom, undefined, true));
  assert.match(wsl, /translated to their WSL/);
});

// SHR-FOLLOWUPS milestone 2 (SHR-WORKTREE2 milestone 5): the branch field
// shows for the worktree source too, its placeholder the default label.
const worktreeProbe: SandboxAvailability = {
  ...probe,
  tools: { "claude-code": { available: true } },
  sources: [
    { id: "live", available: true },
    { id: "clone-remote", available: true },
    { id: "worktree", available: true },
  ],
};

test("the branch field shows for clone-remote and worktree, not for live", async () => {
  const wt = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "worktree" }, worktreeProbe));
  assert.match(wt, /id="new-terminal-sandbox-source"/);
  assert.match(wt, /<input[^>]*id="new-terminal-sandbox-branch"[^>]*placeholder="work"/);
  assert.match(wt, /observer-sandbox\/&lt;run&gt;\/&lt;name&gt;/);
  assert.doesNotMatch(wt, /new-terminal-sandbox-remote/);

  const clone = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "clone-remote" }, worktreeProbe));
  assert.match(clone, /<input[^>]*id="new-terminal-sandbox-branch"[^>]*placeholder="main"/);
  assert.match(clone, /new-terminal-sandbox-remote/);

  const live = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, worktreeProbe));
  assert.match(live, /id="new-terminal-sandbox-source"/);
  assert.doesNotMatch(live, /new-terminal-sandbox-branch/);
});

test("a worktree branch git would refuse is named before the launch", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "worktree", workspaceBranch: "a..b" }, worktreeProbe));
  assert.match(html, /The branch name must not contain \.\. or @\{/);
  const ok = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "worktree", workspaceBranch: "fix-login" }, worktreeProbe));
  assert.doesNotMatch(ok, /The branch name/);
});

test("branchField and worktreeBranchProblem follow the daemon's rules", () => {
  assert.equal(branchField("live"), null);
  assert.equal(branchField("clone-local"), null);
  assert.equal(branchField("worktree")?.placeholder, "work");
  assert.equal(branchField("clone-remote")?.placeholder, "main");
  for (const ok of ["", "work", "fix.v2", "feature_x@2"]) assert.equal(worktreeBranchProblem("worktree", ok), null, ok);
  for (const bad of ["a/b", "a\\b", "-x", ".h", "x.", "x.lock", "a..b", "a@{1}", "@", "a~1", "a^", "a:b", "a?", "a*", "a[0]", "has space", "x".repeat(101)]) {
    assert.notEqual(worktreeBranchProblem("worktree", bad), null, bad);
  }
  // Only the worktree source is checked here; git checks a clone's branch.
  assert.equal(worktreeBranchProblem("clone-remote", "a..b"), null);
});

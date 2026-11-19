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
import { NewTerminalDialog, branchField, withSetupBackend, worktreeBranchProblem, type NewTerminalDraft } from "@/components/NewTerminalDialog";
import { ISOLATION_AUTO, ISOLATION_NONE, isolationOptions } from "@/lib/sandboxIsolation";
import { isolationPickerProps, sandboxLaunchFields } from "@/lib/newTerminalSandbox";
import type { SandboxAvailability } from "@/lib/types";
import type { SandboxSetupPlan, SandboxSetupSummary } from "@/lib/sandboxSetupTypes";

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

test("a backend that only needs enabling reads not enabled, with a link to the Backends setting", () => {
  const options = isolationOptions({
    ...probe,
    backends: [
      ...(probe.backends ?? []),
      { id: "landlock", label: "Landlock only", class: "process", location: "local", maturity: "beta", available: false, verdict: "disabled_by_config", when_enabled_available: true, beta: true, capture_by_tier: {}, component: "terminals.sandbox" },
    ],
  });
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxIsolationPicker options={options} value="bwrap" disabled={false} reason={null} chip={null} onChange={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /<option value="landlock" disabled=""[^>]*>Landlock only - process sandbox \(beta\) \(not enabled\)<\/option>/);
  assert.match(html, /Docker or Podman - container \(beta\) \(unavailable\)/);
  assert.match(html, /1 backend can run here once enabled/);
  assert.match(html, /href="\/terminals#sandbox-backends"/);
  assert.doesNotMatch(html, /module installed/);
});

test("a backend whose module is not installed says so, with a link to Settings > Components", () => {
  const options = isolationOptions({
    ...probe,
    backends: [
      ...(probe.backends ?? []),
      { id: "oci-runsc", label: "Docker with gVisor", class: "userspace_kernel", location: "local", maturity: "beta", available: false, verdict: "disabled_by_config", when_enabled_verdict: "module_inactive", when_enabled_reason: "the terminals.sandbox.oci component is not selected on this node", beta: true, capture_by_tier: {}, component: "terminals.sandbox" },
    ],
  });
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxIsolationPicker options={options} value="bwrap" disabled={false} reason={null} chip={null} onChange={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /Docker with gVisor - user-space kernel \(beta\) \(module not installed\)<\/option>/);
  assert.match(html, /1 backend needs its module installed/);
  assert.match(html, /href="\/settings\/components"/);
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

// Sandbox installation lifecycle plan section 3.7 (lane sbxinstall-ui): the
// picker's one setup line, the inline setup panel and the resume draft.
const setupProbe: SandboxAvailability = {
  ...probe,
  tools: { "claude-code": { available: true } },
  sources: [{ id: "live", available: true }],
  backends: [
    ...(probe.backends ?? []),
    { ...probe.backends![0], id: "landlock", label: "Landlock only", available: false, verdict: "disabled_by_config", when_enabled_available: true, beta: true },
  ],
};

const setupRows: SandboxSetupSummary[] = [
  { backend: "bwrap", label: "Bubblewrap", ready: true },
  { backend: "oci-runc", label: "Docker or Podman", ready: false, next: "Docker Engine" },
  { backend: "landlock", label: "Landlock only", ready: false, next: "Turn on Landlock only" },
  { backend: "openshell", label: "OpenShell", ready: false, blocked: "OpenShell does not run in WSL2" },
];

const landlockPlan: SandboxSetupPlan = {
  backend: "landlock",
  label: "Landlock only",
  next: 0,
  ready: false,
  checked: false,
  fingerprint: "fp-l",
  steps: [
    { prereq: "enable", kind: "enable", label: "Turn on Landlock only", state: "missing", class: "auto", channel: "sandbox_enable", can_run: true, can_undo: false },
  ],
};

function setupDialog(
  draft: NewTerminalDraft,
  summaries?: SandboxSetupSummary[],
  plan?: SandboxSetupPlan,
  switches?: { fresh: boolean; shell: boolean },
): ReactElement {
  return (
    <MemoryRouter>
      <NewTerminalDialog
        onClose={() => {}}
        onLaunched={() => {}}
        initialDraft={draft}
        initialSandboxProbe={setupProbe}
        initialSetupSummaries={summaries}
        initialSetupPlan={plan}
        initialLaunchSwitches={switches}
      />
    </MemoryRouter>
  );
}

const liveDraft: NewTerminalDraft = { ...sandboxDraft, workspaceSource: "live" };

test("with setup offered, the picker shows one setup line with the count instead of the two lines", async () => {
  const html = await renderAll(setupDialog(liveDraft, setupRows));
  assert.match(html, /data-testid="isolation-setup"/);
  assert.match(html, /Set up a sandbox backend \((<!-- -->)?2(<!-- -->)? available to set up\)/);
  assert.doesNotMatch(html, /can run here once enabled/);
  assert.doesNotMatch(html, /module installed/);
  // A row setup can move forward is choosable (it opens the panel); the
  // panel itself is not open until the person asks.
  assert.match(html, /<option value="landlock"[^>]*>Landlock only - process sandbox(<!-- -->)? \(beta\)(<!-- -->)? \(set up\)<\/option>/);
  assert.doesNotMatch(html, /<option value="landlock" disabled/);
  assert.doesNotMatch(html, /data-testid="sandbox-setup-panel"/);
});

test("the picker without onSetup keeps today's two lines and links", () => {
  const options = isolationOptions(setupProbe);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <SandboxIsolationPicker options={options} value="bwrap" disabled={false} reason={null} chip={null} onChange={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /1 backend can run here once enabled/);
  assert.doesNotMatch(html, /Set up a sandbox backend/);
  assert.match(html, /<option value="landlock" disabled=""/);
});

test("a draft naming a setup row opens the panel there, rendered from its plan", async () => {
  const html = await renderAll(setupDialog({ ...liveDraft, setupBackend: "landlock" }, setupRows, landlockPlan));
  assert.match(html, /data-testid="sandbox-setup-panel"/);
  assert.match(html, /<option value="landlock" selected="">Landlock only \(next: Turn on Landlock only\)<\/option>/);
  assert.match(html, /Landlock only is not set up yet\. Next: Turn on Landlock only\./);
  assert.match(html, /<li data-step="enable"/);
  assert.match(html, /Turn on<\/button>|>Turn on</);
});

test("the resume draft carries setupBackend only while the panel is open", () => {
  assert.deepEqual(withSetupBackend(liveDraft, true, "landlock"), { ...liveDraft, setupBackend: "landlock" });
  assert.deepEqual(withSetupBackend({ ...liveDraft, setupBackend: "landlock" }, false, "landlock"), liveDraft);
  assert.deepEqual(withSetupBackend(liveDraft, true, undefined), liveDraft);
});

test("nothing setup-shaped renders when the setup routes are absent", async () => {
  // No summaries: the daemon answered 404 or 501 (or this build has no
  // panel), so the picker reads as before and a resumed setup draft opens
  // no panel.
  const html = await renderAll(setupDialog({ ...liveDraft, setupBackend: "landlock" }));
  assert.doesNotMatch(html, /Set up a sandbox backend/);
  assert.doesNotMatch(html, /data-testid="sandbox-setup-panel"/);
  assert.match(html, /1 backend can(<!-- -->)? run here once enabled/);
});

// D-12: with fresh launch and plain shell both off nothing can start from the
// dialog. It still opens (it holds the sandbox setup line), and it says why
// and names the Settings path, with a link to the launch policy.
test("with both launch switches off the dialog says so and keeps the setup line", async () => {
  const html = await renderAll(setupDialog(liveDraft, setupRows, undefined, { fresh: false, shell: false }));
  assert.match(html, /data-testid="launch-switches-off"/);
  assert.match(html, /Fresh launch and plain shell terminals are both off/);
  assert.match(html, /Terminals &gt; Settings &gt; Fresh-agent launch policy/);
  assert.match(html, /Open the launch policy/);
  assert.match(html, /Set up a sandbox backend/);
});

test("with either launch switch on, or unknown, the dialog says nothing about them", async () => {
  for (const switches of [{ fresh: true, shell: false }, { fresh: false, shell: true }, undefined]) {
    const html = await renderAll(setupDialog(liveDraft, setupRows, undefined, switches));
    assert.doesNotMatch(html, /data-testid="launch-switches-off"/);
  }
});

// D-R4-4: the Isolation section wraps a long unbroken token (an image digest
// reference) instead of widening the dialog.
test("the Isolation section wraps long tokens", async () => {
  const html = await renderAll(setupDialog(liveDraft, setupRows));
  assert.match(html, /class="mb-1 \[overflow-wrap:anywhere\]" data-testid="isolation-picker"/);
});

// The hosted model key line (docs/audits/hosted-sandbox-key-custody-2026-11-18.md):
// when the row a launch resolves to runs on the provider's machines and the
// daemon says this tool's model key cannot reach the agent there, the
// dialog says so under the picker, in plain words with the place to choose,
// before Start.
const hostedKeyProbe: SandboxAvailability = {
  available: true,
  default_on: true,
  backend: "daytona",
  tools: {
    "claude-code": {
      available: true,
      hosted_key: {
        code: "nothing_serves_home_key",
        message: "The agent's model key is set to stay on this machine, but nothing here can add it to the agent's requests, so a hosted sandbox cannot start. Choose how the agent gets its model key.",
        technical: "key custody home_relay needs a key the proxy adds itself",
      },
    },
  },
  sources: [{ id: "live", available: true }],
  backends: [
    { id: "daytona", label: "Daytona", class: "container", location: "remote", maturity: "preview", available: true, beta: false, capture_by_tier: {}, component: "terminals.sandbox.daytona" },
  ],
};

test("a hosted row that cannot give the tool its model key says so before Start", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, hostedKeyProbe));
  assert.match(html, /data-testid="new-terminal-hosted-key"/);
  assert.match(html, /nothing here can add it to the agent(&#x27;|')s requests/);
  assert.match(html, /href="\/terminals\?tab=settings#sandbox-backends"/);
  assert.match(html, /aria-label="Technical details for this refusal"/);
  // The internal names stay in the technical detail, never in the sentence.
  const sentence = html.slice(html.indexOf('data-testid="new-terminal-hosted-key"'));
  assert.doesNotMatch(sentence.slice(0, sentence.indexOf("aria-label")), /home_relay/);
});

test("without the line the dialog shows no key notice", async () => {
  const probeNoLine: SandboxAvailability = { ...hostedKeyProbe, tools: { "claude-code": { available: true } } };
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, probeNoLine));
  assert.doesNotMatch(html, /new-terminal-hosted-key/);
});

// Lane UX (items H4, H5, H10): on a hosted row the dialog names the upload
// for what it is, says the box's own network, and blocks a tool the row
// cannot get into its box, all before Start and from the row's own facts.
const hostedUXProbe: SandboxAvailability = {
  available: true,
  default_on: true,
  backend: "daytona",
  tools: { "claude-code": { available: true } },
  sources: [{ id: "live", available: true }],
  backends: [
    {
      id: "daytona", label: "Daytona", class: "container", location: "remote", maturity: "preview", available: true, beta: false, capture_by_tier: {}, component: "terminals.sandbox.daytona",
      workspace_sources: ["live"], source_deliveries: { live: "sync" },
      tool_notices: { "claude-code": { code: "image_lacks_installer", message: "Daytona's default image has no npm, which every way Observer knows to install Claude Code needs, and no template is set.", technical: "tool_unavailable_in_image: the default image lacks npm" } },
      network_notes: ["On the internet setting the box reaches the network through Daytona's own network, not through Observer."],
    },
  ],
};

test("a hosted row says the upload, its network and a tool it cannot install, before Start", async () => {
  const html = await renderAll(dialog({ ...sandboxDraft, workspaceSource: "live" }, hostedUXProbe));
  assert.match(html, /Upload a copy of the project \(changes come back as a diff\)/);
  assert.doesNotMatch(html, />Live project directory</);
  assert.match(html, /data-testid="new-terminal-hosted-network"/);
  assert.match(html, /through Daytona(&#x27;|')s own network/);
  assert.match(html, /data-testid="new-terminal-hosted-tool"/);
  assert.match(html, /default image has no npm/);
  const sentence = html.slice(html.indexOf('data-testid="new-terminal-hosted-tool"'));
  assert.doesNotMatch(sentence.slice(0, sentence.indexOf("aria-label")), /tool_unavailable/);
});

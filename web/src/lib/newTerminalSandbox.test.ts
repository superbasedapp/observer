import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SHELL_TOOL,
  betaRowChoosable,
  chosenBackendRow,
  hostedHookLine,
  hostedKeyBlock,
  hostedKeyLineControls,
  hostedNetworkNotes,
  hostedToolBlock,
  hostedUploadNeedsRepo,
  hostedWorkspaceBlock,
  rowSourceOffered,
  sandboxSourceLabel,
  sandboxSourceNotes,
  sandboxSourceOptions,
  isolationPickerProps,
  sandboxLaunchFields,
  sandboxDisabledReason,
  sandboxStartBlock,
  sshSystemDisabledReason,
} from "./newTerminalSandbox.ts";
import { ISOLATION_AUTO, ISOLATION_NONE, launchBackend } from "./sandboxIsolation.ts";
import type { SandboxAvailability, SandboxBackendAvail, SandboxKeyNotice } from "./types.ts";

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

// The hosted model key line (docs/audits/hosted-sandbox-key-custody-2026-11-18.md):
// a hosted row the picker resolves to says, before Start, that this tool's
// model key cannot reach the agent there, and Start is blocked with the
// daemon's plain sentence.
const keyLine = {
  code: "tool_provider_not_served",
  message: "This agent chooses its own model provider, so a key kept on this machine cannot be added for it.",
  technical: "credential injection serves only a tool whose model catalogue names exactly one provider",
};
const hostedProbe: SandboxAvailability = {
  available: true,
  default_on: false,
  backend: "bwrap",
  backends: [
    { id: "bwrap", label: "Bubblewrap", class: "namespace", location: "local", maturity: "shipped", available: true, beta: false, capture_by_tier: {}, component: "terminals.sandbox" },
    { id: "daytona", label: "Daytona", class: "container", location: "remote", maturity: "preview", available: true, beta: true, capture_by_tier: {}, component: "terminals.sandbox.daytona" },
  ],
  tools: {
    opencode: { available: true, hosted_key: keyLine },
    "claude-code": { available: true },
  },
};

test("hostedKeyBlock: only a hosted row and a tool the daemon flagged", () => {
  const cases: Array<[string, string, SandboxAvailability | null, boolean, string, string | null]> = [
    ["a hosted row chosen for a flagged tool", "opencode", hostedProbe, true, "daytona", "daytona"],
    ["a local row for the same tool", "opencode", hostedProbe, true, "bwrap", null],
    ["Automatic resolving to the local row", "opencode", hostedProbe, true, ISOLATION_AUTO, null],
    ["Automatic resolving to the hosted row", "opencode", { ...hostedProbe, backend: "daytona" }, true, ISOLATION_AUTO, "daytona"],
    ["a tool the daemon did not flag", "claude-code", hostedProbe, true, "daytona", null],
    ["sandbox off", "opencode", hostedProbe, false, "daytona", null],
    ["no isolation chosen", "opencode", hostedProbe, true, ISOLATION_NONE, null],
    ["no probe", "opencode", null, true, "daytona", null],
    ["a daemon that predates the line", "opencode", { ...hostedProbe, tools: { opencode: { available: true } } }, true, "daytona", null],
  ];
  for (const [name, tool, probe, on, choice, want] of cases) {
    const got = hostedKeyBlock(tool, probe, on, choice);
    if (want === null) assert.equal(got, null, name);
    else {
      assert.equal(got?.backend, want, name);
      assert.equal(got?.message, keyLine.message, name);
    }
  }
});

test("hostedKeyBlock: a line blocks unless the daemon marked it advisory", () => {
  const withLine = (n: SandboxKeyNotice): SandboxAvailability => ({ ...hostedProbe, tools: { opencode: { available: true, hosted_key: n } } });
  const cases: Array<[string, SandboxKeyNotice, boolean]> = [
    ["a daemon that predates the severity: blocks", keyLine, true],
    ["a refusal", { ...keyLine, severity: "blocking" }, true],
    ["an advisory line", { code: "in_box_no_key", message: "No API key this agent can use was found on this machine.", severity: "advisory" }, false],
  ];
  for (const [name, n, blocking] of cases) {
    const got = hostedKeyBlock("opencode", withLine(n), true, "daytona");
    assert.equal(got?.blocking, blocking, name);
    assert.equal(got?.message, n.message, name);
  }
});

test("sandboxStartBlock: a hosted key line blocks Start with its own sentence", () => {
  const block = hostedKeyBlock("opencode", hostedProbe, true, "daytona");
  const base = { sandboxOn: true, controlDisabled: false, source: "live", remote: "", sources: [{ id: "live", available: true }] };
  const got = sandboxStartBlock({ ...base, hostedKey: block });
  assert.equal(got.hostedKey, true);
  assert.equal(got.blocks, true);
  assert.equal(got.message, keyLine.message);
  assert.doesNotMatch(got.message ?? "", /home_relay|in_box_api_key|key_pool|`/);
  const off = sandboxStartBlock({ ...base, hostedKey: null });
  assert.equal(off.hostedKey, false);
  assert.equal(off.blocks, false);
  // A missing remote URL is said first: it is the one the person is typing.
  const both = sandboxStartBlock({ ...base, source: "clone-remote", hostedKey: block });
  assert.match(both.message ?? "", /Enter a remote URL/);
});

test("a row that takes only some workspace sources blocks the others before Start", () => {
  const row = { label: "Daytona", workspace_sources: ["live"] };
  assert.equal(rowSourceOffered(row, "live"), true);
  assert.equal(rowSourceOffered(row, "clone-local"), false);
  assert.equal(rowSourceOffered({ label: "Bubblewrap" }, "clone-local"), true, "a row with no list takes every source");
  assert.equal(rowSourceOffered(undefined, "worktree"), true);
  const base = { sandboxOn: true, controlDisabled: false, source: "clone-local", remote: "", sources: [{ id: "live", available: true }, { id: "clone-local", available: true }] };
  const got = sandboxStartBlock({ ...base, row });
  assert.equal(got.blocks, true);
  assert.equal(got.sourceUnavailable, true);
  assert.match(got.message ?? "", /^Daytona does not take this workspace source/);
  assert.equal(sandboxStartBlock({ ...base, source: "live", row }).blocks, false);
  assert.equal(sandboxStartBlock({ ...base, sandboxOn: false, row }).blocks, false);
});

test("chosenBackendRow: the chosen row, Automatic's pick, or none", () => {
  assert.equal(chosenBackendRow(hostedProbe, true, "daytona")?.id, "daytona");
  assert.equal(chosenBackendRow(hostedProbe, true, ISOLATION_AUTO)?.id, "bwrap");
  assert.equal(chosenBackendRow(hostedProbe, true, ISOLATION_NONE), undefined);
  assert.equal(chosenBackendRow(hostedProbe, false, "daytona"), undefined);
  assert.equal(chosenBackendRow(null, true, "daytona"), undefined);
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
  // Lane CLONE2 (SBXD-5): a launch's own clone location rides a clone of a URL only.
  const clone = { sandboxOn: true, isolationChoice: "daytona", workspaceSource: "clone-remote", workspaceRemote: "https://g/x.git", workspaceBranch: "", branchApplies: false };
  assert.equal(sandboxLaunchFields({ ...clone, workspaceCloneWhere: "home" }).workspace_clone_where, "home");
  assert.equal(sandboxLaunchFields(clone).workspace_clone_where, undefined);
  assert.equal(sandboxLaunchFields({ ...clone, workspaceRemote: " ", workspaceCloneWhere: "home" }).workspace_clone_where, undefined);
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

// Lane UX (items H4, H5, H8, H10): what the dialog says before Start about
// a hosted row, from the row's own probe facts, never its id.
const toolLine = {
  code: "image_lacks_installer",
  message: "Daytona's default image has no npm, which every way Observer knows to install Codex needs, and no template is set.",
  technical: "tool_unavailable_in_image: the default image lacks npm",
};
const uxRow: SandboxBackendAvail = {
  id: "daytona", label: "Daytona", class: "container", location: "remote", maturity: "preview", available: true, beta: true,
  capture_by_tier: {}, component: "terminals.sandbox.daytona",
  workspace_sources: ["live"], source_deliveries: { live: "sync" },
  tool_notices: { codex: toolLine },
  network_notes: ["On the internet setting the box reaches the network through Daytona's own network, not through Observer."],
};
const uxLocal: SandboxBackendAvail = { id: "bwrap", label: "Bubblewrap", class: "namespace", location: "local", maturity: "shipped", available: true, beta: false, capture_by_tier: {}, component: "terminals.sandbox" };
const uxProbe: SandboxAvailability = { available: true, default_on: false, backend: "bwrap", backends: [uxLocal, uxRow], tools: { codex: { available: true }, opencode: { available: true } } };

test("sandboxSourceLabel: a hosted upload never reads as the live folder (H5)", () => {
  const cases: Array<[string, string, SandboxBackendAvail | undefined, RegExp]> = [
    ["live on a hosted upload row", "live", uxRow, /^Upload a copy of the project \(changes come back as a diff\)$/],
    ["live on a local row", "live", uxLocal, /^Live project directory$/],
    ["live with no row", "live", undefined, /^Live project directory$/],
    ["a box-side clone", "clone-remote", { ...uxRow, source_deliveries: { "clone-remote": "remote_clone" } }, /^Clone a remote URL$/],
    ["a delivery the dialog has no label for", "clone-local", { ...uxRow, source_deliveries: { "clone-local": "sync" } }, /^Copy of the project \(clone\)$/],
    ["an unknown source", "something-new", uxRow, /^something-new$/],
  ];
  for (const [name, source, row, want] of cases) assert.match(sandboxSourceLabel(source, row), want, name);
});

test("hostedToolBlock: the chosen hosted row's tool line only (H4)", () => {
  const cases: Array<[string, string, SandboxAvailability | null, boolean, string, boolean]> = [
    ["the hosted row for a refused tool", "codex", uxProbe, true, "daytona", true],
    ["the hosted row for a tool it can install", "opencode", uxProbe, true, "daytona", false],
    ["a local row", "codex", uxProbe, true, "bwrap", false],
    ["Automatic resolving to the local row", "codex", uxProbe, true, ISOLATION_AUTO, false],
    ["sandbox off", "codex", uxProbe, false, "daytona", false],
    ["no tool", "", uxProbe, true, "daytona", false],
    ["no probe", "codex", null, true, "daytona", false],
  ];
  for (const [name, tool, probe, on, choice, want] of cases) {
    const got = hostedToolBlock(tool, probe, on, choice);
    assert.equal(got !== null, want, name);
    if (got) {
      assert.equal(got.message, toolLine.message, name);
      assert.equal(got.backend, "daytona", name);
    }
  }
  const base = { sandboxOn: true, controlDisabled: false, source: "live", remote: "", sources: [{ id: "live", available: true }] };
  const blocked = sandboxStartBlock({ ...base, hostedTool: hostedToolBlock("codex", uxProbe, true, "daytona") });
  assert.equal(blocked.blocks, true);
  assert.equal(blocked.hostedTool, true);
  assert.equal(blocked.message, toolLine.message);
  assert.doesNotMatch(blocked.message ?? "", /tool_unavailable|\[terminal\./);
});

test("hostedNetworkNotes: a hosted row's notes, none for a local row (H10)", () => {
  assert.deepEqual(hostedNetworkNotes(uxRow), uxRow.network_notes);
  assert.deepEqual(hostedNetworkNotes(uxLocal), []);
  assert.deepEqual(hostedNetworkNotes({ ...uxLocal, network_notes: ["x"] }), [], "a local row's notes are not the hosted network's");
  assert.deepEqual(hostedNetworkNotes(undefined), []);
});

test("hostedWorkspaceBlock: an upload that needs a repository folder (H8)", () => {
  const no = { dir: "/mnt/d/tests", ok: false, code: "upload_scope_not_repository", message: "A hosted sandbox uploads only the files of a git repository, and this folder is not one.", technical: "upload_scope_not_repository: ..." };
  const cases: Array<[string, SandboxBackendAvail | undefined, string, string, typeof no | null, boolean]> = [
    ["a non-repository folder on an upload row", uxRow, "live", "/mnt/d/tests", no, true],
    ["a repository folder", uxRow, "live", "/mnt/d/tests", { ...no, ok: true, code: "", message: "" }, false],
    ["a reply for another folder", uxRow, "live", "/w/other", no, false],
    ["a local row", uxLocal, "live", "/mnt/d/tests", no, false],
    ["a box-side clone uploads nothing", { ...uxRow, source_deliveries: { "clone-remote": "remote_clone" } }, "clone-remote", "/mnt/d/tests", no, false],
    ["no reply (an older daemon)", uxRow, "live", "/mnt/d/tests", null, false],
    ["no folder", uxRow, "live", "", no, false],
  ];
  for (const [name, row, source, folder, reply, want] of cases) {
    const got = hostedWorkspaceBlock(row, source, folder, reply);
    assert.equal(got !== null, want, name);
  }
  assert.equal(hostedUploadNeedsRepo(uxRow, ""), true, "the default source is live");
  const base = { sandboxOn: true, controlDisabled: false, source: "live", remote: "", sources: [{ id: "live", available: true }] };
  const got = sandboxStartBlock({ ...base, hostedWorkspace: hostedWorkspaceBlock(uxRow, "live", "/mnt/d/tests", no) });
  assert.equal(got.blocks, true);
  assert.equal(got.hostedWorkspace, true);
  assert.equal(got.message, no.message);
  assert.equal(hostedWorkspaceBlock(uxRow, "live", "/mnt/d/tests", no)?.blocking, true, "a refusal blocks");
});

test("hostedWorkspaceBlock: a folder that is not a repository is a note, not a block (SBXD-8)", () => {
  const note = {
    dir: "/mnt/d/tests",
    ok: true,
    code: "upload_non_repository",
    message: "This folder is not a git repository: Observer uploads its files except ...; the agent's changes come back as a diff file.",
    technical: "upload_non_repository: ...",
  };
  const got = hostedWorkspaceBlock(uxRow, "live", "/mnt/d/tests", note);
  assert.ok(got, "the note is said");
  assert.equal(got?.blocking, false);
  assert.equal(got?.message, note.message);
  const base = { sandboxOn: true, controlDisabled: false, source: "live", remote: "", sources: [{ id: "live", available: true }] };
  const start = sandboxStartBlock({ ...base, hostedWorkspace: got });
  assert.equal(start.blocks, false, "a note never blocks Start");
  assert.equal(start.hostedWorkspace, false);
  assert.equal(start.message, null);
  assert.equal(hostedWorkspaceBlock(uxRow, "live", "/mnt/d/tests", { ...note, message: "" }), null, "an ok answer with nothing to say shows nothing");
});

// A vendor row's upload (upload_snapshot, lane CLONE's name for it) reads
// and checks like any upload, and a source the row delivers but does not
// take now blocks Start with the daemon's own reason (H7).
test("vendor upload_snapshot and the per-source notes", () => {
  const row = {
    label: "Daytona",
    workspace_sources: ["live"],
    source_deliveries: { live: "upload_snapshot", "clone-remote": "remote_clone" },
    workspace_source_notes: { "clone-remote": "Cloning in the box needs the internet network tier." },
  };
  assert.match(sandboxSourceLabel("live", row), /^Upload a copy of the project/);
  assert.equal(hostedUploadNeedsRepo(row, "live"), true);
  assert.equal(hostedUploadNeedsRepo(row, "clone-remote"), false);
  const base = { sandboxOn: true, controlDisabled: false, remote: "https://github.com/o/r.git", sources: undefined };
  const got = sandboxStartBlock({ ...base, source: "clone-remote", row });
  assert.equal(got.blocks, true);
  assert.equal(got.message, "Cloning in the box needs the internet network tier.");
  const plain = sandboxStartBlock({ ...base, source: "worktree", row });
  assert.match(plain.message ?? "", /does not take this workspace source/);
});

// Lane HOOKS (SBXD-6): the per-tool hook line the dialog shows, as served.
test("hostedHookLine: the chosen hosted row's line for the tool, none elsewhere", () => {
  const gated = { gated: true, code: "auto_guard_enforcing", message: "Observer sets up its hooks for Claude Code in the box.", technical: "guard_hooks = auto: auto_guard_enforcing" };
  const open = { gated: false, code: "tool_not_covered", message: "Observer cannot set up its hooks for Aider in a box yet. No hook runs in the box ...", technical: "guard_hooks = auto: tool_not_covered" };
  const row: SandboxBackendAvail = { ...uxRow, hook_notices: { "claude-code": gated, aider: open } };
  const cases: Array<[string, string, SandboxBackendAvail | undefined, string | null]> = [
    ["a covered tool, gated", "claude-code", row, gated.message],
    ["an uncovered tool, the no-hook line", "aider", row, open.message],
    ["a tool the row has no line for", "codex", row, null],
    ["a local row", "claude-code", { ...uxLocal, hook_notices: { "claude-code": gated } }, null],
    ["no row chosen", "claude-code", undefined, null],
    ["no tool", "", row, null],
    ["an older daemon (no hook_notices)", "claude-code", uxRow, null],
  ];
  for (const [name, tool, r, want] of cases) assert.equal(hostedHookLine(tool, r)?.message ?? null, want, name);
  assert.equal(hostedHookLine("aider", row)?.gated, false);
});

test("hostedKeyLineControls: words only what the daemon sent", () => {
  const base = hostedKeyBlock("opencode", hostedProbe, true, "daytona");
  assert.deepEqual(hostedKeyLineControls(null, "OpenCode"), { where: null, keepHome: [], toolKeys: null, loginSeed: null });
  const oldDaemon = hostedKeyLineControls(base, "OpenCode");
  assert.equal(oldDaemon.where, null);
  assert.equal(oldDaemon.toolKeys, null);
  const inBox: SandboxKeyNotice = {
    code: "served_in_box",
    message: "Nothing on this machine can add this agent's key, so the key is put in the box.",
    severity: "advisory",
    custody: "in_box_api_key",
    keep_home: [{ id: "openai", label: "OpenAI API key" }],
    tool_keys: { on: false },
  };
  const got = hostedKeyLineControls(hostedKeyBlock("opencode", { ...hostedProbe, tools: { opencode: { available: true, hosted_key: inBox } } }, true, "daytona"), "OpenCode");
  assert.equal(got.where, "The key goes into the box for this launch.");
  assert.deepEqual(got.keepHome, [{ id: "openai", label: "OpenAI API key" }]);
  assert.deepEqual(got.toolKeys, { on: false, label: "Also use the keys OpenCode saved itself" });
  assert.equal(got.loginSeed, null);
  const home = hostedKeyLineControls({ ...inBox, custody: "home_relay", keep_home: undefined, tool_keys: undefined, backend: "daytona", blocking: false }, "OpenCode");
  assert.equal(home.where, "The key stays on this machine for this launch.");
  assert.equal(home.toolKeys, null);
  for (const c of [got, home]) {
    for (const s of [c.where ?? "", c.toolKeys?.label ?? "", c.loginSeed?.label ?? ""]) assert.doesNotMatch(s, /home_relay|in_box|auto|`|_/);
  }
});

// The live-run report (2026-11-18): with remote clone switched off on this
// machine, a hosted row's "Clone a remote URL" read "(not offered by
// Daytona)". The picker now gives the row's own reason (the daemon's note,
// naming where to turn it on); "not offered" stays for a source the row
// never takes. No branch on the row's name: two rows with the same data
// read the same.
test("sandboxSourceOptions and sandboxSourceNotes: the reason comes from the row's note", () => {
  const off = "Cloning a remote URL into a sandbox is switched off on this machine. Turn on Allow remote clone in Terminals > Settings > Sandbox isolation.";
  const sources = [
    { id: "live", available: true },
    { id: "clone-remote", available: true },
    { id: "worktree", available: true },
    { id: "clone-local", available: false, reason: "git is missing" },
  ];
  for (const label of ["Daytona", "E2B"]) {
    const row = {
      label,
      workspace_sources: ["live", "clone-local"],
      source_deliveries: { live: "upload_snapshot", "clone-remote": "remote_clone" },
      workspace_source_notes: { "clone-remote": off },
    };
    const byID = Object.fromEntries(sandboxSourceOptions(row, sources).map((o) => [o.id, o]));
    assert.equal(byID.live.disabled, false);
    assert.equal(byID["clone-remote"].disabled, true);
    assert.equal(byID["clone-remote"].label, "Clone a remote URL (not available now)");
    assert.equal(byID["clone-remote"].title, off);
    assert.ok(!byID["clone-remote"].label.includes(label), "the reason is not the vendor's name");
    assert.equal(byID.worktree.label, `Worktree (not offered by ${label})`);
    assert.equal(byID["clone-local"].label, "Copy of the project (clone) (unavailable)");
    assert.equal(byID["clone-local"].title, "git is missing");
    assert.deepEqual(sandboxSourceNotes(row, sources), [`Clone a remote URL: ${off}`]);
  }
  // A row that takes every source (no list) disables only what the probe does.
  assert.deepEqual(
    sandboxSourceOptions({ label: "bwrap" }, sources).map((o) => o.disabled),
    [false, false, false, true],
  );
  assert.deepEqual(sandboxSourceNotes({ label: "bwrap" }, sources), []);
  assert.deepEqual(sandboxSourceOptions(undefined, undefined), []);
});

// The live-run report (2026-11-18): a clone URL with a user name on a hosted
// row showed raw internal text and left Start enabled. The Start block now
// carries the plain sentence and blocks Start until the address is valid.
test("sandboxStartBlock: an invalid clone address blocks Start with plain words", () => {
  const base = { sandboxOn: true, controlDisabled: false, source: "clone-remote", sources: undefined };
  const hostedRow = { label: "Daytona", location: "remote" };
  const bad = sandboxStartBlock({ ...base, remote: "https://user@github.com/acme/app.git", row: hostedRow });
  assert.equal(bad.blocks, true);
  assert.match(bad.remoteURLProblem ?? "", /user name, password or token/);
  assert.equal(bad.message, bad.remoteURLProblem);
  const good = sandboxStartBlock({ ...base, remote: "https://github.com/acme/app.git", row: hostedRow });
  assert.equal(good.blocks, false);
  assert.equal(good.remoteURLProblem, null);
  // A local row clones with this machine's own git login: a user name is fine.
  const localUser = sandboxStartBlock({ ...base, remote: "https://user@github.com/acme/app.git", row: { label: "bwrap", location: "local" } });
  assert.equal(localUser.blocks, false);
  // Any row refuses a shape git would run as a program.
  assert.equal(sandboxStartBlock({ ...base, remote: "ext::sh", row: { label: "bwrap", location: "local" } }).blocks, true);
  // Another source never reads the address.
  assert.equal(sandboxStartBlock({ ...base, source: "live", remote: "ext::sh", row: hostedRow }).remoteURLProblem, null);
  // An empty address is asked for, not called invalid.
  const empty = sandboxStartBlock({ ...base, remote: "", row: hostedRow });
  assert.equal(empty.remoteURLMissing, true);
  assert.equal(empty.remoteURLProblem, null);
});

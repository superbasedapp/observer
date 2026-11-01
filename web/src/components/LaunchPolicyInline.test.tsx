// Component tests of the New Terminal dialog's inline launch-policy steps
// (Windows 11 Pro rerun 2026-10-25, R3 and R4), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import type { ReactElement } from "react";
import { renderToPipeableStream, renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import {
  AllowFolderStep,
  FreshLaunchStep,
  absolutePath,
  applyLaunchPolicyChange,
  isFreshLaunchDisabledError,
  policyWithChange,
  type LaunchPolicy,
} from "@/components/LaunchPolicyInline";
import { NewTerminalDialog, type NewTerminalDraft } from "@/components/NewTerminalDialog";
import { ApiError } from "@/lib/api";
import { registerConfigSavePreview, type ConfigSavePreviewRequest } from "@/lib/configSectionSave";
import { PolicyStep, folderNeedsAllow, stepHoldsStart } from "@/lib/launchPolicyStep";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

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

const policy: LaunchPolicy = {
  confirm_token: "t",
  allow_fresh_agent: false,
  allowed_tools: ["claude-code"],
  allowed_project_roots: ["/srv/a"],
  allow_shell: false,
  allow_install: true,
};

test("the inline change is the full policy with one field changed", () => {
  assert.deepEqual(policyWithChange(policy, { addRoot: " C:\\work " }), {
    allow_fresh_agent: false,
    allowed_tools: ["claude-code"],
    allowed_project_roots: ["/srv/a", "C:\\work"],
    allow_shell: false,
    allow_install: true,
  });
  assert.deepEqual(policyWithChange(policy, { addRoot: "/srv/a" }).allowed_project_roots, ["/srv/a"]);
  const fresh = policyWithChange(policy, { allowFresh: true });
  assert.equal(fresh.allow_fresh_agent, true);
  assert.deepEqual(fresh.allowed_project_roots, ["/srv/a"]);
  assert.deepEqual(policyWithChange({ ...policy, allowed_tools: null, allowed_project_roots: null }, { allowFresh: true }).allowed_tools, []);
});

test("only the launch route's allow_fresh_agent refusal opens the fresh-launch step", () => {
  const body = "termsvc: fresh-agent launch is disabled (set [terminal.launch].allow_fresh_agent)";
  assert.equal(isFreshLaunchDisabledError(new ApiError(403, "/api/terminal/launch", body)), true);
  assert.equal(isFreshLaunchDisabledError(new ApiError(400, "/api/terminal/launch", "project root not permitted (allowed_project_roots)")), false);
  assert.equal(isFreshLaunchDisabledError(new Error("network down")), false);
  assert.equal(absolutePath("C:\\Users\\u\\work"), true);
  assert.equal(absolutePath("/home/u/work"), true);
  assert.equal(absolutePath("work"), false);
});

test("Allow this folder asks for a confirm before it writes", () => {
  const idle = renderToStaticMarkup(<AllowFolderStep path="C:\work" onConfirm={async () => {}} />);
  assert.match(idle, /C:\\work<\/code> is not on the launch allow-list/);
  assert.match(idle, />Allow this folder</);
  assert.doesNotMatch(idle, /Confirm: allow this folder/);
  const armed = renderToStaticMarkup(<AllowFolderStep path="C:\work" initialConfirming onConfirm={async () => {}} />);
  assert.match(armed, />Confirm: allow this folder</);
  assert.match(armed, />Cancel</);
  assert.match(armed, /shows the exact change/);
});

test("the fresh-launch toggle asks for a confirm before it writes", () => {
  const idle = renderToStaticMarkup(<FreshLaunchStep onConfirm={async () => {}} />);
  assert.match(idle, /Fresh-agent launch is off/);
  assert.match(idle, />Turn on fresh-agent launch</);
  const armed = renderToStaticMarkup(<FreshLaunchStep initialConfirming onConfirm={async () => {}} />);
  assert.match(armed, />Confirm: turn on fresh-agent launch</);
});

function draft(customRoot: string): NewTerminalDraft {
  return {
    tool: "claude-code",
    rootSel: "\u0000custom",
    customRoot,
    modelSel: "",
    sandboxOn: false,
    workspaceSource: "live",
    workspaceRemote: "",
    workspaceBranch: "",
  };
}

test("the dialog offers Allow this folder for a typed folder the allow-list does not cover", async () => {
  const html = await renderAll(
    <MemoryRouter>
      <NewTerminalDialog onClose={() => {}} onLaunched={() => {}} initialDraft={draft("C:\\Users\\u\\work")} />
    </MemoryRouter>,
  );
  assert.match(html, /data-testid="allow-folder-step"/);
  assert.match(html, /Allow this folder/);
  const relative = await renderAll(
    <MemoryRouter>
      <NewTerminalDialog onClose={() => {}} onLaunched={() => {}} initialDraft={draft("work")} />
    </MemoryRouter>,
  );
  assert.doesNotMatch(relative, /data-testid="allow-folder-step"/);
});

// Windows 11 Pro run 4 (B4): the review of the change sat in the shell's
// preview dialog BEHIND New terminal. It is now the step's own.

function dryRun(): ConfigSavePreviewRequest["dryRun"] {
  return {
    dry_run: true,
    would_write: true,
    changed_keys: ["terminal.launch.allowed_project_roots"],
    restart_required: false,
    restart_required_keys: [],
    applied_live_keys: [],
    next_spawn_keys: [],
    comments_preserved: true,
    write_mode: "surgical",
    config_path: "/home/u/.observer/config.toml",
    config_etag: "etag-7",
    diff: "-allowed_project_roots = ['/srv/work']\n+allowed_project_roots = ['/srv/work', '/srv/work2']\n",
    diff_stats: { added: 1, removed: 1 },
    needs_confirm: false,
    secret_warnings: [],
    section: "terminal.launch",
  };
}

test("the review of the change shows inside the step, with its own Save", () => {
  const review: ConfigSavePreviewRequest = { section: "terminal.launch", title: "t", dryRun: dryRun() };
  const html = renderToStaticMarkup(<AllowFolderStep path="/srv/work2" initialReview={review} onConfirm={async () => {}} />);
  const step = html.slice(html.indexOf('data-testid="allow-folder-step"'));
  assert.match(step, /data-testid="inline-config-review"/);
  assert.match(step, /data-testid="config-preview"/, "the same preview the shell dialog uses");
  assert.match(step, /allowed_project_roots/);
  assert.match(step, /&#x27;\/srv\/work2&#x27;/, "the diff names the folder being added");
  assert.match(step, /data-testid="inline-config-save"[^>]*>Save</);
  assert.doesNotMatch(html, /role="dialog"/, "no second dialog");
  const fresh = renderToStaticMarkup(<FreshLaunchStep initialReview={review} onConfirm={async () => {}} />);
  assert.match(fresh, /data-testid="inline-config-review"/);
});

test("Allow, confirm, review and Save run through the policy route without the shell dialog, and free Start", async () => {
  const policy: LaunchPolicy = {
    confirm_token: "tok",
    allow_fresh_agent: true,
    allowed_tools: ["claude-code"],
    allowed_project_roots: ["/srv/work"],
    allow_shell: false,
    allow_install: true,
  };
  const calls: { method: string; url: string; body?: string }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ method: init?.method ?? "GET", url, body: init?.body as string | undefined });
    const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "Content-Type": "application/json" } });
    if (url === "/api/terminal/policy") return json(policy);
    if (url.includes("dry_run=1")) return json(dryRun());
    return json({ saved: true, section: "terminal.launch", restart_required: false });
  }) as typeof fetch;
  let shellDialog = 0;
  const unregister = registerConfigSavePreview(async () => {
    shellDialog++;
    return true;
  });
  try {
    const saved: string[] = [];
    const step = new PolicyStep<ConfigSavePreviewRequest>(async (review) => {
      await applyLaunchPolicyChange({ addRoot: "/srv/work2" }, "Allow this folder for agent launches", review);
      saved.push("/srv/work2");
    }, () => {});
    step.arm();
    assert.equal(stepHoldsStart(step.state.phase), true);
    const done = step.confirm();
    for (let i = 0; i < 200 && step.state.phase !== "reviewing"; i++) await new Promise((r) => setTimeout(r, 1));
    assert.equal(step.state.phase, "reviewing");
    assert.equal(calls.filter((c) => c.method === "PUT").length, 1, "the dry run only before Save");
    step.save();
    await done;
    const puts = calls.filter((c) => c.method === "PUT");
    assert.equal(puts.length, 2);
    assert.match(puts[1].url, /base_etag=etag-7/);
    assert.deepEqual(JSON.parse(puts[1].body ?? "{}").allowed_project_roots, ["/srv/work", "/srv/work2"]);
    assert.equal(shellDialog, 0, "no second dialog is opened");
    assert.equal(step.state.phase, "idle");
    assert.equal(stepHoldsStart(step.state.phase), false, "Start is enabled again");
    assert.equal(folderNeedsAllow("/srv/work2", ["/srv/work"], []), true, "before the save the folder needs the step");
    assert.equal(folderNeedsAllow("/srv/work2", ["/srv/work"], saved), false, "the step is gone, the folder still selected");
  } finally {
    unregister();
    globalThis.fetch = realFetch;
  }
});

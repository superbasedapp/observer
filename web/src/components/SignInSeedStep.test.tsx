// Component tests of the New Terminal dialog's inline sign-in step (lane
// BOXSIGNIN), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SignInSeedStep,
  postLaunchAskingSignIn,
  rememberSignInSeed,
  sandboxWithSignInTool,
  signInConsentFromError,
  type SignInConsent,
} from "@/components/LaunchPolicyInline";
import { ApiError, fetchJSON } from "@/lib/api";
import { registerConfigSavePreview, type ConfigSavePreviewRequest } from "@/lib/configSectionSave";
import { PolicyStep, stepHoldsStart } from "@/lib/launchPolicyStep";
import { sandboxLaunchFields } from "@/lib/newTerminalSandbox";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

const consent: SignInConsent = {
  tool: "claude-code",
  files: [".claude/.credentials.json"],
  text: "Copy claude-code's sign-in into this sandbox for this run? File copied: ~/.claude/.credentials.json. The tool inside the box can read and use it, and the box's allowed network can carry it. The copy is removed when the run ends.",
};

test("only the launch route's 409 sign_in_consent opens the sign-in step", () => {
  const body = JSON.stringify({ error: "sign_in_consent", ...consent });
  assert.deepEqual(signInConsentFromError(new ApiError(409, "/api/terminal/launch", body)), consent);
  assert.equal(signInConsentFromError(new ApiError(403, "/api/terminal/launch", body)), null);
  assert.equal(signInConsentFromError(new ApiError(409, "/api/terminal/launch", '{"error":"plan_changed"}')), null);
  assert.equal(signInConsentFromError(new ApiError(409, "/api/terminal/launch", "not json")), null);
  assert.equal(signInConsentFromError(new Error("x")), null);
});

test("the step names the tool and each file, answers in place, and opens no second dialog", () => {
  const html = renderToStaticMarkup(<SignInSeedStep consent={consent} onAnswer={() => {}} />);
  assert.match(html, /data-testid="sign-in-seed-step"/);
  assert.match(html, /claude-code/);
  assert.match(html, /~\/\.claude\/\.credentials\.json/);
  assert.match(html, /can read and use it/);
  assert.match(html, /allowed network can carry it/);
  assert.match(html, /removed when the run ends/);
  assert.match(html, /data-testid="sign-in-seed-yes"[^>]*>Copy my sign-in for this run</);
  assert.match(html, /data-testid="sign-in-seed-no"[^>]*>Start without it</);
  assert.match(html, /data-testid="sign-in-seed-always"/);
  assert.doesNotMatch(html, /role="dialog"/, "no second dialog");
  const confirming = renderToStaticMarkup(<SignInSeedStep consent={consent} initialConfirming onAnswer={() => {}} />);
  assert.match(confirming, /sign_in_seed_tools/);
  assert.match(confirming, /Confirm: always for this tool/);
});

test("consent then Start: the dialog's launch asks first, and each answer starts it with sign_in_seed", async () => {
  const bodies: Record<string, unknown>[] = [];
  const realFetch = globalThis.fetch;
  const headers = { "Content-Type": "application/json" };
  // The launch route: a sandboxed launch with no answer yet gets the 409
  // question; an answered one starts.
  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    bodies.push(body);
    if (body.sign_in_seed === undefined) {
      return new Response(JSON.stringify({ error: "sign_in_consent", ...consent }), { status: 409, headers });
    }
    return new Response(JSON.stringify({ token: "T-1", tool: "claude-code", has_project_root: true }), { status: 200, headers });
  }) as typeof fetch;
  // What NewTerminalDialog's submit does for one launch.
  const launch = (signInSeed?: boolean) =>
    postLaunchAskingSignIn(() =>
      fetchJSON<{ token: string }>("/api/terminal/launch", undefined, {
        method: "POST",
        headers,
        body: JSON.stringify({
          tool: "claude-code",
          ...sandboxLaunchFields({
            sandboxOn: true,
            isolationChoice: "oci-runsc",
            workspaceSource: "live",
            workspaceRemote: "",
            workspaceBranch: "",
            branchApplies: false,
            signInSeed,
          }),
        }),
      }),
    );
  try {
    const asked = await launch();
    assert.ok("consent" in asked, "the first Start is answered with the question");
    assert.deepEqual(asked.consent, consent);
    assert.equal(bodies[0].sign_in_ask, true);
    assert.equal("sign_in_seed" in bodies[0], false);
    // The step the dialog shows for that question, in place.
    const html = renderToStaticMarkup(<SignInSeedStep consent={asked.consent} onAnswer={() => {}} />);
    assert.match(html, /Copy my sign-in for this run/);
    const yes = await launch(true);
    assert.ok("started" in yes && yes.started.token === "T-1", "yes starts the launch");
    assert.equal(bodies[1].sign_in_seed, true);
    const no = await launch(false);
    assert.ok("started" in no, "no starts the launch without the sign-in");
    assert.equal(bodies[2].sign_in_seed, false);
    // Every other error is still an error.
    globalThis.fetch = (async () => new Response("forbidden", { status: 403 })) as typeof fetch;
    await assert.rejects(launch());
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("Always: confirm, review and Save write sign_in_seed_tools through the sandbox route, then start", async () => {
  assert.deepEqual(sandboxWithSignInTool({ enabled: true, sign_in_seed_tools: ["codex"], sign_in_seed_catalog: ["claude-code", "codex"], sign_in_seed_forbidden: false }, "claude-code"), {
    enabled: true,
    sign_in_seed_tools: ["codex", "claude-code"],
  });
  const calls: { method: string; url: string; body?: string }[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ method: init?.method ?? "GET", url, body: init?.body as string | undefined });
    const json = (v: unknown) => new Response(JSON.stringify(v), { status: 200, headers: { "Content-Type": "application/json" } });
    if (url === "/api/terminal/sandbox/config") return json({ confirm_token: "tok", sandbox: { enabled: true, sign_in_seed_tools: [] } });
    if (url.includes("dry_run=1")) {
      return json({
        dry_run: true,
        would_write: true,
        changed_keys: ["terminal.sandbox.sign_in_seed_tools"],
        restart_required: false,
        restart_required_keys: [],
        applied_live_keys: [],
        next_spawn_keys: [],
        comments_preserved: true,
        write_mode: "surgical",
        config_path: "/home/u/.observer/config.toml",
        config_etag: "etag-9",
        diff: "+sign_in_seed_tools = ['claude-code']\n",
        diff_stats: { added: 1, removed: 0 },
        needs_confirm: false,
        secret_warnings: [],
        section: "terminal.sandbox",
      });
    }
    return json({ saved: true, section: "terminal.sandbox", restart_required: false });
  }) as typeof fetch;
  let shellDialog = 0;
  const unregister = registerConfigSavePreview(async () => {
    shellDialog++;
    return true;
  });
  try {
    const started: boolean[] = [];
    const step = new PolicyStep<ConfigSavePreviewRequest>(async (review) => {
      await rememberSignInSeed("claude-code", review);
      started.push(true);
    }, () => {});
    step.arm();
    assert.equal(stepHoldsStart(step.state.phase), true);
    const done = step.confirm();
    for (let i = 0; i < 200 && step.state.phase !== "reviewing"; i++) await new Promise((r) => setTimeout(r, 1));
    assert.equal(step.state.phase, "reviewing");
    step.save();
    await done;
    const puts = calls.filter((c) => c.method === "PUT");
    assert.equal(puts.length, 2);
    assert.match(puts[1].url, /base_etag=etag-9/);
    assert.deepEqual(JSON.parse(puts[1].body ?? "{}").sign_in_seed_tools, ["claude-code"]);
    assert.equal(shellDialog, 0, "no second dialog is opened");
    assert.deepEqual(started, [true], "the launch starts after the save");
    assert.equal(stepHoldsStart(step.state.phase), false);
  } finally {
    unregister();
    globalThis.fetch = realFetch;
  }
});

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  cloneConsentBody,
  cloneConsentQuery,
  cloneConsentState,
  cloneWhereChoice,
  cloneWhereLabel,
  cloneWhereLaunchValue,
  cloneWhereLine,
  cloneWhereOptions,
  consentChangeWords,
  hostedConsentRefusalOf,
  isHostedConsentRefusal,
  repositoryChoices,
  WHERE_LINE_LABEL,
} from "./hostedClone.ts";
import type { SandboxCloneWhere } from "./types.ts";

// The hosted clone location and the inline clone consent (lane CLONE2,
// decision SBXD-5): one case per branch.

const auto: SandboxCloneWhere = { setting: "auto", fixed: false, choices: ["auto", "box", "home"], rule: "r" };
const autoNoBox: SandboxCloneWhere = { setting: "auto", fixed: false, choices: ["auto", "home"], notes: { box: "needs internet access" }, rule: "r" };
const home: SandboxCloneWhere = { setting: "home", fixed: true, choices: ["home"], rule: "r" };

test("cloneWhereOptions: every value under auto, the box disabled with its reason", () => {
  assert.deepEqual(cloneWhereOptions(undefined), []);
  assert.deepEqual(
    cloneWhereOptions(auto).map((o) => [o.value, o.disabled]),
    [
      ["auto", false],
      ["box", false],
      ["home", false],
    ],
  );
  const box = cloneWhereOptions(autoNoBox).find((o) => o.value === "box");
  assert.equal(box?.disabled, true);
  assert.equal(box?.note, "needs internet access");
  assert.deepEqual(
    cloneWhereOptions(home).map((o) => o.value),
    ["home"],
  );
  assert.equal(cloneWhereLabel("home"), "On this machine");
  assert.equal(cloneWhereLabel("other"), "other");
});

test("cloneWhereChoice and cloneWhereLaunchValue: only a launch's own different choice is sent", () => {
  assert.equal(cloneWhereChoice(undefined, "box"), "");
  assert.equal(cloneWhereChoice(auto, ""), "auto");
  assert.equal(cloneWhereChoice(auto, "box"), "box");
  assert.equal(cloneWhereChoice(auto, "nowhere"), "auto");
  assert.equal(cloneWhereChoice(autoNoBox, "box"), "auto");
  assert.equal(cloneWhereChoice(home, "box"), "home");
  assert.equal(cloneWhereLaunchValue(auto, "auto"), undefined);
  assert.equal(cloneWhereLaunchValue(auto, ""), undefined);
  assert.equal(cloneWhereLaunchValue(auto, "home"), "home");
  assert.equal(cloneWhereLaunchValue(home, "box"), undefined);
  assert.equal(cloneWhereLaunchValue(undefined, "home"), undefined);
});

test("cloneConsentQuery and cloneConsentBody: one row, the URL, the folder and the choice", () => {
  assert.equal(cloneConsentQuery({ provider: "daytona", folder: "/p", url: "  ", choice: "auto" }), null);
  assert.equal(cloneConsentQuery({ provider: "", folder: "/p", url: "u", choice: "auto" }), null);
  assert.equal(cloneConsentQuery({ provider: "daytona", folder: "", url: "u", choice: "auto" }), null);
  assert.deepEqual(cloneConsentQuery({ provider: "daytona", folder: "/p", url: " https://x/y.git ", choice: "home" }), {
    workspace: "/p",
    repository: "https://x/y.git",
    provider: "daytona",
    clone_where: "home",
  });
  assert.deepEqual(cloneConsentQuery({ provider: "daytona", folder: "/p", url: "u", choice: "" }), { workspace: "/p", repository: "u", provider: "daytona" });
  assert.deepEqual(cloneConsentBody({ provider: "daytona", folder: "/p", url: " u ", choice: "box" }), {
    provider: "daytona",
    workspace: "/p",
    repository: "u",
    clone_where: "box",
  });
});

test("cloneConsentState: agreed, ask, ask again, an error, nothing", () => {
  const screen = { lines: [{ label: WHERE_LINE_LABEL, value: "cloned on this machine: it needs a sign-in" }] };
  assert.deepEqual(cloneConsentState(undefined), { kind: "none" });
  assert.deepEqual(cloneConsentState({ id: "d", name: "D" }), { kind: "none" });
  assert.deepEqual(cloneConsentState({ id: "d", name: "D", screen_error: "the URL cannot be cloned" }), { kind: "error", message: "the URL cannot be cloned" });
  assert.deepEqual(cloneConsentState({ id: "d", name: "D", screen, consent_verdict: "ok" }), { kind: "agreed", where: "cloned on this machine: it needs a sign-in" });
  const ask = cloneConsentState({ id: "d", name: "D", screen, consent_verdict: "consent_required" });
  assert.equal(ask.kind, "ask");
  assert.equal(ask.kind === "ask" && ask.again, false);
  const again = cloneConsentState({ id: "d", name: "D", screen, consent_verdict: "consent_changed_scope" });
  assert.equal(again.kind === "ask" && again.again, true);
  assert.equal(cloneWhereLine({ lines: [] }), "");
});

test("isHostedConsentRefusal: the consent verdicts, nothing else", () => {
  assert.ok(isHostedConsentRefusal("terminal_sandbox: consent_required (consent_changed_scope): review what leaves this machine"));
  assert.ok(isHostedConsentRefusal("terminal_sandbox: consent_required (consent_required): review"));
  assert.ok(isHostedConsentRefusal("x consent_stale_version y"));
  assert.ok(!isHostedConsentRefusal("terminal_sandbox: remote_clone_needs_egress"));
  assert.ok(!isHostedConsentRefusal("sign_in_consent"));
});

test("repositoryChoices: the organization's list, else a typed repository", () => {
  assert.deepEqual(repositoryChoices(["https://g/x.git"]), { mode: "list", options: ["https://g/x.git"] });
  assert.deepEqual(repositoryChoices([]), { mode: "text" });
});

// The live-run report (2026-11-18): an upload whose consent changed scope
// failed Start with "termsvc ... consent_changed_scope". The launch now
// answers 409 {"error":"consent_required","provider","verdict"} and the
// dialog reads that code (never the sentence) to show the consent again.
class FakeApiError extends Error {
  readonly status: number;
  readonly body: string;
  constructor(status: number, body: string) {
    super(`api ${status} /api/terminal/launch: ${body.slice(0, 200)}`);
    this.status = status;
    this.body = body;
  }
}

test("hostedConsentRefusalOf: the 409 consent refusal by its code, nothing else", () => {
  const body = JSON.stringify({ error: "consent_required", message: "What this launch sends changed.", provider: "daytona", verdict: "consent_changed_scope" });
  assert.deepEqual(hostedConsentRefusalOf(new FakeApiError(409, body)), { provider: "daytona", verdict: "consent_changed_scope" });
  // Another 409 (the sign-in question, a step refusal) is not it.
  assert.equal(hostedConsentRefusalOf(new FakeApiError(409, JSON.stringify({ error: "sign_in_consent", tool: "claude-code" }))), null);
  assert.equal(hostedConsentRefusalOf(new FakeApiError(409, JSON.stringify({ error: "custody_unsatisfiable", message: "m" }))), null);
  // The same code without the row and verdict (another route's) is not it.
  assert.equal(hostedConsentRefusalOf(new FakeApiError(409, JSON.stringify({ error: "consent_required" }))), null);
  // Another status, a plain-text body, or no error object.
  assert.equal(hostedConsentRefusalOf(new FakeApiError(500, body)), null);
  assert.equal(hostedConsentRefusalOf(new FakeApiError(409, "terminal_sandbox: consent_required (consent_changed_scope)")), null);
  assert.equal(hostedConsentRefusalOf(new Error("boom")), null);
  assert.equal(hostedConsentRefusalOf(null), null);
});

test("cloneConsentState and consentChangeWords: what changed, in plain words", () => {
  const screen = { lines: [{ label: "Files uploaded", value: "12 files" }] };
  const again = cloneConsentState({ id: "d", name: "D", screen, consent_verdict: "consent_changed_scope" });
  assert.equal(again.kind, "ask");
  assert.equal(again.kind === "ask" && again.changed, "what is uploaded or cloned for this folder");
  const first = cloneConsentState({ id: "d", name: "D", screen, consent_verdict: "consent_required" });
  assert.equal(first.kind === "ask" && first.changed, "");
  assert.equal(consentChangeWords("consent_changed_region"), "the region");
  assert.equal(consentChangeWords("consent_tampered"), "");
  assert.equal(consentChangeWords(""), "");
});

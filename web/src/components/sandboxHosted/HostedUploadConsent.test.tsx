// Component test of the New Terminal dialog's inline hosted consent for an
// upload (the live-run report 2026-11-18: an upload whose consent changed
// scope failed Start with the daemon's raw "consent_changed_scope" sentence
// instead of offering the consent again).

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { HostedUploadConsentView, uploadConsentQuery } from "@/components/sandboxHosted/HostedUploadConsent";
import { consentAskHeading } from "@/components/sandboxHosted/HostedConsentAsk";
import { cloneConsentState } from "@/lib/hostedClone";

const screen = {
  lines: [
    { label: "Files uploaded", value: "128 tracked files of /home/u/app" },
    { label: "Provider", value: "Daytona (us)" },
  ],
};
const noop = () => {};

test("the consent is offered again with the changed scope and what is sent now", () => {
  const state = cloneConsentState({ id: "daytona", name: "Daytona", screen, consent_verdict: "consent_changed_scope" });
  const html = renderToStaticMarkup(<HostedUploadConsentView row={{ label: "Daytona" }} state={state} busy={false} canAgree err={null} onAgree={noop} />);
  assert.match(html, /data-testid="hosted-upload-consent"/);
  assert.match(html, /What leaves this machine changed since you agreed \(what is uploaded or cloned for this folder\)\. Agree again to start:/);
  assert.match(html, /128 tracked files of \/home\/u\/app/);
  assert.match(html, />Agree</);
  assert.doesNotMatch(html, /consent_changed|termsvc|terminal_sandbox/, "plain words only");
});

test("a first agreement, an agreement already made, and a screen that could not be made", () => {
  const first = cloneConsentState({ id: "daytona", name: "Daytona", screen, consent_verdict: "consent_required" });
  assert.equal(first.kind === "ask" && consentAskHeading(first), "Agree to what this launch sends before it starts:");
  const agreed = renderToStaticMarkup(
    <HostedUploadConsentView row={{ label: "Daytona" }} state={cloneConsentState({ id: "daytona", name: "Daytona", screen, consent_verdict: "ok" })} busy={false} canAgree err={null} onAgree={noop} />,
  );
  assert.match(agreed, /Press Start again/);
  const failed = renderToStaticMarkup(
    <HostedUploadConsentView row={{ label: "Daytona" }} state={{ kind: "error", message: "The folder is not a git repository." }} busy={false} canAgree err={null} onAgree={noop} />,
  );
  assert.match(failed, /The folder is not a git repository\./);
  assert.equal(renderToStaticMarkup(<HostedUploadConsentView row={{ label: "D" }} state={{ kind: "none" }} busy={false} canAgree err={null} onAgree={noop} />), "");
});

test("uploadConsentQuery: the row and the folder, no repository", () => {
  assert.deepEqual(uploadConsentQuery("daytona", "/home/u/app"), { workspace: "/home/u/app", provider: "daytona" });
  assert.equal(uploadConsentQuery("daytona", ""), null);
  assert.equal(uploadConsentQuery("", "/p"), null);
});

test("the dialog holds Start on any hosted consent refusal, read by its code", () => {
  // The test runs bundled (scripts/test-components.mjs), from web/ or the repo root.
  const file = ["src/components/NewTerminalDialog.tsx", "web/src/components/NewTerminalDialog.tsx"].map((r) => path.resolve(process.cwd(), r)).find((f) => existsSync(f));
  assert.ok(file, "NewTerminalDialog.tsx found");
  const src = readFileSync(file, "utf8");
  // The refusal is read by the 409's code, for every source on a hosted row
  // (no longer only a clone of a URL).
  assert.match(src, /hostedConsentRefusalOf\(e\) !== null/);
  assert.doesNotMatch(src, /workspaceSource === "clone-remote" &&\s*chosenRow\?\.location === "remote" &&\s*isHostedConsentRefusal/);
  // An upload's consent is shown inline while Start is held.
  assert.match(src, /cloneConsentHeld && workspaceSource !== "clone-remote" && chosenRow\?\.location === "remote" && \(/);
  assert.match(src, /<HostedUploadConsent\s/);
});

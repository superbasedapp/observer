// Component tests of the Code security scan dialog, rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs):
// the default choice (every ready scanner, all active projects), a scanner
// that is not ready (listed unchecked and disabled, with its reason and the
// way to set it up), a preselected project list, and the running state. The
// request body the dialog sends is pinned in src/lib/scanSteps.test.ts
// (scanStartBody); these prove the dialog shows what that body is built from.
// The effect that applies initialProjects runs after a browser paint, so the
// server render shows the first-render state; the preselect is asserted
// through the pure helpers instead.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ScanDialog } from "@/pages/codesecurity/ScanDialog";
import type { SecurityScan } from "@/pages/codesecurity/useSecurityScan";
import type { ScanOnline, ScanStep, SecurityProject } from "@/lib/codeSecurity";

const STEPS: ScanStep[] = [
  { id: "history", label: "Secrets", ready: true },
  { id: "deps", label: "Dependencies (OSV)", ready: true },
  { id: "iac.kics", label: "IaC (KICS)", ready: false, reason: "not_installed" },
];

function project(hash: string, name: string, active: boolean): SecurityProject {
  return { project_root_hash: hash, name, active, state: "ok", reason: "", blocking: 0, open: 0, counts: [], runs: [] };
}

function stub(over: Partial<SecurityScan> = {}): SecurityScan {
  const noop = async () => {};
  return {
    view: { confirm_token: "t", steps: STEPS, job: null },
    loading: false,
    error: null,
    denied: false,
    job: null,
    running: false,
    sending: false,
    start: noop,
    startProject: noop,
    startAll: noop,
    cancel: noop,
    reload: () => {},
    ...over,
  };
}

const PROJECTS = [project("a", "alpha", true), project("b", "beta", true), project("c", "gamma", false)];

test("the default dialog scans all active projects with every ready scanner", () => {
  const html = renderToStaticMarkup(<ScanDialog open onClose={() => {}} scan={stub()} projects={PROJECTS} onOpenScanners={() => {}} />);
  assert.match(html, /All active projects \(2\)/);
  assert.match(html, /Scan 2 projects with 2 scanners/);
  assert.match(html, /recent git history/);
  assert.match(html, /Lockfiles against the local OSV database/);
});

test("a scanner that is not ready is unchecked, disabled, with its reason and a way to set it up", () => {
  const html = renderToStaticMarkup(<ScanDialog open onClose={() => {}} scan={stub()} projects={PROJECTS} onOpenScanners={() => {}} />);
  assert.match(html, /Not ready: not installed/);
  assert.match(html, /Set up in Scanners/);
  const kics = html.match(/<input[^>]*aria-describedby="scan-step-iac\.kics"[^>]*>/)?.[0] ?? "";
  assert.match(kics, /disabled/);
  assert.doesNotMatch(kics, /checked/);
  const noLink = renderToStaticMarkup(<ScanDialog open onClose={() => {}} scan={stub()} projects={PROJECTS} />);
  assert.doesNotMatch(noLink, /Set up in Scanners/);
});

test("closed, the dialog renders nothing", () => {
  assert.equal(renderToStaticMarkup(<ScanDialog open={false} onClose={() => {}} scan={stub()} projects={PROJECTS} />), "");
});

test("while a scan runs the dialog says so and offers Cancel", () => {
  const html = renderToStaticMarkup(
    <ScanDialog open onClose={() => {}} scan={stub({ running: true })} projects={PROJECTS} />,
  );
  assert.match(html, /A scan is running/);
  assert.match(html, /Cancel scan/);
  assert.doesNotMatch(html, /Set up in Scanners/);
});

test("with no ready scanner the button still names the choice", () => {
  const none = stub({ view: { confirm_token: "t", steps: STEPS.map((s) => ({ ...s, ready: false })), job: null } });
  const html = renderToStaticMarkup(<ScanDialog open onClose={() => {}} scan={none} projects={PROJECTS} />);
  assert.match(html, /Scan 2 projects with 0 scanners/);
});

// "Also check online" under the dependency scanner (dashboard CLI parity
// plan, decision P-1): shown while that scanner is chosen, what it sends
// beside it, disabled with why and the way to Package checks while the
// online gate is closed, and absent where the node offers no online check.

function withOnline(online: ScanOnline | undefined): SecurityScan {
  return stub({ view: { confirm_token: "t", steps: STEPS, online, job: null } });
}

test("the online option is offered under the dependency scanner while the gate is open", () => {
  const html = renderToStaticMarkup(
    <ScanDialog open onClose={() => {}} scan={withOnline({ step: "deps", open: true })} projects={PROJECTS} onOpenScanners={() => {}} />,
  );
  assert.match(html, /data-testid="scan-dialog-online"/);
  assert.match(html, /Also check online/);
  assert.match(html, /api\.osv\.dev/);
  const box = html.match(/<input[^>]*aria-describedby="scan-dialog-online-sends"[^>]*>/)?.[0] ?? "";
  assert.doesNotMatch(box, /disabled/);
  // Remembered nothing: unticked by default.
  assert.doesNotMatch(box, /checked/);
  assert.doesNotMatch(html, /Scanners &gt; Package checks/);
});

test("a closed online gate disables the option with why and a link to Package checks", () => {
  const html = renderToStaticMarkup(
    <ScanDialog
      open
      onClose={() => {}}
      scan={withOnline({ step: "deps", open: false, reason: "disclosure_not_shown" })}
      projects={PROJECTS}
      onOpenScanners={() => {}}
    />,
  );
  const box = html.match(/<input[^>]*aria-describedby="scan-dialog-online-sends"[^>]*>/)?.[0] ?? "";
  assert.match(box, /disabled/);
  assert.match(html, /Not available: The online checks&#x27; disclosure has not been accepted/);
  assert.match(html, /Turn on online checks in Scanners &gt; Package checks/);
});

test("a managed node's option names the relay", () => {
  const html = renderToStaticMarkup(
    <ScanDialog open onClose={() => {}} scan={withOnline({ step: "deps", open: true, relay: true })} projects={PROJECTS} />,
  );
  assert.match(html, /organization&#x27;s relay/);
});

test("no online check on the node: no option", () => {
  const html = renderToStaticMarkup(<ScanDialog open onClose={() => {}} scan={withOnline(undefined)} projects={PROJECTS} />);
  assert.doesNotMatch(html, /Also check online/);
});

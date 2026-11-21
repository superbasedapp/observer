// Component tests of the Code security page's IaC scanners card (dashboard
// CLI parity plan B-CS2), rendered with react-dom/server under node's test
// runner (scripts/test-components.mjs). The pure rules are pinned in
// src/lib/codeSecurityIac.test.ts; these prove the card renders them: one
// row per selected engine, an Install button only while a pin is owed, the
// blocked words where the install cannot run, and nothing at all when no
// engine is selected.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { IaCInstallCardView } from "@/components/security/IaCInstallCard";
import type { IaCEngineRow } from "@/lib/codeSecurityIac";

function row(over: Partial<IaCEngineRow> = {}): IaCEngineRow {
  return {
    component: "security.scan.trivy",
    driver: "trivy",
    kind: "process",
    compiled: true,
    platform: "untested",
    beta: true,
    note: "",
    labels: [],
    selected: true,
    installed: false,
    install_pin: "aa11",
    install_bytes: 42_000_000,
    install_consent: "Downloads Trivy",
    ...over,
  };
}

function render(engines: IaCEngineRow[]): string {
  return renderToStaticMarkup(<IaCInstallCardView data={{ engines, confirm_token: "t" }} onInstalled={() => {}} />);
}

test("no selected engine renders nothing", () => {
  assert.equal(render([row({ selected: false }), row({ driver: "kics", compiled: false })]), "");
  assert.equal(renderToStaticMarkup(<IaCInstallCardView data={null} onInstalled={() => {}} />), "");
});

test("an engine owed an install offers it, with its size", () => {
  const html = render([row()]);
  assert.match(html, /IaC scanners/);
  assert.match(html, /data-testid="iac-install-trivy"/);
  assert.match(html, /Install Trivy\.\.\./);
  assert.match(html, /about 42 MB download/);
  assert.match(html, /Not installed/);
});

test("an installed engine and a blocked one offer no install", () => {
  const html = render([
    row({ installed: true, install_pin: "", note: "Trivy: /usr/bin/trivy sha256 aa: verified", labels: ["isolated only"] }),
    row({ driver: "kics", component: "security.scan.kics", install_pin: "", install_blocked: "no vendor release for this platform" }),
  ]);
  assert.doesNotMatch(html, /Install Trivy\.\.\./);
  assert.doesNotMatch(html, /Install KICS\.\.\./);
  assert.match(html, /Installed/);
  assert.match(html, /isolated only/);
  assert.match(html, /Install blocked/);
  assert.match(html, /cannot be installed here: no vendor release for this platform/);
});

test("the card never sends the user to a terminal for the install", () => {
  // The CLI twin may be named in the dialog, never as the only way.
  const html = render([row()]);
  assert.doesNotMatch(html, /Settings &gt; Code security/);
});

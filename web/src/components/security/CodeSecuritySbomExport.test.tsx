// Component tests of the Projects tab's "Export SBOM" (security coverage
// gaps plan section 3): the button, its waiting state, and a refusal shown
// on the button rather than saved as a file.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SbomExportButtonView, sbomFileName, sbomHref } from "@/pages/codesecurity/SbomExportButton";

test("the button exports; busy waits", () => {
  assert.match(renderToStaticMarkup(<SbomExportButtonView busy={false} error={null} onExport={() => {}} />), />Export SBOM</);
  assert.match(renderToStaticMarkup(<SbomExportButtonView busy error={null} onExport={() => {}} />), /<button[^>]*disabled[^>]*>Exporting\.\.\.</);
});

test("a refusal is shown, not saved", () => {
  const html = renderToStaticMarkup(<SbomExportButtonView busy={false} error="no dependency scan yet" onExport={() => {}} />);
  assert.match(html, /data-testid="sbom-export-error"/);
});

test("the route and the file name", () => {
  assert.equal(sbomHref("ab/c"), "/api/security/sbom?project=ab%2Fc");
  assert.equal(sbomFileName(`attachment; filename="my-app.sbom.cdx.json"`, "abcdef0123"), "my-app.sbom.cdx.json");
  assert.equal(sbomFileName(null, "abcdef0123"), "project-abcdef01.sbom.cdx.json");
});

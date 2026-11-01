// Component tests of the Code security page's SARIF upload (component
// security.scan.sarif-import, lane SEC-P4), rendered with react-dom/server
// under node's test runner (scripts/test-components.mjs). The pure half is
// pinned in src/lib/sarifImport.test.ts; these prove the card renders it:
// the picker, the cap, the file input, Import disabled until a file is
// picked, and the honest note.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SARIFImportCardView } from "@/components/security/SARIFImportCard";

const tools = [
  { id: "gosec", label: "gosec" },
  { id: "other", label: "Another tool that writes SARIF" },
];

test("the card shows the picker, the cap and the file input", () => {
  const html = renderToStaticMarkup(
    <SARIFImportCardView tools={tools} maxBytes={32 << 20} projects={[{ project_root_hash: "abcdef0123456789" }]} busy={false} note={null} onUpload={() => {}} />,
  );
  assert.match(html, /data-testid="sarif-import-card"/);
  assert.match(html, /Another tool that writes SARIF/);
  assert.match(html, /abcdef012345/);
  assert.match(html, /at most 32 MB/);
  assert.match(html, /type="file"/);
  assert.match(html, /closes none, so it never shows a project clean/);
});

test("Import is disabled until a file is picked", () => {
  const html = renderToStaticMarkup(
    <SARIFImportCardView tools={tools} maxBytes={1 << 20} projects={[{ project_root_hash: "h" }]} busy={false} note={null} onUpload={() => {}} />,
  );
  assert.match(html, /<button[^>]*disabled[^>]*>Import</);
});

test("no project: no upload, the reason instead", () => {
  const html = renderToStaticMarkup(<SARIFImportCardView tools={tools} maxBytes={1 << 20} projects={[]} busy={false} note={null} onUpload={() => {}} />);
  assert.doesNotMatch(html, /type="file"/);
  assert.match(html, /No projects yet/);
});

test("a refusal reads as an error, plain text", () => {
  const html = renderToStaticMarkup(
    <SARIFImportCardView tools={tools} maxBytes={1 << 20} projects={[{ project_root_hash: "h" }]} busy={false} note={{ ok: false, text: "<b>unknown tool</b>" }} onUpload={() => {}} />,
  );
  assert.match(html, /text-danger">&lt;b&gt;unknown tool&lt;\/b&gt;/);
});

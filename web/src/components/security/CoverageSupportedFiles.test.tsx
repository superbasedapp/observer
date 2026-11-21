// Component test of the Coverage tab's files cell (Code security redesign,
// 2026-11-06): what the scanners read is listed apart from the files they
// find but never read, so a manifest checked only through its lockfile or a
// file no extractor reads (bun.lockb, rebar.lock) never reads as covered.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { SupportedFiles } from "@/pages/codesecurity/CoverageTab";

test("read files and found-but-unread files are listed apart", () => {
  const html = renderToStaticMarkup(<SupportedFiles files={["package-lock.json", "yarn.lock"]} unread={["package.json", "bun.lockb"]} />);
  assert.match(html, /package-lock\.json, yarn\.lock/);
  assert.match(html, /data-testid="coverage-unread-files"[^>]*>.*Found, not read: .*package\.json, bun\.lockb/);
});

test("no unread line when every file is read; a dash when nothing is", () => {
  assert.ok(!/coverage-unread-files/.test(renderToStaticMarkup(<SupportedFiles files={["go.mod"]} unread={[]} />)));
  const none = renderToStaticMarkup(<SupportedFiles files={[]} unread={["Podfile.lock"]} />);
  assert.match(none, />-</);
  assert.match(none, /Podfile\.lock/);
});

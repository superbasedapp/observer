// Render tests of the Baselines tab's status line (lane LEFT2-SEC item
// R-023), rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs): the "approved by the org" label shows
// exactly when the API's org_approved_at does, in the CLI's words.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { BaselineStatus } from "@/components/security/BaselineStatus";

const current = { kind: "commit", ref: "a".repeat(40), approver: "dashboard", created_at: "2026-10-20T09:00:00Z" };

test("a baseline the org approved carries the org label", () => {
  const html = renderToStaticMarkup(<BaselineStatus current={{ ...current, org_approved_at: "2026-10-24T10:00:00Z" }} />);
  assert.match(html, /Baseline: aaaaaaaaaaaa, approved from the dashboard on 2026-10-20/);
  assert.match(html, /data-testid="baseline-org-label"/);
  assert.match(html, /Approved by the org on 2026-10-24T10:00:00Z \(a label: it changes no finding or verdict\)\./);
});

test("a baseline the org did not approve has no org label", () => {
  const html = renderToStaticMarkup(<BaselineStatus current={current} />);
  assert.match(html, /Baseline: aaaaaaaaaaaa/);
  assert.doesNotMatch(html, /Approved by the org/);
});

test("no baseline says so and has no org label", () => {
  const html = renderToStaticMarkup(<BaselineStatus current={null} />);
  assert.match(html, /No baseline: findings read as untrusted baseline/);
  assert.doesNotMatch(html, /Approved by the org/);
});

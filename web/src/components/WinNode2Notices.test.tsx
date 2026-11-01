// Component tests of the node dashboard notices that came back on every
// reload on the 2026-10-28 Windows demo node (WINNODE2 16b), rendered with
// react-dom/server under node's test runner (scripts/test-components.mjs).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ComponentsSetupCardView, componentsCardShown } from "@/components/ComponentsSetupCard";
import { announcementApplies, parseAnnouncement } from "@/lib/version";

test("the Review components card stays hidden once dismissed here or on the daemon", () => {
  const base = { localDismissed: false, serverDismissed: false, wired: true, configured: false };
  assert.equal(componentsCardShown(base), true);
  assert.equal(componentsCardShown({ ...base, serverDismissed: true }), false, "a daemon-kept dismissal hides it");
  assert.equal(componentsCardShown({ ...base, localDismissed: true }), false);
  assert.equal(componentsCardShown({ ...base, configured: true }), false);
  const html = renderToStaticMarkup(
    <MemoryRouter>
      <ComponentsSetupCardView onDismiss={() => {}} />
    </MemoryRouter>,
  );
  assert.match(html, /Review components/);
  assert.match(html, /Dismiss/);
});

test("an announcement fixed in a release the node has reached is not shown", () => {
  const a = parseAnnouncement(
    {
      id: "2026-08-26-disk-maintenance-fix",
      severity: "notice",
      title: "v1.32.0 fixes unbounded database maintenance",
      body: "Upgrade any machines on older versions.",
      expires_at: "2099-01-01T00:00:00Z",
      source: "release",
      fixed_in: "1.32.0",
    },
    Date.parse("2026-10-28T00:00:00Z"),
  );
  assert.ok(a);
  assert.equal(a.fixed_in, "1.32.0");
  assert.equal(announcementApplies(a, "1.36.0"), false, "a v1.36.0 node is past the fix");
  assert.equal(announcementApplies(a, "1.32.0"), false);
  assert.equal(announcementApplies(a, "1.31.2"), true);
  assert.equal(announcementApplies(a, "dev"), true, "a dev build keeps it");
  assert.equal(announcementApplies({}, "1.36.0"), true, "no fixed_in: always news");
});

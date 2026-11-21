// Component test of the AI tool settings page's Organization tab states
// (src/pages/agentconfig/OrgTab.tsx), rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs). The tab reads
// GET /api/agent-config/org; these render the notice it shows for each state.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { OrgStatusNotice } from "@/pages/agentconfig/OrgTab";
import { orgNotice, type OrgPolicyView } from "@/lib/agentConfig";

const consoleError = console.error;
console.error = (...args: unknown[]) => {
  if (typeof args[0] === "string" && args[0].includes("useLayoutEffect does nothing on the server")) return;
  consoleError(...args);
};

function render(v: Pick<OrgPolicyView, "managed" | "status" | "org_name" | "grant_state" | "has_policy">): string {
  const n = orgNotice(v);
  assert.ok(n, "a notice");
  return renderToStaticMarkup(
    <MemoryRouter>
      <OrgStatusNotice notice={n} />
    </MemoryRouter>,
  );
}

test("an enrolled, unmanaged machine names its org and is not told to enrol", () => {
  const html = render({ managed: false, status: "unmanaged", org_name: "localhost:8443", has_policy: false });
  assert.match(html, /Enrolled with localhost:8443, not managed/);
  assert.doesNotMatch(html, /Not enrolled with an organization/);
  assert.doesNotMatch(html, /Not managed by an organization/);
  assert.match(html, /href="\/settings\?section=enrolment"/);
});

test("a machine with no enrolment is told how to enrol", () => {
  const html = render({ managed: false, status: "not_enrolled", has_policy: false });
  assert.match(html, /Not enrolled with an organization/);
  assert.match(html, /Open Settings &gt; Enrolment/);
});

test("a managed machine whose grant is not in force says why", () => {
  const html = render({ managed: false, status: "managed_inactive", org_name: "Acme", grant_state: "no_grant", has_policy: false });
  assert.match(html, /Managed by Acme, not in force/);
  assert.match(html, /has not received its management grant yet/);
});

test("a managed machine with no policy yet has no enrolment link", () => {
  const html = render({ managed: true, status: "managed", org_name: "Acme", has_policy: false });
  assert.match(html, /No AI tool policy yet/);
  assert.doesNotMatch(html, /section=enrolment/);
});

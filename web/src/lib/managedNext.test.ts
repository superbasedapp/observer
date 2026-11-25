import { test } from "node:test";
import assert from "node:assert/strict";

import { LINK_RULES, managedNext, type ManagedNextInput } from "./managedNext.ts";
import type { GovernanceOnline } from "./visibility.ts";

const personal: GovernanceOnline = {
  kind: "personal",
  visibility: { href: "https://me.example.app/settings?section=developer-dashboards", label: "Settings > Developer dashboards" },
  pages: {
    "app-traces": { href: "https://me.example.app/trajectories", label: "AI apps > Explorer", members: true },
    routing: { href: "https://me.example.app/routing", label: "Coding agents > Routing", members: false },
  },
};

const team: GovernanceOnline = {
  kind: "team",
  visibility: { href: "https://org.example/settings?section=developer-dashboards", label: "Settings > Developer dashboards" },
  pages: {
    "app-traces": { href: "https://org.example/trajectories", label: "AI apps > Explorer", members: true },
    routing: { href: "https://org.example/routing", label: "Coding agents > Routing", members: false },
  },
};

const base: ManagedNextInput = { level: "hidden", kind: "page", navId: "app-traces", orgLabel: "Acme", byDefault: false };

const keys = (i: ManagedNextInput) => managedNext(i).links.map((l) => l.key);

// One case per LINK_RULES row: when it adds its link and when it does not.
test("link rules: one case per row", () => {
  const cases: { rule: string; on: ManagedNextInput; off: ManagedNextInput }[] = [
    {
      rule: "online-page",
      on: { ...base, online: personal },
      // A team member cannot open an admin-only page there: no link.
      off: { ...base, online: team, navId: "routing" },
    },
    { rule: "developer-dashboards", on: { ...base, online: personal }, off: { ...base, online: team } },
    {
      rule: "account",
      on: { ...base, online: { ...personal, visibility: { label: "Settings > Developer dashboards" } } },
      off: { ...base, online: personal },
    },
    { rule: "request", on: { ...base, online: team }, off: { ...base, online: team, level: "read_only" } },
    { rule: "message", on: { ...base, online: team }, off: { ...base, online: personal } },
    { rule: "contact", on: { ...base, online: team, contact: "it@acme.example" }, off: { ...base, online: team } },
    {
      rule: "policy",
      on: { ...base, online: team, policyUrl: "https://acme.example/policy" },
      off: { ...base, online: team, policyUrl: "javascript:alert(1)" },
    },
  ];
  assert.equal(cases.length, LINK_RULES.length, "every link rule needs its own case");
  for (const c of cases) {
    assert.ok(keys(c.on).includes(c.rule), `${c.rule} should apply: ${keys(c.on)}`);
    assert.ok(!keys(c.off).includes(c.rule), `${c.rule} should not apply: ${keys(c.off)}`);
  }
});

test("an owner's hidden page says they control it and links to both places online", () => {
  const n = managedNext({ ...base, online: personal, byDefault: true });
  assert.equal(n.title, "Hidden on this machine");
  assert.match(n.body, /setting on your personal dashboard/);
  assert.match(n.body, /You are its owner, so you can show it again in Settings > Developer dashboards on your personal dashboard\./);
  assert.doesNotMatch(n.body, /administrator/);
  assert.deepEqual(
    n.links.map((l) => [l.href, l.external]),
    [
      ["https://me.example.app/trajectories", true],
      ["https://me.example.app/settings?section=developer-dashboards", true],
    ],
  );
  // On their own dashboard every page is theirs to open.
  assert.ok(keys({ ...base, online: personal, navId: "routing" }).includes("online-page"));
});

test("an owner's read-only page offers turning editing back on", () => {
  const n = managedNext({ ...base, online: personal, level: "read_only", navId: "remote" });
  assert.equal(n.title, "Read-only on this machine");
  assert.match(n.body, /turn editing back on in Settings > Developer dashboards/);
  assert.deepEqual(keys({ ...base, online: personal, level: "read_only", navId: "remote" }), ["developer-dashboards"]);
});

test("a team member's hidden page names the administrator and every way to ask", () => {
  const n = managedNext({ ...base, online: team, byDefault: true, contact: "it@acme.example" });
  assert.equal(n.title, "Managed by your organization");
  assert.match(n.body, /managed by Acme and is not available on this machine\. It is hidden by default/);
  assert.match(n.body, /Your administrator \(it@acme\.example\) can make it available\./);
  assert.deepEqual(n.links.map((l) => l.key), ["online-page", "request", "message", "contact"]);
  const req = n.links.find((l) => l.key === "request")!;
  assert.equal(req.href, "/requests?new=page&page=app-traces");
  assert.equal(req.external, false);
});

test("a team member with no contact published is pointed at the admins by name", () => {
  assert.match(managedNext({ ...base, online: team }).body, /The administrators of Acme can make it available\./);
  assert.match(
    managedNext({ ...base, online: team, orgLabel: "your organization" }).body,
    /Your organization's administrators can make it available\./,
  );
});

test("a read-only page on a team machine says editing is off and who can turn it on", () => {
  const n = managedNext({ ...base, online: team, level: "read_only", navId: "compression" });
  assert.equal(n.title, "Read-only on this machine");
  assert.match(n.body, /^Acme manages this page\. You can see everything here, but changes are turned off\./);
  assert.deepEqual(n.links.map((l) => l.key), ["message"]);
});

test("a Settings section has no page equivalent and no page request", () => {
  const owner = managedNext({ level: "hidden", kind: "section", online: personal, orgLabel: "Personal", byDefault: false });
  assert.match(owner.body, /^This settings section is hidden/);
  assert.deepEqual(owner.links.map((l) => l.key), ["developer-dashboards"]);
  const member = managedNext({ level: "hidden", kind: "section", online: team, orgLabel: "Acme", byDefault: true });
  assert.deepEqual(member.links.map((l) => l.key), ["message"]);
});

test("an older daemon with no online block still offers a way forward", () => {
  // No online block reads as the team wording, which always has the in-app
  // message link (and a request on a hidden page).
  for (const level of ["hidden", "read_only"] as const) {
    const n = managedNext({ ...base, level, online: null });
    assert.ok(n.links.length > 0, `${level}: a dead end`);
  }
});

test("an unsafe online address never becomes a link", () => {
  const odd: GovernanceOnline = {
    kind: "personal",
    visibility: { href: "http://evil.example/x", label: "Settings > Developer dashboards" },
    pages: { "app-traces": { href: "javascript:alert(1)", label: "AI apps > Explorer", members: true } },
  };
  const n = managedNext({ ...base, online: odd });
  assert.deepEqual(n.links.map((l) => l.key), ["account"]);
});

test("copy rules: no em dashes, no plane names", () => {
  for (const online of [personal, team, null]) {
    for (const level of ["hidden", "read_only"] as const) {
      for (const kind of ["page", "section"] as const) {
        const n = managedNext({ ...base, online, level, kind, contact: "it@acme.example", byDefault: true });
        for (const s of [n.title, n.body, ...n.links.map((l) => l.label)]) {
          assert.doesNotMatch(s, /—|Plane [AB]/, s);
        }
      }
    }
  }
});

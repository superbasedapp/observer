// Component tests of operator ruling 2 (2026-11-24): a hidden or read-only
// page is never a dead end, and a link to a page this machine hides goes to
// its equivalent on the online dashboard. Rendered with react-dom/server under
// node's test runner (scripts/test-components.mjs, no DOM). The wording and
// the link rules themselves are lib/managedNext.test.ts's; these prove the
// components render them, with real anchors, from the daemon's answer.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { ManagedNotice, ManagedReadOnlyBar, ManagedSettingsReadOnly } from "@/components/ManagedNotice";
import { GatedLink } from "@/components/GatedLink";
import { GlanceView } from "@/components/apps/AppsTrack";
import { buildUrl } from "@/lib/api";
import { apiCache } from "@/lib/useApi";
import type { Governance } from "@/lib/governance";

const GOVERNANCE_PATH = buildUrl("/api/governance");
const lists = { hidden_sections: [], read_only_sections: [], hidden_settings: [], read_only_settings: [] };
const SOLO = { active: false, state: "no_grant", version: 0, notice: {}, ...lists };

const pages = {
  "app-traces": { href: "https://me.example.app/trajectories", label: "AI apps > Explorer", members: true },
  routing: { href: "https://me.example.app/routing", label: "Coding agents > Routing", members: false },
};

// A machine its owner manages that hides the traces page and locks Remote.
const OWNER: Governance = {
  ...SOLO,
  state: "applied",
  active: true,
  managed: true,
  org_name: "Personal",
  notice: {},
  visibility: {
    managed_defaults: true,
    ...lists,
    hidden_sections: ["app-traces"],
    read_only_sections: ["remote"],
    sections: { "app-traces": { level: "hidden", source: "org" }, remote: { level: "read_only", source: "org" } },
  },
  online: {
    kind: "personal",
    visibility: { href: "https://me.example.app/settings?section=developer-dashboards", label: "Settings > Developer dashboards" },
    pages,
  },
} as Governance;

// A team member's machine: the traces page hidden by default.
const TEAM: Governance = {
  ...OWNER,
  org_name: "Acme",
  notice: { contact: "it@acme.example" },
  visibility: {
    ...OWNER.visibility!,
    hidden_sections: ["app-traces", "routing"],
    sections: { "app-traces": { level: "hidden", source: "default" }, routing: { level: "hidden", source: "default" } },
  },
  online: {
    kind: "team",
    visibility: { href: "https://acme.example/settings?section=developer-dashboards", label: "Settings > Developer dashboards" },
    pages: {
      "app-traces": { href: "https://acme.example/trajectories", label: "AI apps > Explorer", members: true },
      routing: { href: "https://acme.example/routing", label: "Coding agents > Routing", members: false },
    },
  },
} as Governance;

const answer = (g: unknown) => apiCache.fetch(GOVERNANCE_PATH, async () => g);
const render = (el: React.ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);

before(() => answer(SOLO));
after(() => answer(SOLO));

test("an owner's hidden page links to Developer dashboards and the page online", () => {
  const html = render(<ManagedNotice gov={OWNER} navId="app-traces" />);
  assert.match(html, /Hidden on this machine/);
  assert.match(html, /You are its owner/);
  assert.match(html, /<a [^>]*href="https:\/\/me\.example\.app\/trajectories"[^>]*target="_blank"/);
  assert.match(html, /<a [^>]*href="https:\/\/me\.example\.app\/settings\?section=developer-dashboards"/);
  assert.match(html, /Open AI apps &gt; Explorer online/);
  assert.doesNotMatch(html, /your administrator can make it available/i);
});

test("a team member's hidden page names the administrator and offers a request, a message and the page online", () => {
  const html = render(<ManagedNotice gov={TEAM} navId="app-traces" />);
  assert.match(html, /Managed by your organization/);
  assert.match(html, /hidden by default on organization-managed machines/);
  assert.match(html, /Your administrator \(it@acme\.example\) can make it available/);
  assert.match(html, /href="\/requests\?new=page&amp;page=app-traces"/);
  assert.match(html, /href="\/messages"/);
  assert.match(html, /href="mailto:it@acme\.example"/);
  assert.match(html, /href="https:\/\/acme\.example\/trajectories"/);
  // An admin-only page there is not offered to a member.
  const admin = render(<ManagedNotice gov={TEAM} navId="routing" />);
  assert.doesNotMatch(admin, /acme\.example\/routing/);
  assert.match(admin, /href="\/messages"/);
});

test("a hidden Settings section is never a dead end either", () => {
  const owner = render(<ManagedNotice gov={OWNER} settingsId="guard" />);
  assert.match(owner, /This settings section is hidden/);
  assert.match(owner, /section=developer-dashboards/);
  const team = render(<ManagedNotice gov={TEAM} settingsId="guard" />);
  assert.match(team, /href="\/messages"/);
});

test("the read-only bar carries the next steps", () => {
  const owner = render(<ManagedReadOnlyBar gov={OWNER} navId="remote" />);
  assert.match(owner, /data-testid="managed-read-only"/);
  assert.match(owner, /turn editing back on/);
  assert.match(owner, /section=developer-dashboards/);
  const team = render(<ManagedReadOnlyBar gov={TEAM} navId="remote" />);
  assert.match(team, /changes are turned off/);
  assert.match(team, /href="\/messages"/);
});

test("a link to a hidden page goes to its online equivalent", async () => {
  await answer(TEAM);
  try {
    const shown = render(
      <GatedLink to="/apps/traces" className="x">
        See the traces
      </GatedLink>,
    );
    assert.match(shown, /<a [^>]*href="https:\/\/acme\.example\/trajectories"[^>]*target="_blank"[^>]*>See the traces<\/a>/);
    // No equivalent a member may open: the managed note, as before.
    const admin = render(<GatedLink to="/routing">Routing</GatedLink>);
    assert.doesNotMatch(admin, /<a /);
    assert.match(admin, /Managed by your organization/);
    // The Overview card's "See the traces" goes through the same gate.
    const glance = render(<GlanceView latest={null} today={3} errors={0} />);
    assert.match(glance, /href="https:\/\/acme\.example\/trajectories"[^>]*>See the traces/);
  } finally {
    await answer(SOLO);
  }
});

test("a shown page keeps its ordinary in-app link", async () => {
  await answer(SOLO);
  const html = render(<GatedLink to="/apps/traces">See the traces</GatedLink>);
  assert.match(html, /<a [^>]*href="\/apps\/traces"/);
});

test("a read-only Settings section names who can change it and where", () => {
  const owner = render(<ManagedSettingsReadOnly gov={OWNER} settingsId="proxy" />);
  assert.match(owner, /This settings section is read-only/);
  assert.match(owner, /section=developer-dashboards/);
  const team = render(<ManagedSettingsReadOnly gov={TEAM} settingsId="proxy" />);
  assert.match(team, /Acme manages this settings section/);
  assert.match(team, /href="\/messages"/);
});

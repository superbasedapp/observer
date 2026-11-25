// Render tests of the personal org (D-IND-8): the "Personal" card on
// Organizations with no personal org, while it is created and set up, and
// once active; and one org's page for a personal org (personal wording, no
// seats, no role, the billing card worded for the personal plans).

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { PersonalOrgCard } from "./PersonalOrgCard";
import { OrgDetailView } from "./OrgDetailView";
import { OrgBillingCard } from "./OrgBillingCard";
import type { OrgBillingView, OrgDetail, PortalOrg } from "../../api";

const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);

function org(over: Partial<PortalOrg> = {}): PortalOrg {
  return {
    org_id: "org_p",
    slug: "u-3f9a2c1d",
    display_name: "Dev Developer",
    kind: "personal",
    status: "active",
    tenancy: "individual",
    console_role: "owner",
    is_billing_owner: true,
    created_at: "2026-11-01T00:00:00Z",
    host: "u-3f9a2c1d.superbased.app",
    machines_page_url: "https://u-3f9a2c1d.superbased.app/me/profile",
    ...over,
  };
}

test("with no personal dashboard yet the card says it is being set up, with no button to press", () => {
  const out = html(<PersonalOrgCard />);
  assert.match(out, /Your personal dashboard/);
  assert.match(out, /Setting up your personal dashboard\.\.\./);
  assert.match(out, /one member: you/);
  assert.match(out, /Summary only/);
  assert.doesNotMatch(out, /<button/);
});

test("an active personal dashboard opens from a button and never shows its address", () => {
  const out = html(<PersonalOrgCard org={org({ open_url: "https://u-3f9a2c1d.superbased.app/" })} />);
  assert.match(out, /Active/);
  assert.match(out, /Open your dashboard/);
  assert.match(out, /href="https:\/\/u-3f9a2c1d\.superbased\.app\/"/);
  assert.match(out, /href="\/orgs\/org_p"/);
  // The address is only ever an href, never text.
  assert.doesNotMatch(out.replace(/href="[^"]*"/g, ""), /u-3f9a2c1d/);
});

test("a personal dashboard still being set up shows its stage in personal words, and no links yet", () => {
  const out = html(
    <PersonalOrgCard org={org({ status: "provisioning", machines_page_url: undefined, provisioning: { stage: "waitlisted", attempts: 1 } })} />,
  );
  assert.match(out, /Waitlisted/);
  assert.match(out, /your personal dashboard is on the waitlist/);
  assert.doesNotMatch(out, /Open your dashboard/);
  assert.doesNotMatch(out, /team/i);
});

function detail(over: Partial<OrgDetail> = {}): OrgDetail {
  return {
    org: org(),
    can: { rename: true, view_billing: true, checkout: true },
    launch_url: "https://u-3f9a2c1d.superbased.app/me/install",
    plan: { name: "free", version: 1, label: "Free", source: "floor", seats_min: 1 },
    seats: { in_use: 1, members: 1, day: "2026-11-15" },
    ...over,
  };
}

test("a personal org's page reads as one: no seats, no role, no team words", () => {
  const out = html(<OrgDetailView detail={detail()} billing={null} onRename={async () => {}} />);
  assert.match(out, /Personal/);
  assert.match(out, /one member: you/);
  assert.match(out, /Open your personal dashboard/);
  assert.match(out, /Display name/);
  assert.match(out, /The address stays the same/);
  assert.doesNotMatch(out, /Seats in use/);
  assert.doesNotMatch(out, /Minimum seats/);
  assert.doesNotMatch(out, /Owner/);
  assert.doesNotMatch(out, /team/i);
});

test("a personal org being set up says so in personal words", () => {
  const out = html(
    <OrgDetailView
      detail={detail({ org: org({ status: "provisioning", provisioning: { stage: "queued", attempts: 0 } }), launch_url: undefined, can: { rename: false, view_billing: true, checkout: true } })}
      billing={null}
      onRename={async () => {}}
    />,
  );
  assert.match(out, /Setting up your personal dashboard/);
  assert.match(out, /queued to be set up/);
  assert.doesNotMatch(out, /team/i);
});

test("the billing card for a personal org offers the personal plan, never the Team plan", () => {
  const billing: OrgBillingView = {
    has_subscription: false,
    plan: { name: "free", version: 1, label: "Free", source: "floor" },
    checkout: {
      available: true,
      environment: "sandbox",
      client_token: "t",
      prices: [{ price_id: "pri_p", plan_name: "personal_pro", plan_version: 2, interval: "month", display: "$9/mo" }],
      trial_days: 0,
    },
    can_checkout: true,
    is_billing_owner: true,
  };
  const out = html(<OrgBillingCard billing={billing} onCheckout={async () => {}} kind="personal" />);
  assert.match(out, /free plan/);
  assert.match(out, />Subscribe</);
  assert.doesNotMatch(out, /Team/);
});

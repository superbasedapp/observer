// Render tests of one org's page (plan 07 M6.5): provisioning and the
// capacity waitlist, the install deep link, the plan and seats, the billing
// card's states, and who sees rename.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { OrgDetailView } from "./OrgDetailView";
import { OrgBillingCard } from "./OrgBillingCard";
import { OrgList } from "./OrgList";
import type { OrgBillingView, OrgDetail, PortalOrg } from "../../api";

const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);
const rename = async () => {};

function org(over: Partial<PortalOrg> = {}): PortalOrg {
  return {
    org_id: "o1",
    slug: "acme",
    display_name: "Acme Engineering",
    kind: "team",
    status: "active",
    tenancy: "managed",
    console_role: "owner",
    is_billing_owner: true,
    created_at: "2026-11-01T00:00:00Z",
    host: "acme.superbased.app",
    ...over,
  };
}

function detail(over: Partial<OrgDetail> = {}): OrgDetail {
  return { org: org(), can: { rename: true, view_billing: true, checkout: true }, ...over };
}

test("a waitlisted team says it is on the capacity waitlist and offers no install link or rename", () => {
  const out = html(
    <OrgDetailView
      detail={detail({
        org: org({
          status: "provisioning",
          provisioning: { stage: "waitlisted", attempts: 2, last_error_class: "refused:capacity_waitlist", queued_at: "2026-11-15T10:00:00Z", next_attempt_at: "2026-11-15T10:15:00Z" },
        }),
        can: { rename: false, view_billing: true, checkout: true },
      })}
      billing={null}
      onRename={rename}
    />,
  );
  assert.match(out, /Waitlisted/);
  assert.match(out, /at capacity right now/);
  assert.match(out, /Next try/);
  assert.doesNotMatch(out, /Open the install page/);
  assert.doesNotMatch(out, /Team name/);
});

test("a failed setup reads as needing attention, a queued one as queued", () => {
  const failed = html(<OrgDetailView detail={detail({ org: org({ status: "provisioning", provisioning: { stage: "failed", attempts: 6 } }), can: { rename: false, view_billing: true, checkout: true } })} billing={null} onRename={rename} />);
  assert.match(failed, /Needs attention/);
  const queued = html(<OrgDetailView detail={detail({ org: org({ status: "provisioning", provisioning: { stage: "queued", attempts: 0 } }), can: { rename: false, view_billing: true, checkout: true } })} billing={null} onRename={rename} />);
  assert.match(queued, /queued to be set up/);
});

test("an active team links to its install page and shows plan, launch window and seats", () => {
  const out = html(
    <OrgDetailView
      detail={detail({
        launch_url: "https://acme.superbased.app/me/install",
        plan: { name: "team", version: 1, label: "Team", source: "launch", not_after: "2026-11-29T00:00:00Z", seats_min: 3 },
        seats: { in_use: 7, members: 9, day: "2026-11-14" },
      })}
      billing={<div>BILLING-SLOT</div>}
      onRename={rename}
    />,
  );
  assert.match(out, /href="https:\/\/acme\.superbased\.app\/me\/install"/);
  assert.match(out, /Free launch period, until/);
  assert.match(out, /Minimum seats/);
  assert.match(out, /7 \(reported 2026-11-14\)/);
  assert.match(out, /BILLING-SLOT/);
  assert.match(out, /Team name/);
});

test("a member's view has no plan and no rename", () => {
  const out = html(
    <OrgDetailView detail={detail({ org: org({ console_role: "member", is_billing_owner: false }), can: { rename: false, view_billing: false, checkout: false } })} billing={null} onRename={rename} />,
  );
  assert.match(out, /Member/);
  assert.doesNotMatch(out, /Team name/);
  assert.doesNotMatch(out, /Plan and seats/);
});

function billing(over: Partial<OrgBillingView> = {}): OrgBillingView {
  return {
    has_subscription: false,
    checkout: { available: true, environment: "sandbox", client_token: "test_x", prices: [{ price_id: "pri_team", plan_name: "team", plan_version: 1, interval: "month", display: "$12/seat/mo" }], trial_days: 0 },
    can_checkout: true,
    is_billing_owner: true,
    ...over,
  };
}
const checkout = async () => {};

test("billing: the billing owner of an unsubscribed team gets the Team checkout", () => {
  const out = html(<OrgBillingCard billing={billing()} onCheckout={checkout} />);
  assert.match(out, /Subscribe to Team/);
  assert.match(out, /\$12\/seat\/mo/);
  assert.match(out, /Refund Policy/);
});

test("billing: an active subscription shows its status and Paddle's links, no checkout", () => {
  const out = html(
    <OrgBillingCard
      billing={billing({
        has_subscription: true,
        can_checkout: false,
        subscription: {
          subscription_id: "sub_1", customer_id: "ctm_1", plan_name: "team", plan_version: 1, status: "active",
          current_period_end: "2027-01-01T00:00:00Z",
          management_urls: { update_payment_method: "https://sandbox-customer-portal.paddle.com/u", cancel: "https://sandbox-customer-portal.paddle.com/c" },
        },
      })}
      onCheckout={checkout}
    />,
  );
  assert.match(out, /subscription is active/);
  assert.match(out, /Update payment method/);
  assert.doesNotMatch(out, /Subscribe to Team/);
});

test("billing: an admin who is not the billing owner, and an unconfigured deployment", () => {
  assert.match(html(<OrgBillingCard billing={billing({ is_billing_owner: false, can_checkout: false })} onCheckout={checkout} />), /Only the team&#x27;s billing owner/);
  const unconfigured = html(<OrgBillingCard billing={billing({ checkout: { available: false, environment: "sandbox", client_token: "", prices: [], trial_days: 0 } })} onCheckout={checkout} />);
  assert.match(unconfigured, /not configured/);
  assert.doesNotMatch(unconfigured, /Subscribe/);
});

test("the account home list shows each org's address, role and stage", () => {
  const out = html(
    <OrgList
      orgs={[
        org(),
        org({ org_id: "o2", slug: "beta", display_name: "Beta", host: "beta.superbased.app", status: "provisioning", console_role: "admin", provisioning: { stage: "waitlisted", attempts: 1 } }),
      ]}
    />,
  );
  assert.match(out, /acme\.superbased\.app/);
  assert.match(out, /href="\/orgs\/o2"/);
  assert.match(out, /Admin/);
  assert.match(out, /Waitlisted/);
  assert.match(out, /Active/);
});

test("an operator grant reads as granted, with its end when it has one", () => {
  const can = { rename: true, view_billing: true, checkout: true };
  const open = html(
    <OrgDetailView detail={detail({ org: org(), can, plan: { name: "business", version: 1, label: "Business", source: "org_grant" } })} billing={null} onRename={rename} />,
  );
  assert.match(open, /Granted by superbased/);
  assert.doesNotMatch(open, /Granted by superbased, until/);
  const bounded = html(
    <OrgDetailView
      detail={detail({ org: org(), can, plan: { name: "team", version: 1, label: "Team", source: "org_grant", not_after: "2027-02-01T00:00:00Z" } })}
      billing={null}
      onRename={rename}
    />,
  );
  assert.match(bounded, /Granted by superbased, until/);
});

test("billing: the billing portal button shows only when the server offers it, and past_due shows when it began", () => {
  const sub = {
    subscription_id: "sub_1", customer_id: "ctm_1", plan_name: "team", plan_version: 1, status: "past_due" as const,
    past_due_since: "2026-11-10T00:00:00Z",
  };
  const portal = async () => ({ url: "https://customer-portal.paddle.com/x" });
  const offered = html(
    <OrgBillingCard billing={billing({ has_subscription: true, can_checkout: false, subscription: sub, portal_available: true })} onCheckout={checkout} onPortal={portal} />,
  );
  assert.match(offered, /Invoices and billing portal/);
  assert.match(offered, /Payment due since/);
  const notOffered = html(
    <OrgBillingCard billing={billing({ has_subscription: true, can_checkout: false, subscription: sub, portal_available: false })} onCheckout={checkout} onPortal={portal} />,
  );
  assert.doesNotMatch(notOffered, /Invoices and billing portal/);
});

test("billing: Team and Business are both offered, Team first, whatever their price ids", () => {
  const out = html(
    <OrgBillingCard
      billing={billing({
        checkout: {
          available: true, environment: "live", client_token: "live_x", trial_days: 0,
          prices: [
            { price_id: "pri_aaa", plan_name: "business", plan_version: 1, interval: "month", display: "$29/seat/mo" },
            { price_id: "pri_zzz", plan_name: "team", plan_version: 1, interval: "month", display: "$15/seat/mo" },
          ],
        },
      })}
      onCheckout={checkout}
    />,
  );
  assert.match(out, /Choose a plan/);
  assert.match(out, /\$15\/seat\/mo/);
  assert.match(out, /\$29\/seat\/mo/);
  assert.ok(out.indexOf("$15/seat/mo") < out.indexOf("$29/seat/mo"), "Team is listed first");
  assert.match(out, /Subscribe to Team/);
});

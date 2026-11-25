// Render tests of the paid individual plan's name (operator ruling
// 2026-11-24): the cards that show a subscription's plan read "Personal Pro"
// for both internal names of the plan (the account plan plus_beta, and
// personal_pro once the subscription is re-keyed onto the personal org),
// never the raw token and never "Plus", the September beta's name.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";
import { SubscriptionCard } from "./SubscriptionCard";
import { humanPlanLabel } from "./util";
import { OrgBillingCard } from "../orgs/OrgBillingCard";
import type { BillingSubscription, OrgBillingView } from "../../api";

const html = (el: ReactElement) => renderToStaticMarkup(<MemoryRouter>{el}</MemoryRouter>);

function sub(planName: string, version: number): BillingSubscription {
  return {
    subscription_id: "sub_01hz9k3m4n5p6q7r8s9t0u1v2w",
    customer_id: "ctm_01hz9k3m4n5p6q7r8s9t0u1v2w",
    plan_name: planName,
    plan_version: version,
    status: "active",
    current_period_end: "2026-12-24T00:00:00Z",
  };
}

function assertPersonalPro(out: string, token: string) {
  assert.match(out, /Personal Pro/);
  assert.doesNotMatch(out, /\bPlus\b/);
  assert.doesNotMatch(out, new RegExp(token));
}

for (const [token, version] of [
  ["plus_beta", 5],
  ["personal_pro", 2],
] as const) {
  test(`the Billing page's subscription card names ${token} Personal Pro`, () => {
    assertPersonalPro(html(<SubscriptionCard sub={sub(token, version)} showResubscribeOffer={false} />), token);
  });

  test(`an org's billing card names a ${token} subscription Personal Pro`, () => {
    const billing: OrgBillingView = {
      has_subscription: true,
      subscription: sub(token, version),
      checkout: { available: false, environment: "sandbox", client_token: "", prices: [], trial_days: 0 },
      can_checkout: false,
      is_billing_owner: true,
    };
    assertPersonalPro(html(<OrgBillingCard billing={billing} onCheckout={async () => {}} kind="personal" />), token);
  });
}

test("the Billing page's header pill reads Personal Pro for the paid plan and Free otherwise", () => {
  assert.equal(humanPlanLabel("plus_beta"), "Personal Pro");
  assert.equal(humanPlanLabel("free"), "Free");
  assert.equal(humanPlanLabel(undefined), "Free");
});

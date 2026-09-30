import { useEffect, useState } from "react";
import { Stagger } from "@shared/primitives/Motion";
import { invalidatePortal, usePortalQuery } from "../lib/query";
import { DashboardSkeleton, ErrorPanel } from "../components/LoadState";
import { InlineLoading } from "@shared/primitives/Spinner";
import { SuccessCheck } from "@shared/primitives/SuccessCheck";
import { getBilling } from "../api";
import type { BillingSubscription, BillingView } from "../api";
import { HERO_VARIANT } from "../lib/vocab";
import { PageHeader } from "@shared/primitives/PageHeader";
import { StatCard } from "@shared/primitives/StatCard";
import { HeroStat, type HeroStatVariant } from "@shared/primitives/HeroStat";
import { Pill } from "@shared/primitives/Pill";
import { fmtInt } from "@shared/lib/format";
import { PortalMetricIcon } from "../lib/metricIcons";
import { routeIcon } from "../lib/nav";
import { PlanComparison } from "../components/billing/PlanComparison";
import { SubscriptionCard } from "../components/billing/SubscriptionCard";
import {
  dateWithRelative,
  humanPlanLabel,
  isFuture,
  isPlusPlan,
  statusMeta,
} from "../components/billing/util";

// Billing (divergence plan §3 W9 / R4; checkout G2-07 / Wave B; redesigned
// onto the shared design system 2026-09-16). Paddle is the merchant of
// record: no card data is ever collected in this portal. This page shows the
// developer their current plan + subscription state, and - when the
// deployment has a checkout catalogue configured - opens a Paddle.js
// overlay to purchase a paid plan. Payment-method and cancellation
// MANAGEMENT still happens on Paddle's own hosted pages, reached through
// `management_urls` when Paddle has sent them for this subscription; when it
// hasn't (Paddle's docs note subscription.updated omits them), the receipt-
// email fallback copy is shown instead of a dead link.
//
// The page is split three ways: this file owns data loading + the
// checkout-confirmation lifecycle + the top "current plan" row; the two-plan
// comparison (with the checkout flow itself) lives in
// components/billing/PlanComparison.tsx; the per-subscription detail card
// lives in components/billing/SubscriptionCard.tsx.

// While a checkout is being confirmed the billing query polls every
// CONFIRM_POLL_MS until has_subscription flips true (the Paddle webhook lands
// asynchronously after checkout completes) or CONFIRM_TIMEOUT_MS passes. One
// query, one timer: a second "confirming" signal (the Paddle event AND the
// ?checkout=success land-back) no longer starts a second poll chain.
const CONFIRM_POLL_MS = 3000;
const CONFIRM_TIMEOUT_MS = 120_000;

// planDisplayValue picks the friendliest name available for the current
// entitlement, falling back to the live subscription's plan name and then
// to an honest generic label - never a raw plan token.
function planDisplayValue(view: BillingView): string {
  if (view.plan?.plan_label) return view.plan.plan_label;
  if (view.plan?.plan) return view.plan.plan;
  if (view.subscription?.plan_name) return view.subscription.plan_name;
  return "Free plan";
}

// heroStatus builds the one honest status sentence for the Current-plan
// hero card, plus which variant (accent/warn/danger) it should render in.
// Every status branch here mirrors a behaviour the previous, unstyled page
// rendered as its own banner - the wording is preserved even though it now
// lives in the hero card's sub line instead of a separate <div className=
// "banner">.
function heroStatus(view: BillingView): { text: string; variant: HeroStatVariant } {
  const sub = view.subscription;
  if (!view.has_subscription || !sub) {
    return { text: "Free plan. Runs at no cost.", variant: "accent" };
  }
  // The hero's colour is the status pill's tone (SUBSCRIPTION_STATUS),
  // mapped onto the hero's accent / warn / danger (HERO_VARIANT); only the
  // sentence is per status. Defensive: an unknown status still gets an honest
  // sentence rather than silently rendering nothing.
  const text = HERO_TEXT[sub.status]?.(sub) ?? `${statusMeta(sub.status).label}.`;
  return { text, variant: HERO_VARIANT[statusMeta(sub.status).variant] };
}

// HERO_TEXT is the one honest status sentence per subscription status.
const HERO_TEXT: Partial<Record<string, (sub: BillingSubscription) => string>> = {
  trialing: (sub) =>
    sub.trial_ends_at
      ? `You are in your free trial - it ends ${dateWithRelative(sub.trial_ends_at)}.`
      : "You are in your free trial.",
  active: (sub) =>
    sub.current_period_end ? `Active. Renews ${dateWithRelative(sub.current_period_end)}.` : "Active.",
  past_due: () =>
    "Your last payment did not go through. Access continues for now, " +
    "but update your payment method in the Paddle billing portal to " +
    "avoid an interruption.",
  refunded: () => "This subscription was refunded. Paid access has been revoked.",
  charged_back: () =>
    "A chargeback was recorded against this subscription. Paid access has been revoked.",
  paused: () => "Subscription paused.",
  canceled: (sub) => {
    const base = isFuture(sub.current_period_end)
      ? `Canceled - access continues until ${dateWithRelative(sub.current_period_end)}.`
      : "Canceled.";
    const canceledOn = sub.canceled_at ? ` (canceled on ${dateWithRelative(sub.canceled_at)})` : "";
    return base + canceledOn;
  },
};

export function Billing() {
  // "confirming" starts either from the Paddle checkout.completed event or
  // from landing back on ?checkout=success - both mean the purchase almost
  // certainly succeeded but the webhook that actually grants the plan lands
  // asynchronously, so the page polls rather than trusting the client-side
  // signal alone.
  const [confirming, setConfirming] = useState(false);
  const [confirmTimedOut, setConfirmTimedOut] = useState(false);
  // A confirmation that resolved while this page was open: the self-drawing
  // check replaces the "Confirming" line (additive feedback only).
  const [confirmed, setConfirmed] = useState(false);
  const q = usePortalQuery<BillingView>("billing", getBilling, [], {
    refreshMs: confirming ? CONFIRM_POLL_MS : 0,
  });
  const data = q.data;
  const error = q.error && !data ? q.error : null;

  // Land-back detection: strip ?checkout=success from the address bar and
  // start confirming, exactly like the Paddle eventCallback path does.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("checkout") !== "success") {
      return;
    }
    params.delete("checkout");
    const rest = params.toString();
    window.history.replaceState(
      null,
      "",
      window.location.pathname + (rest ? "?" + rest : ""),
    );
    setConfirming(true);
  }, []);

  // Confirmation window: stop (and say so) after the timeout.
  useEffect(() => {
    if (!confirming) return;
    setConfirmTimedOut(false);
    setConfirmed(false);
    const t = window.setTimeout(() => {
      setConfirming(false);
      setConfirmTimedOut(true);
    }, CONFIRM_TIMEOUT_MS);
    return () => window.clearTimeout(t);
  }, [confirming]);

  // The subscription landed: stop polling, and refresh the plan-dependent
  // usage view other pages read.
  const hasSubscription = data?.has_subscription ?? false;
  useEffect(() => {
    if (confirming && hasSubscription) {
      setConfirming(false);
      setConfirmed(true);
      invalidatePortal("usage");
    }
  }, [confirming, hasSubscription]);

  if (error) {
    return <ErrorPanel variant="page" what="billing" error={error} onRetry={q.reload} />;
  }
  if (!data) {
    return <DashboardSkeleton />;
  }

  const plan = data.plan;
  const sub = data.subscription;
  const terminal = sub?.status === "refunded" || sub?.status === "charged_back";
  const canceled = sub?.status === "canceled";
  const showResubscribeOffer = data.has_subscription && (terminal || canceled);

  // Header pill: the human plan name, never the raw token. A subscribed
  // account with no plan snapshot for some reason still reads as Plus - it
  // has an active paid subscription regardless.
  const planToken = plan?.plan ?? (data.has_subscription ? "plus_beta" : "free");
  const hero = heroStatus(data);

  return (
    <Stagger className="flex flex-col gap-6">
      <PageHeader
        title="Billing"
        icon={routeIcon("/billing")}
        sub="Your plan and subscription status. Paid plans are billed through Paddle, our merchant of record - no card details are ever entered in this portal."
        right={
          <div className="flex items-center gap-2">
            <Pill variant={isPlusPlan(planToken) ? "accent" : "neutral"}>
              {humanPlanLabel(planToken)}
            </Pill>
            {data.has_subscription && sub && (
              <Pill variant={statusMeta(sub.status).variant} icon={statusMeta(sub.status).icon}>
                {statusMeta(sub.status).label}
              </Pill>
            )}
          </div>
        }
      />

      {confirming && (
        <div className="rounded-3 border border-info/30 bg-bg-2 px-4 py-3 text-fg-2">
          <InlineLoading label="Confirming your subscription" />
        </div>
      )}
      {confirmed && (
        <div className="rounded-3 border border-success/30 bg-bg-2 px-4 py-3">
          <SuccessCheck label="Your subscription is confirmed" />
        </div>
      )}
      {confirmTimedOut && (
        <div className="rounded-3 border border-warn/30 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
          Your subscription has not shown up yet. This can take a few
          minutes while Paddle&apos;s confirmation lands - reload this page
          shortly, or check your email for a receipt from Paddle.
        </div>
      )}

      <Stagger className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HeroStat
          label="Current plan"
          icon={<PortalMetricIcon metric="plan" />}
          value={planDisplayValue(data)}
          sub={hero.text}
          variant={hero.variant}
        />
        <StatCard
          label="Daily"
          icon={<PortalMetricIcon metric="dailyAllowance" />}
          value={fmtInt(plan?.daily_cap)}
          sub="enrichment jobs per day"
        />
        <StatCard
          label="Monthly"
          icon={<PortalMetricIcon metric="monthlyAllowance" />}
          value={fmtInt(plan?.monthly_cap)}
          sub="enrichment jobs per month"
        />
        <StatCard
          label="Concurrent"
          icon={<PortalMetricIcon metric="concurrency" />}
          value={fmtInt(plan?.concurrency_cap)}
          sub="enrichment jobs at once"
        />
      </Stagger>
      {!plan && (
        <p className="text-[11px] text-fg-3">
          Plan allowances are not available right now.
        </p>
      )}

      <PlanComparison view={data} onConfirming={() => setConfirming(true)} />

      {data.has_subscription && sub && (
        <SubscriptionCard sub={sub} showResubscribeOffer={showResubscribeOffer} />
      )}
    </Stagger>
  );
}

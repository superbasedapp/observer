import { useCallback, useEffect, useRef, useState } from "react";
import { getBilling } from "../api";
import type { BillingView } from "../api";
import { PageHeader } from "@shared/primitives/PageHeader";
import { StatCard } from "@shared/primitives/StatCard";
import { HeroStat, type HeroStatVariant } from "@shared/primitives/HeroStat";
import { Pill } from "@shared/primitives/Pill";
import { fmtInt } from "@shared/lib/format";
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

// pollForSubscription polls getBilling every intervalMs, up to maxAttempts
// times, until has_subscription flips true (the Paddle webhook lands
// asynchronously after checkout completes) or the caller aborts.
function pollForSubscription(
  onUpdate: (v: BillingView) => void,
  onTimeout: () => void,
  live: { current: boolean },
) {
  const intervalMs = 3000;
  const maxAttempts = 40; // ~2 minutes
  let attempt = 0;
  const tick = () => {
    if (!live.current) return;
    attempt += 1;
    getBilling()
      .then((v) => {
        if (!live.current) return;
        onUpdate(v);
        if (v.has_subscription) {
          return;
        }
        if (attempt >= maxAttempts) {
          onTimeout();
          return;
        }
        window.setTimeout(tick, intervalMs);
      })
      .catch(() => {
        // A transient poll failure is not fatal - keep trying until the
        // attempt budget runs out.
        if (!live.current) return;
        if (attempt >= maxAttempts) {
          onTimeout();
          return;
        }
        window.setTimeout(tick, intervalMs);
      });
  };
  window.setTimeout(tick, intervalMs);
}

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
  switch (sub.status) {
    case "trialing":
      return {
        text: sub.trial_ends_at
          ? `You are in your free trial - it ends ${dateWithRelative(sub.trial_ends_at)}.`
          : "You are in your free trial.",
        variant: "accent",
      };
    case "active":
      return {
        text: sub.current_period_end
          ? `Active. Renews ${dateWithRelative(sub.current_period_end)}.`
          : "Active.",
        variant: "accent",
      };
    case "past_due":
      return {
        text:
          "Your last payment did not go through. Access continues for now, " +
          "but update your payment method in the Paddle billing portal to " +
          "avoid an interruption.",
        variant: "warn",
      };
    case "refunded":
      return {
        text: "This subscription was refunded. Paid access has been revoked.",
        variant: "danger",
      };
    case "charged_back":
      return {
        text:
          "A chargeback was recorded against this subscription. Paid access " +
          "has been revoked.",
        variant: "danger",
      };
    case "paused":
      return { text: "Subscription paused.", variant: "warn" };
    case "canceled": {
      const stillActive = isFuture(sub.current_period_end);
      const base = stillActive
        ? `Canceled - access continues until ${dateWithRelative(sub.current_period_end)}.`
        : "Canceled.";
      const canceledOn = sub.canceled_at
        ? ` (canceled on ${dateWithRelative(sub.canceled_at)})`
        : "";
      return { text: base + canceledOn, variant: "accent" };
    }
    default:
      // Defensive: an unknown status still gets an honest sentence rather
      // than silently rendering nothing.
      return { text: `${statusMeta(sub.status).label}.`, variant: "accent" };
  }
}

export function Billing() {
  const [data, setData] = useState<BillingView | null>(null);
  const [error, setError] = useState<string | null>(null);
  // "confirming" starts either from the Paddle checkout.completed event or
  // from landing back on ?checkout=success - both mean the purchase almost
  // certainly succeeded but the webhook that actually grants the plan lands
  // asynchronously, so the page polls rather than trusting the client-side
  // signal alone.
  const [confirming, setConfirming] = useState(false);
  const [confirmTimedOut, setConfirmTimedOut] = useState(false);
  const liveRef = useRef(true);

  const load = useCallback(() => {
    getBilling()
      .then((d) => {
        if (liveRef.current) setData(d);
      })
      .catch((err: unknown) => {
        if (liveRef.current)
          setError(err instanceof Error ? err.message : "failed to load");
      });
  }, []);

  useEffect(() => {
    liveRef.current = true;
    load();
    return () => {
      liveRef.current = false;
    };
  }, [load]);

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

  useEffect(() => {
    if (!confirming) return;
    setConfirmTimedOut(false);
    const live = liveRef;
    pollForSubscription(
      (v) => {
        setData(v);
        if (v.has_subscription) setConfirming(false);
      },
      () => {
        setConfirming(false);
        setConfirmTimedOut(true);
      },
      live,
    );
  }, [confirming]);

  if (error) {
    return (
      <div className="rounded-3 border border-danger/30 bg-bg-2 px-4 py-3 text-[13px] text-danger">
        Could not load billing: {error}
      </div>
    );
  }
  if (!data) {
    return <div className="text-[13px] text-fg-3">Loading billing...</div>;
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
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Billing"
        sub="Your plan and subscription status. Paid plans are billed through Paddle, our merchant of record - no card details are ever entered in this portal."
        right={
          <div className="flex items-center gap-2">
            <Pill variant={isPlusPlan(planToken) ? "accent" : "neutral"}>
              {humanPlanLabel(planToken)}
            </Pill>
            {data.has_subscription && sub && (
              <Pill variant={statusMeta(sub.status).variant}>
                {statusMeta(sub.status).label}
              </Pill>
            )}
          </div>
        }
      />

      {confirming && (
        <div className="rounded-3 border border-info/30 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
          Confirming your subscription...
        </div>
      )}
      {confirmTimedOut && (
        <div className="rounded-3 border border-warn/30 bg-bg-2 px-4 py-3 text-[12px] text-fg-2">
          Your subscription has not shown up yet. This can take a few
          minutes while Paddle&apos;s confirmation lands - reload this page
          shortly, or check your email for a receipt from Paddle.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HeroStat
          label="Current plan"
          value={planDisplayValue(data)}
          sub={hero.text}
          variant={hero.variant}
        />
        <StatCard
          label="Daily"
          value={fmtInt(plan?.daily_cap)}
          sub="enrichment jobs per day"
        />
        <StatCard
          label="Monthly"
          value={fmtInt(plan?.monthly_cap)}
          sub="enrichment jobs per month"
        />
        <StatCard
          label="Concurrent"
          value={fmtInt(plan?.concurrency_cap)}
          sub="enrichment jobs at once"
        />
      </div>
      {!plan && (
        <p className="text-[11px] text-fg-3">
          Plan allowances are not available right now.
        </p>
      )}

      <PlanComparison view={data} onConfirming={() => setConfirming(true)} />

      {data.has_subscription && sub && (
        <SubscriptionCard sub={sub} showResubscribeOffer={showResubscribeOffer} />
      )}
    </div>
  );
}

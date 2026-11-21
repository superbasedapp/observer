import { useState } from "react";
import {
  ApiError,
  createCheckout,
} from "../../api";
import type {
  BillingView,
  CheckoutIntent,
  CheckoutPrice,
} from "../../api";
import { ensurePaddleReady, loadPaddleJs, paddleFailureText } from "./paddleCheckout";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { Pill } from "@shared/primitives/Pill";
import {
  PLAN_COMPARISON_FOOTNOTE,
  PLAN_COMPARISON_ROWS,
  PLAN_FEATURE_CELL,
  PLAN_FEATURE_TONE,
  isPlusPlan,
} from "./util";
import { Button } from "@shared/primitives/Button";
import { Card } from "@shared/primitives/Card";
import { Icon } from "@shared/primitives/Icon";
import { PORTAL_METRIC_ICONS } from "../../lib/metricIcons";
import { vocabIcon } from "@shared/lib/vocabIcons";
import { Check, Sparkles } from "lucide-react";

// PlanComparison renders the "Plans" row: two side-by-side cards (Free /
// Plus) sharing the design-system card surface, each a proper definition
// list of the same comparison rows so the values line up. The Plus card
// additionally carries whichever of the three states applies: the checkout
// offer (consent checkbox + Upgrade/Subscribe-again button), an honest
// "Current plan" state when the reader is already on a live Plus
// subscription, or the honest unavailable copy when this deployment has no
// checkout catalogue configured.
//
// Showcase (design-kit WS10): the Plus card is the featured card (accent
// border, soft glow, a "Recommended" tag unless it is already the reader's
// plan); a yes / no comparison cell draws its planFeature glyph (Check /
// Minus) beside the words; "Current plan" is a status, never a disabled
// primary button (Button.tsx: a disabled button reads as "not allowed", and
// this is not an action at all).

// PriceDisplay renders one purchasable price plus its trial line: the free
// trial when this account would get one, or a plain "billed from the first
// day" once it has had its trial (the server then opens a trial-less price).
function PriceDisplay({
  price,
  trialDays,
  trialUsed,
}: {
  price: CheckoutPrice;
  trialDays: number;
  trialUsed?: boolean;
}) {
  return (
    <div className="mt-3 flex items-baseline gap-1.5">
      <span className="text-[26px] font-bold leading-none tracking-[-0.02em] text-fg-0">
        {price.display || price.plan_name}
      </span>
      {price.interval && !price.display.includes("/") && (
        <span className="text-[12px] text-fg-3">/ {price.interval}</span>
      )}
      {trialDays > 0 && (
        <span className="ml-1 text-[11px] text-fg-3">
          {trialDays}-day free trial
        </span>
      )}
      {trialDays <= 0 && trialUsed && (
        <span className="ml-1 text-[11px] text-fg-3">
          free trial used, billed from the first day
        </span>
      )}
    </div>
  );
}

const rowsClass = "mt-3 divide-y divide-line-1 text-[12px]";

// PlanCell renders one comparison value: a yes / no cell (PLAN_FEATURE_CELL)
// gets its planFeature glyph beside the unchanged words; any other value
// (a count, a window) stays plain text.
function PlanCell({ text }: { text: string }) {
  const feature = PLAN_FEATURE_CELL[text];
  if (!feature) return <>{text}</>;
  return (
    <span className="inline-flex items-center justify-end gap-1">
      <Icon
        icon={vocabIcon("planFeature", feature)}
        size="xs"
        className={`shrink-0 ${PLAN_FEATURE_TONE[feature]}`}
      />
      {text}
    </span>
  );
}

function ComparisonRows({ pick }: { pick: "free" | "plus" }) {
  return (
    <DefinitionList className={rowsClass}>
      {PLAN_COMPARISON_ROWS.map((row) => (
        <DefinitionRow key={row.label} label={row.label} value={<PlanCell text={row[pick]} />} />
      ))}
    </DefinitionList>
  );
}

export function PlanComparison({
  view,
  onConfirming,
}: {
  view: BillingView;
  onConfirming: () => void;
}) {
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const plan = view.plan;
  const sub = view.subscription;
  const checkout = view.checkout;
  const price = checkout.prices[0];

  // The current plan token drives which card gets the "Your plan" badge. A
  // missing plan snapshot leaves this unknown rather than guessing free.
  // A subscription billed through the personal dashboard (after the move
  // onto it) is the paid plan even though the account snapshot is absent.
  const viaPersonalOrg = view.paid_through_personal_org === true;
  const currentIsPlus = viaPersonalOrg ? true : plan ? isPlusPlan(plan.plan) : null;

  const terminal = sub?.status === "refunded" || sub?.status === "charged_back";
  const canceled = sub?.status === "canceled";
  // Both a terminal (refunded/charged-back) row and a canceled one are
  // re-purchasable - Paddle has no "resume" for a canceled subscription, so
  // the only honest path back to paid access is a fresh checkout.
  const resubscribe = view.has_subscription && (terminal || canceled);
  const onLivePlus = currentIsPlus === true && view.has_subscription && !resubscribe;

  async function onUpgrade() {
    if (!price) return;
    setError(null);
    setBusy(true);

    // The three failure points below get distinct copy on purpose: a
    // rejected checkout intent (incl. the server's 409 when a live
    // subscription already exists), a failed Paddle.js load, and a failed
    // checkout-overlay open are different problems with different next
    // steps for the developer.
    let intent: CheckoutIntent;
    try {
      intent = await createCheckout(price.price_id);
    } catch (err) {
      if (err instanceof ApiError && err.code === "already_subscribed") {
        setError(
          "You already have an active subscription - refresh this page to see it.",
        );
      } else {
        setError(
          err instanceof Error ? err.message : "could not start checkout",
        );
      }
      setBusy(false);
      return;
    }

    try {
      await loadPaddleJs();
    } catch {
      setError(
        "Could not load Paddle's checkout script. Check your connection and try again.",
      );
      setBusy(false);
      return;
    }

    try {
      const paddle = ensurePaddleReady(checkout, (event) => {
        if (event.name === "checkout.completed") {
          onConfirming();
        } else if (event.name === "checkout.failed") {
          // Paddle failures arrive asynchronously, after Checkout.open has
          // returned. Show them on our page so support remains reachable even
          // if the vendor's iframe cannot navigate to its mail handler.
          setError(paddleFailureText(event));
          window.Paddle?.Checkout.close?.();
        }
      });
      paddle.Checkout.open({
        items: [{ priceId: intent.price_id, quantity: intent.quantity ?? 1 }],
        customData: intent.custom_data,
        settings: {
          displayMode: "overlay",
          successUrl:
            window.location.origin + "/portal/billing?checkout=success",
        },
      });
    } catch (err) {
      setError(
        "Could not open the checkout overlay" +
          (err instanceof Error ? ": " + err.message : "") +
          ". Try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2 className="flex items-center gap-1.5 text-[13px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        <Icon icon={PORTAL_METRIC_ICONS.plan} size="sm" className="shrink-0" />
        Plans
      </h2>
      <div className="mt-2 grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card>
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-[14px] font-semibold text-fg-0">Free</h3>
            {currentIsPlus === false && <Pill variant="accent">Your plan</Pill>}
          </div>
          <p className="mt-1 text-[11px] text-fg-3">
            Runs at no cost, forever.
          </p>
          <ComparisonRows pick="free" />
        </Card>

        <Card tone="featured">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-[14px] font-semibold text-fg-0">Personal Pro</h3>
            {currentIsPlus === true ? (
              <Pill variant="accent">Your plan</Pill>
            ) : (
              <Pill variant="accent" icon={Sparkles}>Recommended</Pill>
            )}
          </div>
          {checkout.available && price ? (
            <PriceDisplay
              price={price}
              trialDays={checkout.trial_days}
              trialUsed={checkout.trial_used}
            />
          ) : (
            <p className="mt-1 text-[11px] text-fg-3">
              A paid plan billed through Paddle.
            </p>
          )}
          <ComparisonRows pick="plus" />

          <div className="mt-4 border-t border-line-1 pt-4">
            {onLivePlus ? (
              <div className="flex justify-center">
                <Pill variant="success" icon={Check}>
                  Current plan
                </Pill>
              </div>
            ) : !checkout.available || !price ? (
              <p className="text-[11px] text-fg-3">
                Checkout is not configured for this deployment yet, so there
                is nothing to click here today.
              </p>
            ) : (
              <>
                <p className="text-[11px] text-fg-3">
                  {resubscribe
                    ? "Your paid access has ended. Subscribe again to raise your daily, monthly and concurrent enrichment allowances. Checkout runs in a Paddle-hosted overlay - card details are entered there, never in this portal."
                    : "Checkout runs in a Paddle-hosted overlay - card details are entered there, never in this portal."}
                </p>
                {error && (
                  <div role="alert" className="mt-2 rounded-2 border border-danger/30 bg-danger-soft px-3 py-2 text-[11px] text-danger">
                    <p>{error}</p>
                    <a href="mailto:help@paddle.com" target="_blank" rel="noopener" className="mt-1 inline-block underline">
                      Email Paddle support: help@paddle.com
                    </a>
                  </div>
                )}
                <label className="mt-3 flex items-start gap-2 text-[11px] leading-snug text-fg-3">
                  <input
                    type="checkbox"
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-accent"
                    checked={accepted}
                    onChange={(e) => setAccepted(e.target.checked)}
                    disabled={busy}
                  />
                  <span>
                    By subscribing you agree to the{" "}
                    <a
                      href="https://superbased.app/terms"
                      target="_blank"
                      rel="noopener"
                      className="text-accent"
                    >
                      Terms
                    </a>
                    ,{" "}
                    <a
                      href="https://superbased.app/privacy"
                      target="_blank"
                      rel="noopener"
                      className="text-accent"
                    >
                      Privacy Policy
                    </a>{" "}
                    and{" "}
                    <a
                      href="https://superbased.app/refund-policy"
                      target="_blank"
                      rel="noopener"
                      className="text-accent"
                    >
                      Refund Policy
                    </a>
                  </span>
                </label>
                <p className="mt-2 text-[11px] text-fg-3">
                  Paddle&apos;s own checkout screen will ask you to confirm
                  this again before you pay.
                </p>
                <Button
                  type="button"
                  variant="primary"
                  size="sm"
                  className="mt-3 w-full"
                  disabled={!accepted}
                  loading={busy}
                  onClick={onUpgrade}
                >
                  {busy
                    ? "Opening checkout"
                    : resubscribe
                      ? "Subscribe again"
                      : "Upgrade"}
                </Button>
              </>
            )}
          </div>
        </Card>
      </div>
      <p className="mt-3 text-caption text-fg-3">{PLAN_COMPARISON_FOOTNOTE}</p>
    </section>
  );
}

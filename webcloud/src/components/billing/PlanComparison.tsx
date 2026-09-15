import { useState } from "react";
import {
  ApiError,
  createCheckout,
} from "../../api";
import type {
  BillingView,
  CheckoutCatalog,
  CheckoutIntent,
  CheckoutPrice,
} from "../../api";
import { DefinitionList, DefinitionRow } from "@shared/primitives/DefinitionList";
import { Pill } from "@shared/primitives/Pill";
import {
  PLAN_COMPARISON_FOOTNOTE,
  PLAN_COMPARISON_ROWS,
  isPlusPlan,
} from "./util";

// PlanComparison renders the "Plans" row: two side-by-side cards (Free /
// Plus) sharing the design-system card surface, each a proper definition
// list of the same comparison rows so the values line up. The Plus card
// additionally carries whichever of the three states applies: the checkout
// offer (consent checkbox + Upgrade/Subscribe-again button), an honest
// "Current plan" state when the reader is already on a live Plus
// subscription, or the honest unavailable copy when this deployment has no
// checkout catalogue configured.

const PADDLE_JS_SRC = "https://cdn.paddle.com/paddle/v2/paddle.js";

// loadPaddleJs loads the Paddle.js CDN script exactly once (module-scope
// promise), never as an npm dependency (operator ruling: no Paddle SDK
// bundled - loaded only on this page, at the moment of checkout). Every
// caller shares the same in-flight/resolved promise, so a second Upgrade
// click does not inject a second <script> tag.
let paddleJsPromise: Promise<void> | null = null;
function loadPaddleJs(): Promise<void> {
  if (window.Paddle) {
    return Promise.resolve();
  }
  if (paddleJsPromise) {
    return paddleJsPromise;
  }
  paddleJsPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = PADDLE_JS_SRC;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => {
      paddleJsPromise = null;
      reject(new Error("could not load Paddle.js"));
    };
    document.head.appendChild(script);
  });
  return paddleJsPromise;
}

// paddleInitialized / paddleInitKey track whether Paddle.Initialize() has
// already run this page load. Paddle documents that Initialize throws on a
// second call, so every checkout open after the first must reuse the same
// instance and, if the browser's Paddle.js build supports it, push a fresh
// eventCallback through Paddle.Update instead. The key (client token +
// environment) is recorded for diagnostics; once initialized, later opens
// always go through Update rather than attempting a second Initialize even
// if the key were somehow to change.
let paddleInitialized = false;
let paddleInitKey = "";

function paddleKey(checkout: CheckoutCatalog): string {
  return checkout.environment + "::" + checkout.client_token;
}

// ensurePaddleReady initializes Paddle.js exactly once per page load and
// wires the given eventCallback - via Initialize the first time, via Update
// on every later call - then hands back the non-null global so the caller
// never needs its own non-null assertion. Throws if window.Paddle is not
// present (the caller is expected to have awaited loadPaddleJs() first).
function ensurePaddleReady(
  checkout: CheckoutCatalog,
  eventCallback: (event: PaddleEventData) => void,
): PaddleGlobal {
  const paddle = window.Paddle;
  if (!paddle) {
    throw new Error("Paddle.js failed to load");
  }
  if (paddleInitialized) {
    if (paddleInitKey !== paddleKey(checkout) && import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.warn(
        "Paddle already initialized with a different client token or " +
          "environment; Paddle.js only supports one Initialize call per " +
          "page, so the original one stays in effect.",
      );
    }
    paddle.Update?.({ eventCallback });
    return paddle;
  }
  if (checkout.environment === "sandbox") {
    paddle.Environment.set("sandbox");
  }
  paddle.Initialize({ token: checkout.client_token, eventCallback });
  paddleInitialized = true;
  paddleInitKey = paddleKey(checkout);
  return paddle;
}

// PriceDisplay renders one purchasable price plus its trial line, if any.
function PriceDisplay({
  price,
  trialDays,
}: {
  price: CheckoutPrice;
  trialDays: number;
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
    </div>
  );
}

const cardClass = "bg-bg-2 border border-line-1 rounded-xl p-5";
const rowsClass = "mt-3 divide-y divide-line-1 text-[12px]";

function ComparisonRows({ pick }: { pick: "free" | "plus" }) {
  return (
    <DefinitionList className={rowsClass}>
      {PLAN_COMPARISON_ROWS.map((row) => (
        <DefinitionRow key={row.label} label={row.label} value={row[pick]} />
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
  const currentIsPlus = plan ? isPlusPlan(plan.plan) : null;

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
          const detail = event.error && typeof event.error === "object"
            ? (event.error as Record<string, unknown>).detail
            : undefined;
          const reference = typeof detail === "string" ? detail.match(/\bE-\d{3,4}\b/)?.[0] : undefined;
          setError("Paddle could not complete checkout." + (reference ? ` Reference: ${reference}.` : "") +
            " Please try again later or contact Paddle support below.");
          window.Paddle?.Checkout.close?.();
        }
      });
      paddle.Checkout.open({
        items: [{ priceId: intent.price_id, quantity: 1 }],
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
      <h2 className="text-[13px] font-semibold uppercase tracking-[0.06em] text-fg-3">
        Plans
      </h2>
      <div className="mt-2 grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className={cardClass}>
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-[14px] font-semibold text-fg-0">Free</h3>
            {currentIsPlus === false && <Pill variant="accent">Your plan</Pill>}
          </div>
          <p className="mt-1 text-[11px] text-fg-3">
            Runs at no cost, forever.
          </p>
          <ComparisonRows pick="free" />
        </div>

        <div className={cardClass}>
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-[14px] font-semibold text-fg-0">Plus</h3>
            {currentIsPlus === true && <Pill variant="accent">Your plan</Pill>}
          </div>
          {checkout.available && price ? (
            <PriceDisplay price={price} trialDays={checkout.trial_days} />
          ) : (
            <p className="mt-1 text-[11px] text-fg-3">
              A paid plan billed through Paddle.
            </p>
          )}
          <ComparisonRows pick="plus" />

          <div className="mt-4 border-t border-line-1 pt-4">
            {onLivePlus ? (
              <button
                type="button"
                className="btn btn-primary w-full"
                disabled
              >
                Current plan
              </button>
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
                <button
                  type="button"
                  className="btn btn-primary mt-3 w-full"
                  disabled={!accepted || busy}
                  onClick={onUpgrade}
                >
                  {busy
                    ? "Opening checkout..."
                    : resubscribe
                      ? "Subscribe again"
                      : "Upgrade"}
                </button>
              </>
            )}
          </div>
        </div>
      </div>
      <p className="mt-3 text-[11px] text-fg-3">{PLAN_COMPARISON_FOOTNOTE}</p>
    </section>
  );
}

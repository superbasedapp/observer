// paddleCheckout - the one Paddle.js owner of the portal: loading the CDN
// script once, initializing it once per page load, and opening a checkout
// overlay. Both checkouts use it: the personal Billing page's Personal Pro checkout
// (PlanComparison.tsx) and an org's Team checkout (OrgBillingCard.tsx), so
// Paddle's "Initialize only once" rule holds across both.

import type { CheckoutCatalog } from "../../api";

const PADDLE_JS_SRC = "https://cdn.paddle.com/paddle/v2/paddle.js";

// loadPaddleJs loads the Paddle.js CDN script exactly once (module-scope
// promise), never as an npm dependency (operator ruling: no Paddle SDK
// bundled - loaded only at the moment of checkout). Every caller shares the
// same in-flight/resolved promise, so a second click does not inject a second
// <script> tag.
let paddleJsPromise: Promise<void> | null = null;
export function loadPaddleJs(): Promise<void> {
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
export function ensurePaddleReady(
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

/** paddleFailureText is the one sentence for an asynchronous
 * checkout.failed event, with Paddle's E-nnn reference when it sent one. */
export function paddleFailureText(event: PaddleEventData): string {
  const detail =
    event.error && typeof event.error === "object"
      ? (event.error as Record<string, unknown>).detail
      : undefined;
  const reference = typeof detail === "string" ? detail.match(/\bE-\d{3,4}\b/)?.[0] : undefined;
  return (
    "Paddle could not complete checkout." +
    (reference ? ` Reference: ${reference}.` : "") +
    " Please try again later or contact Paddle support below."
  );
}

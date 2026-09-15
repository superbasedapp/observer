// paddle.d.ts — the minimal window.Paddle shape the Billing page's checkout
// flow needs. Paddle.js (https://cdn.paddle.com/paddle/v2/paddle.js) is
// loaded dynamically at runtime from Billing.tsx, never as an npm dependency
// (operator ruling: no Paddle SDK bundled — it is loaded only on the Billing
// page, at the moment of checkout). This declares just enough of the global
// to typecheck that call site; see
// https://developer.paddle.com/paddlejs/overview and
// https://developer.paddle.com/paddlejs/methods/paddle-checkout-open for the
// full API.

interface PaddleCheckoutOpenItem {
  priceId: string;
  quantity: number;
}

interface PaddleCheckoutOpenSettings {
  displayMode?: "overlay" | "inline";
  successUrl?: string;
}

interface PaddleCheckoutOpenOptions {
  items: PaddleCheckoutOpenItem[];
  customData?: Record<string, string>;
  settings?: PaddleCheckoutOpenSettings;
}

interface PaddleEventData {
  name?: string;
  [key: string]: unknown;
}

interface PaddleInitializeOptions {
  token: string;
  eventCallback?: (event: PaddleEventData) => void;
}

interface PaddleUpdateOptions {
  eventCallback?: (event: PaddleEventData) => void;
}

interface PaddleGlobal {
  Environment: {
    set: (env: "sandbox" | "production") => void;
  };
  Initialize: (options: PaddleInitializeOptions) => void;
  // Update changes options (notably eventCallback) on an already-initialized
  // Paddle instance. Paddle.Initialize() throws if called a second time, so
  // Billing.tsx calls Initialize exactly once per page load and reaches for
  // Update on every later checkout open. Declared optional since only newer
  // Paddle.js builds ship it - the call site feature-detects before using it.
  Update?: (options: PaddleUpdateOptions) => void;
  Checkout: {
    open: (options: PaddleCheckoutOpenOptions) => void;
    close?: () => void;
  };
}

interface Window {
  Paddle?: PaddleGlobal;
}

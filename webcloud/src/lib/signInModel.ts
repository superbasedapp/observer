// signInModel - the pure rules of the console's signed-out entry (hosted
// sign-in fix, lane A): the sign-in and the sign-up ("Create an account")
// variants of the one page, the server start link each sends the browser to,
// and the copy. No React, no fetch: SignIn.tsx renders these and
// signInModel.test.ts pins them.

import { safeReturnTo } from "./connectModel.ts";

/** SignInVariant is which entry the page is: "/" (sign in) or "/sign-up"
 * (create an account). */
export type SignInVariant = "sign-in" | "sign-up";

/** WORKOS_START_PATH is the server's rate-limited sign-in start
 * (internal/cloudserver/api/portalauth.go handleWorkOSStart). The path keeps
 * the broker name; nothing a person reads does. */
export const WORKOS_START_PATH = "/portal/auth/workos/start";

/** SIGN_UP_ROUTE is the router path of the create-an-account entry (under the
 * /portal basename: https://cloud.superbased.app/portal/sign-up). */
export const SIGN_UP_ROUTE = "/sign-up";

/** START_SCREEN is the server start's screen_hint per variant: a sign-up
 * opens AuthKit's sign-up screen; a sign-in sends no hint (the default
 * screen). The server accepts exactly these values (parseScreenHint). */
const START_SCREEN: Readonly<Record<SignInVariant, string | null>> = {
  "sign-in": null,
  "sign-up": "sign-up",
};

/** startUrl is the server start link for a variant, carrying return_to when
 * it is a safe /portal/ path (connectModel.safeReturnTo; the server checks it
 * again). */
export function startUrl(variant: SignInVariant, returnTo: string | null): string {
  const q = new URLSearchParams();
  const screen = START_SCREEN[variant];
  if (screen) q.set("screen_hint", screen);
  const back = safeReturnTo(returnTo);
  if (back) q.set("return_to", back);
  const qs = q.toString();
  return qs ? `${WORKOS_START_PATH}?${qs}` : WORKOS_START_PATH;
}

/** VariantText is one variant's copy. */
export interface VariantText {
  title: string;
  lead: string;
  /** primary is the main button, which starts this variant. */
  primary: string;
  /** busy is the main button's label while the browser leaves for sign-in. */
  busy: string;
  /** otherPrompt and otherAction offer the other variant. */
  otherPrompt: string;
  otherAction: string;
  sendsNothing: string;
  /** provider says where the next page is: the sign-in service's own page,
   * which carries little of superbased's look. */
  provider: string;
}

const SENDS_NOTHING = "Signing in alone sends nothing from your machine.";

/** PROVIDER_NAME is the sign-in service whose pages the buttons open. It is
 * named on purpose (operator, 2026-11-18): those pages are on a WorkOS
 * address with little of superbased's look, and a person told so beforehand
 * does not take them for a glitch or a phishing page. */
export const PROVIDER_NAME = "WorkOS";
const LEAD =
  "An account gives you one dashboard across your machines, teams, and AI session titles (opt-in).";

/** SIGN_IN_COPY is each variant's copy (index.html carries the sign-in lines
 * for a browser with JavaScript off). */
export const SIGN_IN_COPY: Readonly<Record<SignInVariant, VariantText>> = {
  "sign-in": {
    title: "Sign in to superbased",
    lead: LEAD,
    primary: "Continue with your superbased account",
    busy: "Opening sign-in",
    otherPrompt: "New to superbased?",
    otherAction: "Create an account",
    sendsNothing: SENDS_NOTHING,
    provider: `Sign-in opens on ${PROVIDER_NAME}, the sign-in service superbased uses, and brings you back here.`,
  },
  "sign-up": {
    title: "Create your superbased account",
    lead: LEAD,
    primary: "Create an account",
    busy: "Opening sign-up",
    otherPrompt: "Already have an account?",
    otherAction: "Sign in",
    sendsNothing: SENDS_NOTHING,
    provider: `Your account is created on ${PROVIDER_NAME}, the sign-in service superbased uses, and you come straight back here.`,
  },
};

/** otherVariant is the variant the page's second action starts. */
export function otherVariant(v: SignInVariant): SignInVariant {
  return v === "sign-in" ? "sign-up" : "sign-in";
}

/** autoStarts says whether the page leaves for the provider by itself once
 * it knows browser sign-in is on: only the create-an-account entry does (a
 * "Get started" link should land on the sign-up screen, not on a button).
 * It counts down AUTO_START_SECONDS first, saying where it is going, with
 * "Continue now" and "Stay on this page"; an instant hand-off flashed the
 * console and then a page without superbased's name, which read as a glitch
 * (operator, 2026-11-18). The page leaves with location.replace, so Back
 * from the provider returns to the page before it, never to a page that
 * leaves again. */
export function autoStarts(v: SignInVariant): boolean {
  return v === "sign-up";
}

/** AUTO_START_SECONDS is the create-an-account entry's countdown before it
 * leaves for the sign-up page by itself (autoStarts). */
export const AUTO_START_SECONDS = 10;

/** countdownText is the countdown's line for the seconds left: whole
 * seconds, never below zero, "1 second" singular. */
export function countdownText(secondsLeft: number): string {
  const s = Math.max(0, Math.ceil(secondsLeft));
  if (s === 0) return `Opening the ${PROVIDER_NAME} sign-up page now`;
  return `Opening the ${PROVIDER_NAME} sign-up page in ${s} ${s === 1 ? "second" : "seconds"}`;
}

/** COUNTDOWN_ACTIONS are the countdown's two buttons. */
export const COUNTDOWN_ACTIONS = {
  now: "Continue now",
  stay: "Stay on this page",
} as const;

/** SIGN_IN_ERROR_PARAM is the query parameter the server's callback sends a
 * browser back with when a sign-in cannot finish but signing in again will
 * (internal/cloudserver/api/portalauth.go callbackRefuse, L-142). */
export const SIGN_IN_ERROR_PARAM = "signin_error";

/** SignInErrorNotice is what the sign-in page says about a returned code. */
export interface SignInErrorNotice {
  title: string;
  body: string;
}

const START_AGAIN: SignInErrorNotice = {
  title: "Sign in again.",
  body:
    "That sign-in page was open too long, or was opened in another tab or browser. If you just created your account, it is ready: sign in to continue.",
};

/** SIGN_IN_ERROR_NOTICES maps each code the callback sends back to its
 * notice; a code not in the table shows nothing. */
const SIGN_IN_ERROR_NOTICES: Readonly<Record<string, SignInErrorNotice>> = {
  transaction_missing: START_AGAIN,
  state_mismatch: START_AGAIN,
  transaction_invalid: START_AGAIN,
  code_rejected: START_AGAIN,
  provider_error: {
    title: "Sign-in was cancelled.",
    body: "Nothing was changed. You can sign in again when you are ready.",
  },
};

/** signInErrorNotice is the notice for the page's query string, or null. */
export function signInErrorNotice(search: string): SignInErrorNotice | null {
  const code = new URLSearchParams(search).get(SIGN_IN_ERROR_PARAM);
  if (!code || !Object.prototype.hasOwnProperty.call(SIGN_IN_ERROR_NOTICES, code)) return null;
  return SIGN_IN_ERROR_NOTICES[code];
}

// signInModel.test.ts pins the console's signed-out entry (hosted sign-in
// fix, lane A): the start link per variant (screen_hint only for a sign-up,
// return_to only when safe), the copy, and which entry leaves by itself.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AUTO_START_SECONDS,
  COUNTDOWN_ACTIONS,
  PROVIDER_NAME,
  SIGN_IN_COPY,
  WORKOS_START_PATH,
  autoStarts,
  countdownText,
  otherVariant,
  signInErrorNotice,
  startUrl,
  type SignInVariant,
} from "./signInModel.ts";

// [variant, return_to, want]
const START_CASES: Array<[SignInVariant, string | null, string]> = [
  ["sign-in", null, WORKOS_START_PATH],
  ["sign-up", null, `${WORKOS_START_PATH}?screen_hint=sign-up`],
  ["sign-in", "/portal/orgs/new", `${WORKOS_START_PATH}?return_to=%2Fportal%2Forgs%2Fnew`],
  ["sign-up", "/portal/orgs/new", `${WORKOS_START_PATH}?screen_hint=sign-up&return_to=%2Fportal%2Forgs%2Fnew`],
  ["sign-up", "/portal/connect/abc", `${WORKOS_START_PATH}?screen_hint=sign-up&return_to=%2Fportal%2Fconnect%2Fabc`],
  // An unsafe return path is dropped, never forwarded.
  ["sign-up", "https://evil.example/", `${WORKOS_START_PATH}?screen_hint=sign-up`],
  ["sign-in", "/portal/../x", WORKOS_START_PATH],
  ["sign-in", "/portal/orgs?x=1", WORKOS_START_PATH],
];
for (const [variant, back, want] of START_CASES) {
  test(`startUrl(${variant}, ${back}) -> ${want}`, () => {
    assert.equal(startUrl(variant, back), want);
  });
}

test("screen_hint is sent only for a sign-up", () => {
  for (const v of ["sign-in", "sign-up"] as const) {
    const q = new URLSearchParams(startUrl(v, null).split("?")[1] ?? "");
    assert.equal(q.get("screen_hint"), v === "sign-up" ? "sign-up" : null);
  }
});

test("each variant offers the other, and the sign-in page shows Create an account", () => {
  assert.equal(otherVariant("sign-in"), "sign-up");
  assert.equal(otherVariant("sign-up"), "sign-in");
  assert.equal(SIGN_IN_COPY["sign-in"].otherAction, "Create an account");
  assert.equal(SIGN_IN_COPY["sign-up"].primary, "Create an account");
  assert.equal(SIGN_IN_COPY["sign-in"].title, "Sign in to superbased");
  // The retired invisible line is gone.
  for (const v of Object.values(SIGN_IN_COPY)) {
    assert.doesNotMatch(JSON.stringify(v), /The same button creates your account/);
  }
});

test("only the create-an-account entry leaves for the provider by itself", () => {
  assert.equal(autoStarts("sign-up"), true);
  assert.equal(autoStarts("sign-in"), false);
});

test("the sign-up entry counts down ten seconds, naming where it goes", () => {
  assert.equal(AUTO_START_SECONDS, 10);
  assert.equal(countdownText(10), "Opening the WorkOS sign-up page in 10 seconds");
  assert.equal(countdownText(1), "Opening the WorkOS sign-up page in 1 second");
  assert.equal(countdownText(0.4), "Opening the WorkOS sign-up page in 1 second");
  assert.equal(countdownText(0), "Opening the WorkOS sign-up page now");
  assert.equal(countdownText(-3), "Opening the WorkOS sign-up page now");
  assert.equal(COUNTDOWN_ACTIONS.now, "Continue now");
  assert.equal(COUNTDOWN_ACTIONS.stay, "Stay on this page");
});

test("both entries say the next page is the sign-in service's", () => {
  for (const v of Object.values(SIGN_IN_COPY)) {
    assert.match(v.provider, new RegExp(PROVIDER_NAME));
    assert.match(v.provider, /back here/);
  }
});

test("a code the callback sends back explains itself; anything else shows nothing", () => {
  for (const code of ["transaction_missing", "state_mismatch", "transaction_invalid", "code_rejected"]) {
    const n = signInErrorNotice(`?signin_error=${code}`);
    assert.equal(n?.title, "Sign in again.");
    assert.match(n?.body ?? "", /your account is ready|it is ready/);
  }
  assert.equal(signInErrorNotice("?signin_error=provider_error")?.title, "Sign-in was cancelled.");
  assert.equal(signInErrorNotice(""), null);
  assert.equal(signInErrorNotice("?signin_error=internal"), null);
  assert.equal(signInErrorNotice("?signin_error=toString"), null);
  assert.equal(signInErrorNotice("?return_to=%2Fportal%2Fx"), null);
});

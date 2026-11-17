import { test } from "node:test";
import assert from "node:assert/strict";
import { b64urlToBytes, bytesToB64url, safeNext } from "./webauthn.ts";

test("base64url round trip", () => {
  for (const n of [0, 1, 2, 3, 31, 32, 33]) {
    const b = new Uint8Array(n).map((_, i) => (i * 37 + 251) & 255);
    const s = bytesToB64url(b);
    assert.doesNotMatch(s, /[+/=]/);
    assert.deepEqual(Array.from(b64urlToBytes(s)), Array.from(b));
  }
});

test("safeNext keeps the destination same-origin", () => {
  const ok = ["/oauth2/authorize?client_id=org%3Ax&state=s", "/portal/", "/portal/orgs/abc"];
  for (const v of ok) assert.equal(safeNext(v), v);
  const bad = [
    "",
    null,
    "https://evil.example/",
    "//evil.example/x",
    "/\\evil",
    "javascript:alert(1)",
    "/portal/../admin",
    "/staff/api/log",
    "/oauth2/token",
    "/portal/ x",
  ];
  for (const v of bad) assert.equal(safeNext(v as string), "/portal/", String(v));
});

// Pins the Policies samples (pages/policies/samples.ts) to the denied-topics
// matching rule (UI review U-17): the template ships singular terms, and the
// Test tab has a sample each key term catches.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DENIED_TOPICS, TEST_SAMPLES } from "../pages/policies/samples.ts";

// words mirrors the node matcher's split (admission prefilter.go
// stemmedWords) closely enough for this pin: lowercase words, an apostrophe
// or punctuation splits, a trailing plural s is dropped.
function words(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .map((w) => (w.length > 3 && w.endsWith("s") && !w.endsWith("ss") ? w.slice(0, -1) : w));
}

function hasRun(hay: string[], needle: string[]): boolean {
  for (let i = 0; i + needle.length <= hay.length; i++) {
    if (needle.every((w, j) => hay[i + j] === w)) return true;
  }
  return false;
}

test("the Denied topics template ships singular terms", () => {
  assert.ok(DENIED_TOPICS.includes("competitor"));
  assert.ok(!DENIED_TOPICS.includes("competitors"));
});

test("a Test sample exercises the competitor and legal advice terms", () => {
  for (const term of ["competitor", "legal advice"]) {
    assert.ok(DENIED_TOPICS.includes(term), `${term} is a template term`);
    assert.ok(
      TEST_SAMPLES.some((s) => hasRun(words(s), words(term))),
      `no Test sample exercises "${term}"`,
    );
  }
});

test("the samples keep an allowed request and a jailbreak", () => {
  assert.ok(TEST_SAMPLES.some((s) => /poem/i.test(s)));
  assert.ok(TEST_SAMPLES.some((s) => /ignore all previous instructions/i.test(s)));
});

// Pins the pure store behind the shared confirmDialog
// (shared/primitives/confirmDialogModel.ts): one answer per request, a queue
// that never replaces an open question, ids that cannot answer the next one,
// and the body-to-paragraphs rule.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  answerConfirm,
  confirmDialog,
  confirmParagraphs,
  currentConfirm,
  pendingConfirmCount,
  subscribeConfirm,
} from "../../../shared/primitives/confirmDialogModel.ts";

test("confirmDialog resolves true on confirm and false on cancel", async () => {
  const yes = confirmDialog({ title: "Restart?" });
  const head = currentConfirm();
  assert.ok(head);
  assert.equal(head.title, "Restart?");
  answerConfirm(head.id, true);
  assert.equal(await yes, true);
  assert.equal(currentConfirm(), null);

  const no = confirmDialog({ title: "Discard?" });
  answerConfirm(currentConfirm()!.id, false);
  assert.equal(await no, false);
  assert.equal(pendingConfirmCount(), 0);
});

test("a second question waits behind the open one", async () => {
  const first = confirmDialog({ title: "first" });
  const second = confirmDialog({ title: "second" });
  assert.equal(pendingConfirmCount(), 2);
  const a = currentConfirm()!;
  assert.equal(a.title, "first");
  answerConfirm(a.id, false);
  const b = currentConfirm()!;
  assert.equal(b.title, "second");
  // A late or double answer to the first question is ignored: it can never
  // answer the second.
  answerConfirm(a.id, true);
  assert.equal(currentConfirm()?.id, b.id);
  answerConfirm(b.id, true);
  assert.deepEqual(await Promise.all([first, second]), [false, true]);
});

test("subscribers hear every change and the snapshot is stable between them", () => {
  let calls = 0;
  const off = subscribeConfirm(() => (calls += 1));
  void confirmDialog({ title: "x" });
  const snap = currentConfirm();
  assert.equal(currentConfirm(), snap);
  answerConfirm(snap!.id, false);
  off();
  void confirmDialog({ title: "y" });
  assert.equal(calls, 2);
  answerConfirm(currentConfirm()!.id, false);
});

test("confirmParagraphs splits an array body and drops empty parts", () => {
  assert.deepEqual(confirmParagraphs(undefined), []);
  assert.deepEqual(confirmParagraphs(""), []);
  assert.deepEqual(confirmParagraphs("one"), ["one"]);
  assert.deepEqual(confirmParagraphs(["one", "", null, "two"]), ["one", "two"]);
});

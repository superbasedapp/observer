// Render tests of the shared confirm dialog (shared/primitives/ConfirmDialog),
// rendered with react-dom/server under node's test runner
// (scripts/test-components.mjs): the labelled / described dialog, the
// buttons in safe order (Cancel first, so it takes focus), the tone, and the
// host rendering the head of the confirmDialog queue.

import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { ConfirmDialogHost, ConfirmDialogView, confirmDialog } from "@shared/primitives";
import { answerConfirm, currentConfirm } from "@shared/primitives/confirmDialogModel";

const noop = () => {};

function attr(html: string, name: string): string | undefined {
  return html.match(new RegExp(`${name}="([^"]*)"`))?.[1];
}

test("the dialog is named by its title and described by its body", () => {
  const html = renderToStaticMarkup(
    <ConfirmDialogView
      title="Restart the daemon now?"
      body={["This applies your pending config changes.", "No proxied requests in the last minute."]}
      confirmLabel="Restart daemon"
      tone="danger"
      onConfirm={noop}
      onCancel={noop}
    />,
  );
  assert.match(html, /role="dialog"/);
  assert.match(html, /aria-modal="true"/);
  const labelledBy = attr(html, "aria-labelledby");
  const describedBy = attr(html, "aria-describedby");
  assert.ok(labelledBy && describedBy);
  assert.match(html, new RegExp(`<h2 id="${labelledBy}"[^>]*>Restart the daemon now\\?</h2>`));
  assert.match(html, new RegExp(`<div id="${describedBy}"[^>]*><p>This applies your pending config changes.</p><p>No proxied requests`));
  // Cancel comes first (it is the first focusable, so Enter never confirms
  // by accident); there is no header close button to take focus instead.
  assert.ok(html.indexOf("confirm-dialog-cancel") < html.indexOf("confirm-dialog-confirm"));
  assert.doesNotMatch(html, /aria-label="Close"/);
  assert.match(html, />Restart daemon</);
  assert.match(html, />Cancel</);
});

test("a dialog with no body has no description and default labels", () => {
  const html = renderToStaticMarkup(<ConfirmDialogView title="Sure?" onConfirm={noop} onCancel={noop} />);
  assert.equal(attr(html, "aria-describedby"), undefined);
  assert.match(html, />Confirm</);
  assert.match(html, />Cancel</);
});

test("the tone picks the confirm button's look", () => {
  const danger = renderToStaticMarkup(<ConfirmDialogView title="a" tone="danger" confirmLabel="Discard" onConfirm={noop} onCancel={noop} />);
  const primary = renderToStaticMarkup(<ConfirmDialogView title="a" confirmLabel="Apply" onConfirm={noop} onCancel={noop} />);
  assert.match(danger, /bg-warn-soft/);
  assert.match(primary, /bg-accent-soft/);
  assert.notEqual(
    danger.match(/<button[^>]*data-testid="confirm-dialog-confirm"[^>]*>/)?.[0],
    primary.match(/<button[^>]*data-testid="confirm-dialog-confirm"[^>]*>/)?.[0],
  );
});

test("the host renders nothing idle and the head of the queue when asked", async () => {
  assert.equal(renderToStaticMarkup(<ConfirmDialogHost />), "");
  const answer = confirmDialog({ title: "Discard what you typed in this budget?", confirmLabel: "Discard", cancelLabel: "Keep editing" });
  const html = renderToStaticMarkup(<ConfirmDialogHost />);
  assert.match(html, /Discard what you typed in this budget\?/);
  assert.match(html, />Keep editing</);
  answerConfirm(currentConfirm()!.id, false);
  assert.equal(await answer, false);
  assert.equal(renderToStaticMarkup(<ConfirmDialogHost />), "");
});

// Pins the "New terminal" dock stepping aside for an open overlay (the
// request/grant lane's 375px finding: the dock, z-70, sat over a Modal's
// footer, z-60, covering its Send button). Modal and SlideOver mark the body
// through shared/lib/scrollLock.ts's markOverlay; one CSS rule hides the dock
// while the mark is present.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { OVERLAY_OPEN_ATTR, markOverlay } from "../../../shared/lib/scrollLock.ts";

const body = () => ({ dataset: {} as Record<string, string | undefined> });

test("one overlay marks the body and its undo clears it", () => {
  const b = body();
  const undo = markOverlay(b);
  assert.equal(b.dataset.overlayOpen, "1");
  undo();
  assert.equal(b.dataset.overlayOpen, undefined);
});

test("nested overlays count; the outer one keeps the mark until it closes", () => {
  const b = body();
  const outer = markOverlay(b);
  const inner = markOverlay(b);
  assert.equal(b.dataset.overlayOpen, "2");
  inner();
  assert.equal(b.dataset.overlayOpen, "1");
  outer();
  assert.equal(b.dataset.overlayOpen, undefined);
});

test("a double undo cannot unmark another overlay that is still open", () => {
  const b = body();
  const a = markOverlay(b);
  const c = markOverlay(b);
  a();
  a();
  assert.equal(b.dataset.overlayOpen, "1");
  c();
  assert.equal(b.dataset.overlayOpen, undefined);
});

test("the dock carries the class the CSS rule hides under an open overlay", () => {
  assert.equal(OVERLAY_OPEN_ATTR, "data-overlay-open");
  const dock = readFileSync(new URL("../components/LaunchDock.tsx", import.meta.url), "utf8");
  assert.match(dock, /className="sb-launch-dock fixed bottom-4 right-4 z-\[25\]/);
  const css = readFileSync(new URL("../index.css", import.meta.url), "utf8");
  assert.match(css, /body\[data-overlay-open\] \.sb-launch-dock\s*\{\s*display:\s*none;?\s*\}/);
});

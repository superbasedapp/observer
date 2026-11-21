// scrollHighlight: the settings-link landing rule (lane UI).

import { test } from "node:test";
import assert from "node:assert/strict";
import { hashNames, revealTarget, type RevealTarget } from "./scrollHighlight.ts";

test("hashNames", () => {
  const cases: [string, string, boolean][] = [
    ["#hosted-sandboxes", "hosted-sandboxes", true],
    ["hosted-sandboxes", "hosted-sandboxes", true],
    ["#sandbox-backends", "hosted-sandboxes", false],
    ["", "hosted-sandboxes", false],
    ["#", "", false],
    ["#component-terminals%2Esandbox", "component-terminals.sandbox", true],
    ["#%E0%A4%A", "%E0%A4%A", true],
  ];
  for (const [hash, id, want] of cases) assert.equal(hashNames(hash, id), want, `${hash} ${id}`);
});

type Node = RevealTarget & { scrolled: number };

function node(tag: string, open: boolean | undefined, parent: RevealTarget | null): Node {
  const n: Node = {
    tagName: tag,
    open,
    parentElement: parent,
    scrolled: 0,
    scrollIntoView() {
      n.scrolled++;
    },
  };
  return n;
}

test("revealTarget opens the target and every closed disclosure around it, then scrolls", () => {
  const outer = node("DETAILS", false, null);
  const mid = node("div", undefined, outer);
  const target = node("details", false, mid);
  assert.equal(revealTarget(target), 2);
  assert.equal(target.open, true);
  assert.equal(outer.open, true);
  assert.equal(target.scrolled, 1);
});

test("revealTarget leaves an open disclosure and a plain element as they are", () => {
  const open = node("DETAILS", true, null);
  const li = node("LI", undefined, open);
  assert.equal(revealTarget(li), 0);
  assert.equal(open.open, true);
  assert.equal(li.scrolled, 1);
});

// Pins shared/lib/vocabIcons.ts, the ONE table mapping every closed dashboard
// vocabulary value to a lucide glyph: every value is a real icon component
// (a lucide name that does not exist in the pinned lucide-react would be
// undefined here), and an unknown value falls back to CircleHelp (unknown
// means unknown, never a guess).
import { test } from "node:test";
import assert from "node:assert/strict";
import { CircleHelp } from "lucide-react";
import { VOCAB_ICONS, vocabIcon, type Vocab } from "../../../shared/lib/vocabIcons.ts";

// lucide-react icons are forwardRef exotic components: an object with a
// render function, not a plain function.
function isIconComponent(v: unknown): boolean {
  if (typeof v === "function") return true;
  return typeof v === "object" && v !== null && typeof (v as { render?: unknown }).render === "function";
}

test("every VOCAB_ICONS value is an icon component", () => {
  const bad: string[] = [];
  for (const [vocab, table] of Object.entries(VOCAB_ICONS)) {
    for (const [value, icon] of Object.entries(table)) {
      if (!isIconComponent(icon)) bad.push(`${vocab}.${value}`);
    }
  }
  assert.deepEqual(bad, []);
  assert.ok(Object.keys(VOCAB_ICONS).length >= 100, "the vocabulary table is populated");
});

test("vocabIcon falls back to CircleHelp for an unknown or missing value", () => {
  const vocab = Object.keys(VOCAB_ICONS)[0] as Vocab;
  assert.equal(vocabIcon(vocab, "no-such-value"), CircleHelp);
  assert.equal(vocabIcon(vocab, null), CircleHelp);
  assert.equal(vocabIcon(vocab, undefined), CircleHelp);
});

test("vocabIcon returns the table entry for a known value", () => {
  for (const [vocab, table] of Object.entries(VOCAB_ICONS)) {
    for (const [value, icon] of Object.entries(table)) {
      assert.equal(vocabIcon(vocab as Vocab, value), icon, `${vocab}.${value}`);
    }
  }
});

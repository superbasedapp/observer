// vocabDef - the closed-vocabulary def seam (design-kit WS5), promoted from
// web2/src/lib/vocab.ts (Plane A B5-0, 2026-11-19; web2 keeps a re-export
// shim at the old path) so the Plane A components in shared/components/planea
// can draw the same pills on the node and the org dashboards.
//
// Every closed vocabulary the org dashboard renders as a pill is ONE table
// of `{ tone, label? }` entries, colocated with the module that owns the
// enum (lib/vocabs/*.ts for the enums that live in lib/api.ts, or the lib
// model that already owns the value, e.g. agentAccessModel.ts). The glyph is
// never chosen here: it comes from the shared VOCAB_ICONS table
// (shared/lib/vocabIcons.ts) through `vocab`, so the node and the org
// dashboards draw one value with one glyph. A glyph the shared table does not
// carry yet sits in the def's `icons` (listed for folding into vocabIcons).
//
// CLAUDE.md #5: a component renders <VocabPill of={DEF} value={v} />; it never
// grows an if/else ladder or a switch over the values. An unknown value is
// neutral, labelled by its raw id, and drawn with CircleHelp (unknown means
// unknown - never a guess).
//
// Pure data + lookups (no React, no JSX) so a plain node:test can import it.
// (lib/vocabs.test.ts resolves the @shared alias for node:test.)
import { CircleHelp, LoaderCircle, type LucideIcon } from "lucide-react";
import type { Tone } from "./tone.ts";
import type { VocabEntry as SharedVocabEntry } from "./vocabEntry.ts";
import { VOCAB_ICONS, vocabIcon, type Vocab } from "./vocabIcons.ts";
import type { PillCase } from "../primitives/Pill";

export type { Tone };

/** One value of a closed vocabulary: the shared row shape
 *  (shared/lib/vocabEntry.ts: tone, label, spin - an in-flight value draws
 *  the turning LoaderCircle, as every app does) plus org-side fields that
 *  are candidates to fold into the shared row. */
export type VocabEntry = SharedVocabEntry & {
  /** Read the glyph under this key of the shared vocab instead of the value
   *  itself (two spellings of one meaning, e.g. `med` and `medium`). */
  glyph?: string;
  /** Tooltip text: what the value means to the reader. */
  hint?: string;
  /** How the pill transforms the label. Absent is the pill's lowercase
   *  default; "none" keeps a label that is an acronym ("SCIM", "MFA") as
   *  written, so it never renders as "scim". */
  case?: PillCase;
};

/** A closed vocabulary: its tone/label table plus where its glyphs live. */
export type VocabDef<K extends string = string> = {
  /** The shared VOCAB_ICONS table that holds this vocabulary's glyphs.
   *  Absent only when the shared table has no such vocabulary yet and every
   *  glyph is local (`icons`). */
  vocab?: Vocab;
  /** Glyphs the shared table does not carry yet (fold into vocabIcons). */
  icons?: Readonly<Partial<Record<K, LucideIcon>>>;
  entries: Readonly<Record<K, VocabEntry>>;
};

/** defineVocab types a vocabulary table (identity; keeps the key union). */
export function defineVocab<K extends string>(def: VocabDef<K>): VocabDef<K> {
  return def;
}

/** Everything a pill needs to draw one vocabulary value. */
export type VocabView = {
  tone: Tone;
  label: string;
  icon: LucideIcon;
  spin: boolean;
  hint?: string;
  /** False for a value outside the table (neutral, CircleHelp, raw id). */
  known: boolean;
  /** The entry's text transform when it sets one (VocabEntry.case). */
  textCase?: PillCase;
};

function own<T>(table: Readonly<Record<string, T>> | undefined, key: string): T | undefined {
  return table && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

/** vocabView resolves one value against its vocabulary table. */
export function vocabView<K extends string>(def: VocabDef<K>, value: string | null | undefined): VocabView {
  const key = value ?? "";
  const entry = own<VocabEntry>(def.entries as Record<string, VocabEntry>, key);
  const glyphKey = entry?.glyph ?? key;
  const local = own<LucideIcon>(def.icons as Record<string, LucideIcon> | undefined, glyphKey);
  return {
    tone: entry?.tone ?? "neutral",
    label: entry?.label ?? (key || "unknown"),
    icon: entry?.spin
      ? LoaderCircle
      : (local ?? (def.vocab ? vocabIcon(def.vocab, glyphKey === "" ? null : glyphKey) : CircleHelp)),
    spin: entry?.spin ?? false,
    hint: entry?.hint,
    known: entry !== undefined,
    ...(entry?.case ? { textCase: entry.case } : {}),
  };
}

/** vocabTone - the tone of one value, "neutral" when unknown. */
export function vocabTone<K extends string>(def: VocabDef<K>, value: string | null | undefined): Tone {
  return vocabView(def, value).tone;
}

/** vocabLabel - the display label of one value, its raw id when unknown. */
export function vocabLabel<K extends string>(def: VocabDef<K>, value: string | null | undefined): string {
  return vocabView(def, value).label;
}

/** hasGlyph reports whether a table value has an explicit glyph (shared or
 *  local), i.e. it does not fall back to CircleHelp. Used by the tests. */
export function hasGlyph<K extends string>(def: VocabDef<K>, value: string): boolean {
  const entry = own<VocabEntry>(def.entries as Record<string, VocabEntry>, value);
  const key = entry?.glyph ?? value;
  if (own(def.icons as Record<string, LucideIcon> | undefined, key)) return true;
  return def.vocab !== undefined && own(VOCAB_ICONS[def.vocab] as Record<string, LucideIcon>, key) !== undefined;
}

// TONE_COLOR lives with the Tone type in shared/lib/tone.ts (one owner).
export { TONE_COLOR } from "./tone.ts";

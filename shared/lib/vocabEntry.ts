import { LoaderCircle, type LucideIcon } from "lucide-react";
import type { Tone } from "./tone.ts";
import { vocabIcon, type Vocab } from "./vocabIcons.ts";

// vocabEntry - the ONE row shape of a closed-vocabulary presentation table
// (CLAUDE.md #5: data, never an if/else ladder in a component). A table maps
// each value to its tone (shared/lib/tone.ts, = the Pill variant set), an
// optional display label (the value itself when absent, so a table only
// spells out a label that differs from the wire id) and an optional `spin`
// flag for an in-flight state (running / queued / in progress). The glyph is
// NOT stored here: it comes from shared/lib/vocabIcons.ts, so glyph and tone
// each have exactly one owner. Tables live next to their vocabulary's
// metadata owner (shared/lib/cacheVocab.ts, shared/lib/sessionVocab.ts,
// web/src/lib/vocabTones.ts, ...).

/** One value's presentation: tone, optional label, optional in-flight spin. */
export type VocabEntry = { tone: Tone; label?: string; spin?: boolean };

/** A closed vocabulary's presentation table, keyed by the wire value. */
export type VocabTable = Readonly<Record<string, VocabEntry>>;

/** The resolved presentation of one value, ready for <Pill>. */
export type VocabView = { tone: Tone; label: string; icon: LucideIcon; spin: boolean };

/**
 * vocabView resolves one vocabulary value against its table and glyph set.
 * An unknown value is honest: neutral tone, the raw value as its label and
 * the CircleHelp glyph (vocabIcon's fallback), never a guess. An in-flight
 * value (spin) draws the LoaderCircle so every running / queued / in-progress
 * pill turns the same glyph.
 */
export function vocabView(vocab: Vocab, table: VocabTable, value: string | null | undefined): VocabView {
  const entry = value != null ? table[value] : undefined;
  const spin = entry?.spin === true;
  return {
    tone: entry?.tone ?? "neutral",
    label: entry?.label ?? value ?? "",
    icon: spin ? LoaderCircle : vocabIcon(vocab, value),
    spin,
  };
}

/** vocabTone reads only the tone of a value, "neutral" when unknown. */
export function vocabTone(table: VocabTable, value: string | null | undefined): Tone {
  return (value != null && table[value]?.tone) || "neutral";
}

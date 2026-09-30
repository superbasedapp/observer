// Tone: the closed set of semantic colours a vocabulary value can take. It is
// exactly the Pill variant set (shared/primitives/Pill.tsx), so a vocabulary
// table's tone feeds <Pill variant={tone}> directly. Every closed dashboard
// vocabulary maps each value to ONE tone in ONE table, colocated with that
// vocabulary's metadata owner (guardCatalog.ts for guard decisions and
// severities, and so on); the glyph comes from shared/lib/vocabIcons.ts.
// An unknown value falls back to "neutral" (unknown means unknown).
export type Tone = "neutral" | "success" | "warn" | "danger" | "info" | "accent";

/** toneOf reads a vocabulary tone table, "neutral" for an unknown value. */
export function toneOf<K extends string>(
  table: Readonly<Record<K, Tone>>,
  value: string | null | undefined,
): Tone {
  return (value != null && (table as Record<string, Tone>)[value]) || "neutral";
}

/** TONE_COLOR - each tone's CSS colour, for a mark that is not a pill (a
 *  chart series, a donut slice, a meter fill) but must agree with the pill
 *  of the same value. */
export const TONE_COLOR: Readonly<Record<Tone, string>> = {
  neutral: "var(--fg-4)",
  success: "var(--success)",
  warn: "var(--warn)",
  danger: "var(--danger)",
  info: "var(--info)",
  accent: "var(--accent)",
};

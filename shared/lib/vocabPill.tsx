import type { ReactNode } from "react";
import { Pill } from "../primitives/Pill";
import type { Tone } from "./tone";
import { vocabIcon, type Vocab } from "./vocabIcons";
import { vocabView, type VocabTable } from "./vocabEntry";

// VocabPill - a <Pill> for one closed-vocabulary value: the glyph from
// shared/lib/vocabIcons.ts, the tone (and label / in-flight spin) from the
// vocabulary's presentation table (shared/lib/vocabEntry.ts). Pass `table`
// for a VocabEntry table, or `tone` when the vocabulary's owner exposes a
// plain tone table (guardCatalog's decisionTone / severityTone). `children`
// replaces the label when the pill carries more than the value (a count, an
// enforced mark).

/** VocabPill renders one vocabulary value as a glyph + tone pill. */
export function VocabPill({
  vocab,
  value,
  table,
  tone,
  title,
  className,
  children,
}: {
  vocab: Vocab;
  value: string | null | undefined;
  table?: VocabTable;
  tone?: Tone;
  title?: ReactNode;
  className?: string;
  children?: ReactNode;
}) {
  const v = table
    ? vocabView(vocab, table, value)
    : { tone: tone ?? "neutral", label: value ?? "", icon: vocabIcon(vocab, value), spin: false };
  return (
    <Pill variant={tone ?? v.tone} icon={v.icon} spin={v.spin} title={title} className={className}>
      {children ?? v.label}
    </Pill>
  );
}

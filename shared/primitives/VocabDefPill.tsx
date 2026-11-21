import type { ReactNode } from "react";
import { Pill } from "./Pill";
import { vocabView, type VocabDef } from "../lib/vocabDef";

// VocabDefPill (web2's VocabPill, promoted 2026-11-19 for Plane A B5-0;
// web2/src/components/VocabPill.tsx re-exports it under its old name) draws one closed-vocabulary value: tone and label from the
// vocabulary's table (lib/vocab.ts), glyph from the shared VOCAB_ICONS, a
// spinning glyph for an in-flight value. `children` overrides the label
// (e.g. to add a count) without changing the tone or the glyph; the
// entry's `hint` is the default tooltip.
export function VocabDefPill<K extends string>({
  of,
  value,
  children,
  title,
  className,
  quiet,
}: {
  of: VocabDef<K>;
  value: string | null | undefined;
  children?: ReactNode;
  title?: ReactNode;
  className?: string;
  /** Neutral tone, same glyph and label: a closed / inactive row of a value
   *  that is loud while open (a resolved finding). */
  quiet?: boolean;
}) {
  const v = vocabView(of, value);
  return (
    <Pill
      variant={quiet ? "neutral" : v.tone}
      icon={v.icon}
      spin={v.spin}
      title={title ?? v.hint}
      className={className}
      case={v.textCase}
    >
      {children ?? v.label}
    </Pill>
  );
}

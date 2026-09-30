import clsx from "clsx";
import { Icon } from "@shared/primitives/Icon";
import { Pill } from "@shared/primitives/Pill";
import { vocabIcon, type Vocab } from "@shared/lib/vocabIcons";
import { vocabView } from "@shared/lib/vocabEntry";
import {
  byDisclosure,
  CONSENT_PURPOSE,
  DISCLOSURE_LEVEL,
  FIELD_CLASS,
  type Disclosure,
} from "../lib/vocab";

// Disclosure - how the portal draws a consent purpose or a field class: the
// value's glyph and human label (lib/vocab.ts + VOCAB_ICONS) and a 1-4 dot
// meter of how much it lets leave the account, so every list reads as an
// escalating ladder. An id this build does not know keeps its raw id, the
// CircleHelp glyph and NO meter (its sensitivity is unknown, not low).

const LEVELS: readonly Disclosure[] = [1, 2, 3, 4];

/** SensitivityMeter draws `level` of four dots filled. */
export function SensitivityMeter({ level, className }: { level: Disclosure; className?: string }) {
  const label = `Disclosure ${level} of 4: ${DISCLOSURE_LEVEL[level]}`;
  return (
    <span role="img" aria-label={label} className={clsx("inline-flex items-center gap-[3px]", className)}>
      {LEVELS.map((n) => (
        <span
          key={n}
          aria-hidden
          className={clsx(
            "h-[5px] w-[5px] rounded-full",
            n <= level ? "bg-accent" : "border border-line-2 bg-transparent",
          )}
        />
      ))}
    </span>
  );
}

type Kind = "purpose" | "fieldClass";

const KIND: Readonly<Record<Kind, { vocab: Vocab; table: typeof CONSENT_PURPOSE }>> = {
  purpose: { vocab: "consentPurpose", table: CONSENT_PURPOSE },
  fieldClass: { vocab: "fieldClass", table: FIELD_CLASS },
};

/** DisclosureChip is one purpose / field class: glyph, label and meter. */
export function DisclosureChip({ kind, id, title }: { kind: Kind; id: string; title?: string }) {
  const { vocab, table } = KIND[kind];
  const v = vocabView(vocab, table, id);
  const level = table[id]?.disclosure;
  return (
    <Pill variant={v.tone} icon={vocabIcon(vocab, id)} title={title ?? id}>
      {v.label}
      {level && <SensitivityMeter level={level} className="ml-1" />}
    </Pill>
  );
}

/** DisclosureMark is the compact form beside a value's own sentence label:
 *  the glyph and the meter, no chip. */
export function DisclosureMark({ kind, id }: { kind: Kind; id: string }) {
  const { vocab, table } = KIND[kind];
  const level = table[id]?.disclosure;
  return (
    <span className="inline-flex items-center gap-1.5 align-middle text-fg-3">
      <Icon icon={vocabIcon(vocab, id)} size="xs" />
      {level && <SensitivityMeter level={level} />}
    </span>
  );
}

/** DisclosureChips lists ids least to most sensitive as a chip set. */
export function DisclosureChips({ kind, ids, empty }: { kind: Kind; ids: readonly string[]; empty: string }) {
  if (ids.length === 0) return <span className="muted small">{empty}</span>;
  return (
    <span className="inline-flex flex-wrap items-center justify-end gap-1.5">
      {byDisclosure(KIND[kind].table, ids).map((id) => (
        <DisclosureChip key={id} kind={kind} id={id} />
      ))}
    </span>
  );
}

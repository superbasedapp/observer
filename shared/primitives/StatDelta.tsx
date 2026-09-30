import clsx from "clsx";
import type { ReactNode } from "react";

// StatDelta - the period-over-period delta a KPI tile renders under its value:
// a direction glyph, the cost-aware coloured % text, then the prior-period
// value (or a free-form label). Extracted from StatCard so StatCard and
// HeroStat render one delta the same way. Pure: no fetch, state or router.
//
// Colour follows the design's cost-aware convention (`design/app.css:442-443`):
// UP renders danger-red, DOWN renders success-green, because the tiles measure
// cost or volume where "up" is the worse outcome. A page that wants the
// opposite sense (cache savings) flips the sign upstream.

/** StatDeltaKind is the direction class of a delta. */
export type StatDeltaKind = "up" | "down" | "flat" | "new" | "none";

/**
 * StatDeltaGuarded is an already-classified delta (web2's
 * `format.computeDelta` DeltaDisplay is structurally one): `kind` picks the
 * glyph and tone, `label` is the text, and a leading `arrow` baked into the
 * label is dropped because the glyph carries the direction.
 */
export type StatDeltaGuarded = {
  kind: StatDeltaKind;
  label: string;
  arrow: string;
};

/** StatDeltaValue is a signed fraction (0.12 = +12%) or a guarded delta. */
export type StatDeltaValue = number | StatDeltaGuarded;

// DELTA_TONE / DELTA_GLYPH: the colour and direction glyph per kind. "new",
// "flat" and "none" are neutral (a fresh or unchanged baseline is not good or
// bad); only a real move is coloured.
const DELTA_TONE: Record<StatDeltaKind, string> = {
  up: "text-danger",
  down: "text-success",
  flat: "text-fg-3",
  new: "text-fg-3",
  none: "text-fg-3",
};
const DELTA_GLYPH: Record<StatDeltaKind, string> = {
  up: "↑",
  down: "↓",
  flat: "·",
  new: "",
  none: "",
};
// SIGN_KIND classifies a numeric fraction by Math.sign.
const SIGN_KIND: Record<string, StatDeltaKind> = {
  "1": "up",
  "-1": "down",
  "0": "flat",
};

type ResolvedDelta = { kind: StatDeltaKind; text: string };

/**
 * resolveStatDelta normalises a delta to its kind and text, or null when
 * there is nothing to show (a non-finite fraction, a "none" kind, or an
 * empty label).
 */
export function resolveStatDelta(delta: StatDeltaValue | undefined): ResolvedDelta | null {
  if (delta == null) return null;
  if (typeof delta === "number") {
    if (!Number.isFinite(delta)) return null;
    return {
      kind: SIGN_KIND[String(Math.sign(delta))] ?? "flat",
      text: `${(Math.abs(delta) * 100).toFixed(1)}%`,
    };
  }
  if (delta.kind === "none" || !delta.label) return null;
  const text =
    delta.arrow && delta.label.startsWith(delta.arrow)
      ? delta.label.slice(delta.arrow.length)
      : delta.label;
  return { kind: delta.kind, text };
}

export type StatDeltaProps = {
  delta?: StatDeltaValue;
  /** Free-form text after the delta, shown when `deltaPrior` is absent. */
  deltaLabel?: string;
  /** Concrete prior-period value (`vs prior 30d $6,073.08`); wins over deltaLabel. */
  deltaPrior?: ReactNode;
};

/**
 * StatDelta renders the delta badge and its prior / label as inline siblings,
 * for the caller's flex row (StatCard's sub row, HeroStat's delta row).
 */
export function StatDelta({ delta, deltaLabel, deltaPrior }: StatDeltaProps) {
  const d = resolveStatDelta(delta);
  return (
    <>
      {d && (
        <span className={clsx("inline-flex items-center gap-0.5 font-semibold", DELTA_TONE[d.kind])}>
          {DELTA_GLYPH[d.kind]}
          {d.text}
        </span>
      )}
      {deltaPrior != null ? <span>{deltaPrior}</span> : deltaLabel && <span>{deltaLabel}</span>}
    </>
  );
}

// meterSegments: the pure layout of a STACKED Meter (several fills in one
// track), pinned in web/src/lib/meterSegments.test.ts. Each segment's value is
// its share of the whole track (0..1, like Meter's `ratio`). Segments are laid
// left to right; a non-finite or negative value draws nothing, and the running
// total is clamped to the track, so an over-full stack is truncated at the
// right edge instead of overflowing. The accessible summary reports each
// segment's own share (clamped to 0..100%), never the truncated drawn width,
// so the words stay true when the picture had to clip.

export interface MeterSegmentValue {
  value: number;
  label: string;
}

export interface MeterSegmentLayout {
  /** Index into the caller's segments array (stable key + colour lookup). */
  index: number;
  /** Left edge, 0..1 of the track. */
  start: number;
  /** Drawn width, 0..1 of the track (after clamping to what is left). */
  share: number;
}

function clampShare(v: number): number {
  return Number.isFinite(v) ? Math.max(0, Math.min(1, v)) : 0;
}

/** layoutMeterSegments returns the drawn segments (zero-width ones omitted). */
export function layoutMeterSegments(segments: readonly MeterSegmentValue[]): MeterSegmentLayout[] {
  const out: MeterSegmentLayout[] = [];
  let at = 0;
  segments.forEach((s, index) => {
    const share = Math.min(clampShare(s.value), 1 - at);
    if (share <= 0) return;
    out.push({ index, start: at, share });
    at += share;
  });
  return out;
}

/** meterSegmentsSummary is the accessible name of a stacked meter, e.g.
 *  "Token mix: Input 40%, Output 25%". */
export function meterSegmentsSummary(
  segments: readonly MeterSegmentValue[],
  label?: string,
): string {
  const parts = segments.map((s) => `${s.label} ${Math.round(clampShare(s.value) * 100)}%`);
  const body = parts.join(", ");
  return label ? `${label}: ${body || "empty"}` : body || "empty";
}

import clsx from "clsx";
import type { LucideIcon } from "lucide-react";
import { Icon } from "./Icon";
import { Tooltip } from "./Tooltip";
import { TONE_COLOR, type Tone } from "../lib/tone";

// GlyphBadge: a vocabulary value drawn as its glyph alone, for a dense table
// cell where the pill's word would truncate. The words live in the tooltip
// (and the accessible name), so nothing is lost: the badge is a real
// focusable element, opens its tooltip on keyboard focus, and reads its
// label to a screen reader. SurfaceBadge and ExecutionLocationBadge render
// through it in their `glyph` mode; their vocabulary tables stay the owners
// of the words, glyphs and tones.

export function GlyphBadge({
  icon,
  label,
  tone = "neutral",
  size = 12,
  className,
}: {
  icon: LucideIcon;
  /** The full words: tooltip text and accessible name. */
  label: string;
  /** Neutral glyphs use the muted text colour; any other tone its colour. */
  tone?: Tone;
  size?: number;
  className?: string;
}) {
  return (
    <Tooltip content={label} maxWidth={320}>
      <span
        role="img"
        tabIndex={0}
        aria-label={label}
        className={clsx(
          "inline-grid shrink-0 cursor-help place-items-center rounded-1 text-fg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-ring)]",
          className,
        )}
        style={tone === "neutral" ? undefined : { color: TONE_COLOR[tone] }}
      >
        <Icon icon={icon} size={size} />
      </span>
    </Tooltip>
  );
}

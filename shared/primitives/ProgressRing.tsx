import clsx from "clsx";
import type { ReactNode } from "react";
import { TONE_COLOR, type Tone } from "../lib/tone";

// ProgressRing: a circular share-of-whole (a policy's ACK convergence, an
// update rollout %, a cache window's remaining life). The arc is a
// stroke-dashoffset on a pathLength=100 circle, eased by a transition, so it
// needs no JS animation; reduced motion snaps it. `children` sits centred
// (a percentage, or an icon for a countdown).
export function ProgressRing({
  ratio,
  tone = "accent",
  size = 40,
  stroke = 4,
  label,
  children,
  className,
}: {
  /** Filled share, 0..1 (clamped; non-finite renders an empty ring). */
  ratio: number;
  tone?: Tone;
  size?: number;
  stroke?: number;
  /** Accessible name; the value is announced as a percentage. */
  label?: string;
  children?: ReactNode;
  className?: string;
}) {
  const fill = Math.max(0, Math.min(1, Number.isFinite(ratio) ? ratio : 0));
  const r = (size - stroke) / 2;
  return (
    <span
      className={clsx("relative inline-grid shrink-0 place-items-center", className)}
      style={{ width: size, height: size }}
      role={label ? "meter" : undefined}
      aria-valuemin={label ? 0 : undefined}
      aria-valuemax={label ? 100 : undefined}
      aria-valuenow={label ? Math.round(fill * 100) : undefined}
      aria-label={label}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="absolute inset-0 -rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--bg-3)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={TONE_COLOR[tone]}
          strokeWidth={stroke}
          strokeLinecap="round"
          pathLength={100}
          strokeDasharray="100 100"
          strokeDashoffset={100 - fill * 100}
          style={{ transition: "stroke-dashoffset var(--dur-slower) var(--ease-out), stroke var(--dur) var(--ease)" }}
        />
      </svg>
      {children != null && <span className="relative text-[10px] font-semibold tabular-nums text-fg-1">{children}</span>}
    </span>
  );
}

import clsx from "clsx";

// Toggle — themed boolean switch. Wraps the on/off pill + label in
// a flex row so the label can't overlap the track at any zoom level
// (the earlier inline version pinned the knob with position:absolute
// inside an inline-block span, which collided with adjacent text on
// some breakpoints). Use this anywhere a config or filter has a
// binary on/off value.
//
// Size = "sm" (default) → 32×18 track / 14px knob; "md" → 40×22 / 18.
export function Toggle({
  on,
  onChange,
  size = "sm",
  disabled,
  label,
  className,
  labelClassName,
}: {
  on: boolean;
  onChange?: (next: boolean) => void;
  size?: "sm" | "md";
  disabled?: boolean;
  label?: React.ReactNode;
  className?: string;
  labelClassName?: string;
}) {
  const trackW = size === "md" ? 40 : 32;
  const trackH = size === "md" ? 22 : 18;
  const knob = size === "md" ? 18 : 14;
  const inset = (trackH - knob) / 2;
  const knobX = on ? trackW - knob - inset : inset;
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange?.(!on)}
      className={clsx(
        "group inline-flex items-center gap-2.5 disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
    >
      <span
        aria-hidden
        className={clsx(
          "relative inline-block shrink-0 rounded-pill transition-colors",
          on ? "bg-accent" : "bg-bg-4",
          "shadow-[inset_0_1px_2px_rgba(0,0,0,0.35)]",
        )}
        style={{ width: trackW, height: trackH }}
      >
        <span
          className="absolute top-0 inline-block rounded-full bg-white shadow-[0_1px_2px_rgba(0,0,0,0.4)] transition-transform"
          style={{
            width: knob,
            height: knob,
            top: inset,
            left: 0,
            transform: `translateX(${knobX}px)`,
          }}
        />
      </span>
      {label !== undefined && (
        <span
          className={clsx(
            "text-[11.5px] leading-none text-fg-3 transition-colors",
            on && "text-fg-1",
            labelClassName,
          )}
        >
          {label}
        </span>
      )}
    </button>
  );
}

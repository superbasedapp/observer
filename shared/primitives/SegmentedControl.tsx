import clsx from "clsx";
import type { ReactNode } from "react";

export type Segment<T extends string> = {
  value: T;
  label: ReactNode;
  /** When true the segment is not selectable; `disabledReason` is then
   * required (honest-disabled-copy convention — see Tabs.tsx). */
  disabled?: boolean;
  /** Names the exact missing dependency. Shown as the segment's title
   * tooltip. */
  disabledReason?: string;
};

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  size = "md",
  className,
}: {
  options: Segment<T>[];
  value: T;
  onChange: (v: T) => void;
  size?: "sm" | "md";
  className?: string;
}) {
  const padding = size === "sm" ? "px-2 py-0.5 text-[10.5px]" : "px-2.5 py-1 text-[11px]";
  return (
    <div
      role="tablist"
      className={clsx(
        "inline-flex items-center gap-0.5 rounded-2 border border-line-2 bg-bg-2 p-0.5",
        className,
      )}
    >
      {options.map((opt) => {
        const active = opt.value === value && !opt.disabled;
        return (
          <button
            key={opt.value}
            type="button"
            role="tab"
            aria-selected={active}
            aria-disabled={opt.disabled || undefined}
            disabled={opt.disabled}
            title={opt.disabled ? opt.disabledReason : undefined}
            onClick={() => !opt.disabled && onChange(opt.value)}
            className={clsx(
              "rounded-1 font-medium transition-colors",
              padding,
              opt.disabled
                ? "cursor-not-allowed text-fg-4"
                : active
                  ? "bg-bg-4 text-fg-0"
                  : "text-fg-2 hover:text-fg-1",
            )}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

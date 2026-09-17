import clsx from "clsx";
import type { ReactNode } from "react";

// SettingRow — one labelled setting: a label (plus optional help and
// badges) beside or above its control, with an optional status line under
// the control. Generalised from the Settings forms' `FieldRow` / `Field`
// so the config surfaces stop each inventing their own grid.
//
// `layout`:
//   "grid"  (default) label column + control column at >= lg, stacked on
//           phones. `help` sits under the LABEL, as the config forms do.
//   "stack" label above the control, `help` under the CONTROL — the shape
//           the Intelligence panel's small fields use.
//
// The label-column width is an enum, not a free number, because Tailwind
// cannot see a class assembled from a variable.

export type SettingRowProps = {
  label: ReactNode;
  help?: ReactNode;
  /** Rendered under the control: effective value, validation, "saved". */
  status?: ReactNode;
  layout?: "grid" | "stack";
  /** Label-column width in the grid layout. */
  width?: "sm" | "md";
  /** Tints the row, e.g. for an unsaved edit. */
  highlight?: boolean;
  className?: string;
  children: ReactNode;
};

const WIDTH_CLASS: Record<"sm" | "md", string> = {
  sm: "lg:grid-cols-[180px_minmax(0,1fr)]",
  md: "lg:grid-cols-[220px_minmax(0,1fr)]",
};

export function SettingRow({
  label,
  help,
  status,
  layout = "grid",
  width = "sm",
  highlight,
  className,
  children,
}: SettingRowProps) {
  if (layout === "stack") {
    return (
      <div className={className}>
        <div className="mb-1 text-[10.5px] font-semibold uppercase tracking-[0.06em] text-fg-3">
          {label}
        </div>
        {children}
        {help !== undefined && (
          <div className="mt-1 text-[11px] leading-snug text-fg-3">{help}</div>
        )}
        {status !== undefined && <div className="mt-1">{status}</div>}
      </div>
    );
  }

  return (
    <div
      className={clsx(
        "grid grid-cols-1 gap-1.5 lg:items-start lg:gap-4",
        WIDTH_CLASS[width],
        highlight && "rounded-2 bg-accent/5",
        className,
      )}
    >
      <div className="lg:pt-1.5">
        <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-fg-2">
          {label}
        </div>
        {help !== undefined && (
          <div className="mt-1 text-[11px] leading-snug text-fg-3">{help}</div>
        )}
      </div>
      <div className="min-w-0">
        {children}
        {status !== undefined && <div className="mt-1">{status}</div>}
      </div>
    </div>
  );
}

import clsx from "clsx";
import type { ReactNode } from "react";
import { Meter } from "@/components/primitives";
import { fmtPct } from "@/lib/format";

// tableCells: the header / data / mix-bar cells the Cost and Cache tables
// both render. One module so the two pages cannot drift apart (they held
// byte-identical private copies before 2026-09-28).

/** Th is a compact header cell, left- or right-aligned. */
export function Th({
  children,
  align,
}: {
  children?: ReactNode;
  align?: "left" | "right";
}) {
  return (
    <th className={clsx("px-2 py-1.5 font-medium", align === "right" ? "text-right" : "text-left")}>
      {children}
    </th>
  );
}

/** Td is a compact data cell; `align="right"` also sets tabular numerals,
 *  `mono` renders an id / path. `title` only reveals the full string of a
 *  truncated value (plain text, not an interactive hint). */
export function Td({
  children,
  align,
  mono,
  title,
}: {
  children?: ReactNode;
  align?: "left" | "right";
  mono?: boolean;
  title?: string;
}) {
  return (
    <td
      title={title}
      className={clsx(
        "px-2 py-1.5",
        align === "right" && "text-right tabular-nums",
        mono ? "font-mono text-fg-2" : "text-fg-1",
      )}
    >
      {children}
    </td>
  );
}

/** MixCell is a right-aligned share cell: a small meter plus the percent. */
export function MixCell({ pct, color }: { pct: number; color: string }) {
  return (
    <td className="px-2 py-1.5 text-right">
      <div className="ml-auto flex max-w-[88px] items-center justify-end gap-2">
        <Meter ratio={pct} color={color} trackClassName="h-1.5 w-12" />
        <span className="tabular-nums text-fg-2">{fmtPct(pct)}</span>
      </div>
    </td>
  );
}

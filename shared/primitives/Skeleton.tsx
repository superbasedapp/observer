import clsx from "clsx";
import type { CSSProperties } from "react";

// Pulse skeleton placeholder. The animate-shimmer utility is
// defined in src/index.css and uses --ease from tokens.css so
// theme switches stay consistent.
export function Skeleton({
  className,
  style,
}: {
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      aria-hidden="true"
      className={clsx(
        "relative overflow-hidden rounded-2 bg-bg-3/60 animate-shimmer",
        className,
      )}
      style={style}
    />
  );
}

// Pre-fab block sized like a chart slot.
export function ChartSkeleton({ height = 220 }: { height?: number }) {
  return (
    <div className="flex flex-col gap-2" style={{ height }}>
      <div className="flex items-end gap-2" style={{ flex: 1 }}>
        {[0.6, 0.85, 0.5, 0.9, 0.7, 0.95, 0.55, 0.8, 0.65, 0.9].map((h, i) => (
          <Skeleton
            key={i}
            className="flex-1"
            style={{ height: `${h * 100}%` }}
          />
        ))}
      </div>
      <div className="flex gap-2">
        <Skeleton className="h-2 flex-1" />
        <Skeleton className="h-2 flex-1" />
        <Skeleton className="h-2 flex-1" />
      </div>
    </div>
  );
}

// Pre-fab block sized like a table.
export function TableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Skeleton className="h-4 w-full" />
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-6 w-full" />
      ))}
    </div>
  );
}

// Pre-fab block sized like a StatCard value.
export function StatCardSkeleton() {
  return (
    <div className="flex flex-col gap-2 rounded-3 border border-line-2 bg-bg-2 px-4 py-3">
      <Skeleton className="h-2.5 w-20" />
      <Skeleton className="h-7 w-28" />
      <Skeleton className="h-2.5 w-32" />
    </div>
  );
}

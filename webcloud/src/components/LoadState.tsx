import {
  ChartSkeleton,
  Skeleton,
  StatCardSkeleton,
  TableSkeleton,
} from "@shared/primitives/Skeleton";
import { ErrorState } from "@shared/primitives/ErrorState";

// Loading + error frames shared by every portal page. Skeletons are shaped
// like the page they stand in for, so content lands without the layout
// jumping; errors always offer a retry instead of a dead end.

/** ErrorPanel: what failed, the server's reason, and a Retry button, drawn
 *  by the shared ErrorState. `page` is the whole-page failure (the error
 *  illustration), `section` (default) a card body or a panel slot, and
 *  `compact` a one-line row under a list (e.g. a failed "Load more"). */
export function ErrorPanel({
  what,
  error,
  onRetry,
  variant = "section",
}: {
  what: string;
  error: string;
  onRetry?: () => void;
  variant?: "page" | "section" | "compact";
}) {
  const title = `Could not load ${what}`;
  if (variant === "page") {
    return (
      <ErrorState variant="page" title={title} error={error} onRetry={onRetry} />
    );
  }
  if (variant === "compact") {
    return (
      <ErrorState variant="compact" title={title} error={error} onRetry={onRetry} />
    );
  }
  return (
    <ErrorState variant="inline" title={title} error={error} onRetry={onRetry} className="py-5" />
  );
}

/** HeaderSkeleton: a page title + one line of intro. */
export function HeaderSkeleton() {
  return (
    <div className="flex flex-col gap-2">
      <Skeleton className="h-5 w-40" />
      <Skeleton className="h-3 w-[min(420px,80%)]" />
    </div>
  );
}

/** DashboardSkeleton: header, a KPI strip and a chart (Overview, Usage). */
export function DashboardSkeleton({ stats = 4 }: { stats?: number }) {
  return (
    <div className="flex flex-col gap-6" role="status" aria-label="Loading">
      <HeaderSkeleton />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: stats }).map((_, i) => (
          <StatCardSkeleton key={i} />
        ))}
      </div>
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <ChartSkeleton height={220} />
      </div>
    </div>
  );
}

/** ListSkeleton: header + a table-shaped block (Sessions, Privacy cards). */
export function ListSkeleton({ rows = 6, header = true }: { rows?: number; header?: boolean }) {
  return (
    <div className="flex flex-col gap-4" role="status" aria-label="Loading">
      {header && <HeaderSkeleton />}
      <div className="rounded-3 border border-line-2 bg-bg-2 p-4">
        <TableSkeleton rows={rows} />
      </div>
    </div>
  );
}

/** CardSkeleton: a small inline block for one card's body. */
export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="flex flex-col gap-2" role="status" aria-label="Loading">
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={i === 0 ? "h-4 w-1/3" : "h-3 w-full"} />
      ))}
    </div>
  );
}

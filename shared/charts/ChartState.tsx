import type { ReactNode } from "react";
import { ChartSkeleton, Skeleton, TableSkeleton } from "../primitives/Skeleton";
import { staleClass } from "../primitives/Motion";
import { EmptyState } from "../primitives/EmptyState";
import { ErrorState } from "../primitives/ErrorState";
import { PermissionDenied } from "../primitives/PermissionDenied";
import { Icon } from "../primitives/Icon";
import { Link } from "react-router-dom";
import { Lock } from "lucide-react";
import { chartDenialLayout, chartStateMode } from "../lib/chartStateMode";
import { MountTurn } from "./MountTurn";

/** The shape the loading placeholder takes (default: a bar chart). */
export type ChartStateKind = "chart" | "table" | "list" | "donut";

// Shared loading / error / empty wrapper used by every chart slot.
// Lifted out of Overview because Cost + Analysis pages need the
// same three states with identical visual treatment.
//
// 2026-09-28 (visual upgrade): error and empty render through the shared
// ErrorState (CircleAlert + Retry) and the illustrated EmptyState.
//
// 2026-09-27 (UI review): the skeleton now matches the content's shape
// (`kind`), content that replaces a skeleton fades in once (the wrapper mounts
// when the data lands, so a background refresh never replays it), and
// `stale` dims content that belongs to the previous filter while the new
// response is in flight.
//
// 2026-09-28 (denial slot): `denied` renders the permission-denied state
// (shared PermissionDenied, compact in a short slot) inside the chart frame.
// An RBAC denial is not an error (web2 lib/apiFailure.ts): no Retry, the
// missing key named only when the caller passes it (`deniedPermission`,
// never inferred). The precedence is the ordered table in
// lib/chartStateMode.ts: denied, then the pre-existing loading > error > empty.
export function ChartState({
  loading,
  error,
  empty,
  emptyHint,
  height = 220,
  kind = "chart",
  stale,
  onRetry,
  denied,
  deniedPermission,
  deniedAccessTo,
  deniedAccessLabel,
  children,
}: {
  loading: boolean;
  error: Error | null;
  empty: boolean;
  emptyHint?: string;
  height?: number;
  kind?: ChartStateKind;
  /** Content belongs to the previous filter; dim it until the new data lands. */
  stale?: boolean;
  /** Offer a retry button on the error state. */
  onRetry?: () => void;
  /** The read was an RBAC denial (HTTP 403, e.g. web2 useApi's `denied`).
   *  Wins over every other state. */
  denied?: boolean;
  /** The missing permission key, only when the server named it (web2
   *  useApi's `deniedPermission`). Never inferred. */
  deniedPermission?: string | null;
  /** The app's own route where access is granted (shared never assumes one). */
  deniedAccessTo?: string;
  deniedAccessLabel?: string;
  children: ReactNode;
}) {
  const mode = chartStateMode({ denied, loading, error, empty });
  if (mode === "denied") {
    return (
      <ChartDenied
        height={height}
        permission={deniedPermission}
        accessTo={deniedAccessTo}
        accessLabel={deniedAccessLabel}
      />
    );
  }
  if (mode === "loading") {
    return <ShapedSkeleton kind={kind} height={height} />;
  }
  if (mode === "error") {
    return <ErrorState error={error} onRetry={onRetry} height={height} />;
  }
  if (mode === "empty") {
    // The shared illustrated empty state, inline; the art only when the slot
    // is tall enough to hold it above the line of copy.
    return (
      <div className="flex items-center justify-center overflow-hidden" style={{ height }}>
        <EmptyState
          variant="inline"
          className="py-0"
          title={emptyHint || "No data in this range"}
          illustration={height >= 160 ? "chart" : undefined}
          illustrationSize={Math.min(112, Math.round(height * 0.5))}
        />
      </div>
    );
  }
  // First mounts take turns across the page (MountTurn): charts that resolve
  // together no longer mount in one long task.
  return (
    <MountTurn fallback={<ShapedSkeleton kind={kind} height={height} />}>
      <div className={`sb-fade-in ${staleClass(stale)}`}>{children}</div>
    </MountTurn>
  );
}

// ChartDenied: the permission-denied state sized to the chart slot. A tall
// slot gets the shared PermissionDenied (locked illustration, the key when
// named, the access link); a short one gets the same copy as one compact
// lock row so the slot never jumps or clips the illustration.
function ChartDenied({
  height,
  permission,
  accessTo,
  accessLabel = "People & Access",
}: {
  height: number;
  permission?: string | null;
  accessTo?: string;
  accessLabel?: string;
}) {
  if (chartDenialLayout(height) === "illustrated") {
    return (
      <div className="flex items-center justify-center overflow-hidden" style={{ height }}>
        <PermissionDenied
          variant="inline"
          permission={permission}
          accessTo={accessTo}
          accessLabel={accessLabel}
          className="!py-0"
        />
      </div>
    );
  }
  return (
    <div
      className="sb-fade-in flex flex-col items-center justify-center gap-1 overflow-hidden px-4 text-center text-[11.5px]"
      style={{ height }}
    >
      <span className="inline-flex items-center gap-1.5 font-medium text-fg-1">
        <Icon icon={Lock} size="sm" className="text-fg-3" />
        You don&apos;t have access to this
      </span>
      <span className="max-w-lg text-fg-3">
        {permission ? (
          <>
            This needs the <code className="font-mono text-fg-2">{permission}</code> permission.
          </>
        ) : (
          "Your role does not include this."
        )}
        {accessTo && (
          <>
            {" "}
            <Link
              to={accessTo}
              className="font-medium text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
            >
              {accessLabel}
            </Link>
          </>
        )}
      </span>
    </div>
  );
}

function ShapedSkeleton({ kind, height }: { kind: ChartStateKind; height: number }) {
  if (kind === "table") {
    return (
      <div style={{ minHeight: Math.min(height, 260) }}>
        <TableSkeleton rows={Math.max(3, Math.round(height / 40))} />
      </div>
    );
  }
  if (kind === "list") {
    const rows = Math.max(3, Math.round(height / 34));
    return (
      <div className="flex flex-col gap-3" style={{ minHeight: height }} aria-hidden>
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex flex-col gap-1.5">
            <div className="flex justify-between gap-4">
              <Skeleton className="h-2.5" style={{ width: `${55 - (i % 3) * 12}%` }} />
              <Skeleton className="h-2.5 w-16" />
            </div>
            <Skeleton className="h-2" style={{ width: `${92 - i * 9}%` }} />
          </div>
        ))}
      </div>
    );
  }
  if (kind === "donut") {
    const d = Math.min(height - 20, 170);
    return (
      <div className="flex items-center gap-6" style={{ height }} aria-hidden>
        <Skeleton className="shrink-0 rounded-full" style={{ width: d, height: d }} />
        <div className="flex flex-1 flex-col gap-2.5">
          {[70, 55, 62, 40, 48].map((w, i) => (
            <Skeleton key={i} className="h-2.5" style={{ width: `${w}%` }} />
          ))}
        </div>
      </div>
    );
  }
  return <ChartSkeleton height={height} />;
}

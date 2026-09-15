import type { ReactNode } from "react";
import { ChartSkeleton } from "../primitives";

// Shared loading / error / empty wrapper used by every chart slot.
// Lifted out of Overview because Cost + Analysis pages need the
// same three states with identical visual treatment.
export function ChartState({
  loading,
  error,
  empty,
  emptyHint,
  height = 220,
  children,
}: {
  loading: boolean;
  error: Error | null;
  empty: boolean;
  emptyHint?: string;
  height?: number;
  children: ReactNode;
}) {
  if (loading) {
    return <ChartSkeleton height={height} />;
  }
  if (error) {
    return (
      <div
        className="flex items-center justify-center px-4 text-center text-[11px] text-danger"
        style={{ height }}
      >
        {error.message.slice(0, 240)}
      </div>
    );
  }
  if (empty) {
    return (
      <div
        className="flex items-center justify-center text-[11px] text-fg-3"
        style={{ height }}
      >
        {emptyHint || "No data."}
      </div>
    );
  }
  return <>{children}</>;
}

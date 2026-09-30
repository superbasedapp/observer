import clsx from "clsx";
import { CircleAlert, LoaderCircle, RefreshCw } from "lucide-react";
import { Icon } from "./Icon";
import { EmptyIllustration } from "./EmptyIllustration";

// ErrorState: the one "this failed to load" state for every app. `inline`
// (default) is a compact row for a panel or chart slot (CircleAlert + message
// + Retry); `compact` is a left-aligned row for a narrow rail or a list
// section; `page` is the full-page treatment with the `error` illustration.
// A permission denial (HTTP 403) is NOT an error: render PermissionDenied.
export function ErrorState({
  error,
  title = "Couldn't load this",
  onRetry,
  retrying,
  variant = "inline",
  height,
  className,
}: {
  /** The failure; its message is shown (trimmed). A string is shown as is. */
  error?: Error | string | null;
  title?: string;
  onRetry?: () => void;
  /** A retry is in flight: the button spins and is disabled. */
  retrying?: boolean;
  variant?: "inline" | "compact" | "page";
  /** Inline only: reserve this height (a chart slot). */
  height?: number;
  className?: string;
}) {
  const message = (typeof error === "string" ? error : error?.message ?? "").slice(0, 240);
  const retry = onRetry && (
    <button
      type="button"
      onClick={onRetry}
      disabled={retrying}
      aria-busy={retrying || undefined}
      className="sb-press disabled:cursor-progress disabled:opacity-70 inline-flex items-center gap-1.5 rounded-2 border border-line-3 px-2.5 py-1 text-[11px] font-medium text-fg-1 hover:bg-bg-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-ring"
    >
      <Icon icon={retrying ? LoaderCircle : RefreshCw} size="xs" className={retrying ? "animate-spin" : undefined} />
      {retrying ? "Retrying" : "Try again"}
    </button>
  );
  if (variant === "page") {
    return (
      <div
        role="alert"
        className={clsx(
          "sb-scale-in mx-auto flex max-w-md flex-col items-center gap-2 py-10 text-center",
          className,
        )}
      >
        <EmptyIllustration kind="error" size={160} />
        <h3 className="text-[14px] font-semibold text-fg-0">{title}</h3>
        {message && <p className="text-[12.5px] leading-relaxed text-fg-3">{message}</p>}
        {retry && <div className="mt-2">{retry}</div>}
      </div>
    );
  }
  if (variant === "compact") {
    return (
      <div
        role="alert"
        className={clsx("sb-fade-in flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px]", className)}
      >
        <span className="inline-flex items-center gap-1.5 font-medium text-danger">
          <Icon icon={CircleAlert} size="sm" />
          {title}
        </span>
        {message && <span className="min-w-0 text-fg-3">{message}</span>}
        {retry}
      </div>
    );
  }
  return (
    <div
      role="alert"
      className={clsx(
        "sb-fade-in flex flex-col items-center justify-center gap-2 px-4 text-center text-[11.5px]",
        className,
      )}
      style={height ? { height } : undefined}
    >
      <span className="inline-flex items-center gap-1.5 font-medium text-danger">
        <Icon icon={CircleAlert} size="sm" />
        {title}
      </span>
      {message && <span className="max-w-lg text-fg-3">{message}</span>}
      {retry}
    </div>
  );
}

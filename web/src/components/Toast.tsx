import { useSyncExternalStore } from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import { Icon } from "@/components/primitives";
import { X } from "lucide-react";

// Toast — a small, generic, module-level toast store rendered as
// stacked auto-dismiss notices bottom-right. Kept deliberately generic
// (text + optional variant) so any surface can raise one: the
// session-attach writer-takeover notices (LaunchTerminal §6 decision 5),
// and future one-offs.
//
// Why a module-level store instead of React context: the only existing
// toast (FirstCaptureToast) lives under <App>, but LaunchTerminal is
// mounted by LaunchDockProvider as a SIBLING of <App> (see main.tsx), so
// a context provider inside App can't reach it. A module store lets any
// component push regardless of its position in the tree; <ToastViewport>
// (mounted once beside FirstCaptureToast) is the sole renderer. This
// matches the codebase's other cross-tree state seams (the LaunchDock
// rehydrate, the dashboard-refresh CustomEvent).

export type ToastVariant = "info" | "success" | "warn" | "danger";

type Toast = { id: number; text: string; variant: ToastVariant };

const DISMISS_MS = 4000;

let counter = 0;
let toasts: Toast[] = [];
const listeners = new Set<() => void>();

function emit() {
  for (const l of listeners) l();
}

/** pushToast adds a notice and schedules its auto-dismiss (~4s). Safe to
 *  call from anywhere (event handlers, ws frames) — it's a plain module
 *  function, so long-lived closures capture a stable reference. */
export function pushToast(text: string, variant: ToastVariant = "info") {
  const id = ++counter;
  toasts = [...toasts, { id, text, variant }];
  emit();
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id);
    emit();
  }, DISMISS_MS);
}

function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id);
  emit();
}

// Dev-only test seam: lets the Playwright harness raise a toast without a
// live control frame. `import.meta.env.DEV` is statically false in a
// production build, so this whole block tree-shakes away and never ships.
if (typeof window !== "undefined" && import.meta.env.DEV) {
  (window as unknown as { __sbPushToast?: typeof pushToast }).__sbPushToast =
    pushToast;
}

/** useToast returns the stable push function for use inside components. */
export function useToast() {
  return pushToast;
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function getSnapshot() {
  return toasts;
}

const DOT: Record<ToastVariant, string> = {
  info: "bg-accent",
  success: "bg-success",
  warn: "bg-warn",
  danger: "bg-danger",
};

const BORDER: Record<ToastVariant, string> = {
  info: "border-line-2",
  success: "border-success/40",
  warn: "border-warn/40",
  danger: "border-danger/40",
};

// ToastViewport renders the live stack. Mount ONCE (App.tsx, beside
// FirstCaptureToast). Bottom-right, above the terminal dock (z-[90]).
export function ToastViewport() {
  const items = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  if (items.length === 0) return null;
  return createPortal(
    <div className="pointer-events-none fixed bottom-5 right-5 z-[90] flex flex-col items-end gap-2">
      {items.map((t) => (
        <div
          key={t.id}
          role="status"
          aria-live="polite"
          className={clsx(
            "pointer-events-auto flex max-w-[360px] items-start gap-2.5 rounded-3 border bg-bg-2 px-4 py-2.5 text-[12px] shadow-3",
            BORDER[t.variant],
          )}
        >
          <span
            aria-hidden
            className={clsx("mt-1 h-2 w-2 shrink-0 rounded-pill", DOT[t.variant])}
          />
          <span className="text-fg-1">{t.text}</span>
          <button
            type="button"
            onClick={() => dismiss(t.id)}
            className="ml-1 shrink-0 self-start text-[11px] text-fg-4 hover:text-fg-2"
            aria-label="Dismiss"
          >
            <Icon icon={X} size="xs" />
          </button>
        </div>
      ))}
    </div>,
    document.body,
  );
}

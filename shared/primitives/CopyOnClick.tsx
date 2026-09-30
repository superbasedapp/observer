import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import clsx from "clsx";
import { Check, Copy } from "lucide-react";
import { Icon } from "./Icon";
import { Tooltip } from "./Tooltip";

// CopyOnClick — wraps any content with a click-to-copy affordance.
// Hover reveals a small copy glyph; click writes `value` to the
// system clipboard and surfaces a brief "copied" toast.
//
// The toast is rendered via a portal anchored to the document body
// rather than inline, so it floats above adjacent row text and the
// page-level slide-over without being clipped by table cells or
// `overflow-hidden` ancestors. Position tracks the trigger via
// getBoundingClientRect at flash time.
export function CopyOnClick({
  value,
  resolveValue,
  children,
  className,
  title,
  ariaLabel,
}: {
  value: string;
  // resolveValue, when provided, is awaited on click and its result
  // is what actually lands in the clipboard. Used by rows whose
  // inline `value` is a truncated preview (full_text_elided) — the
  // resolver hits /api/action/<id>/full_text to retrieve the
  // untruncated body only when the operator actually clicks copy,
  // keeping the /messages payload bounded. Falls back to `value` if
  // the resolver throws or returns empty.
  resolveValue?: () => Promise<string>;
  children: React.ReactNode;
  className?: string;
  title?: React.ReactNode;
  /** Accessible name for the copy button (e.g. "Copy session id"), for
   *  content that does not read as a name on its own (an icon, a hash). */
  ariaLabel?: string;
}) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const [toast, setToast] = useState<{ top: number; left: number } | null>(
    null,
  );

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 1100);
    return () => window.clearTimeout(t);
  }, [toast]);

  const onCopy = useCallback(
    async (e: React.MouseEvent) => {
      e.stopPropagation();
      let toCopy = value;
      if (resolveValue) {
        try {
          const resolved = await resolveValue();
          if (resolved) toCopy = resolved;
        } catch {
          // Network error or 404 — fall back to the inline preview
          // value so the operator still gets SOMETHING in the
          // clipboard rather than a silent no-op.
        }
      }
      try {
        await navigator.clipboard.writeText(toCopy);
        const rect = btnRef.current?.getBoundingClientRect();
        if (rect) {
          // Anchor the toast a hair above the trigger, centered on
          // the visible content. The portal coordinate space is
          // document, so use rect (viewport) + window.scroll*.
          setToast({
            top: rect.top + window.scrollY - 6,
            left: rect.left + window.scrollX + rect.width / 2,
          });
        }
      } catch {
        // Clipboard API unavailable; leave the affordance silent.
      }
    },
    [value, resolveValue],
  );

  const tooltipBody =
    title ??
    (
      <>
        Click to copy <span className="text-fg-3">·</span>{" "}
        <span className="break-all font-mono">{value}</span>
      </>
    );

  return (
    <>
      <Tooltip content={tooltipBody} maxWidth={360}>
        <button
          ref={btnRef}
          type="button"
          onClick={onCopy}
          aria-label={ariaLabel}
          className={clsx(
            "group/copy relative inline-flex items-center gap-1 text-left transition-colors hover:text-accent",
            className,
          )}
        >
          {children}
          {/* Copy morphs to a Check while the "copied" toast shows. */}
          <Icon
            icon={toast ? Check : Copy}
            size={10}
            className={clsx(
              "transition-opacity",
              toast ? "text-success opacity-100" : "opacity-0 group-hover/copy:opacity-100",
            )}
          />
        </button>
      </Tooltip>
      {toast &&
        createPortal(
          <span
            role="status"
            aria-live="polite"
            style={{ top: toast.top, left: toast.left }}
            className="pointer-events-none fixed z-[100] -translate-x-1/2 -translate-y-full whitespace-nowrap rounded-1 border border-success/50 bg-bg-1 px-2 py-1 text-[10px] font-medium text-success shadow-drawer"
          >
            copied
          </span>,
          document.body,
        )}
    </>
  );
}

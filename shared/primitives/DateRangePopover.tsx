import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
// Inlined from web's filters module — the DS component only needs the shape,
// not the stateful URL/localStorage hook that owns it.
type CustomRange = { since: string; until: string };

// DateRangePopover — the "Custom…" range editor anchored under the
// Window chip. Styled to match ComboChip's popover (rounded-3 border
// + bg-bg-1 + shadow-drawer). Two datetime-local inputs (start /
// optional end) + Apply/Cancel. Times are entered in the browser's
// local zone and converted to RFC3339-UTC on Apply. `until` empty =
// "now" (a left-open range). Apply is disabled unless the range is
// valid: start present, and either an explicit end strictly after
// start, or a blank end with a start strictly in the past.
//
// The parent owns open/close state and provides the anchoring
// `relative` container. Escape and outside-click both close.

function toLocalInput(iso: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(
    d.getDate(),
  )}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromLocalInput(local: string): string {
  if (!local) return "";
  const d = new Date(local);
  if (Number.isNaN(d.getTime())) return "";
  return d.toISOString();
}

export function DateRangePopover({
  value,
  onApply,
  onClose,
  width = 300,
}: {
  value: CustomRange;
  onApply: (r: CustomRange) => void;
  onClose: () => void;
  width?: number;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  const [since, setSince] = useState(() => toLocalInput(value.since));
  const [until, setUntil] = useState(() => toLocalInput(value.until));

  // Click-outside + Escape close (mirrors ComboChip).
  useEffect(() => {
    function onDown(e: MouseEvent) {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target as Node)) onClose();
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  const now = Date.now();
  const sinceMs = since ? new Date(since).getTime() : NaN;
  const untilMs = until ? new Date(until).getTime() : NaN;
  const validSince = since !== "" && Number.isFinite(sinceMs);
  // `until` is optional (empty = now): a blank end resolves to the
  // present, so the start must be strictly in the past — otherwise
  // the resolved [start, now] interval is reversed/empty. When set,
  // `until` must be strictly after start.
  const validUntil =
    until === ""
      ? validSince && sinceMs < now
      : Number.isFinite(untilMs) && untilMs > sinceMs;
  const canApply = validSince && validUntil;

  function apply() {
    if (!canApply) return;
    onApply({
      since: fromLocalInput(since),
      until: until ? fromLocalInput(until) : "",
    });
  }

  const inputCls =
    "h-7 w-full appearance-none rounded-2 border border-line-2 bg-bg-1 px-2 text-[11px] text-fg-1 placeholder:text-fg-4 focus:border-accent focus:outline-none";

  return (
    <div
      ref={rootRef}
      className="absolute left-0 top-[calc(100%+4px)] z-50 overflow-hidden rounded-3 border border-line-2 bg-bg-1 p-3 shadow-drawer"
      style={{ width }}
      role="dialog"
      aria-label="Custom date range"
    >
      <div className="space-y-2.5">
        <label className="block">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
            Start
          </span>
          <input
            type="datetime-local"
            value={since}
            max={until || undefined}
            onChange={(e) => setSince(e.target.value)}
            className={inputCls}
            autoFocus
          />
        </label>
        <label className="block">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-[0.08em] text-fg-3">
            End <span className="font-normal normal-case text-fg-4">(blank = now)</span>
          </span>
          <input
            type="datetime-local"
            value={until}
            min={since || undefined}
            onChange={(e) => setUntil(e.target.value)}
            className={inputCls}
          />
        </label>
      </div>
      {!canApply && (
        <p className="mt-2 text-[10.5px] text-fg-3">
          {!validSince
            ? "Pick a start time."
            : until === ""
              ? "Start must be in the past (blank end = now)."
              : "End must be after start."}
        </p>
      )}
      <div className="mt-3 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="h-7 rounded-2 border border-line-2 bg-bg-2 px-2.5 text-[11px] text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-1"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={apply}
          disabled={!canApply}
          className={clsx(
            "h-7 rounded-2 px-2.5 text-[11px] font-semibold transition-colors",
            canApply
              ? "bg-accent text-accent-on hover:opacity-90"
              : "cursor-not-allowed bg-bg-3 text-fg-4",
          )}
        >
          Apply
        </button>
      </div>
    </div>
  );
}

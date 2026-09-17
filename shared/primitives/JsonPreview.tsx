import clsx from "clsx";
import type { ReactNode } from "react";
import { CopyOnClick } from "./CopyOnClick";

// JsonPreview — a read-only structured value (a list, a map, an API
// envelope) rendered as pretty-printed monospace with a capped height and
// a copy affordance. Replaces the bare `<pre>` blocks that rendered JSON
// on one squashed line and could not be copied.
//
// The fill is `bg-bg-3`, never `bg-bg-1`: bg-1 and bg-2 are the same white
// in the light theme, so a bg-1 block on a card has no visible edge.

export type JsonPreviewProps = {
  value: unknown;
  /** Max rendered height in px before the block scrolls. */
  maxHeight?: number;
  /** Shown when the value is null/undefined. */
  emptyLabel?: string;
  /** Hides the copy affordance (e.g. inside an already-copyable row). */
  copy?: boolean;
  /** Small caption above the block. */
  label?: ReactNode;
  className?: string;
};

// A rendered/copied block this large is already unreadable and risks
// choking the DOM / clipboard on a pathological value — cap it and say so,
// rather than silently freezing the tab.
const MAX_PREVIEW_BYTES = 256 * 1024;

/** formatJsonPreview is the exact text JsonPreview renders (before the
 *  size cap below is applied). A circular reference stringifies as
 *  "[Circular]" instead of throwing, and a bigint (JSON.stringify throws
 *  on those natively) stringifies as its decimal text. */
export function formatJsonPreview(value: unknown, emptyLabel = "(unset)"): string {
  if (value == null) return emptyLabel;
  if (typeof value === "string") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value !== "object") return String(value);
  const seen = new WeakSet<object>();
  try {
    // A throwing getter/toJSON is the only other way this can fail once
    // circular refs and bigints are handled above — caught below rather
    // than falling back to `String(value)`, which renders objects as the
    // useless "[object Object]".
    const out = JSON.stringify(
      value,
      (_key, v) => {
        if (typeof v === "bigint") return v.toString();
        if (typeof v === "object" && v !== null) {
          if (seen.has(v)) return "[Circular]";
          seen.add(v);
        }
        return v;
      },
      2,
    );
    return out ?? "[Unserializable value]";
  } catch {
    return "[Unserializable value]";
  }
}

/** capPreviewText truncates `text` to `max` bytes (UTF-16 code units are
 *  close enough here — this is a display cap, not a wire encoding) and
 *  appends a visible truncation tail naming how much was cut. */
function capPreviewText(text: string, max = MAX_PREVIEW_BYTES): string {
  if (text.length <= max) return text;
  const cut = text.length - max;
  return `${text.slice(0, max)}\n... truncated (${cut.toLocaleString()} bytes)`;
}

export function JsonPreview({
  value,
  maxHeight = 160,
  emptyLabel = "(unset)",
  copy = true,
  label,
  className,
}: JsonPreviewProps) {
  const raw = formatJsonPreview(value, emptyLabel);
  const text = capPreviewText(raw);
  const empty = value == null;
  return (
    <div className={clsx("min-w-0", className)}>
      {(label !== undefined || (copy && !empty)) && (
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="text-[10px] uppercase tracking-[0.06em] text-fg-4">
            {label}
          </span>
          {copy && !empty && (
            <CopyOnClick value={text} className="text-[10px] text-fg-3">
              copy
            </CopyOnClick>
          )}
        </div>
      )}
      <pre
        className="m-0 overflow-auto whitespace-pre-wrap break-all rounded-2 border border-line-1 bg-bg-3 px-2.5 py-1.5 font-mono text-[11.5px] leading-snug text-fg-2"
        style={{ maxHeight }}
      >
        {text}
      </pre>
    </div>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import clsx from "clsx";
import { ChevronLeft, ChevronRight } from "lucide-react";
import {
  DATE_RANGE_PRESETS,
  MINUTE_CHOICES,
  END_OF_HOUR_MINUTE,
  atTime,
  fmtSpan,
  monthGrid,
  nearestMinuteChoice,
  sameDay,
  startOfDay,
} from "../lib/dateRange";

// Inlined from web's filters module - the DS component only needs the shape,
// not the stateful URL/localStorage hook that owns it.
type CustomRange = { since: string; until: string };

// DateRangePopover - the "Custom..." range editor anchored under the
// Window chip. A picker, not a typing exercise:
//   - one-click presets (Today, Yesterday, This week, ...) apply at once;
//   - a Monday-first month calendar: click the start day, then the end
//     day (a range highlight follows); future days are disabled;
//   - hour + minute selects for each end (minute 59 on the end means
//     "through the end of that minute", so 23:59 covers the whole day);
//   - the end defaults to "Now" (a left-open range) and has a Now button.
// Everything is in the browser's local zone; Apply converts to
// RFC3339-UTC. `until` empty = now. mode="since" (the org dashboard,
// whose rollups always end now) hides the end and the ended presets.
//
// The parent owns open/close state and provides the anchoring
// `relative` container. Escape and outside-click both close.

type Field = "start" | "end";

const WEEKDAYS = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
const HOURS = Array.from({ length: 24 }, (_, h) => h);
const pad = (n: number) => String(n).padStart(2, "0");

function parseIso(iso: string): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

function fmtDay(d: Date): string {
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

export function DateRangePopover({
  value,
  onApply,
  onClose,
  mode = "range",
  width = 312,
}: {
  value: CustomRange;
  onApply: (r: CustomRange) => void;
  onClose: () => void;
  /** "since" = start only; the range always ends now. */
  mode?: "range" | "since";
  width?: number;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  const initial = useMemo(() => {
    const now = new Date();
    const since = parseIso(value.since) ?? startOfDay(now);
    const until = mode === "since" ? null : parseIso(value.until);
    return { since, until };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [startDay, setStartDay] = useState<Date>(startOfDay(initial.since));
  const [startH, setStartH] = useState(initial.since.getHours());
  const [startM, setStartM] = useState(nearestMinuteChoice(initial.since.getMinutes()));
  const [endDay, setEndDay] = useState<Date | null>(initial.until ? startOfDay(initial.until) : null);
  const [endH, setEndH] = useState(initial.until ? initial.until.getHours() : 23);
  const [endM, setEndM] = useState(initial.until ? nearestMinuteChoice(initial.until.getMinutes()) : END_OF_HOUR_MINUTE);
  const [field, setField] = useState<Field>("start");
  const [view, setView] = useState(() => ({ y: initial.since.getFullYear(), m: initial.since.getMonth() }));

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

  const now = new Date();
  const today = startOfDay(now);
  const since = atTime(startDay, startH, startM);
  const untilRaw = endDay ? atTime(endDay, endH, endM, true) : null;
  // An end at or after now is the same as "now" (a left-open range).
  const until = untilRaw && untilRaw.getTime() < now.getTime() ? untilRaw : null;
  const endMs = until ? until.getTime() : now.getTime();
  const valid = since.getTime() < now.getTime() && endMs > since.getTime();

  function pickDay(d: Date) {
    if (d.getTime() > today.getTime()) return;
    if (mode === "since" || field === "start") {
      setStartDay(d);
      if (endDay && d.getTime() > endDay.getTime()) setEndDay(null);
      if (mode === "range") setField("end");
      return;
    }
    if (d.getTime() < startDay.getTime()) {
      // Clicking before the start restarts the range from that day.
      setStartDay(d);
      setEndDay(null);
      return;
    }
    setEndDay(d);
    if (sameDay(d, today)) {
      // Ending today reads as "to now" unless the operator sets a time.
      setEndH(23);
      setEndM(END_OF_HOUR_MINUTE);
    }
  }

  function applyRange(s: Date, u: Date | null) {
    onApply({ since: s.toISOString(), until: u ? u.toISOString() : "" });
  }

  function shiftMonth(delta: number) {
    setView((v) => {
      const d = new Date(v.y, v.m + delta, 1);
      return { y: d.getFullYear(), m: d.getMonth() };
    });
  }

  const grid = monthGrid(view.y, view.m);
  const canNext = new Date(view.y, view.m + 1, 1).getTime() <= today.getTime();
  const monthLabel = new Date(view.y, view.m, 1).toLocaleDateString(undefined, { month: "long", year: "numeric" });
  const rangeEnd = endDay ?? today;
  const presets = DATE_RANGE_PRESETS.filter((p) => mode === "range" || p.openEnded);

  const selectCls =
    "h-7 rounded-2 border border-line-2 bg-bg-2 px-1.5 text-[11px] text-fg-1 focus:border-accent focus:outline-none";

  function timeSelects(h: number, m: number, setH: (n: number) => void, setM: (n: number) => void, label: string) {
    return (
      <span className="flex items-center gap-1">
        <select aria-label={`${label} hour`} value={h} onChange={(e) => setH(Number(e.target.value))} className={selectCls}>
          {HOURS.map((x) => (
            <option key={x} value={x}>
              {pad(x)}
            </option>
          ))}
        </select>
        <span className="text-fg-3">:</span>
        <select aria-label={`${label} minute`} value={m} onChange={(e) => setM(Number(e.target.value))} className={selectCls}>
          {MINUTE_CHOICES.map((x) => (
            <option key={x} value={x}>
              {pad(x)}
            </option>
          ))}
        </select>
      </span>
    );
  }

  function fieldButton(f: Field, title: string, text: string) {
    const active = mode === "range" && field === f;
    return (
      <button
        type="button"
        onClick={() => setField(f)}
        aria-pressed={active}
        className={clsx(
          "min-w-0 flex-1 rounded-2 border px-2 py-1 text-left transition-colors",
          active ? "border-accent bg-bg-2" : "border-line-2 bg-bg-1 hover:bg-bg-2",
        )}
      >
        <span className="block text-[9.5px] font-semibold uppercase tracking-[0.08em] text-fg-3">{title}</span>
        <span className="block truncate text-[11px] text-fg-1">{text}</span>
      </button>
    );
  }

  return (
    <div
      ref={rootRef}
      className="absolute left-0 top-[calc(100%+4px)] z-50 overflow-hidden rounded-3 border border-line-2 bg-bg-1 p-3 shadow-drawer"
      style={{ width }}
      role="dialog"
      aria-label={mode === "since" ? "Custom window start" : "Custom date range"}
    >
      <div className="mb-2.5 flex flex-wrap gap-1">
        {presets.map((p) => (
          <button
            key={p.key}
            type="button"
            onClick={() => {
              const r = p.resolve(new Date());
              applyRange(r.since, r.until);
            }}
            className="h-6 rounded-2 border border-line-2 bg-bg-2 px-2 text-[10.5px] text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-1"
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="mb-2 flex gap-1.5">
        {fieldButton("start", mode === "since" ? "Since" : "Start", `${fmtDay(startDay)}, ${pad(startH)}:${pad(startM)}`)}
        {mode === "range" &&
          fieldButton("end", "End", endDay ? `${fmtDay(endDay)}, ${pad(endH)}:${pad(endM)}` : "Now")}
      </div>

      <div className="mb-1 flex items-center justify-between">
        <button
          type="button"
          aria-label="Previous month"
          onClick={() => shiftMonth(-1)}
          className="grid h-6 w-6 place-items-center rounded-2 text-fg-2 hover:bg-bg-3 hover:text-fg-1"
        >
          <ChevronLeft size={14} />
        </button>
        <span className="text-[11.5px] font-semibold text-fg-1">{monthLabel}</span>
        <button
          type="button"
          aria-label="Next month"
          disabled={!canNext}
          onClick={() => shiftMonth(1)}
          className="grid h-6 w-6 place-items-center rounded-2 text-fg-2 hover:bg-bg-3 hover:text-fg-1 disabled:cursor-not-allowed disabled:opacity-30"
        >
          <ChevronRight size={14} />
        </button>
      </div>
      <div className="grid grid-cols-7 gap-y-0.5 text-center" role="grid" aria-label={monthLabel}>
        {WEEKDAYS.map((w) => (
          <span key={w} className="py-0.5 text-[9.5px] font-semibold uppercase text-fg-4">
            {w}
          </span>
        ))}
        {grid.map((d) => {
          const future = d.getTime() > today.getTime();
          const outside = d.getMonth() !== view.m;
          const isStart = sameDay(d, startDay);
          const isEnd = mode === "range" && endDay !== null && sameDay(d, endDay);
          const inRange = mode === "range" && d.getTime() > startDay.getTime() && d.getTime() < rangeEnd.getTime();
          return (
            <button
              key={d.getTime()}
              type="button"
              disabled={future}
              onClick={() => pickDay(d)}
              aria-label={fmtDay(d)}
              aria-pressed={isStart || isEnd}
              className={clsx(
                "mx-auto grid h-7 w-full place-items-center text-[11px] transition-colors",
                isStart || isEnd
                  ? "rounded-2 bg-accent font-semibold text-accent-on"
                  : inRange
                    ? "bg-bg-3 text-fg-1"
                    : outside
                      ? "rounded-2 text-fg-4 hover:bg-bg-2"
                      : "rounded-2 text-fg-1 hover:bg-bg-2",
                future && "cursor-not-allowed opacity-30 hover:bg-transparent",
                sameDay(d, today) && !(isStart || isEnd) && "underline decoration-accent underline-offset-2",
              )}
            >
              {d.getDate()}
            </button>
          );
        })}
      </div>

      <div className="mt-2.5 space-y-1.5 border-t border-line-1 pt-2.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10.5px] text-fg-3">{mode === "since" ? "Since time" : "Start time"}</span>
          {timeSelects(startH, startM, setStartH, setStartM, "Start")}
        </div>
        {mode === "range" && (
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10.5px] text-fg-3">End time</span>
            {endDay ? (
              <span className="flex items-center gap-1.5">
                {timeSelects(endH, endM, setEndH, setEndM, "End")}
                <button
                  type="button"
                  onClick={() => setEndDay(null)}
                  className="h-7 rounded-2 border border-line-2 bg-bg-2 px-2 text-[10.5px] text-fg-2 hover:bg-bg-3 hover:text-fg-1"
                >
                  Now
                </button>
              </span>
            ) : (
              <span className="text-[11px] text-fg-2">Now (pick a day to set an end)</span>
            )}
          </div>
        )}
      </div>

      <p className={clsx("mt-2 text-[10.5px]", valid ? "text-fg-3" : "text-warn")}>
        {valid
          ? `${fmtSpan(endMs - since.getTime())} window${until ? "" : ", ending now"}`
          : since.getTime() >= now.getTime()
            ? "Start must be in the past."
            : "End must be after start."}
      </p>

      <div className="mt-2.5 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="h-7 rounded-2 border border-line-2 bg-bg-2 px-2.5 text-[11px] text-fg-2 transition-colors hover:bg-bg-3 hover:text-fg-1"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={() => valid && applyRange(since, until)}
          disabled={!valid}
          className={clsx(
            "h-7 rounded-2 px-2.5 text-[11px] font-semibold transition-colors",
            valid ? "bg-accent text-accent-on hover:opacity-90" : "cursor-not-allowed bg-bg-3 text-fg-4",
          )}
        >
          Apply
        </button>
      </div>
    </div>
  );
}

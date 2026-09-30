import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useLocation, useNavigate, useNavigationType } from "react-router-dom";
import {
  FILTER_DEFAULTS,
  applyFilterParams,
  canonicalIso,
  isWindow,
  reconcileFromUrl,
  sameUrlFilters,
  validRange,
  type CustomRange,
  type UrlFilters,
  type Window,
} from "./filterUrl";
import {
  effectiveChoice,
  granParams,
  resolveGranularity,
  type GranChoice,
  type Granularity,
} from "@shared/lib/granularity";

// Window is the global time-scope selector shared by every page.
// Day-grained presets map to `days=<int>`; the two sub-day presets
// map to `hours=<int>`; "1d" is deliberately days=1 (NOT hours);
// "all" keeps each page's own far-horizon / zero sentinel; "custom"
// carries an explicit [since, until] range on the wire. The type and
// CustomRange (RFC3339-UTC strings; `until` "" = now) live in the pure
// lib/filterUrl.ts codec and are re-exported here for existing importers.
export type { CustomRange, Window };

// WindowParams is the wire-shape a window resolves to. It spreads
// cleanly into a page's QueryParams object (day preset → {days},
// sub-day preset → {hours}, custom → {since, until}).
export type WindowParams =
  | { days: number }
  | { hours: number }
  | { since: string; until: string };

export type Filters = {
  win: Window;
  customRange: CustomRange;
  tool: string;
  project: string;
  // Global free-text search, set by FilterBar's "Search anything…"
  // input. Pages opt-in by reading `query` and filtering whatever
  // makes sense for that surface (Sessions filters by id/project,
  // Actions by target, etc.). Empty string = no filter.
  query: string;
  // Chart time granularity (`gran=`), global like the window. "auto" =
  // the shared Auto rule (shared/lib/granularity.ts).
  gran: GranChoice;
};

type FilterCtx = Filters & {
  setWin: (w: Window) => void;
  setCustomRange: (r: CustomRange) => void;
  setTool: (t: string) => void;
  setProject: (p: string) => void;
  setQuery: (q: string) => void;
  setGran: (g: GranChoice) => void;
};

const Ctx = createContext<FilterCtx | null>(null);

const WIN_LS_KEY = "sb_win";
const RANGE_LS_KEY = "sb_win_range";

// The free-text query is written to the URL only after typing pauses, so a
// keystroke never rewrites the address bar (the state itself, which pages
// filter on, updates immediately).
const QUERY_URL_DEBOUNCE_MS = 400;

// readStoredRange returns a VALIDATED, canonicalized custom range or
// null. A range is valid when `since` canonicalizes and (if present)
// `until` canonicalizes AND is strictly after `since`.
function readStoredRange(): CustomRange | null {
  try {
    const raw = localStorage.getItem(RANGE_LS_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw) as { since?: unknown; until?: unknown };
    return validRange(obj.since, typeof obj.until === "string" ? obj.until : "");
  } catch {
    return null;
  }
}

// readStoredWin restores the persisted window, defaulting to "30d" on
// anything unrecognised. "custom" only survives restore when the
// stored range is itself valid — otherwise it falls back to default.
function readStoredWin(): Window {
  try {
    const v = localStorage.getItem(WIN_LS_KEY);
    if (isWindow(v)) {
      if (v === "custom") return readStoredRange() ? "custom" : "30d";
      return v;
    }
  } catch {
    // localStorage unavailable (SSR / privacy mode); fall through.
  }
  return "30d";
}

// initialFilters applies the load precedence: the URL wins, then the
// viewer's stored window/range (localStorage convenience), then defaults.
function initialFilters(): UrlFilters {
  const stored: UrlFilters = {
    ...FILTER_DEFAULTS,
    win: readStoredWin(),
    customRange: readStoredRange() ?? FILTER_DEFAULTS.customRange,
  };
  const search = typeof window === "undefined" ? "" : window.location.search;
  return reconcileFromUrl(stored, search, "pop", stored);
}

// FilterProvider owns the global filters and keeps them in the URL
// (route-aware): a change is written with a history REPLACE (never a new
// entry per keystroke), params are omitted at their default, page-owned
// params are never touched (lib/filterUrl.ts owns only its own names), an
// in-app navigation carries the active filters into the new page's URL, and
// back/forward restores them from the URL. Must render inside the router.
export function FilterProvider({ children }: { children: ReactNode }) {
  const [init] = useState(initialFilters);
  const [win, setWinState] = useState<Window>(init.win);
  const [customRange, setCustomRangeState] = useState<CustomRange>(init.customRange);
  const [tool, setTool] = useState<string>(init.tool);
  const [project, setProject] = useState<string>(init.project);
  const [query, setQuery] = useState<string>(init.query);
  const [gran, setGran] = useState<GranChoice>(init.gran);
  // urlQuery is the debounced copy of `query` that the URL carries.
  const [urlQuery, setUrlQuery] = useState<string>(init.query);
  useEffect(() => {
    if (query === urlQuery) return;
    const id = window.setTimeout(() => setUrlQuery(query), QUERY_URL_DEBOUNCE_MS);
    return () => window.clearTimeout(id);
  }, [query, urlQuery]);

  const setWin = useCallback((w: Window) => {
    setWinState(w);
    try {
      localStorage.setItem(WIN_LS_KEY, w);
    } catch {
      // Ignore; preference falls back to default on next load.
    }
  }, []);

  const setCustomRange = useCallback((r: CustomRange) => {
    // Normalize to canonical RFC3339-UTC before persisting/using, so a
    // stored range always round-trips through the strict backend even
    // if a caller ever hands us a non-canonical value.
    const norm: CustomRange = {
      since: canonicalIso(r.since) ?? "",
      until: r.until ? (canonicalIso(r.until) ?? "") : "",
    };
    setCustomRangeState(norm);
    try {
      localStorage.setItem(RANGE_LS_KEY, JSON.stringify(norm));
    } catch {
      // Ignore; preference falls back to default on next load.
    }
  }, []);

  // ---- URL sync --------------------------------------------------------
  const location = useLocation();
  const navType = useNavigationType();
  const navigate = useNavigate();
  const lastLocationKey = useRef<string | null>(null);
  useEffect(() => {
    // What the URL should carry right now (the query debounced).
    const projected: UrlFilters = { win, customRange, tool, project, query: urlQuery, gran };
    if (lastLocationKey.current !== location.key) {
      lastLocationKey.current = location.key;
      // A location change: back/forward restores from the URL; any other
      // navigation adopts what the URL carries and keeps the rest. URL-sourced
      // values are not written to localStorage (a shared link must not
      // overwrite the viewer's own preference).
      const next = reconcileFromUrl(
        projected,
        location.search,
        navType === "POP" ? "pop" : "push",
        { ...FILTER_DEFAULTS, customRange },
      );
      if (!sameUrlFilters(next, projected)) {
        setWinState(next.win);
        setCustomRangeState(next.customRange);
        setTool(next.tool);
        setProject(next.project);
        setGran(next.gran);
        if (next.query !== urlQuery) {
          setQuery(next.query);
          setUrlQuery(next.query);
        }
        // The write-back runs on the re-render with the adopted state.
        return;
      }
    }
    const desired = applyFilterParams(location.search, projected);
    if (desired !== location.search) {
      navigate(
        { pathname: location.pathname, search: desired, hash: location.hash },
        { replace: true, state: location.state },
      );
    }
  }, [location, navType, navigate, win, customRange, tool, project, urlQuery, gran]);

  const value = useMemo(
    () => ({
      win,
      customRange,
      tool,
      project,
      query,
      gran,
      setWin,
      setCustomRange,
      setTool,
      setProject,
      setQuery,
      setGran,
    }),
    [win, customRange, tool, project, query, gran, setWin, setCustomRange],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useFilters(): FilterCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useFilters must be used inside <FilterProvider>");
  return v;
}

const WINDOW_TO_DAYS: Record<
  Exclude<Window, "1h" | "12h" | "all" | "custom">,
  number
> = {
  "1d": 1,
  "7d": 7,
  "14d": 14,
  "30d": 30,
  "90d": 90,
  "1y": 365,
};

// capWindowParams clamps a resolved WindowParams to at most `maxDays`
// of span — used by pages (Compression) whose backend caps some
// endpoints at a year regardless of the global window.
function capWindowParams(p: WindowParams, maxDays: number): WindowParams {
  if ("days" in p) return { days: Math.min(p.days, maxDays) };
  if ("hours" in p) return { hours: Math.min(p.hours, maxDays * 24) };
  const untilMs = Date.parse(p.until) || Date.now();
  const minSinceMs = untilMs - maxDays * 86_400_000;
  const sinceMs = Date.parse(p.since);
  const since =
    Number.isFinite(sinceMs) && sinceMs < minSinceMs
      ? new Date(minSinceMs).toISOString()
      : p.since;
  return { since, until: p.until };
}

// windowParams is the SINGLE source of truth for turning the global
// window into query params. Pages spread the result into their
// useApi params instead of hand-rolling a daysParam. `allSentinel`
// customises the far-horizon value ("all") per endpoint family
// (36500 for most; 0 on the Cache endpoints). `maxDays` optionally
// caps the span (Compression's 1-year-capped endpoints).
export function windowParams(
  win: Window,
  custom: CustomRange,
  opts?: { allSentinel?: number; maxDays?: number },
): WindowParams {
  const allSentinel = opts?.allSentinel ?? 36500;
  let p: WindowParams;
  switch (win) {
    case "all":
      p = { days: allSentinel };
      break;
    case "1h":
      p = { hours: 1 };
      break;
    case "12h":
      p = { hours: 12 };
      break;
    case "custom": {
      // Defensive: an invalid stored custom range shouldn't reach
      // here (readStoredWin downgrades it), but if it does, fall back
      // to the 30-day default rather than emitting a bad range. Both
      // ends are re-canonicalized so the wire value is always a
      // timezone-explicit UTC string the strict backend accepts.
      const since = canonicalIso(custom.since);
      if (!since) {
        p = { days: 30 };
        break;
      }
      const until = canonicalIso(custom.until) ?? new Date().toISOString();
      p = { since, until };
      break;
    }
    default:
      p = { days: WINDOW_TO_DAYS[win] };
      break;
  }
  if (opts?.maxDays != null) p = capWindowParams(p, opts.maxDays);
  return p;
}

const WINDOW_SPAN_HOURS: Record<
  Exclude<Window, "all" | "custom">,
  number
> = {
  "1h": 1,
  "12h": 12,
  "1d": 24,
  "7d": 168,
  "14d": 336,
  "30d": 720,
  "90d": 2160,
  "1y": 8760,
};

// windowSpanHours returns the window's span in hours (Infinity for
// "all"). The chart granularity (useGranularity) derives from it through
// the shared rule in shared/lib/granularity.ts - never an inline span
// threshold.
export function windowSpanHours(win: Window, custom: CustomRange): number {
  if (win === "all") return Infinity;
  if (win === "custom") {
    const since = Date.parse(custom.since);
    const until = custom.until ? Date.parse(custom.until) : Date.now();
    // A non-finite or REVERSED range (until <= since) is invalid.
    // Signal it as Infinity rather than clamping to 0 — a 0 span
    // reads as "sub-day" and would wrongly select bucket=hour.
    if (!Number.isFinite(since) || !Number.isFinite(until) || until <= since) {
      return Infinity;
    }
    return (until - since) / 3_600_000;
  }
  return WINDOW_SPAN_HOURS[win];
}

// windowDaysApprox returns an integer day-count for the few surfaces
// that need a plain number rather than the wire params (the Sessions
// calendar span, the verbosity endpoint's since_days). Sub-day
// windows round up to 1 day.
export function windowDaysApprox(
  win: Window,
  custom: CustomRange,
  allSentinel = 36500,
): number {
  const h = windowSpanHours(win, custom);
  if (!Number.isFinite(h)) return allSentinel;
  return Math.max(1, Math.ceil(h / 24));
}

function fmtRangePart(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "?";
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

const WINDOW_SHORT_LABEL: Partial<Record<Window, string>> = {
  all: "All",
};

// windowLabel is the compact chip / sub-heading label for a window.
// Presets render as their key ("1h", "30d", "1y"); "all" → "All";
// "custom" → "Jul 10 → Jul 16" (or "Jul 10 → now" for an open end).
export function windowLabel(win: Window, custom: CustomRange): string {
  if (win === "custom") {
    const start = custom.since ? fmtRangePart(custom.since) : "?";
    const end = custom.until ? fmtRangePart(custom.until) : "now";
    return `${start} → ${end}`;
  }
  return WINDOW_SHORT_LABEL[win] ?? win;
}

// GranularityState is what a time-series card needs: the viewer's choice
// (for the control), the window span, the query params to send, and the
// setter. `params.gran` is the EFFECTIVE choice (a choice the span no
// longer allows falls back to "auto", so a stale `gran=5m` after widening
// the window never produces a server 400).
export type GranularityState = {
  choice: GranChoice;
  spanMs: number;
  /** The granularity Auto (or the choice) resolves to for this span. */
  expected: Granularity;
  params: { gran: GranChoice; tz: string };
  setGran: (g: GranChoice) => void;
};

// useGranularity binds the global `gran=` choice to the global window. An
// optional `only` restricts the surface (e.g. DAILY_ONLY).
export function useGranularity(only?: readonly Granularity[]): GranularityState {
  const { win, customRange, gran, setGran } = useFilters();
  const spanMs = windowSpanHours(win, customRange) * 3_600_000;
  const eff = effectiveChoice(gran, spanMs, only);
  const params = useMemo(() => granParams(eff), [eff]);
  return {
    choice: gran,
    spanMs,
    expected: resolveGranularity(gran, spanMs, only),
    params,
    setGran,
  };
}

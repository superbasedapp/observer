import {
  createContext,
  lazy,
  Suspense,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { clampStepIndex, shouldAutoStart, type TourStep } from "../../lib/tour";

// TourProvider owns the guided tour's state and the first-run auto-start gate
// for BOTH dashboards (T-447: promoted from web/src/components/tour). Each app
// wraps it in a thin adapter that passes its own steps (already filtered to
// the pages the viewer may open) and its own completion key. Mount it INSIDE
// the router: the overlay it lazy-renders navigates between steps.
//
// Persistence: localStorage `storageKey = "1"` once the user finishes OR
// skips. Every read and write is wrapped in try/catch, so a private-mode
// browser degrades to "tour always available, never auto-persisted".

const AUTO_START_DELAY_MS = 600;

function hasCompleted(key: string): boolean {
  try {
    return localStorage.getItem(key) === "1";
  } catch {
    return false;
  }
}

function markCompleted(key: string): void {
  try {
    localStorage.setItem(key, "1");
  } catch {
    // ignore: persistence is best-effort (private mode / disabled storage)
  }
}

export type TourContextValue = {
  active: boolean;
  stepIndex: number;
  steps: TourStep[];
  startTour: () => void;
  endTour: (completed: boolean) => void;
  next: () => void;
  back: () => void;
  goTo: (index: number) => void;
};

const TourContext = createContext<TourContextValue | null>(null);

// useTour reads the tour context. Throws if used outside <TourProvider>
// so a mis-wire fails loudly at dev time rather than silently no-op'ing.
export function useTour(): TourContextValue {
  const ctx = useContext(TourContext);
  if (!ctx) {
    throw new Error("useTour must be used within <TourProvider>");
  }
  return ctx;
}

// Overlay is its own lazy chunk: the spotlight/floating-ui code never enters
// the shell bundle and only downloads once the tour runs.
const TourOverlay = lazy(() => import("./TourOverlay").then((m) => ({ default: m.TourOverlay })));

export type TourProviderProps = {
  steps: TourStep[];
  /** localStorage key recording that this viewer finished or skipped. */
  storageKey: string;
  /**
   * Called when the viewer finishes or skips the tour, beside the
   * localStorage mark: an app that also keeps the mark elsewhere (the node
   * dashboard keeps it on its daemon, WINNODE2 16b) records it there.
   */
  onComplete?: () => void;
  /** Start on first visit (desktop only). Default true. */
  autoStart?: boolean;
  children: ReactNode;
};

export function TourProvider({ steps, storageKey, autoStart = true, onComplete, children }: TourProviderProps) {
  const [active, setActive] = useState(false);
  const [stepIndex, setStepIndex] = useState(0);
  const stepCountRef = useRef(steps.length);
  useEffect(() => {
    stepCountRef.current = steps.length;
  }, [steps.length]);

  // activeRef mirrors `active` so the deferred auto-start timer can bail if a
  // manual start won the race, without re-subscribing the timer.
  const activeRef = useRef(active);
  useEffect(() => {
    activeRef.current = active;
  }, [active]);

  // The element that had focus when the tour opened (Help button, command
  // palette item, or whatever was focused at auto-start). Restored on any exit
  // so focus doesn't collapse to <body> after the overlay unmounts.
  const lastFocusedRef = useRef<HTMLElement | null>(null);

  const captureFocus = useCallback(() => {
    const el = document.activeElement;
    lastFocusedRef.current = el instanceof HTMLElement ? el : null;
  }, []);

  const restoreFocus = useCallback(() => {
    const el = lastFocusedRef.current;
    lastFocusedRef.current = null;
    if (!el) return;
    // Defer past the overlay unmount, then restore only if the element is
    // still connected and focusable; else no-op (never throw).
    requestAnimationFrame(() => {
      if (el.isConnected && typeof el.focus === "function") {
        el.focus();
      }
    });
  }, []);

  const startTour = useCallback(() => {
    // Manual entry ignores the width gate + the completed flag (replay).
    captureFocus();
    setStepIndex(0);
    setActive(true);
  }, [captureFocus]);

  const endTour = useCallback(
    (completed: boolean) => {
      setActive(false);
      setStepIndex(0);
      if (completed) {
        markCompleted(storageKey);
        onComplete?.();
      }
      restoreFocus();
    },
    [restoreFocus, storageKey, onComplete],
  );

  const next = useCallback(() => {
    setStepIndex((i) => clampStepIndex(i + 1, stepCountRef.current));
  }, []);

  const back = useCallback(() => {
    setStepIndex((i) => clampStepIndex(i - 1, stepCountRef.current));
  }, []);

  const goTo = useCallback((index: number) => {
    setStepIndex(() => clampStepIndex(index, stepCountRef.current));
  }, []);

  // Auto-start: fire at most once on a real mount, ~600ms after mount, only
  // when the flag is absent and the desktop rail is present. A `mounted`
  // generation guard + clearTimeout in cleanup means React 18 StrictMode's
  // mount/cleanup/mount double-invoke reschedules cleanly and no setter lands
  // on an unmounted fiber. The activeRef re-guard still lets a manual start
  // win the race.
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!shouldAutoStart({ enabled: autoStart, completed: hasCompleted(storageKey), width: window.innerWidth })) return;
    let mounted = true;
    const id = window.setTimeout(() => {
      if (!mounted) return;
      if (activeRef.current) return; // a manual start already opened it
      if (hasCompleted(storageKey)) return; // finished/skipped in the interim
      captureFocus();
      setStepIndex(0);
      setActive(true);
    }, AUTO_START_DELAY_MS);
    return () => {
      mounted = false;
      window.clearTimeout(id);
    };
  }, [captureFocus, autoStart, storageKey]);

  const value = useMemo<TourContextValue>(
    () => ({ active, stepIndex, steps, startTour, endTour, next, back, goTo }),
    [active, stepIndex, steps, startTour, endTour, next, back, goTo],
  );

  return (
    <TourContext.Provider value={value}>
      {children}
      {active && (
        <Suspense fallback={null}>
          <TourOverlay />
        </Suspense>
      )}
    </TourContext.Provider>
  );
}

// deferredShow: the timing rules for every mascot loader (D-665..D-669,
// proposal "Timing"), as a framework-free controller with the clock
// injected. The React binding is shared/lib/useDeferredShow.ts.
//
//   - nothing shows for a wait under `delayMs` (300 ms): no flash;
//   - once shown, it stays at least `minMs` (600 ms), so it never blinks in
//     and out;
//   - after `slowMs` (8 s) of the same wait, `slow` turns on: the caller
//     shows one honest line naming what is being waited on;
//   - a failure stops it at once (no cheerful flight over an error) until
//     the wait ends and a new one starts.

/** Timing options; every field has the proposal's default. */
export type DeferredShowOptions = {
  delayMs?: number;
  minMs?: number;
  slowMs?: number;
};

/** What the caller renders. */
export type DeferredShowView = { show: boolean; slow: boolean };

/** The injected clock (window timers in the app, a fake in tests). */
export type DeferredShowClock = {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
};

/** DEFERRED_SHOW_DEFAULTS are the proposal's numbers. */
export const DEFERRED_SHOW_DEFAULTS = { delayMs: 300, minMs: 600, slowMs: 8000 } as const;

/** The controller a hook or a test drives. */
export type DeferredShowController = {
  /** Report the current wait: `active` while waiting, `failed` once it failed. */
  update(active: boolean, failed?: boolean): void;
  /** Cancel every pending timer. */
  dispose(): void;
  /** The view right now. */
  view(): DeferredShowView;
};

/**
 * createDeferredShow returns a controller that calls `onChange` whenever the
 * view changes. It owns its timers; the caller only reports state.
 */
export function createDeferredShow(
  opts: DeferredShowOptions,
  onChange: (v: DeferredShowView) => void,
  clock: DeferredShowClock,
): DeferredShowController {
  const delayMs = opts.delayMs ?? DEFERRED_SHOW_DEFAULTS.delayMs;
  const minMs = opts.minMs ?? DEFERRED_SHOW_DEFAULTS.minMs;
  const slowMs = opts.slowMs ?? DEFERRED_SHOW_DEFAULTS.slowMs;

  let view: DeferredShowView = { show: false, slow: false };
  let waiting = false; // a wait is in progress (active seen, not yet ended)
  let stopped = false; // the current wait failed
  let shownAt = 0;
  let tShow: unknown = null;
  let tSlow: unknown = null;
  let tHide: unknown = null;

  const set = (next: DeferredShowView) => {
    if (next.show === view.show && next.slow === view.slow) return;
    view = next;
    onChange(view);
  };
  const clear = (h: unknown) => {
    if (h != null) clock.clearTimeout(h);
  };
  const clearAll = () => {
    clear(tShow);
    clear(tSlow);
    clear(tHide);
    tShow = tSlow = tHide = null;
  };

  function start() {
    waiting = true;
    stopped = false;
    clearAll();
    tShow = clock.setTimeout(() => {
      tShow = null;
      shownAt = clock.now();
      set({ show: true, slow: view.slow });
    }, delayMs);
    tSlow = clock.setTimeout(() => {
      tSlow = null;
      set({ show: view.show, slow: true });
    }, slowMs);
  }

  function end() {
    waiting = false;
    clear(tShow);
    clear(tSlow);
    tShow = tSlow = null;
    if (!view.show) {
      set({ show: false, slow: false });
      return;
    }
    const hold = Math.max(0, shownAt + minMs - clock.now());
    if (hold === 0) {
      set({ show: false, slow: false });
      return;
    }
    tHide = clock.setTimeout(() => {
      tHide = null;
      set({ show: false, slow: false });
    }, hold);
  }

  return {
    update(active, failed = false) {
      if (failed) {
        if (!stopped) {
          stopped = true;
          clearAll();
          set({ show: false, slow: false });
        }
        waiting = active;
        return;
      }
      if (stopped) {
        // Stay stopped until the failed wait ends; a fresh wait restarts.
        if (!active) {
          stopped = false;
          waiting = false;
        }
        return;
      }
      if (active && !waiting) {
        if (tHide != null) {
          // Back to waiting inside the minimum hold: keep showing.
          clear(tHide);
          tHide = null;
          waiting = true;
          tSlow = clock.setTimeout(() => {
            tSlow = null;
            set({ show: view.show, slow: true });
          }, slowMs);
          return;
        }
        start();
      } else if (!active && waiting) {
        end();
      }
    },
    dispose() {
      clearAll();
    },
    view() {
      return view;
    },
  };
}

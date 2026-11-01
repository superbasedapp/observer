import { useEffect, useRef, useState } from "react";
import { createDeferredShow, type DeferredShowController, type DeferredShowOptions, type DeferredShowView } from "./deferredShow";

// useDeferredShow is the React binding of shared/lib/deferredShow.ts: 300 ms
// delay, 600 ms minimum once shown, `slow` after 8 s, and a failure stops it.
// The timing rules live in the controller (pure, unit-tested); this file only
// wires real timers and re-renders on a change.

const windowClock = {
  now: () => (typeof performance !== "undefined" ? performance.now() : Date.now()),
  setTimeout: (fn: () => void, ms: number): unknown => setTimeout(fn, ms),
  clearTimeout: (h: unknown) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

/** useDeferredShow reports whether a loader for this wait should be on screen. */
export function useDeferredShow(
  active: boolean,
  opts: DeferredShowOptions & { failed?: boolean } = {},
): DeferredShowView {
  const [view, setView] = useState<DeferredShowView>({ show: false, slow: false });
  const ctl = useRef<DeferredShowController | null>(null);
  if (ctl.current === null) {
    ctl.current = createDeferredShow(opts, setView, windowClock);
  }
  useEffect(() => {
    ctl.current?.update(active, opts.failed ?? false);
  }, [active, opts.failed]);
  useEffect(() => () => ctl.current?.dispose(), []);
  return view;
}

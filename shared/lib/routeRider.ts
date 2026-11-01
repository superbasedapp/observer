import { useEffect, useReducer } from "react";

// routeRider decides when Obs rides the TopProgress line: on a SLOW ROUTE
// LOAD only (D-665..D-669). A route load starts when the route key changes
// (or the app first mounts) and ends the first time the foreground requests
// it started settle. A filter change, a refetch or polling on the same page
// later keeps the plain bar, never the mascot. TopProgress itself keeps the
// 250 ms threshold, so a fast load shows neither.
//
// The decision is the pure reducer below (table of events, one test each);
// useRouteRider is the React binding.

/** Reducer state. */
export type RouteRiderState = {
  routeKey: string;
  /** Inside a route load. */
  armed: boolean;
  /** The route load's requests have started. */
  sawActive: boolean;
};

/** Events: a render with the current route and activity, or the arm window
 *  closing with nothing started. */
export type RouteRiderEvent = { type: "tick"; routeKey: string; active: boolean } | { type: "expire" };

/** A route load that never starts a request disarms after this long. */
export const ROUTE_RIDER_ARM_MS = 1500;

/** routeRiderInit arms the first load (the app's own cold route). */
export function routeRiderInit(routeKey: string): RouteRiderState {
  return { routeKey, armed: true, sawActive: false };
}

/** routeRiderStep is the reducer. */
export function routeRiderStep(s: RouteRiderState, e: RouteRiderEvent): RouteRiderState {
  if (e.type === "expire") return s.armed && !s.sawActive ? { ...s, armed: false } : s;
  if (e.routeKey !== s.routeKey) return { routeKey: e.routeKey, armed: true, sawActive: e.active };
  if (!s.armed) return s;
  if (e.active && !s.sawActive) return { ...s, sawActive: true };
  if (!e.active && s.sawActive) return { ...s, armed: false };
  return s;
}

/** routeRiderShows: the rider is on while a route load's requests run. */
export function routeRiderShows(s: RouteRiderState, active: boolean): boolean {
  return s.armed && active;
}

/** useRouteRider returns whether Obs should ride the progress line now. */
export function useRouteRider(routeKey: string, active: boolean): boolean {
  const [s, dispatch] = useReducer(routeRiderStep, routeKey, routeRiderInit);
  useEffect(() => {
    dispatch({ type: "tick", routeKey, active });
  }, [routeKey, active]);
  useEffect(() => {
    if (!s.armed || s.sawActive) return;
    const t = setTimeout(() => dispatch({ type: "expire" }), ROUTE_RIDER_ARM_MS);
    return () => clearTimeout(t);
  }, [s.armed, s.sawActive, s.routeKey]);
  return routeRiderShows(s, active) && s.routeKey === routeKey;
}

// Pins shared/lib/routeRider.ts (D-665..D-669): Obs rides the TopProgress
// line only during a route load, never for a later filter change, refetch or
// poll on the same page.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  routeRiderInit,
  routeRiderShows,
  routeRiderStep,
  type RouteRiderEvent,
  type RouteRiderState,
} from "../../../shared/lib/routeRider.ts";

type Row = { name: string; events: Array<[route: string, active: boolean] | "expire">; shows: boolean };
const ROWS: Row[] = [
  { name: "cold load with requests in flight rides", events: [["/a", true]], shows: true },
  { name: "cold load settles: rider stops", events: [["/a", true], ["/a", false]], shows: false },
  { name: "a refetch on the same page after the load keeps the plain bar", events: [["/a", true], ["/a", false], ["/a", true]], shows: false },
  { name: "navigating re-arms", events: [["/a", true], ["/a", false], ["/b", false], ["/b", true]], shows: true },
  { name: "a route that started its requests with the navigation rides", events: [["/a", false], ["/b", true]], shows: true },
  { name: "a route that never starts a request disarms after the window", events: [["/a", false], "expire", ["/a", true]], shows: false },
  { name: "the window does not cut a load that already started", events: [["/a", true], "expire"], shows: true },
];

for (const r of ROWS) {
  test(r.name, () => {
    let s: RouteRiderState = routeRiderInit("/a");
    let active = false;
    for (const e of r.events) {
      const ev: RouteRiderEvent = e === "expire" ? { type: "expire" } : { type: "tick", routeKey: e[0], active: e[1] };
      if (e !== "expire") active = e[1];
      s = routeRiderStep(s, ev);
    }
    assert.equal(routeRiderShows(s, active), r.shows);
  });
}

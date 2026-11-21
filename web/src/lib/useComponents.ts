import { useEffect, useMemo, useSyncExternalStore } from "react";
import { apiCache, useApi, type ApiState } from "./useApi";
import { NAV_COMPONENTS } from "./components.gen";
import {
  inactiveNavIds,
  inactiveRoutesSnapshot,
  setInactiveRoutes,
  subscribeInactiveRoutes,
  tileVisible,
  type TileOwner,
  type CatalogComponent,
  type CatalogReport,
  type ComponentsStateResponse,
} from "./componentState";

// useComponents: the React side of lib/componentState (modular packaging plan
// section 7, lane MP-DASH). One state read and one catalog read, both shared
// through the query cache, so the sidebar, the route guard and the Settings >
// Components page ask the daemon once.

/** How often the shell re-reads the component state while visible. A change
 *  made on the Components page reloads it at once; this only catches a hand
 *  edit of config.toml or an `observer components` run in a terminal. */
const COMPONENT_STATE_REFRESH_MS = 30_000;

/** The component state read, and the AI Apps routes probe (useObsRoutesUp). */
export const COMPONENT_STATE_PATH = "/api/components/state";
export const OBS_ROUTES_PROBE_PATH = "/api/obs/enabled";

/** The reads an AI Apps on or off changes at once: the component state (the
 *  route guard, the fetch skip list, the nav) and the routes probe. */
export const APPS_CHANGE_REFRESH_PATHS: readonly string[] = [COMPONENT_STATE_PATH, OBS_ROUTES_PROBE_PATH];

/** refreshAfterAppsChange re-reads them now, after POST /api/apps/enable or
 *  /disable answers (review FR-M10): a hot enable makes the obs component
 *  active and opens the AI Apps routes while the daemon runs, and without
 *  this the AI Apps links read "not installed" and the /api/obs reads stay
 *  skipped until the next 30 s poll. invalidate is the query cache's own
 *  mutation hook, injectable for tests. */
export function refreshAfterAppsChange(invalidate: (key: string) => void = (k) => apiCache.invalidate(k)): void {
  for (const p of APPS_CHANGE_REFRESH_PATHS) invalidate(p);
}

/** useComponentState reads GET /api/components/state and keeps the fetch
 *  skip list (lib/componentState) in step with it. */
export function useComponentState(): ApiState<ComponentsStateResponse> {
  const st = useApi<ComponentsStateResponse>(COMPONENT_STATE_PATH, undefined, [], {
    refreshMs: COMPONENT_STATE_REFRESH_MS,
  });
  const routes = st.data ? st.data.inactive_routes.join("\n") : null;
  useEffect(() => {
    if (routes != null) setInactiveRoutes(routes ? routes.split("\n") : []);
  }, [routes]);
  return st;
}

/** useComponentCatalog reads GET /api/components (static per binary). */
export function useComponentCatalog(): ApiState<CatalogReport> {
  return useApi<CatalogReport>("/api/components");
}

/** useCatalogRow returns one catalog row by id, or undefined. */
export function useCatalogRow(id: string | undefined): CatalogComponent | undefined {
  const cat = useComponentCatalog();
  return useMemo(() => cat.data?.components.find((c) => c.id === id), [cat.data, id]);
}

/** useInactiveNavIds lists the nav ids whose component is not active. Empty
 *  until the state is known (fail open: a slow read never hides a page). */
export function useInactiveNavIds(): string[] {
  const st = useComponentState();
  const view = st.data?.view;
  return useMemo(() => inactiveNavIds(view, NAV_COMPONENTS), [view]);
}

/** useTileVisible returns the tile gate (lib/componentState tileVisible) bound
 *  to this node's component state; it re-renders when the state or the
 *  inactive-route list changes, and shows every tile until the state is known. */
export function useTileVisible(): (owner: TileOwner) => boolean {
  const st = useComponentState();
  // Subscribing re-renders the reader when the inactive-route list changes;
  // tileVisible reads that list from the module store.
  useSyncExternalStore(subscribeInactiveRoutes, inactiveRoutesSnapshot, inactiveRoutesSnapshot);
  const view = st.data?.view;
  return (owner: TileOwner) => tileVisible(view, owner);
}

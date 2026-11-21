import { useApi } from "./useApi";
import { APPS_NAV_IDS } from "./nav";

// useObsRoutesUp - whether this machine's /api/obs routes answer (app
// observability is on and the daemon has loaded it): GET /api/obs/enabled is
// registered only then. Shared by the nav (the Your apps group) and the
// Your apps pages' gate (Plane A lane B5).

/** useObsRoutesUp: true when the probe answered enabled, false when it
 *  failed (404, or the SPA shell), null while in flight. */
export function useObsRoutesUp(): boolean | null {
  const probe = useApi<{ enabled?: boolean }>("/api/obs/enabled", undefined, [], { refreshMs: 30_000 });
  if (probe.data) return probe.data.enabled === true;
  if (probe.error) return false;
  return null;
}

/** useAppsNavHidden lists the Your apps nav ids to leave out: all of them
 *  until the routes answer (a slow probe keeps them out rather than flash
 *  pages that would show the first-run card). */
export function useAppsNavHidden(): readonly string[] {
  return useObsRoutesUp() === true ? [] : APPS_NAV_IDS;
}

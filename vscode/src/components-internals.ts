// Pure logic of the extension's component gate (modular packaging, T-670).
// No vscode import, so test/unit/components.test.ts exercises it directly.
//
// The daemon's GET /api/components/state says which catalog components are
// active on this machine and which routes belong to inactive ones (the same
// read the dashboard's nav filter and fetch skip use). The extension hides a
// view whose component is not active instead of rendering it dead: the cache
// status bar (its route belongs to the analytics component) and the proxied
// terminal commands (they need the API proxy component). It branches on
// component ids and routes, never on a tool name, and fails OPEN: a slow or
// failed read, an older daemon without the route, or an unknown id shows
// everything as it did before.

/** The subset of GET /api/components/state the extension reads. */
export interface ComponentsStateLite {
  view?: { components?: { id: string; state: string }[] | null } | null;
  inactive_routes?: string[] | null;
}

/** One gated extension surface: the context key it sets and what it needs. */
export interface GatedSurface {
  /** VS Code context key set to true while the surface's need is inactive. */
  contextKey: string;
  /** Catalog component id the surface needs active. */
  component?: string;
  /** Daemon route the surface reads. */
  route?: string;
}

/**
 * GATED_SURFACES is the table of extension surfaces that belong to an
 * optional component. package.json's commandPalette `when` clauses read the
 * context keys; the cache status bar reads its route.
 */
export const GATED_SURFACES: readonly GatedSurface[] = [
  // Launch Claude / Codex (proxied), Copy proxy env vars, and the proxied
  // terminal profile all point a tool at the local proxy.
  { contextKey: 'observer.proxyInactive', component: 'capture.proxy' },
  // The cache-expiry status bar polls this route.
  { contextKey: 'observer.cacheStatusInactive', route: '/api/cache/status' },
  // Code security diagnostics, status bar and "Show code security
  // findings" (lane sec-c3) belong to the security module.
  { contextKey: 'observer.securityInactive', component: 'security' },
];

/** isComponentInactive: true only when the view lists the id and it is not active. */
export function isComponentInactive(st: ComponentsStateLite | undefined, id: string): boolean {
  if (!st || !id || id === 'core') return false;
  const row = (st.view?.components ?? []).find((c) => c.id === id);
  return row ? row.state !== 'active' : false;
}

/**
 * routeMatches mirrors the dashboard's matcher (web/src/lib/concealedRoutes.ts)
 * over a registered route pattern: exact, a "/x/" prefix, "{name}" one
 * segment, "{name...}" the rest.
 */
export function routeMatches(pathname: string, pattern: string): boolean {
  if (!pattern.includes('{')) {
    return pattern.endsWith('/') ? pathname.startsWith(pattern) : pathname === pattern;
  }
  const want = pattern.split('/');
  const got = pathname.split('/');
  for (let i = 0; i < want.length; i++) {
    const seg = want[i];
    if (seg.startsWith('{') && seg.endsWith('...}')) return got.length > i;
    if (i >= got.length) return false;
    if (seg.startsWith('{') && seg.endsWith('}')) {
      if (got[i] === '') return false;
      continue;
    }
    if (seg !== got[i]) return false;
  }
  return got.length === want.length;
}

/**
 * isRouteInactive: true when path matches a registered route of an inactive
 * component. A listed route may carry a method prefix ("GET /api/x").
 */
export function isRouteInactive(st: ComponentsStateLite | undefined, path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0] || '/';
  return (st?.inactive_routes ?? []).some((r) => routeMatches(pathname, r.replace(/^[A-Z]+ /, '')));
}

/** surfaceInactive applies one GATED_SURFACES row. */
export function surfaceInactive(st: ComponentsStateLite | undefined, s: GatedSurface): boolean {
  return (!!s.component && isComponentInactive(st, s.component)) || (!!s.route && isRouteInactive(st, s.route));
}

/** contextValues is every gated context key's value for one state read. */
export function contextValues(st: ComponentsStateLite | undefined): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const s of GATED_SURFACES) out[s.contextKey] = surfaceInactive(st, s);
  return out;
}

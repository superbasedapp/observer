// entityLinks — the ONE table-driven map from a platform entity
// (a coding session, a developer, a project, a team, a model, a trace, a
// dataset, …) to the route that shows it.
//
// One owner. Every surface that renders an entity id or an entity name as
// something clickable resolves through this table:
//
//   - the `EntityLink` primitive (shared/primitives/EntityLink.tsx) — the
//     component every dashboard call site uses;
//   - the org dashboard's assistant chat (web2/src/lib/entityLinks.ts, which
//     re-exports this module and adds the `sb://` remark plugin on top).
//
// Keeping the table here rather than in a page means a route change is a
// one-line edit, and a destination can never drift per call site — the class
// of bug this module was extracted to end (two coding pages linked at
// `/sessions?session=` while the sessions page only ever read `?focus=`, so
// both links silently landed on an unfiltered list).
//
// Pure TypeScript: no React import, no router import, no I/O. Unit-tested
// directly (web2/src/lib/entityLinks.test.ts runs under `node --test`).

// -----------------------------------------------------------------------------
// The kind table. One row per entity kind this platform knows about — see
// docs/plans/assistant-ui-library-evaluation-2026-08-16.md for the wider
// evaluation the sb:// half of this table is part of.
// -----------------------------------------------------------------------------

export type EntityKind =
  | "trace"
  | "session"
  | "coding-session"
  | "dataset"
  | "coding-dataset"
  | "job"
  | "coding-job"
  | "policy"
  | "provider"
  | "enduser"
  | "developer"
  | "project"
  | "team"
  | "model";

interface EntityRoute {
  // Whether this kind takes an id. Id-less kinds (policy) ignore any id
  // that was parsed and always resolve to the same route.
  hasId: boolean;
  // Builds the react-router `to` target. Called with the id only when
  // hasId is true (empty string otherwise).
  to: (id: string) => string;
  // Short human label used as the link's accessible name / fallback text
  // when the surrounding markdown didn't supply its own link text.
  label: (id: string) => string;
}

const ENTITY_ROUTES: Record<EntityKind, EntityRoute> = {
  trace: { hasId: true, to: (id) => `/trajectories/${id}`, label: (id) => `trace ${short(id)}` },
  // ObsTrajectoriesPage reads ?session= on mount (see Assistant-driven wiring
  // added alongside this module) and pre-fills its session filter.
  session: { hasId: true, to: (id) => `/trajectories?session=${encodeURIComponent(id)}`, label: (id) => `session ${short(id)}` },
  // SessionsPage consumes ?focus= on mount and opens that session's drawer.
  // It has never read ?session= — see the module header.
  "coding-session": { hasId: true, to: (id) => `/sessions?focus=${encodeURIComponent(id)}`, label: (id) => `coding session ${short(id)}` },
  dataset: { hasId: true, to: (id) => `/trajectories/datasets/${id}`, label: (id) => `dataset ${short(id)}` },
  "coding-dataset": { hasId: true, to: (id) => `/coding/datasets/${id}`, label: (id) => `dataset ${short(id)}` },
  job: { hasId: true, to: (id) => `/trajectories/workflows/${id}`, label: (id) => `job ${short(id)}` },
  "coding-job": { hasId: true, to: (id) => `/coding/workflows/${id}`, label: (id) => `job ${short(id)}` },
  // policy/provider/enduser land on their list/registry page rather than a
  // per-id detail route — none of those pages expose an id-addressable
  // detail view today (checked 2026-08-16), so linking to the list is
  // honest; a wrong deep link would be worse than a plain list link.
  policy: { hasId: false, to: () => "/policy", label: () => "policy" },
  provider: { hasId: true, to: () => "/intelligence", label: (id) => `provider ${short(id)}` },
  enduser: { hasId: true, to: () => "/trajectories/end-users", label: (id) => `end user ${short(id)}` },
  // The org-rollup identities. `developer` keys on the org member's user_id
  // (never their email — /people/:userId is the route param).
  developer: { hasId: true, to: (id) => `/people/${encodeURIComponent(id)}`, label: (id) => `developer ${short(id)}` },
  project: { hasId: true, to: (id) => `/projects/${encodeURIComponent(id)}`, label: (id) => `project ${short(id)}` },
  team: { hasId: true, to: (id) => `/teams/${encodeURIComponent(id)}`, label: (id) => `team ${short(id)}` },
  // A model has no detail page: /models is a leaderboard keyed on the model
  // string, and the canonical "show me this model" destination the Models
  // page itself links to is the session list filtered by model.
  model: { hasId: true, to: (id) => `/sessions?model=${encodeURIComponent(id)}`, label: (id) => `model ${id}` },
};

/** Every kind the table knows, in declaration order. Exported so a test can
 * assert the table is total — a kind added to `EntityKind` without a route
 * row would resolve to nothing at runtime and render as plain text, which is
 * exactly the silent degrade this module exists to prevent. */
export const ENTITY_KINDS = Object.keys(ENTITY_ROUTES) as EntityKind[];

function short(id: string): string {
  return id.length > 10 ? `${id.slice(0, 10)}…` : id;
}

/** Truncates an id to `chars` characters with an ellipsis, leaving anything
 * shorter untouched. The rendering half of the "short id + full id in a
 * tooltip" pattern every id-bearing table cell uses. */
export function shortenId(id: string, chars: number): string {
  if (!id || chars <= 0 || id.length <= chars) return id;
  return `${id.slice(0, chars)}…`;
}

/** Resolves one entity kind + id straight to a react-router target, without
 * going through the sb:// scheme. Returns null when the reference cannot
 * honestly be linked — an unknown kind, or a missing id for a kind that
 * requires one — so a caller renders plain text instead of a dead link. */
export function entityLinkTarget(kind: EntityKind, id: string): string | null {
  const route = ENTITY_ROUTES[kind];
  if (!route) return null;
  if (route.hasId && !id) return null;
  return route.to(route.hasId ? id : "");
}

/** The short human label for an entity kind + id — the link text a caller
 * uses when it has nothing better (assistant prose, an aria-label). */
export function entityLinkLabel(kind: EntityKind, id: string): string {
  const route = ENTITY_ROUTES[kind];
  return route ? route.label(id) : id;
}

// -----------------------------------------------------------------------------
// sb:// URI parsing + resolution.
// -----------------------------------------------------------------------------

export interface ParsedSbUri {
  kind: EntityKind;
  id: string; // "" for id-less kinds
}

const SB_URI_RE = /^sb:\/\/([a-z-]+)(?:\/([A-Za-z0-9_.:-]+))?$/;

/** Parses one `sb://<kind>/<id>` reference. Returns null for anything else —
 * an unknown kind, malformed id, or a URI missing its id when the kind
 * requires one. */
export function parseSbUri(uri: string): ParsedSbUri | null {
  const m = SB_URI_RE.exec(uri.trim());
  if (!m) return null;
  const kind = m[1] as EntityKind;
  const route = ENTITY_ROUTES[kind];
  if (!route) return null;
  const id = m[2] ?? "";
  if (route.hasId && id === "") return null;
  return { kind, id };
}

export interface ResolvedEntityLink {
  to: string;
  label: string;
}

/** Resolves an already-parsed sb:// reference to a react-router target +
 * fallback label. Table-driven — see ENTITY_ROUTES above. */
export function resolveEntityLink(ref: ParsedSbUri): ResolvedEntityLink {
  const route = ENTITY_ROUTES[ref.kind];
  return { to: route.to(ref.id), label: route.label(ref.id) };
}

/** Convenience: parse + resolve an sb:// URI in one call. Returns null for
 * anything parseSbUri rejects. */
export function resolveSbUri(uri: string): ResolvedEntityLink | null {
  const parsed = parseSbUri(uri);
  return parsed ? resolveEntityLink(parsed) : null;
}

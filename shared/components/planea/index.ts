// Plane A components - the pure, presentational pieces of the hosted-app
// observability views, promoted out of the org dashboard (web2/src/pages/obs)
// for Plane A B5-0 (2026-11-19) so the node dashboard's "Your apps" pages
// render the same design over the node's /api/obs/*. See
// docs/app-design-system.md "Plane A components".
//
// App behaviour is injected: cost through the PlaneAMoneyProvider slot
// (money.tsx), router links through render callbacks, the org's extras
// (annotation row, KPI strip, admission panel) through TraceInspectorView's
// slots. Nothing here fetches, routes, reads app state, or couples to a
// help drawer.

export * from "./types";
export * from "./money";
export * from "./costSource";
export * from "./costCell";
export * from "./chips";
export * from "./identity";
export * from "./AgentGraphSvg";
export * from "./GroupTable";
export * from "./inspector";
export * from "./analytics";
export * from "./evals";
export * from "./scorers";
export * from "./prompts";
export * from "./promptRollout";
export * from "./explorerFilters";
export * from "./explorerViewsModel";
export * from "./savedViews";
export * from "./liveTail";
